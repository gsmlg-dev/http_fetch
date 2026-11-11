defmodule HTTP.RetryTest do
  use ExUnit.Case, async: false

  # Each attempt pops one scripted step and reports it to the test process.
  defmodule ScriptedAdapter do
    @behaviour HTTP.Adapter

    @impl true
    def prepare(_request, context), do: {:ok, context}

    @impl true
    def execute(request, {script, observer}, signal) do
      step =
        Agent.get_and_update(script, fn
          [step | rest] -> {step, rest}
          [] -> {:exhausted, []}
        end)

      send(observer, {:attempt, request.method, request.transport_options[:timeout]})
      if signal, do: HTTP.AbortController.set_request_id(signal, self())
      run(step, observer)
    end

    defp run({:sleep, ms, step}, observer) do
      Process.sleep(ms)
      run(step, observer)
    end

    defp run({:error, reason}, _observer), do: {:error, reason}
    defp run({:status, status}, _observer), do: HTTP.Response.new(status: status)

    defp run({:status, status, headers}, _observer),
      do: HTTP.Response.new(status: status, headers: HTTP.Headers.new(headers))

    defp run({:stream, status}, observer) do
      {:ok, stream} = HTTP.Stream.start_link(0, [], response_body: true, telemetry: false)
      Process.unlink(stream)
      send(observer, {:response_stream, stream})
      HTTP.Response.new(status: status, body: stream)
    end

    defp run(:exhausted, _observer), do: {:error, :script_exhausted}
  end

  defp fetch(steps, opts) do
    {:ok, script} = Agent.start_link(fn -> steps end)

    "https://retry.test/resource"
    |> HTTP.fetch([adapter: {ScriptedAdapter, {script, self()}}, retry_delay: 0] ++ opts)
    |> HTTP.Promise.await(10_000)
  end

  defp attempts do
    receive do
      {:attempt, _, _} -> 1 + attempts()
    after
      0 -> 0
    end
  end

  defp with_telemetry(events, fun) do
    ref = make_ref()
    parent = self()
    id = {__MODULE__, ref}

    :telemetry.attach_many(
      id,
      events,
      fn event, measurements, metadata, _ ->
        send(parent, {ref, event, measurements, metadata})
      end,
      nil
    )

    try do
      fun.(ref)
    after
      :telemetry.detach(id)
    end
  end

  test "the default performs exactly one attempt" do
    assert %HTTP.Response{status: 503} = fetch([{:status, 503}, {:status, 200}], retry_delay: nil)
    assert attempts() == 1
  end

  test ":transient retries idempotent requests on 408/429/500/502/503/504" do
    for status <- [408, 429, 500, 502, 503, 504] do
      assert %HTTP.Response{status: 200} =
               fetch([{:status, status}, {:status, 200}], retry: :transient)

      assert attempts() == 2
    end

    for status <- [400, 404, 501, 505] do
      assert %HTTP.Response{status: ^status} =
               fetch([{:status, status}, {:status, 200}], retry: :transient)

      assert attempts() == 1
    end
  end

  test "built-in modes retry only idempotent methods" do
    for method <- [:get, :head, :options, :put, :delete, "TRACE"] do
      assert %HTTP.Response{status: 200} =
               fetch([{:status, 503}, {:status, 200}], retry: :transient, method: method)

      assert attempts() == 2
    end

    for method <- [:post, :patch, "LOCK"] do
      assert %HTTP.Response{status: 503} =
               fetch([{:status, 503}, {:status, 200}], retry: :transient, method: method)

      assert {:error, :econnrefused} =
               fetch([{:error, :econnrefused}, {:status, 200}],
                 retry: :safe_transient,
                 method: method
               )

      assert attempts() == 2
    end
  end

  test "transport failures without a response are retried by both modes" do
    for mode <- [:transient, :safe_transient],
        reason <- [
          :econnrefused,
          :connect_timeout,
          :closed,
          :econnreset,
          :ehostunreach,
          :enetunreach
        ] do
      assert %HTTP.Response{status: 200} = fetch([{:error, reason}, {:status, 200}], retry: mode)
      assert attempts() == 2
    end

    for reason <- [:nxdomain, {:tls_alert, {:bad_certificate, ~c"x"}}, :invalid_http_response] do
      assert {:error, ^reason} = fetch([{:error, reason}, {:status, 200}], retry: :transient)
      assert attempts() == 1
    end
  end

  test ":safe_transient never retries a status the server chose to send" do
    assert %HTTP.Response{status: 503} =
             fetch([{:status, 503}, {:status, 200}], retry: :safe_transient)

    assert attempts() == 1
  end

  test "max_retries bounds the number of additional attempts" do
    steps = List.duplicate({:status, 503}, 10)
    assert %HTTP.Response{status: 503} = fetch(steps, retry: :transient)
    assert attempts() == 4

    assert %HTTP.Response{status: 503} = fetch(steps, retry: :transient, max_retries: 1)
    assert attempts() == 2

    assert %HTTP.Response{status: 503} = fetch(steps, retry: :transient, max_retries: 0)
    assert attempts() == 1
  end

  test "a custom function overrides classification" do
    parent = self()

    decide = fn request, result ->
      send(parent, {:decide, request.method, result})
      match?(%HTTP.Response{status: 409}, result) or result == {:error, :nxdomain}
    end

    assert %HTTP.Response{status: 201} =
             fetch([{:status, 409}, {:error, :nxdomain}, {:status, 201}],
               retry: decide,
               method: :post
             )

    assert attempts() == 3
    assert_received {:decide, :post, %HTTP.Response{status: 409}}
    assert_received {:decide, :post, {:error, :nxdomain}}
    assert_received {:decide, :post, %HTTP.Response{status: 201}}
  end

  test "a custom function cannot replay aborted, expired or streamed-upload attempts" do
    always = fn _request, _result -> true end

    assert {:error, :aborted} = fetch([{:error, :aborted}, {:status, 200}], retry: always)
    assert attempts() == 1

    assert {:error, :timeout} = fetch([{:error, :request_timeout}, {:status, 200}], retry: always)
    assert attempts() == 1

    {:ok, upload} = HTTP.Stream.start_link(0, [], telemetry: false)

    assert %HTTP.Response{status: 503} =
             fetch([{:status, 503}, {:status, 200}],
               retry: always,
               method: :put,
               body: upload,
               duplex: "half"
             )

    assert attempts() == 1
  end

  @tag :capture_log
  test "an invalid custom function result raises in the request worker" do
    Process.flag(:trap_exit, true)

    assert {{%ArgumentError{message: message}, _}, _} =
             catch_exit(fetch([{:status, 503}], retry: fn _, _ -> :yes end))

    assert message =~ "must return a boolean"
  end

  test "retry_delay accepts milliseconds or a function of the retry number" do
    with_telemetry([[:http_fetch, :request, :retry]], fn ref ->
      assert %HTTP.Response{status: 200} =
               fetch([{:status, 503}, {:status, 503}, {:status, 200}],
                 retry: :transient,
                 retry_delay: fn attempt -> attempt * 10 end
               )

      assert_received {^ref, _, %{attempt: 1, delay: 10}, _}
      assert_received {^ref, _, %{attempt: 2, delay: 20}, _}

      assert %HTTP.Response{status: 200} =
               fetch([{:status, 503}, {:status, 200}], retry: :transient, retry_delay: 15)

      assert_received {^ref, _, %{attempt: 1, delay: 15}, _}
    end)
  end

  test "the default delay is exponential and capped" do
    assert Enum.map(1..8, &HTTP.Retry.default_delay/1) ==
             [500, 1_000, 2_000, 4_000, 8_000, 10_000, 10_000, 10_000]
  end

  test "Retry-After delta-seconds and HTTP-date are honored on 429 and 503" do
    with_telemetry([[:http_fetch, :request, :retry]], fn ref ->
      started = System.monotonic_time(:millisecond)

      assert %HTTP.Response{status: 200} =
               fetch([{:status, 503, [{"retry-after", "1"}]}, {:status, 200}],
                 retry: :transient
               )

      assert System.monotonic_time(:millisecond) - started >= 1_000
      assert_received {^ref, _, %{attempt: 1, delay: 1_000}, %{reason: 503}}

      past = "Sun, 06 Nov 1994 08:49:37 GMT"

      assert %HTTP.Response{status: 200} =
               fetch([{:status, 429, [{"retry-after", past}]}, {:status, 200}],
                 retry: :transient,
                 retry_delay: 5_000
               )

      assert_received {^ref, _, %{attempt: 1, delay: 0}, %{reason: 429}}

      # Retry-After is not consulted for other statuses.
      assert %HTTP.Response{status: 200} =
               fetch([{:status, 502, [{"retry-after", "60"}]}, {:status, 200}],
                 retry: :transient
               )

      assert_received {^ref, _, %{attempt: 1, delay: 0}, %{reason: 502}}
    end)
  end

  test "HTTP-date forms parse to a delay relative to now" do
    now = ~U[1994-11-06 08:49:30Z]

    for value <- [
          "Sun, 06 Nov 1994 08:49:37 GMT",
          "Sunday, 06-Nov-94 08:49:37 GMT",
          "Sun Nov  6 08:49:37 1994"
        ] do
      assert HTTP.Retry.retry_after(value, now) == {:ok, 7_000}
    end

    assert HTTP.Retry.retry_after("120", now) == {:ok, 120_000}
    assert HTTP.Retry.retry_after("Sun, 06 Nov 1994 08:49:00 GMT", now) == {:ok, 0}

    for value <- ["", "-1", "1.5", "soon", "Sun, 32 Nov 1994 08:49:37 GMT"] do
      assert HTTP.Retry.retry_after(value, now) == :error
    end
  end

  test "a Retry-After wait that reaches the deadline returns the last response" do
    started = System.monotonic_time(:millisecond)

    assert %HTTP.Response{status: 503} =
             fetch([{:status, 503, [{"retry-after", "30"}]}, {:status, 200}],
               retry: :transient,
               timeout: 2_000
             )

    assert System.monotonic_time(:millisecond) - started < 1_000
    assert attempts() == 1
  end

  test "one timeout bounds every attempt and delay" do
    started = System.monotonic_time(:millisecond)

    result =
      fetch(
        [{:sleep, 150, {:status, 503}}, {:sleep, 150, {:status, 503}}, {:status, 200}],
        retry: :transient,
        retry_delay: 100,
        timeout: 400
      )

    elapsed = System.monotonic_time(:millisecond) - started
    assert elapsed < 1_000
    assert %HTTP.Response{status: 503} = result

    assert_received {:attempt, :get, 400}
    assert_received {:attempt, :get, remaining}
    assert remaining < 400 - 150 - 100 + 20
    refute_received {:attempt, _, _}
  end

  test "abort during a retry delay stops the fetch" do
    controller = HTTP.AbortController.new()
    {:ok, script} = Agent.start_link(fn -> [{:status, 503}, {:status, 200}] end)

    promise =
      HTTP.fetch("https://retry.test/",
        adapter: {ScriptedAdapter, {script, self()}},
        retry: :transient,
        retry_delay: 5_000,
        signal: controller
      )

    assert_receive {:attempt, :get, _}
    Process.sleep(50)
    started = System.monotonic_time(:millisecond)
    HTTP.AbortController.abort(controller)
    assert HTTP.Promise.await(promise, 2_000) == {:error, :aborted}
    assert System.monotonic_time(:millisecond) - started < 1_000
    refute_received {:attempt, _, _}
  end

  test "an already aborted signal is never retried" do
    controller = HTTP.AbortController.new()
    HTTP.AbortController.abort(controller)

    assert {:error, :aborted} =
             fetch([{:status, 503}, {:status, 200}], retry: :transient, signal: controller)

    assert attempts() == 1
  end

  test "a retried streamed response body is stopped" do
    assert %HTTP.Response{status: 200} =
             fetch([{:stream, 503}, {:status, 200}], retry: :transient)

    assert_received {:response_stream, stream}
    monitor = Process.monitor(stream)
    assert_receive {:DOWN, ^monitor, :process, ^stream, _}, 1_000
  end

  test "a returned streamed response is final" do
    assert %HTTP.Response{status: 200, body: stream} =
             fetch([{:stream, 200}, {:status, 200}], retry: fn _, _ -> false end)

    assert is_pid(stream) and Process.alive?(stream)
    assert attempts() == 1
    HTTP.Stream.stop(stream, :aborted)
  end

  test "structured errors classify the raw reason and wrap only the final failure" do
    assert {:error, %HTTP.RequestError{reason: :econnrefused}} =
             fetch([{:error, :econnrefused}, {:error, :econnrefused}],
               retry: :transient,
               max_retries: 1,
               error_mode: :structured
             )

    assert attempts() == 2
  end

  test "telemetry reports one start/stop per fetch and one retry event per retry" do
    events = [
      [:http_fetch, :request, :start],
      [:http_fetch, :request, :stop],
      [:http_fetch, :request, :exception],
      [:http_fetch, :request, :retry]
    ]

    with_telemetry(events, fn ref ->
      assert %HTTP.Response{status: 200} =
               fetch([{:error, :econnrefused}, {:status, 503}, {:status, 200}],
                 retry: :transient,
                 retry_delay: 1
               )

      assert_received {^ref, [:http_fetch, :request, :start], _, _}

      assert_received {^ref, [:http_fetch, :request, :retry], %{attempt: 1, delay: 1},
                       %{scheme: :https, reason: :econnrefused} = first}

      assert_received {^ref, [:http_fetch, :request, :retry], %{attempt: 2, delay: 1},
                       %{scheme: :https, reason: 503} = second}

      assert Map.keys(first) == [:reason, :scheme] and Map.keys(second) == [:reason, :scheme]
      assert_received {^ref, [:http_fetch, :request, :stop], _, %{status: 200}}
      refute_received {^ref, _, _, _}

      assert {:error, :econnrefused} =
               fetch([{:error, :econnrefused}, {:error, :econnrefused}],
                 retry: :transient,
                 max_retries: 1
               )

      assert_received {^ref, [:http_fetch, :request, :start], _, _}
      assert_received {^ref, [:http_fetch, :request, :retry], _, _}
      assert_received {^ref, [:http_fetch, :request, :exception], _, %{error: :econnrefused}}
      refute_received {^ref, _, _, _}
    end)
  end

  test "telemetry: false suppresses retry events" do
    with_telemetry([[:http_fetch, :request, :retry]], fn ref ->
      assert %HTTP.Response{status: 200} =
               fetch([{:status, 503}, {:status, 200}], retry: :transient, telemetry: false)

      refute_received {^ref, _, _, _}
    end)
  end
end
