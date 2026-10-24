defmodule HTTP.ExSSLPooledCompletionTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :p3_ex_ssl_pool

  alias HTTP.HTTP1.Pool
  alias HTTP.{Promise, RequestCompletion, RequestLifecycle, Response}
  alias HTTP.Transport.ExSSL

  @fixtures Path.expand("../support/fixtures", __DIR__)

  for {version, wire, negotiated} <- [
        {:"tlsv1.2", "tls12", "TLSv1.2"},
        {:"tlsv1.3", "tls13", "TLSv1.3"}
      ] do
    test "verified #{version} reuse releases both request completions" do
      {peer, origin, os_pid} = peer(unquote(wire), ["--gate-response", "2"])
      options = options(unquote(version))
      first = HTTP.fetch(origin <> "/first?x=1", options)
      assert %Response{status: 200} = response = Promise.await(first, 5_000)
      assert Response.read_all(response) == <<0, 255, 10, 13>>

      assert event(peer, "tls") == %{
               "event" => "tls",
               "alpn" => nil,
               "sni" => "localhost",
               "version" => unquote(negotiated)
             }

      assert event(peer, "request") == %{
               "event" => "request",
               "line" => "GET /first?x=1 HTTP/1.1",
               "host" => "localhost:#{URI.parse(origin).port}",
               "body" => "",
               "content_length" => ""
             }

      first_completion = Promise.completion(first)
      assert :ok = RequestCompletion.await(first_completion, 1_000)
      assert :ok = RequestCompletion.await(first_completion, 0)

      waiters =
        for _ <- 1..3, do: Task.async(fn -> RequestCompletion.await(first_completion, 100) end)

      assert Enum.all?(waiters, &(Task.await(&1) == :ok))

      body = <<0, 13, 10, 255, 42>>
      second = HTTP.fetch(origin <> "/second", options ++ [method: :post, body: body])

      assert event(peer, "request") == %{
               "event" => "request",
               "line" => "POST /second HTTP/1.1",
               "host" => "localhost:#{URI.parse(origin).port}",
               "body" => Base.encode16(body, case: :lower),
               "content_length" => "5"
             }

      assert event(peer, "response_waiting") == %{"event" => "response_waiting", "request" => 2}
      assert :ok = RequestCompletion.abort_and_await(first_completion, 0)
      assert {:error, :cleanup_pending} = RequestCompletion.await(Promise.completion(second), 20)
      assert Port.command(peer, "respond\n")
      assert %Response{status: 200} = response = Promise.await(second, 5_000)
      assert Response.read_all(response) == <<0, 255, 10, 13>>
      assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)

      assert %{"event" => "closed", "transport" => closure} = event(peer, "closed")
      assert closure in ["eof", "reset"]

      assert event(peer, "complete") == %{
               "event" => "complete",
               "connections" => 1,
               "requests" => 2
             }

      assert_peer_stopped(peer, origin, os_pid)

      assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
      assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
    end

    for terminal <- [:abort, :deadline] do
      test "#{version} queued checkout #{terminal} sends no POST and joins current cleanup" do
        {peer, origin, os_pid} = peer(unquote(wire), ["--requests", "1"])
        pool = Process.whereis(Pool)
        options = options(unquote(version))
        first = HTTP.fetch(origin <> "/first", options)
        assert %Response{status: 200} = Promise.await(first)
        assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
        assert event(peer, "tls")["version"] == unquote(negotiated)
        assert event(peer, "request")["line"] == "GET /first HTTP/1.1"
        :sys.suspend(pool)

        timeout = if unquote(terminal) == :deadline, do: 100, else: 3_000

        second =
          HTTP.fetch(
            origin <> "/second",
            Keyword.merge(options, method: :post, body: "never", timeout: timeout)
          )

        try do
          queued(pool, :checkout)

          case unquote(terminal) do
            :abort ->
              assert {:error, :cleanup_pending} =
                       RequestCompletion.abort_and_await(Promise.completion(second), 20)

            :deadline ->
              witness = :erlang.start_timer(110, self(), :request_expired)
              assert_receive {:timeout, ^witness, :request_expired}, 1_000
          end

          expected = if unquote(terminal) == :abort, do: :aborted, else: :request_timeout
          assert {:error, ^expected} = Promise.await(second, 1_500)
          assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
        after
          :sys.resume(pool)
        end

        assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)
        assert_closed(peer, 1)
        assert_peer_stopped(peer, origin, os_pid)
        wait_until(fn -> origin_entries(pool, origin) == [] end)
      end
    end

    test "#{version} accepted cancellation before checkin prevents idle publication" do
      {peer, origin, os_pid} = peer(unquote(wire), ["--requests", "1", "--gate-response", "1"])
      pool = Process.whereis(Pool)
      promise = HTTP.fetch(origin <> "/first", options(unquote(version)))
      assert event(peer, "tls")["version"] == unquote(negotiated)
      assert event(peer, "request")["line"] == "GET /first HTTP/1.1"
      assert event(peer, "response_waiting")["request"] == 1
      :sys.suspend(pool)

      try do
        assert Port.command(peer, "respond\n")
        queued(pool, :prepare)

        assert {:error, :cleanup_pending} =
                 RequestCompletion.abort_and_await(Promise.completion(promise), 20)

        # The owner must finish even while prepare remains queued at the pool.
        assert :ok = RequestCompletion.await(Promise.completion(promise), 1_500)
      after
        :sys.resume(pool)
      end

      assert %Response{status: 200} = Promise.await(promise)
      assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
      assert_closed(peer, 1)
      assert_peer_stopped(peer, origin, os_pid)
      assert origin_entries(pool, origin) == []
    end

    test "#{version} reused peer closure never replays the POST and confirms cleanup" do
      {peer, origin, os_pid} = peer(unquote(wire), ["--drop"])
      options = options(unquote(version))
      first = HTTP.fetch(origin <> "/first", options)
      assert %Response{status: 200} = Promise.await(first)
      assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
      assert event(peer, "tls")["version"] == unquote(negotiated)
      assert event(peer, "request")["line"] == "GET /first HTTP/1.1"
      second = HTTP.fetch(origin <> "/second", options ++ [method: :post, body: "once"])
      assert {:error, _} = Promise.await(second)
      assert event(peer, "request")["body"] == Base.encode16("once", case: :lower)
      assert :ok = RequestCompletion.await(Promise.completion(second), 1_000)

      assert event(peer, "complete") == %{
               "event" => "complete",
               "connections" => 1,
               "requests" => 2
             }

      assert_peer_stopped(peer, origin, os_pid)
    end

    test "#{version} queued checkin activation releases caller without late offer or publication" do
      {peer, origin, os_pid} = peer(unquote(wire), ["--requests", "1"])
      options = options(unquote(version))
      first = HTTP.fetch(origin <> "/first", options)
      assert %Response{status: 200} = Promise.await(first)
      assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
      assert event(peer, "tls")["version"] == unquote(negotiated)
      assert event(peer, "request")["line"] == "GET /first HTTP/1.1"
      parent = self()
      delayed_pool = Task.async(fn -> delay_checkin_activation(parent) end)
      fetch_options = HTTP.FetchOptions.new(options)

      request = %HTTP.Request{
        url: URI.parse(origin <> "/unused"),
        transport_options: HTTP.FetchOptions.to_transport_options(fetch_options)
      }

      completion = RequestCompletion.new(fetch_options, request)

      owner =
        Task.async(fn ->
          receive do: (:start -> :ok)
          Process.put(RequestLifecycle, completion.tracker)

          try do
            assert {:ok, socket} =
                     Pool.checkout(
                       request,
                       System.monotonic_time(:millisecond) + 1_000
                     )

            request = %{
              request
              | transport_options:
                  Keyword.put(request.transport_options, :http1_pool, delayed_pool.pid)
            }

            Pool.checkin(
              request,
              ExSSL,
              socket,
              System.monotonic_time(:millisecond) + 100
            )
          after
            RequestLifecycle.complete(completion.tracker)
          end
        end)

      RequestLifecycle.register(completion.tracker, owner.pid, :owner)
      send(owner.pid, :start)
      assert_receive {:activation_queued, delayed_pid}, 1_000
      assert delayed_pid == delayed_pool.pid
      assert {:error, :handoff_unconfirmed} = Task.await(owner, 500)
      assert :ok = RequestCompletion.await(completion, 1_000)
      send(delayed_pool.pid, :resume_activation)
      assert :expired = Task.await(delayed_pool, 1_000)
      assert_closed(peer, 1)
      assert_peer_stopped(peer, origin, os_pid)
    end

    test "#{version} lost checkout ACK preserves accepted owner and replays the same transfer" do
      {peer, origin, os_pid} = peer(unquote(wire), [])
      options = options(unquote(version))
      first = HTTP.fetch(origin <> "/first", options)
      assert %Response{status: 200} = Promise.await(first)
      assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
      assert event(peer, "tls")["version"] == unquote(negotiated)
      assert event(peer, "request")["line"] == "GET /first HTTP/1.1"
      pool = Process.whereis(Pool)
      assert [{_, entry}] = origin_entries(pool, origin)
      parent = self()
      tracker = Task.async(fn -> withhold_checkout_ack(parent) end)

      request = %HTTP.Request{
        url: URI.parse(origin <> "/second"),
        transport_options:
          options |> HTTP.FetchOptions.new() |> HTTP.FetchOptions.to_transport_options()
      }

      owner =
        Task.async(fn ->
          Process.put(RequestLifecycle, tracker.pid)
          result = Pool.checkout(request, System.monotonic_time(:millisecond) + 1_000)
          send(parent, {:checkout_ack_result, self(), result})

          receive do
            :send_post ->
              assert :ok =
                       ExSSL.send(entry.socket, [
                         "POST /second HTTP/1.1\r\nHost: localhost:",
                         Integer.to_string(URI.parse(origin).port),
                         "\r\nContent-Length: 4\r\n\r\nonce"
                       ])

              assert {:ok, response} = ExSSL.recv(entry.socket, 0, 1_000)

              assert response ==
                       "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n" <> <<0, 255, 10, 13>>

              send(parent, :accepted_owner_survived)

              receive do
                :finish -> :ok
              after
                2_000 -> flunk("accepted owner was not released")
              end
          after
            2_000 -> flunk("accepted owner did not receive its wire gate")
          end
        end)

      assert_receive {:checkout_committed, carrier}, 1_000
      assert_receive {:checkout_ack_result, owner_pid, {:error, :handoff_unconfirmed}}, 1_500
      assert owner_pid == owner.pid
      assert RequestLifecycle.transfer_state(carrier) == :accepted
      assert origin_entries(pool, origin) == []
      send(owner.pid, :send_post)
      assert event(peer, "request")["body"] == Base.encode16("once", case: :lower)
      assert_receive :accepted_owner_survived, 1_000
      send(tracker.pid, :recover_ack)
      assert :ok = Task.await(tracker, 2_000)
      assert_closed(peer, 2)
      assert_peer_stopped(peer, origin, os_pid)
      send(owner.pid, :finish)
      assert :ok = Task.await(owner)
    end
  end

  defp delay_checkin_activation(parent) do
    {:ok, initial} = Pool.init([])

    receive do
      {:"$gen_call", from, {:prepare, _, _, _, _, _} = message} ->
        {:reply, prepared, pending} = Pool.handle_call(message, from, initial)
        GenServer.reply(from, prepared)

        receive do
          {:"$gen_call", activation_from, {:activate_provider, _, _, _} = activation} ->
            send(parent, {:activation_queued, self()})

            receive do
              :resume_activation ->
                {:reply, :expired, empty} =
                  Pool.handle_call(activation, activation_from, pending)

                assert empty.entries == %{}
                :erlang.cancel_timer(pending.expiry_timer)
                GenServer.reply(activation_from, :expired)
                :expired
            after
              2_000 -> flunk("activation resume was not delivered")
            end
        after
          1_000 -> flunk("activation was not queued")
        end
    after
      1_000 -> flunk("prepare was not queued")
    end
  end

  defp withhold_checkout_ack(parent) do
    {:ok, initial} = RequestLifecycle.init({parent, :atomics.new(1, [])})

    receive do
      {:"$gen_call", from, {:accept_provider, carrier, socket, _deadline} = message} ->
        {:reply, :ok, state} = RequestLifecycle.handle_call(message, from, initial)
        send(parent, {:checkout_committed, carrier})

        receive do
          :recover_ack ->
            replay =
              {:accept_provider, carrier, socket, System.monotonic_time(:millisecond) + 250}

            {:reply, :ok, recovered} = RequestLifecycle.handle_call(replay, from, state)

            assert recovered.providers[carrier.handle].lease ==
                     state.providers[carrier.handle].lease

            receive do
              :abort ->
                {:noreply, _} = RequestLifecycle.handle_info(:abort, recovered)

                assert {:ok, %{cleanup: :confirmed}} =
                         SSL.Lifecycle.await(
                           carrier.handle,
                           {:abs_ms, System.monotonic_time(:millisecond) + 1_000}
                         )

                :ok
            after
              1_000 -> flunk("pool did not abort its unacknowledged recipient")
            end
        after
          2_000 -> flunk("lost ACK recovery gate expired")
        end
    after
      1_000 -> flunk("pool did not offer to its named HTTP tracker")
    end
  end

  defp options(version) do
    [
      tls_backend: :ex_ssl,
      http_version: :http1,
      http1_reuse: true,
      http1_idle_timeout: 500,
      redirect: :manual,
      connect_address: {127, 0, 0, 1},
      timeout: 3_000,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem"), versions: [version]]
    ]
  end

  defp peer(version, extra) do
    python = System.find_executable("python3") || raise "python3 is required for independent TLS"

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args:
          [
            "-B",
            Path.expand("../support/managed_h1_alpn_peer.py", __DIR__),
            Path.join(@fixtures, "localhost.pem"),
            Path.join(@fixtures, "localhost.key"),
            "--version",
            version
          ] ++ extra
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)
    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    {port, "https://localhost:#{event(port, "ready")["port"]}", os_pid}
  end

  defp assert_closed(peer, requests) do
    assert %{"event" => "closed", "transport" => closure} = event(peer, "closed")
    assert closure in ["eof", "reset"]

    assert event(peer, "complete") == %{
             "event" => "complete",
             "connections" => 1,
             "requests" => requests
           }
  end

  defp queued(pool, operation) do
    wait_until(fn ->
      {:messages, messages} = Process.info(pool, :messages)

      Enum.any?(messages, fn
        {:"$gen_call", _, request} when is_tuple(request) -> elem(request, 0) == operation
        _ -> false
      end)
    end)
  end

  defp origin_entries(pool, origin) do
    port = URI.parse(origin).port
    Enum.filter(:sys.get_state(pool).entries, fn {_, entry} -> entry.key.port == port end)
  end

  defp wait_until(fun), do: wait_until(fun, System.monotonic_time(:millisecond) + 1_000)

  defp wait_until(fun, deadline) do
    if fun.() do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline, "HTTP actor condition did not settle"

      receive do
      after
        1 -> wait_until(fun, deadline)
      end
    end
  end

  defp event(port, name) do
    receive do
      {^port, {:data, {:eol, data}}} ->
        event = JSON.decode!(data)
        assert event["event"] == name
        event

      {^port, {:exit_status, status}} ->
        flunk("TLS peer exited #{status} before #{name}")
    after
      5_000 -> flunk("missing TLS peer event #{name}")
    end
  end

  defp assert_peer_stopped(peer, origin, os_pid) do
    assert_receive {^peer, {:exit_status, 0}}, 1_000
    assert Port.info(peer) == nil

    {message, status} =
      System.cmd("kill", ["-0", Integer.to_string(os_pid)], stderr_to_stdout: true)

    assert status != 0
    assert message =~ "No such process"

    assert {:error, :econnrefused} =
             :gen_tcp.connect(
               ~c"127.0.0.1",
               URI.parse(origin).port,
               [:binary, active: false],
               1_000
             )
  end
end
