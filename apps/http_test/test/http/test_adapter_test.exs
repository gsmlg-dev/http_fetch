defmodule HTTP.Test.AdapterTest do
  use ExUnit.Case, async: true

  defp fetch(name, opts \\ []) do
    HTTP.fetch(
      "https://unreachable.invalid/path",
      Keyword.merge([adapter: {HTTP.Test, name}], opts)
    )
  end

  test "default HTTP/HTTPS fixtures preserve encoded JSON and ordered duplicate headers" do
    HTTP.Test.expect(:same_name, fn request ->
      assert request.url.path == "/path"
      assert request.method == :get

      HTTP.Test.json(%{ok: true})
      |> HTTP.Test.headers([
        {"content-type", "application/json"},
        {"set-cookie", "a=1"},
        {"set-cookie", "b=2"}
      ])
    end)

    response = fetch(:same_name) |> HTTP.Promise.await()
    assert response.body == ~s({"ok":true})
    assert HTTP.Response.json(response) == {:ok, %{"ok" => true}}

    assert Enum.filter(HTTP.Headers.to_list(response.headers), &(elem(&1, 0) == "set-cookie")) ==
             [{"set-cookie", "a=1"}, {"set-cookie", "b=2"}]

    assert HTTP.RequestCompletion.await(HTTP.Promise.completion(fetch_missing())) ==
             {:error, {:unsupported_completion, :redirect}}

    assert HTTP.Test.verify!() == :ok
  end

  defp fetch_missing, do: fetch(:missing)

  test "same fixture name is independent in concurrent owner processes" do
    tasks =
      for value <- ["one", "two"] do
        Task.async(fn ->
          HTTP.Test.expect(:same_name, fn _ -> HTTP.Test.text(value) end)
          response = fetch(:same_name) |> HTTP.Promise.await()
          assert HTTP.Test.verify!() == :ok
          response.body
        end)
      end

    assert Enum.map(tasks, &Task.await/1) == ["one", "two"]
  end

  test "Task caller chains inherit fixtures and counted expectations are atomic" do
    HTTP.Test.expect(:counted, 24, fn _ -> HTTP.Test.status(204) end)

    results =
      1..24
      |> Task.async_stream(fn _ -> fetch(:counted) |> HTTP.Promise.await() end,
        max_concurrency: 12
      )
      |> Enum.to_list()

    assert Enum.all?(results, &match?({:ok, %HTTP.Response{status: 204}}, &1))
    assert HTTP.Test.verify!() == :ok
  end

  test "expectations are ordered and excess calls cannot fall through to a stub" do
    HTTP.Test.expect(:ordered, fn _ -> HTTP.Test.text("first") end)
    HTTP.Test.expect(:ordered, 2, fn _ -> HTTP.Test.text("next") end)

    assert_raise ArgumentError, ~r/conflicting_fixture_mode/, fn ->
      HTTP.Test.stub(:ordered, fn _ -> HTTP.Test.text("fallback") end)
    end

    assert Enum.map(1..3, fn _ -> fetch(:ordered) |> HTTP.Promise.await() |> Map.fetch!(:body) end) ==
             ["first", "next", "next"]

    assert fetch(:ordered) |> HTTP.Promise.await() == {:error, {:http_test, :unexpected_call}}
    assert_raise HTTP.Test.VerificationError, ~r/unexpected_call/, &HTTP.Test.verify!/0
  end

  defmodule Client do
    use GenServer
    def init(owner), do: {:ok, owner}

    def handle_call(:fetch, _, owner) do
      result =
        HTTP.fetch("http://unreachable.invalid/path", adapter: {HTTP.Test, :server})
        |> HTTP.Promise.await()

      {:reply, result, owner}
    end
  end

  test "independent GenServer requires explicit allowance" do
    HTTP.Test.expect(:server, fn _ -> HTTP.Test.text("allowed") end)
    {:ok, server} = GenServer.start_link(Client, self())
    assert GenServer.call(server, :fetch) == {:error, {:http_test, :no_fixture_or_allowance}}
    owner = self()

    assert Task.async(fn ->
             assert_raise ArgumentError, ~r/only the fixture owner/, fn ->
               HTTP.Test.allow(:server, owner, self())
             end
           end)
           |> Task.await()

    HTTP.Test.allow(:server, self(), server)
    assert GenServer.call(server, :fetch).body == "allowed"
    GenServer.stop(server)
    assert HTTP.Test.verify!() == :ok
  end

  test "common pure request validation runs before callback ownership or execution" do
    parent = self()

    HTTP.Test.stub(:validated, fn _ ->
      send(parent, :invalid_callback_executed)
      HTTP.Test.status(200)
    end)

    assert_raise ArgumentError, ~r/request target/, fn ->
      HTTP.fetch("http://mock.invalid/bad path", adapter: {HTTP.Test, :validated})
    end

    assert_raise ArgumentError, fn ->
      HTTP.fetch("http://mock.invalid/",
        headers: [{"bad\r\nheader", "value"}],
        adapter: {HTTP.Test, :validated}
      )
    end

    assert_raise ArgumentError, ~r/duplex/, fn ->
      HTTP.fetch("http://mock.invalid/",
        method: :post,
        body: self(),
        adapter: {HTTP.Test, :validated}
      )
    end

    refute_receive :invalid_callback_executed
    assert HTTP.Test.verify!() == :ok
  end

  test "buffered multipart validation never opens file streams before fixture ownership" do
    source = File.stream!("/http-test-fixture-never-open/#{System.unique_integer([:positive])}")
    form = HTTP.FormData.new() |> HTTP.FormData.append_file("file", "upload.bin", source)

    HTTP.Test.expect(:multipart, fn request ->
      assert request.body == form
      HTTP.Test.status(201)
    end)

    assert HTTP.fetch("https://mock.invalid/",
             method: :post,
             body: form,
             adapter: {HTTP.Test, :missing_multipart}
           )
           |> HTTP.Promise.await() ==
             {:error, {:http_test, :no_fixture_or_allowance}}

    assert HTTP.fetch("https://mock.invalid/",
             method: :post,
             body: form,
             adapter: {HTTP.Test, :multipart}
           )
           |> HTTP.Promise.await()
           |> Map.fetch!(:status) == 201

    assert HTTP.Test.verify!() == :ok
  end

  test "unknown fixtures reject before DNS, TLS and ManagedTransport admission" do
    assert fetch(:missing) |> HTTP.Promise.await() ==
             {:error, {:http_test, :no_fixture_or_allowance}}

    HTTP.Test.stub(:mock, fn _ -> HTTP.Test.text("mock") end)

    assert fetch(:mock, transport_scope: :does_not_exist) |> HTTP.Promise.await() ==
             {:error, {:http_test, :transport_scope_unsupported}}

    assert fetch(:mock, pool: :does_not_exist) |> HTTP.Promise.await() ==
             {:error, {:http_test, :pool_unsupported}}

    assert fetch(:mock) |> HTTP.Promise.await() |> Map.fetch!(:body) == "mock"
    assert HTTP.Test.verify!() == :ok
  end

  test "unmet expectations fail and freeze further claims" do
    HTTP.Test.expect(:missing_call, fn _ -> HTTP.Test.status(200) end)
    assert_raise HTTP.Test.VerificationError, ~r/unmet_expectation/, &HTTP.Test.verify!/0
    assert fetch(:missing_call) |> HTTP.Promise.await() == {:error, {:http_test, :owner_frozen}}
  end

  test "intentional errors preserve raw and structured contracts" do
    HTTP.Test.stub(:error, fn _ -> HTTP.Test.transport_error(:econnrefused) end)
    assert fetch(:error) |> HTTP.Promise.await() == {:error, :econnrefused}

    assert {:error, %HTTP.RequestError{reason: :econnrefused}} =
             fetch(:error, error_mode: :structured) |> HTTP.Promise.await()

    assert HTTP.Test.verify!() == :ok
  end

  test "structured fixture errors are not wrapped twice" do
    error = %HTTP.RequestError{reason: :closed}
    HTTP.Test.expect(:structured, fn _ -> {:error, error} end)
    assert fetch(:structured, error_mode: :structured) |> HTTP.Promise.await() == {:error, error}
    assert HTTP.Test.verify!() == :ok
  end

  test "default follow only rejects actual redirect candidates and claims one fixture" do
    HTTP.Test.expect(:redirect, fn _ -> HTTP.Test.response(302, "", [{"location", "/next"}]) end)

    assert fetch(:redirect) |> HTTP.Promise.await() ==
             {:error, {:unsupported_test_policy, :redirect_follow}}

    assert HTTP.Test.verify!() == :ok
  end

  test "manual and error redirects mirror single-attempt transport behavior" do
    HTTP.Test.stub(:redirect, fn _ -> HTTP.Test.response(307, "body", [{"location", "/next"}]) end)

    assert fetch(:redirect, redirect: :manual) |> HTTP.Promise.await() |> Map.fetch!(:status) ==
             307

    assert fetch(:redirect, redirect: :error) |> HTTP.Promise.await() == {:error, :redirect}
    assert HTTP.Test.verify!() == :ok
  end

  test "302 without Location and 304 are ordinary responses" do
    for status <- [302, 304] do
      HTTP.Test.expect(:ordinary, fn _ -> HTTP.Test.response(status) end)
    end

    assert Enum.map(1..2, fn _ ->
             fetch(:ordinary) |> HTTP.Promise.await() |> Map.fetch!(:status)
           end) == [302, 304]

    assert HTTP.Test.verify!() == :ok
  end

  test "verify_on_exit retains a successful owner token through owner death" do
    HTTP.Test.verify_on_exit!()
    HTTP.Test.expect(:exit_verify, fn _ -> HTTP.Test.status(200) end)
    assert fetch(:exit_verify) |> HTTP.Promise.await() |> Map.fetch!(:status) == 200
  end

  test "each retried Fetch attempt claims one ordered expectation" do
    parent = self()

    HTTP.Test.expect(:retried, 2, fn request ->
      send(parent, {:attempt, request.method})
      HTTP.Test.status(503)
    end)

    HTTP.Test.expect(:retried, fn _ -> HTTP.Test.text("recovered") end)

    response =
      fetch(:retried, retry: :transient, retry_delay: 0) |> HTTP.Promise.await(5_000)

    assert %HTTP.Response{status: 200, body: "recovered"} = response
    assert_received {:attempt, :get}
    assert_received {:attempt, :get}
    assert HTTP.Test.verify!() == :ok
  end

  test "a retry beyond the registered expectations is an unexpected call" do
    HTTP.Test.expect(:short, fn _ -> HTTP.Test.transport_error(:econnrefused) end)

    assert fetch(:short, retry: :transient, retry_delay: 0) |> HTTP.Promise.await(5_000) ==
             {:error, {:http_test, :unexpected_call}}

    assert_raise HTTP.Test.VerificationError, ~r/unexpected_call/, &HTTP.Test.verify!/0
  end

  test "a retried fixture stream is stopped before the next attempt" do
    parent = self()

    HTTP.Test.expect(:stream_retry, fn _ ->
      HTTP.Test.stream(["unread"], status: 503, observer: parent)
    end)

    HTTP.Test.expect(:stream_retry, fn _ -> HTTP.Test.status(204) end)

    assert %HTTP.Response{status: 204} =
             fetch(:stream_retry, retry: :transient, retry_delay: 0)
             |> HTTP.Promise.await(5_000)

    assert_received {:http_test_stream, stream, _producer}
    refute Process.alive?(stream)
    assert HTTP.Test.verify!() == :ok
  end
end
