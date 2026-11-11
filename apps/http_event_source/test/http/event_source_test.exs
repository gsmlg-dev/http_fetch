defmodule HTTP.EventSourceTest do
  use ExUnit.Case, async: false

  alias HTTP.EventSource
  alias HTTP.EventSource.Event.Error
  alias HTTP.EventSource.Event.Message
  alias HTTP.EventSource.Event.Open

  @certfile Path.expand("../support/fixtures/localhost.pem", __DIR__)
  @cacertfile Path.expand("../support/fixtures/localhost-ca.pem", __DIR__)
  @keyfile Path.expand("../support/fixtures/localhost.key", __DIR__)

  test "defines browser ready state constants" do
    assert EventSource.connecting() == 0
    assert EventSource.open() == 1
    assert EventSource.closed() == 2
  end

  @tag :integration
  test "connects, receives events, and closes" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(
        body: "event: add\nid: 1\ndata: 123\n\n",
        close: false
      )

    source =
      EventSource.new("http://127.0.0.1:#{port}/events",
        with_credentials: true,
        reconnect_time: 10
      )

    assert %EventSource{} = source
    assert EventSource.url(source) == "http://127.0.0.1:#{port}/events"
    assert EventSource.with_credentials(source) == true

    assert_receive {:event_source_server_request, request}, 1_000
    assert request =~ "Accept: text/event-stream"
    assert request =~ "Cache-Control: no-cache"

    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert EventSource.ready_state(source) == EventSource.open()

    assert_receive {EventSource, ^source, %Message{type: "add", data: "123", last_event_id: "1"}},
                   1_000

    assert EventSource.last_event_id(source) == "1"
    assert :ok = EventSource.close(source)
    assert EventSource.ready_state(source) == EventSource.closed()
    assert_receive :event_source_server_closed, 1_000
  end

  @tag :integration
  test "reconnects with last event id after EOF" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(
        responses: [
          [body: "id: 7\ndata: first\n\n"],
          [body: "data: second\n\n", close: false]
        ]
      )

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {:event_source_server_request, first_request}, 1_000
    refute first_request =~ "Last-Event-ID"
    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert_receive {EventSource, ^source, %Message{data: "first", last_event_id: "7"}}, 1_000
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 1_000

    assert_receive {:event_source_server_request, second_request}, 1_000
    assert second_request =~ "Last-Event-ID: 7"
    assert_receive {EventSource, ^source, %Open{}}, 1_000

    assert_receive {EventSource, ^source, %Message{data: "second", last_event_id: "7"}},
                   1_000

    assert :ok = EventSource.close(source)
  end

  @tag :integration
  test "stops on 204 responses" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(status: 204, content_type: nil, body: "")

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Error{reason: {:http_status, 204}}}, 1_000
    assert EventSource.ready_state(source) == EventSource.closed()
  end

  @tag :integration
  test "stops on invalid content type" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(content_type: "application/json", body: "{}")

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Error{reason: :invalid_content_type}}, 1_000
    assert EventSource.ready_state(source) == EventSource.closed()
  end

  @tag :integration
  test "honors retry fields from the stream" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(body: "retry: 25\ndata: ready\n\n", close: false)

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert_receive {EventSource, ^source, %Message{data: "ready"}}, 1_000
    assert EventSource.reconnect_time(source) == 25
    assert :ok = EventSource.close(source)
  end

  @tag :integration
  test "delivers events over verified TLS 1.3 for each backend" do
    for backend <- [nil, :ex_ssl] do
      {:ok, _server, port} =
        HTTPEventSource.TestServer.start_link(
          tls: true,
          certfile: @certfile,
          keyfile: @keyfile,
          body: "data: secure\n\n",
          close: false
        )

      source =
        EventSource.new("https://127.0.0.1:#{port}/events",
          tls_backend: backend,
          ssl: [cacertfile: @cacertfile]
        )

      assert_receive {EventSource, ^source, %Open{}}, 1_000
      assert_receive {EventSource, ^source, %Message{data: "secure"}}, 1_000
      assert :ok = EventSource.close(source)
      assert_receive :event_source_server_closed, 1_000
    end
  end

  @tag :integration
  test "retains the configured TLS backend across reconnects" do
    previous = Application.get_env(:http_core, :tls_backend)
    on_exit(fn -> restore_tls_backend(previous) end)
    Application.put_env(:http_core, :tls_backend, :ex_ssl)

    {:ok, server, port} =
      HTTPEventSource.TestServer.start_link(
        tls: true,
        certfile: @certfile,
        keyfile: @keyfile,
        responses: [
          [body: "data: first\n\n", wait_for: :close_first_response],
          [body: "data: second\n\n", close: false]
        ]
      )

    source =
      EventSource.new("https://127.0.0.1:#{port}/events",
        ssl: [cacertfile: @cacertfile],
        reconnect_time: 10
      )

    assert_receive {:event_source_server_request, _first_request}, 1_000
    assert_receive {EventSource, ^source, %Message{data: "first"}}, 1_000
    Application.put_env(:http_core, :tls_backend, :invalid)
    refute_receive {:event_source_server_request, _request}, 50
    send(server, :close_first_response)
    assert_receive {EventSource, ^source, %Message{data: "second"}}, 1_000
    assert :ok = EventSource.close(source)
  end

  test "rejects invalid constructor input synchronously" do
    assert {:error, {:unsupported_scheme, "ftp"}} = EventSource.new("ftp://example.com/events")
  end

  test "rejects URLs whose request target cannot be sent" do
    assert {:error, :invalid_url} = EventSource.new("http://127.0.0.1:1/x y")
    assert {:error, :invalid_url} = EventSource.new("http://127.0.0.1:1/x?a=\x01")
    assert {:error, :invalid_url} = EventSource.new("http://127.0.0.1:1/x\x7F")
  end

  @tag :integration
  test "fails instead of reconnecting forever once cleanup capacity stays exhausted" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listener)

    source =
      EventSource.new("https://127.0.0.1:#{port}/events",
        reconnect_time: 10,
        connect_timeout: 10_000
      )

    # Killing an opening dial leaves its attempt cleanup unconfirmed for life.
    for _ <- 1..2 do
      worker = wait_for_worker(source.pid)
      Process.exit(worker, :kill)

      assert_receive {EventSource, ^source, %Error{reason: {:connect_worker_down, :killed}}},
                     2_000
    end

    assert_receive {EventSource, ^source, %Error{reason: :cleanup_capacity}}, 2_000
    assert_receive {EventSource, ^source, %Error{reason: :cleanup_capacity}}, 2_000
    assert_receive {EventSource, ^source, %Error{reason: :cleanup_capacity}}, 2_000
    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {EventSource, ^source, %Error{}}, 300
    :gen_tcp.close(listener)
  end

  defp wait_for_worker(pid, attempts \\ 100) do
    case :sys.get_state(pid).worker do
      worker when is_pid(worker) ->
        worker

      _ when attempts > 0 ->
        Process.sleep(10)
        wait_for_worker(pid, attempts - 1)
    end
  end

  @tag :integration
  test "fails permanently on a redirect to an unsendable request target" do
    {:ok, _server, port} =
      HTTPEventSource.TestServer.start_link(
        status: 307,
        content_type: nil,
        headers: [{"location", "/x y"}],
        body: ""
      )

    source = EventSource.new("http://127.0.0.1:#{port}/events", reconnect_time: 10)

    assert_receive {EventSource, ^source, %Error{reason: :invalid_redirect}}, 1_000
    assert EventSource.ready_state(source) == EventSource.closed()
    refute_receive {EventSource, ^source, %Error{}}, 100
  end

  @tag :integration
  test "crashed dial attempts release cleanup capacity across reconnects" do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(listener)

    source =
      EventSource.new("http://127.0.0.1:#{port}/events",
        reconnect_time: 20,
        socket_opts: [nodelay: :invalid]
      )

    reasons =
      for _ <- 1..6 do
        assert_receive {EventSource, ^source, %Error{reason: reason}}, 2_000
        reason
      end

    refute :cleanup_capacity in reasons
    assert Enum.all?(reasons, &match?({:connect_worker_down, _}, &1))
    assert EventSource.ready_state(source) == EventSource.connecting()
    assert :ok = EventSource.close(source)
    :gen_tcp.close(listener)
  end

  @tag :integration
  test "finalizes events when TLS closes before a delayed consumer rearms" do
    {:ok, server, port} =
      HTTPEventSource.TestServer.start_link(
        tls: true,
        certfile: @certfile,
        keyfile: @keyfile,
        body: fn ->
          receive do
            :send_body -> "data: final\r\r"
          after
            5_000 -> flunk("consumer did not release the server")
          end
        end
      )

    source =
      EventSource.new("https://127.0.0.1:#{port}/events",
        tls_backend: :ex_ssl,
        ssl: [cacertfile: @cacertfile],
        reconnect_time: 60_000
      )

    assert_receive {EventSource, ^source, %Open{}}, 5_000
    %{socket: %{pid: tls_pid}} = :sys.get_state(source.pid)
    monitor = Process.monitor(tls_pid)
    :ok = :sys.suspend(source.pid)

    # Let TLS deliver data and its terminal notification while the consumer is
    # paused. Rearming after it parses the data now necessarily returns :closed.
    try do
      send(server, :send_body)
      assert_receive {:DOWN, ^monitor, :process, ^tls_pid, _}, 5_000
    after
      :sys.resume(source.pid)
    end

    assert_receive {EventSource, ^source, %Message{data: "final"}}, 5_000
    assert_receive {EventSource, ^source, %Error{reason: :eof}}, 5_000
    assert :ok = EventSource.close(source)
  end

  defp restore_tls_backend(nil), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_tls_backend(value), do: Application.put_env(:http_core, :tls_backend, value)
end
