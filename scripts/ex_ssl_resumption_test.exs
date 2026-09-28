# Runtime code is always loaded from the packaged dependency. Fixtures are
# deliberately separate so published mode does not load an ex_ssl checkout.
fixture_dir = System.get_env("EX_SSL_FIXTURE_DIR") || System.fetch_env!("EX_SSL_SOURCE_DIR")

for fixture <- ["signature_fixtures.ex", "client_auth_fixtures.ex"] do
  Code.require_file(Path.join([fixture_dir, "test", "support", fixture]))
end

defmodule CandidateResumptionTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias HTTP.EventSource
  alias HTTP.WebSocket

  @timeout 10_000
  @python Path.join(__DIR__, "ex_ssl_tls12_peer.py")

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "http-resumption-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "HTTP/1.1 only resumes when tickets are enabled", %{fixtures: fixtures} do
    with_peer(fixtures, "resumption", [], fn peer ->
      fetch_pair(peer, fixtures, :auto, [false, true])
    end)

    with_peer(fixtures, "resumption", [], fn peer ->
      fetch_pair(peer, fixtures, :default, [false, false])
    end)
  end

  test "rejected HTTP/1.1 ticket does one verified full handshake per request", %{
    fixtures: fixtures
  } do
    with_peer(fixtures, "resumption", ["--reject-ticket"], fn peer ->
      fetch_pair(peer, fixtures, :auto, [false, false], [false, true])
    end)
  end

  test "HTTP/2 resumption streams a flow-control-sized response", %{fixtures: fixtures} do
    with_peer(fixtures, "resumption-h2", [], fn peer ->
      for {reused, index} <- Enum.with_index([false, true], 1) do
        promise = fetch(peer, fixtures, :http2, :auto)
        assert_handshake(peer, index, reused, "h2")
        response = HTTP.Promise.await(promise, @timeout)
        assert response.status == 200
        assert is_pid(response.stream)
        assert HTTP.Response.get_header(response, "content-length") == "6291456"
        stream = response.stream
        stream_monitor = Process.monitor(stream)
        assert HTTP.Response.read_all(response) == :binary.copy("B", 6 * 1024 * 1024)
        assert_receive {:DOWN, ^stream_monitor, :process, ^stream, :normal}, @timeout
        refute_receive {:stream_end, ^stream}, 0
        refute_receive {:stream_chunk, ^stream, _}, 0
        refute_receive {:stream_chunk, ^stream, _, _}, 0

        assert {:ok, %{"bytes" => 6_291_456, "window_updates" => updates}} =
                 event(peer, "exchange")

        assert updates > 0
        true = Port.command(peer.handle, "go\n")
        assert {:ok, _} = event(peer, "released")
      end
    end)
  end

  test "HTTP/2 defaults to full handshakes and rejected tickets do not add requests", %{
    fixtures: fixtures
  } do
    with_peer(fixtures, "resumption-h2", [], fn peer ->
      h2_pair(peer, fixtures, :default, [false, false])
    end)

    with_peer(fixtures, "resumption-h2", ["--reject-ticket"], fn peer ->
      h2_pair(peer, fixtures, :auto, [false, false], [false, true])
    end)
  end

  test "separate WSS connections resume through upgrade, frame, close, and cleanup", %{
    fixtures: fixtures
  } do
    with_peer(fixtures, "resumption-wss", [], fn peer ->
      wss_pair(peer, fixtures, [false, true])
    end)
  end

  test "disabled and rejected WSS tickets do not duplicate frames", %{fixtures: fixtures} do
    with_peer(fixtures, "resumption-wss", [], fn peer ->
      wss_pair(peer, fixtures, [false, false], :default)
    end)

    with_peer(fixtures, "resumption-wss", ["--reject-ticket"], fn peer ->
      wss_pair(peer, fixtures, [false, false], :auto, [false, true])
    end)
  end

  test "SSE reconnect resumes with Last-Event-ID and its captured backend", %{fixtures: fixtures} do
    previous = Application.get_env(:http_core, :tls_backend, :unset)
    on_exit(fn -> restore_backend(previous) end)
    Application.put_env(:http_core, :tls_backend, :ex_ssl)

    with_peer(fixtures, "resumption-sse", [], fn peer ->
      sse_pair(
        peer,
        fixtures,
        [false, true],
        fn -> Application.put_env(:http_core, :tls_backend, :invalid) end,
        :auto,
        [false, true],
        nil
      )
    end)
  end

  test "disabled and rejected SSE tickets retain one event per connection", %{fixtures: fixtures} do
    with_peer(fixtures, "resumption-sse", [], fn peer ->
      sse_pair(peer, fixtures, [false, false], nil, :default, [false, false])
    end)

    with_peer(fixtures, "resumption-sse", ["--reject-ticket"], fn peer ->
      sse_pair(peer, fixtures, [false, false], nil, :auto, [false, true])
    end)
  end

  defp fetch_pair(peer, fixtures, tickets, expected, offered \\ nil) do
    offered = offered || expected

    for {{reused, ticket_offered}, index} <- Enum.with_index(Enum.zip(expected, offered), 1) do
      promise = fetch(peer, fixtures, :http1, tickets)
      assert_handshake(peer, index, reused, "http/1.1", ticket_offered)
      assert {:ok, %{"bytes" => 6}} = event(peer, "exchange")
      response = HTTP.Promise.await(promise, @timeout)
      assert response.status == 200
      assert HTTP.Response.read_all(response) == "BBBBBB"
    end
  end

  defp h2_pair(peer, fixtures, tickets, expected, offered \\ nil) do
    offered = offered || expected

    for {{reused, ticket_offered}, index} <- Enum.with_index(Enum.zip(expected, offered), 1) do
      promise = fetch(peer, fixtures, :http2, tickets)
      assert_handshake(peer, index, reused, "h2", ticket_offered)
      response = HTTP.Promise.await(promise, @timeout)
      assert is_pid(response.stream)
      assert response.status == 200
      assert HTTP.Response.get_header(response, "content-length") == "6291456"
      stream = response.stream
      stream_monitor = Process.monitor(stream)
      assert HTTP.Response.read_all(response) == :binary.copy("B", 6 * 1024 * 1024)
      assert_receive {:DOWN, ^stream_monitor, :process, ^stream, :normal}, @timeout
      refute_receive {:stream_end, ^stream}, 0
      refute_receive {:stream_chunk, ^stream, _}, 0
      refute_receive {:stream_chunk, ^stream, _, _}, 0
      assert {:ok, %{"bytes" => 6_291_456, "window_updates" => updates}} = event(peer, "exchange")
      assert updates > 0
      true = Port.command(peer.handle, "go\n")
      assert {:ok, _} = event(peer, "released")
    end
  end

  defp wss_pair(peer, fixtures, expected, tickets \\ :auto, offered \\ nil) do
    offered = offered || expected

    for {{reused, ticket_offered}, index} <- Enum.with_index(Enum.zip(expected, offered), 1) do
      socket =
        WebSocket.new("wss://127.0.0.1:#{peer.port}/socket", [],
          tls_backend: :ex_ssl,
          ssl: tls_options(fixtures, "http/1.1", ticket_option(tickets)),
          timeout: @timeout,
          connect_timeout: @timeout
        )

      try do
        assert_handshake(peer, index, reused, "http/1.1", ticket_offered)
        assert {:ok, %{"greeting" => "hello"}} = event(peer, "upgrade")
        assert_receive {WebSocket, ^socket, %HTTP.WebSocket.Event.Open{}}, @timeout

        assert_receive {WebSocket, ^socket, %HTTP.WebSocket.Event.Message{data: "hello"}},
                       @timeout

        assert :ok = WebSocket.send(socket, "resume-echo")

        assert_receive {WebSocket, ^socket,
                        %HTTP.WebSocket.Event.Message{data: "echo:resume-echo"}},
                       @timeout

        socket_pid = socket.pid
        socket_monitor = Process.monitor(socket_pid)
        assert :ok = WebSocket.close(socket, 1000, "done")

        assert_receive {WebSocket, ^socket,
                        %HTTP.WebSocket.Event.Close{code: 1000, was_clean: true}},
                       @timeout

        assert {:ok, %{"bytes" => 11, "frames" => 1}} = event(peer, "exchange")
        assert WebSocket.ready_state(socket) == WebSocket.closed()
        assert_receive {:DOWN, ^socket_monitor, :process, ^socket_pid, reason}, @timeout
        assert reason in [:normal, :noproc]
        refute_receive {WebSocket, ^socket, %HTTP.WebSocket.Event.Message{}}
      after
        _ = WebSocket.close(socket)
      end
    end
  end

  defp sse_pair(
         peer,
         fixtures,
         expected,
         after_first,
         tickets,
         offered,
         tls_backend \\ :ex_ssl
       ) do
    source =
      EventSource.new("https://127.0.0.1:#{peer.port}/events",
        tls_backend: tls_backend,
        reconnect_time: 10,
        connect_timeout: @timeout,
        ssl: tls_options(fixtures, "http/1.1", ticket_option(tickets))
      )

    try do
      assert_handshake(peer, 1, Enum.at(expected, 0), "http/1.1", Enum.at(offered, 0))
      assert {:ok, %{"index" => 1, "last_id_ok" => false}} = event(peer, "request")
      assert_receive {EventSource, ^source, %HTTP.EventSource.Event.Open{}}, @timeout

      assert_receive {EventSource, ^source,
                      %HTTP.EventSource.Event.Message{data: "first", last_event_id: "41"}},
                     @timeout

      assert {:ok, _} = event(peer, "first_ready")
      if after_first, do: after_first.()
      true = Port.command(peer.handle, "go\n")
      assert_handshake(peer, 2, Enum.at(expected, 1), "http/1.1", Enum.at(offered, 1))
      assert {:ok, %{"index" => 2, "last_id_ok" => true}} = event(peer, "request")
      assert_receive {EventSource, ^source, %HTTP.EventSource.Event.Open{}}, @timeout

      assert_receive {EventSource, ^source,
                      %HTTP.EventSource.Event.Message{data: "second", last_event_id: "41"}},
                     @timeout

      assert {:ok, _} = event(peer, "second_ready")
      assert EventSource.last_event_id(source) == "41"
      source_pid = source.pid
      source_monitor = Process.monitor(source_pid)
      assert :ok = EventSource.close(source)
      assert_receive {:DOWN, ^source_monitor, :process, ^source_pid, reason}, @timeout
      assert reason in [:normal, :noproc]
      refute_receive {EventSource, ^source, %HTTP.EventSource.Event.Message{}}
    after
      _ = EventSource.close(source)
    end
  end

  defp fetch(peer, fixtures, :http1, tickets),
    do:
      HTTP.fetch("https://127.0.0.1:#{peer.port}/resumption",
        tls_backend: :ex_ssl,
        ssl: tls_options(fixtures, "http/1.1", ticket_option(tickets)),
        timeout: @timeout,
        connect_timeout: @timeout
      )

  defp fetch(peer, fixtures, :http2, tickets),
    do:
      HTTP.fetch("https://127.0.0.1:#{peer.port}/resumption",
        tls_backend: :ex_ssl,
        http_version: :http2,
        ssl: tls_options(fixtures, "h2", ticket_option(tickets)),
        timeout: @timeout,
        connect_timeout: @timeout
      )

  defp tls_options(fixtures, alpn, extra) do
    Keyword.merge(
      [
        versions: [:"tlsv1.3"],
        verify: :verify_peer,
        cacerts: [fixtures.ca.der],
        server_name_indication: ~c"exssl.test",
        alpn_advertised_protocols: [alpn]
      ],
      extra
    )
  end

  defp ticket_option(:default), do: []
  defp ticket_option(value), do: [session_tickets: value]

  defp assert_handshake(peer, index, reused, alpn, ticket_offered \\ :any) do
    assert {:ok,
            %{
              "index" => ^index,
              "version" => "TLSv1.3",
              "alpn" => ^alpn,
              "session_reused" => ^reused,
              "client_der_b64" => :null
            } = handshake} = event(peer, "handshake")

    if ticket_offered != :any, do: assert(handshake["ticket_offered"] == ticket_offered)
  end

  defp with_peer(fixtures, mode, extra, function) do
    peer = start_peer(fixtures, mode, extra)

    try do
      function.(peer)
    after
      stop_peer(peer)
    end

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 1_000)
  end

  defp start_peer(fixtures, mode, extra) do
    executable = System.find_executable("python3") || raise "python3 unavailable"
    assert File.regular?(@python)

    args =
      [
        "-B",
        "-u",
        @python,
        "--certfile",
        fixtures.server.certificate,
        "--keyfile",
        fixtures.server.key,
        "--cafile",
        fixtures.ca.certificate,
        "--mode",
        mode
      ] ++ extra

    handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: args
      ])

    {:os_pid, os_pid} = Port.info(handle, :os_pid)
    peer = %{handle: handle, os_pid: os_pid, port: nil}

    case event(peer, "ready") do
      {:ok, %{"port" => port}} ->
        %{peer | port: port}

      error ->
        stop_peer(peer)
        raise "resumption peer startup failed: #{inspect(error)}"
    end
  end

  defp event(%{handle: handle}, expected) do
    receive do
      {^handle, {:data, {:eol, line}}} ->
        case :json.decode(line) do
          %{"kind" => ^expected} = value -> {:ok, value}
          %{"kind" => "failure"} = value -> {:error, value}
          other -> {:error, {:unexpected_peer_event, other}}
        end

      {^handle, {:data, {:noeol, _}}} ->
        {:error, :peer_line_too_long}

      {^handle, {:exit_status, status}} ->
        {:error, {:peer_exit, status}}
    after
      @timeout -> {:error, :peer_timeout}
    end
  rescue
    _ -> {:error, :invalid_peer_event}
  end

  defp stop_peer(%{handle: handle, os_pid: os_pid}) do
    case Port.info(handle, :os_pid) do
      {:os_pid, ^os_pid} ->
        _ = System.cmd("kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)

        receive do
          {^handle, {:exit_status, _}} -> :ok
        after
          2_000 -> raise "resumption peer did not stop"
        end

      nil ->
        :ok
    end
  end

  defp restore_backend(:unset), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_backend(value), do: Application.put_env(:http_core, :tls_backend, value)
end
