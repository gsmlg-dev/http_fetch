# Run only through scripts/ex_ssl_source_smoke.sh with an explicit source checkout.
for fixture <- ["signature_fixtures.ex", "client_auth_fixtures.ex"] do
  Code.require_file(Path.join([System.fetch_env!("EX_SSL_SOURCE_DIR"), "test/support", fixture]))
end

defmodule CandidateTLS12Test do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias HTTP.EventSource
  alias HTTP.WebSocket

  @timeout 10_000
  @python Path.join(__DIR__, "ex_ssl_tls12_peer.py")

  setup_all do
    directory = Path.join(System.tmp_dir!(), "http-tls12-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  for protocol <- [:http1, :http2], versions <- [[:"tlsv1.2"], [:"tlsv1.3", :"tlsv1.2"]] do
    test "packaged #{protocol} fetch uses required mTLS over #{inspect(versions)} and returns large response",
         %{
           fixtures: fixtures
         } do
      mode = if unquote(protocol) == :http2, do: "h2", else: "http1"

      with_peer(fixtures, mode, ["--large"], fn peer ->
        promise =
          HTTP.fetch("https://127.0.0.1:#{peer.port}/tls12",
            tls_backend: :ex_ssl,
            http_version: unquote(protocol),
            ssl:
              client_ssl(
                fixtures,
                unquote(versions),
                if(mode == "h2", do: "h2", else: "http/1.1")
              ),
            timeout: @timeout,
            connect_timeout: @timeout
          )

        expected_bytes = 262_144
        assert_handshake(peer, fixtures, "TLSv1.2", if(mode == "h2", do: "h2", else: "http/1.1"))
        assert {:ok, %{"bytes" => ^expected_bytes} = exchange} = event(peer, "exchange")
        if mode == "h2", do: assert(exchange["window_updates"] > 0)
        response = HTTP.Promise.await(promise, @timeout)
        assert response.status == 200
        assert HTTP.Response.read_all(response) == :binary.copy("B", expected_bytes)
      end)
    end
  end

  test "mixed offer selects TLS 1.3 on a capable peer without retry", %{fixtures: fixtures} do
    with_peer(fixtures, "http1", ["--max-version", "tls13"], fn peer ->
      response =
        HTTP.fetch("https://127.0.0.1:#{peer.port}/tls12",
          tls_backend: :ex_ssl,
          ssl: client_ssl(fixtures, [:"tlsv1.3", :"tlsv1.2"], "http/1.1"),
          timeout: @timeout,
          connect_timeout: @timeout
        )
        |> HTTP.Promise.await(@timeout)

      assert response.status == 200
      assert HTTP.Response.read_all(response) == "BBBBBB"
      assert_handshake(peer, fixtures, "TLSv1.3", "http/1.1")
      assert {:ok, %{"bytes" => 6}} = event(peer, "exchange")
    end)
  end

  test "packaged WSS upgrades through TLS 1.2 mTLS and echoes an active-once frame", %{
    fixtures: fixtures
  } do
    with_peer(fixtures, "wss", [], fn peer ->
      socket =
        WebSocket.new("wss://127.0.0.1:#{peer.port}/socket", [],
          tls_backend: :ex_ssl,
          ssl: client_ssl(fixtures, [:"tlsv1.2"], "http/1.1")
        )

      try do
        assert_handshake(peer, fixtures, "TLSv1.2", "http/1.1")
        assert {:ok, _} = event(peer, "upgrade")
        assert_receive {WebSocket, ^socket, %HTTP.WebSocket.Event.Open{}}, @timeout
        assert :ok = WebSocket.send(socket, "tls12-echo")

        assert_receive {WebSocket, ^socket,
                        %HTTP.WebSocket.Event.Message{data: "echo:tls12-echo"}},
                       @timeout

        assert :ok = WebSocket.close(socket, 1000, "done")

        assert_receive {WebSocket, ^socket,
                        %HTTP.WebSocket.Event.Close{code: 1000, was_clean: true}},
                       @timeout

        assert {:ok, %{"bytes" => 10}} = event(peer, "exchange")
      after
        _ = WebSocket.close(socket)
      end
    end)
  end

  test "packaged SSE reconnects to same TLS 1.2 mTLS origin with backend and Last-Event-ID pinned",
       %{
         fixtures: fixtures
       } do
    previous = Application.get_env(:http_core, :tls_backend, :unset)
    on_exit(fn -> restore_backend(previous) end)

    with_peer(fixtures, "sse", [], fn peer ->
      source =
        EventSource.new("https://127.0.0.1:#{peer.port}/events",
          tls_backend: :ex_ssl,
          reconnect_time: 10,
          ssl: client_ssl(fixtures, [:"tlsv1.2"], "http/1.1")
        )

      try do
        assert_handshake(peer, fixtures, "TLSv1.2", "http/1.1", 1)
        assert {:ok, %{"index" => 1, "last_id_ok" => false}} = event(peer, "request")
        assert_receive {EventSource, ^source, %HTTP.EventSource.Event.Open{}}, @timeout

        assert_receive {EventSource, ^source,
                        %HTTP.EventSource.Event.Message{data: "first", last_event_id: "41"}},
                       @timeout

        assert {:ok, _} = event(peer, "first_ready")
        Application.put_env(:http_core, :tls_backend, :invalid)
        assert %{tls_backend: :ex_ssl} = :sys.get_state(source.pid)
        true = Port.command(peer.handle, "go\n")

        assert_handshake(peer, fixtures, "TLSv1.2", "http/1.1", 2)
        assert {:ok, %{"index" => 2, "last_id_ok" => true}} = event(peer, "request")
        assert_receive {EventSource, ^source, %HTTP.EventSource.Event.Open{}}, @timeout

        assert_receive {EventSource, ^source,
                        %HTTP.EventSource.Event.Message{data: "second", last_event_id: "41"}},
                       @timeout

        assert {:ok, _} = event(peer, "second_ready")
      after
        _ = EventSource.close(source)
      end
    end)
  end

  defp client_ssl(fixtures, versions, protocol) do
    [
      versions: versions,
      verify: :verify_peer,
      alpn_advertised_protocols: [protocol],
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      certfile: fixtures.rsa.certificate,
      keyfile: fixtures.rsa.key
    ]
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
    assert File.regular?(@python)
    executable = System.find_executable("python3") || raise "python3 unavailable"

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
        raise "TLS 1.2 peer startup failed: #{inspect(error)}"
    end
  end

  defp assert_handshake(peer, fixtures, version, alpn, index \\ 1) do
    assert {:ok,
            %{
              "index" => ^index,
              "version" => ^version,
              "alpn" => ^alpn,
              "client_der_b64" => client_der,
              "cipher" => cipher
            }} = event(peer, "handshake")

    assert Base.decode64!(client_der) == fixtures.rsa.der
    if version == "TLSv1.2", do: assert(cipher == "ECDHE-RSA-AES128-GCM-SHA256")
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
          2_000 -> raise "TLS 1.2 peer did not stop"
        end

      nil ->
        :ok
    end
  end

  defp restore_backend(:unset), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_backend(value), do: Application.put_env(:http_core, :tls_backend, value)
end
