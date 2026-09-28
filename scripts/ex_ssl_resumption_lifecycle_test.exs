for fixture <- ["signature_fixtures.ex", "client_auth_fixtures.ex"] do
  Code.require_file(Path.join([System.fetch_env!("EX_SSL_FIXTURE_DIR"), "test/support", fixture]))
end

defmodule CandidateResumptionLifecycleTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.ClientAuthFixtures
  alias HTTP.{EventSource, WebSocket}

  @timeout 10_000

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "resumption-lifecycle-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "fetch cancellation closes a ticket-offering connection before application I/O", %{
    fixtures: f
  } do
    with_peer(f, fn peer ->
      controller = HTTP.AbortController.new()

      try do
        promise = fetch(peer, f, signal: controller)
        assert %{"ticket_offered" => true} = event(peer, "setup")
        HTTP.AbortController.abort(controller)
        assert {:error, :aborted} = HTTP.Promise.await(promise, 2_000)
        assert %{"index" => 2} = event(peer, "setup_closed")
      after
        GenServer.stop(controller)
      end
    end)
  end

  test "fetch deadline closes a ticket-offering connection before application I/O", %{fixtures: f} do
    with_peer(f, fn peer ->
      promise = fetch(peer, f, timeout: 1_000)
      assert %{"ticket_offered" => true} = event(peer, "setup")
      assert {:error, reason} = HTTP.Promise.await(promise, 2_000)
      assert reason in [:request_timeout, :connect_timeout]
      assert %{"index" => 2} = event(peer, "setup_closed")
    end)
  end

  for family <- [:wss, :sse] do
    test "#{family} owner shutdown interrupts a ticket-offering handshake", %{fixtures: f} do
      with_peer(f, fn peer ->
        owner =
          spawn(fn ->
            receive do
              :stop -> :ok
            end
          end)

        client = new_client(unquote(family), peer, f, owner: owner)
        monitor = Process.monitor(client.pid)

        try do
          assert %{"ticket_offered" => true} = event(peer, "setup")
          send(owner, :stop)
          # The handshake remains held for ten seconds. Owner cleanup must not
          # wait for that connect timeout or for a server response.
          assert_receive {:DOWN, ^monitor, :process, _, :shutdown}, 2_000
          assert %{"index" => 2} = event(peer, "setup_closed")
        after
          Process.exit(owner, :kill)
          if Process.alive?(client.pid), do: Process.exit(client.pid, :kill)
        end
      end)
    end

    test "#{family} connect deadline closes a ticket-offering handshake", %{fixtures: f} do
      with_peer(f, fn peer ->
        client = new_client(unquote(family), peer, f, connect_timeout: 1_000)

        try do
          assert %{"ticket_offered" => true} = event(peer, "setup")
          assert_client_timeout(unquote(family), client)
          assert %{"index" => 2} = event(peer, "setup_closed")
        after
          if Process.alive?(client.pid), do: Process.exit(client.pid, :kill)
        end
      end)
    end
  end

  defp new_client(:wss, peer, f, extra) do
    WebSocket.new(
      "wss://127.0.0.1:#{peer.port}/socket",
      [],
      Keyword.merge([tls_backend: :ex_ssl, ssl: ssl(f), connect_timeout: @timeout], extra)
    )
  end

  defp new_client(:sse, peer, f, extra) do
    EventSource.new(
      "https://127.0.0.1:#{peer.port}/events",
      Keyword.merge(
        [
          tls_backend: :ex_ssl,
          ssl: ssl(f),
          connect_timeout: @timeout,
          reconnect_time: 60_000,
          max_reconnect_time: 60_000
        ],
        extra
      )
    )
  end

  defp assert_client_timeout(:wss, client) do
    assert_receive {WebSocket, ^client, %HTTP.WebSocket.Event.Error{reason: :timeout}}, 2_000
    refute_receive {WebSocket, ^client, %HTTP.WebSocket.Event.Open{}}, 0
  end

  defp assert_client_timeout(:sse, client) do
    assert_receive {EventSource, ^client, %HTTP.EventSource.Event.Error{reason: :timeout}}, 2_000
    assert :ok = EventSource.close(client)
    refute_receive {EventSource, ^client, %HTTP.EventSource.Event.Open{}}, 0
    refute_receive {EventSource, ^client, %HTTP.EventSource.Event.Message{}}, 0
  end

  defp ssl(f) do
    [
      versions: [:"tlsv1.3"],
      verify: :verify_peer,
      cacerts: [f.ca.der],
      server_name_indication: ~c"exssl.test",
      alpn_advertised_protocols: ["http/1.1"],
      session_tickets: :auto
    ]
  end

  defp fetch(peer, f, extra \\ []) do
    HTTP.fetch(
      "https://127.0.0.1:#{peer.port}/resumption",
      Keyword.merge(
        [tls_backend: :ex_ssl, ssl: ssl(f), timeout: @timeout, connect_timeout: @timeout],
        extra
      )
    )
  end

  defp with_peer(f, function) do
    peer = start_peer(f)

    try do
      promise = fetch(peer, f)

      assert %{
               "index" => 1,
               "session_reused" => false,
               "version" => "TLSv1.3",
               "alpn" => "http/1.1"
             } = event(peer, "handshake")

      assert %{"bytes" => 6} = event(peer, "exchange")
      response = HTTP.Promise.await(promise, @timeout)
      assert response.status == 200
      # This public response is after NewSessionTicket in the peer's TLS output.
      assert HTTP.Response.read_all(response) == "BBBBBB"
      function.(peer)
      assert_receive {handle, {:exit_status, 0}} when handle == peer.handle, @timeout
    after
      stop_peer(peer)
    end

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 1_000)
  end

  defp start_peer(f) do
    python = System.find_executable("python3") || raise "python3 missing"

    handle =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          "-u",
          Path.join(__DIR__, "ex_ssl_tls12_peer.py"),
          "--certfile",
          f.server.certificate,
          "--keyfile",
          f.server.key,
          "--cafile",
          f.ca.certificate,
          "--mode",
          "resumption",
          "--hold-second-handshake"
        ]
      ])

    {:os_pid, os_pid} = Port.info(handle, :os_pid)
    peer = %{handle: handle, os_pid: os_pid}

    try do
      %{"port" => port} = event(peer, "ready")
      Map.put(peer, :port, port)
    rescue
      error ->
        stop_peer(peer)
        reraise error, __STACKTRACE__
    end
  end

  defp event(%{handle: handle}, kind) do
    receive do
      {^handle, {:data, {:eol, line}}} ->
        decoded = :json.decode(line)
        assert %{"kind" => ^kind} = decoded
        decoded

      {^handle, {:exit_status, status}} ->
        flunk("peer exited #{status} before #{kind}")
    after
      @timeout -> flunk("peer timed out before #{kind}")
    end
  end

  defp stop_peer(%{handle: handle, os_pid: os_pid}) do
    if Port.info(handle) do
      _ = System.cmd("kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)
      assert_receive {^handle, {:exit_status, _}}, 2_000
    end
  end
end
