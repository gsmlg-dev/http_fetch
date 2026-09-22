# Source-candidate package test; run through scripts/ex_ssl_source_smoke.sh.
for fixture <- ["signature_fixtures.ex", "client_auth_fixtures.ex"] do
  Code.require_file(Path.join([System.fetch_env!("EX_SSL_SOURCE_DIR"), "test/support", fixture]))
end

defmodule CandidateResumptionTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures

  @timeout 10_000
  @python Path.join(__DIR__, "ex_ssl_tls12_peer.py")

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "http-resumption-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "packaged HTTP/1.1 forwards TLS 1.3 auto tickets across fresh connections", %{
    fixtures: fixtures
  } do
    peer = start_peer(fixtures)

    try do
      for {index, resumed} <- [{1, false}, {2, true}] do
        promise =
          HTTP.fetch("https://127.0.0.1:#{peer.port}/resumption",
            tls_backend: :ex_ssl,
            ssl: [
              versions: [:"tlsv1.3"],
              verify: :verify_peer,
              cacerts: [fixtures.ca.der],
              server_name_indication: ~c"exssl.test",
              alpn_advertised_protocols: ["http/1.1"],
              session_tickets: :auto
            ],
            timeout: @timeout,
            connect_timeout: @timeout
          )

        assert {:ok,
                %{
                  "index" => ^index,
                  "version" => "TLSv1.3",
                  "alpn" => "http/1.1",
                  "session_reused" => ^resumed,
                  "client_der_b64" => :null
                }} = event(peer, "handshake")

        assert {:ok, %{"bytes" => 6}} = event(peer, "exchange")
        response = HTTP.Promise.await(promise, @timeout)
        assert response.status == 200
        assert HTTP.Response.read_all(response) == "BBBBBB"
      end
    after
      stop_peer(peer)
    end
  end

  defp start_peer(fixtures) do
    executable = System.find_executable("python3") || raise "python3 unavailable"
    assert File.regular?(@python)

    handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
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
          "resumption"
        ]
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
end
