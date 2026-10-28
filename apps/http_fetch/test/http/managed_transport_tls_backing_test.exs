defmodule HTTP.ManagedTransportTLSBackingTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @tls12_peer Path.expand("../support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

  test "borrowed CA preparation preserves verification, digest, overrides and redaction" do
    {origin, listener} = listener()
    peer = peer(listener)
    {scope, input_bytes, backing_bytes} = borrowed_scope(origin, "localhost-ca.pem")
    assert backing_bytes > input_bytes
    :erlang.garbage_collect(self())
    ca = ca("localhost-ca.pem")
    compact = open(origin, ssl(ca))

    assert {:ok, snapshot} = ManagedTransport.snapshot(scope, 100)
    assert {:ok, compact_snapshot} = ManagedTransport.snapshot(compact, 100)
    assert snapshot.identity == compact_snapshot.identity
    assert snapshot.active_requests == 0
    assert snapshot.connections == 0

    assert Map.keys(snapshot) |> Enum.sort() ==
             Enum.sort([
               :active_requests,
               :pending,
               :preparing_requests,
               :connections,
               :resources,
               :limits,
               :identity,
               :lifecycle,
               :provider_resources
             ])

    assert {:error, :timeout} = :ssl.transport_accept(listener, 0)
    promise = fetch(origin, scope, ssl: ssl(ca))
    assert %Response{status: 200} = response = Promise.await(promise)
    assert Response.read_all(response) == "verified"
    assert :ok = RequestCompletion.await(Promise.completion(promise), 3_000)
    assert {:request, ~c"localhost", head} = Task.await(peer, 3_000)
    assert head =~ "GET /verified HTTP/1.1\r\n"
    assert head =~ "Host: localhost:#{URI.parse(origin).port}\r\n"
    retire(scope)

    assert {:ok, %{lifecycle: :open, active_requests: 0}} =
             ManagedTransport.snapshot(compact, 100)

    retire(compact)
  end

  for backend <- [:default, :ex_ssl],
      version <- [:"tlsv1.2", :"tlsv1.3"],
      {host, ca_file, rejection} <- [
        {"localhost", "pinned-ca.pem", :wrong_ca},
        {"wrong.invalid", "localhost-ca.pem", :wrong_identity}
      ] do
    alert =
      case {version, rejection} do
        {:"tlsv1.2", _} -> :bad_certificate
        {:"tlsv1.3", :wrong_identity} -> :certificate_unknown
        {:"tlsv1.3", :wrong_ca} -> :unknown_ca
      end

    cleanup = :ok

    test "#{backend} #{version} borrowed CA keeps #{rejection} #{alert} refusal without HTTP bytes or replay" do
      {origin, peer} = rejection_peer(unquote(host), unquote(backend), unquote(version))

      try do
        {scope, input_bytes, backing_bytes} =
          borrowed_scope(origin, unquote(ca_file), unquote(backend), unquote(version))

        assert backing_bytes > input_bytes
        :erlang.garbage_collect(self())
        promise = fetch(origin, scope)
        assert {:error, {:tls_alert, {unquote(alert), _}}} = Promise.await(promise)

        assert unquote(Macro.escape(cleanup)) ==
                 RequestCompletion.await(Promise.completion(promise), 3_000)

        assert_rejection_peer(peer, unquote(alert))
        assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
        assert unquote(Macro.escape(cleanup)) == ManagedTransport.await_retired(receipt, 3_000)
        assert unquote(Macro.escape(cleanup)) == ManagedTransport.await_retired(receipt, 0)
        assert {:error, :transport_scope_retired} = Promise.await(fetch(origin, scope))
      after
        stop_rejection_peer(peer)
      end
    end
  end

  # OTP's TLS 1.2 peer lacks required EMS, so it cannot reach ExSSL certificate checks.
  defp rejection_peer(host, backend, :"tlsv1.2") when backend in [:default, :ex_ssl] do
    port =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          @tls12_peer,
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key"),
          "--tls",
          "TLSv1.2",
          "--protocol",
          "http/1.1",
          "--route",
          "forward"
        ]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    assert %{"event" => "ready", "port" => number, "tls" => "TLSv1.2"} = peer_event(port)
    {"https://#{host}:#{number}", {:openssl, port}}
  end

  defp rejection_peer(host, _, _) do
    {origin, listener} = listener(host)
    {origin, {:otp, listener, peer(listener)}}
  end

  defp assert_rejection_peer({:otp, listener, task}, _alert) do
    assert {:handshake_error, _} = Task.await(task, 3_000)
    assert {:error, :timeout} = :ssl.transport_accept(listener, 100)
  end

  defp assert_rejection_peer({:openssl, port}, alert) do
    state = peer_closed(port, System.monotonic_time(:millisecond) + 2_000)
    assert state["active_connections"] == 0
    assert state["handshakes"] == []
    assert [%{"kind" => "tls", "reason" => reason}] = state["errors"]
    assert reason =~ alert |> Atom.to_string() |> String.upcase()
    # Keep the listener available for the same no-replay observation as the OTP peer.
    Process.sleep(100)
    assert Port.command(port, JSON.encode!(%{command: "stats"}) <> "\n")

    assert %{"requests" => [], "accepted_connections" => 1, "closed_connections" => 1} =
             peer_event(port)
  end

  defp peer_closed(port, deadline) do
    assert Port.command(port, JSON.encode!(%{command: "stats"}) <> "\n")
    remaining = deadline - System.monotonic_time(:millisecond)
    assert remaining > 0
    state = peer_event(port, remaining)
    assert System.monotonic_time(:millisecond) < deadline

    if state["closed_connections"] == 1 do
      state
    else
      Process.sleep(2)
      peer_closed(port, deadline)
    end
  end

  defp peer_event(port, timeout \\ 5_000) do
    receive do
      {^port, {:data, {:eol, line}}} -> JSON.decode!(line)
      {^port, {:exit_status, code}} -> flunk("borrowed CA peer exited with #{code}")
    after
      timeout -> flunk("borrowed CA peer event timeout")
    end
  end

  defp stop_rejection_peer({:otp, _, _}), do: :ok

  defp stop_rejection_peer({:openssl, port}) do
    assert Port.command(port, JSON.encode!(%{command: "stop"}) <> "\n")
    assert %{"event" => "stop"} = peer_event(port)
    assert_receive {^port, {:exit_status, 0}}, 5_000
    assert Port.info(port) == nil
  end

  defp borrowed_scope(origin, name, backend \\ :default, version \\ nil) do
    parent = self()

    {helper, monitor} =
      spawn_monitor(fn ->
        der = ca(name)
        backing = der <> :binary.copy(<<0>>, 8 * 1_048_576)
        slice = binary_part(backing, 0, byte_size(der))
        bytes = :binary.referenced_byte_size(slice)
        assert bytes > byte_size(slice)
        send(parent, {:borrowed_ca, self(), slice, bytes})
      end)

    receive do
      {:borrowed_ca, ^helper, der, backing_bytes} ->
        assert_receive {:DOWN, ^monitor, :process, ^helper, :normal}
        # This caller creates and keeps the scope alive; the producer has exited.
        ssl_options =
          if URI.parse(origin).host == "localhost",
            do: ssl(der),
            else: [verify: :verify_peer, cacerts: [der]]

        ssl_options =
          if version, do: Keyword.put(ssl_options, :versions, [version]), else: ssl_options

        scope = open(origin, ssl_options, backend)
        {scope, byte_size(der), backing_bytes}
    after
      3_000 -> flunk("missing finite borrowed CA fixture")
    end
  end

  defp ca(name) do
    [{:Certificate, der, :not_encrypted}] =
      @fixtures |> Path.join(name) |> File.read!() |> :public_key.pem_decode()

    der
  end

  defp ssl(der) do
    [
      server_name_indication: ~c"localhost",
      depth: 4,
      versions: [:"tlsv1.3", :"tlsv1.2"],
      verify: :verify_peer,
      cacerts: [der]
    ]
  end

  defp open(origin, ssl, backend \\ :default) do
    options = [
      origin: origin,
      connect_address: {127, 0, 0, 1},
      http_version: :http1,
      max_connections: 2,
      max_requests: 32,
      max_pending: 0,
      idle_timeout: 30_000,
      socket_opts: [
        buffer: 8_192,
        recbuf: 8_192,
        sndbuf: 8_192,
        send_timeout: 1_000,
        send_timeout_close: true
      ],
      ssl: ssl
    ]

    options =
      if backend == :default, do: options, else: Keyword.put(options, :tls_backend, backend)

    assert {:ok, scope} = ManagedTransport.open(options)

    on_exit(fn ->
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      _ = ManagedTransport.await_retired(receipt, 3_000)
    end)

    scope
  end

  defp listener(host \\ "localhost") do
    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1},
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key")
      )

    on_exit(fn -> :ssl.close(listener) end)
    {:ok, {_, port}} = :ssl.sockname(listener)
    {"https://#{host}:#{port}", listener}
  end

  defp peer(listener) do
    task =
      Task.async(fn ->
        {:ok, accepted} = :ssl.transport_accept(listener, 3_000)

        case :ssl.handshake(accepted, 3_000) do
          {:ok, socket} ->
            {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
            {:ok, head} = :ssl.recv(socket, 0, 3_000)

            :ok =
              :ssl.send(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nverified"
              )

            :ssl.close(socket)
            {:request, info[:sni_hostname], head}

          {:error, reason} ->
            {:handshake_error, reason}
        end
      end)

    on_exit(fn -> if Process.alive?(task.pid), do: Process.exit(task.pid, :kill) end)
    task
  end

  defp fetch(origin, scope, opts \\ []) do
    HTTP.fetch(
      origin <> "/verified",
      Keyword.merge(
        [
          transport_scope: scope,
          redirect: :manual,
          stream_response: true,
          decode_body: false,
          timeout: 3_000
        ],
        opts
      )
    )
  end

  defp retire(scope) do
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 3_000)
  end
end
