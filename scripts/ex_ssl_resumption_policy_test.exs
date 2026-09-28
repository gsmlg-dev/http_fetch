# Consumer option propagation, with an independent OTP TLS server. Library cache
# internals are never queried: a server handshake and application I/O are the oracle.
for fixture <- ["signature_fixtures.ex", "client_auth_fixtures.ex"] do
  Code.require_file(Path.join([System.fetch_env!("EX_SSL_FIXTURE_DIR"), "test/support", fixture]))
end

defmodule CandidateResumptionPolicyTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias HTTP.HTTP2.{Frame, HPACK}
  alias HTTP.{EventSource, WebSocket}

  @timeout 5_000

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "resumption-policy-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  for family <- [:http1, :http2, :wss, :sse] do
    test "#{family} forwards unsupported ticket combinations as explicit pre-I/O option errors",
         %{fixtures: f} do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      on_exit(fn -> :gen_tcp.close(listener) end)
      {:ok, {_, port}} = :inet.sockname(listener)

      for override <- [
            [versions: [:"tlsv1.2"]],
            [versions: [:"tlsv1.3", :"tlsv1.2"]],
            [certfile: f.rsa.certificate, keyfile: f.rsa.key],
            [verify: :verify_none]
          ] do
        assert {:error, {:options, _}} =
                 rejected_client(
                   unquote(family),
                   port,
                   Keyword.merge(ssl(f, unquote(family)), override)
                 )

        assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
      end
    end

    test "#{family} cannot reuse authenticated tickets after bad trust, hostname, or ALPN changes",
         %{fixtures: f} do
      # Each policy gets its own listener and freshly authenticated ticket. This
      # avoids one rejected attempt consuming the ticket needed by another case.
      for change <- [
            [cacerts: [f.wrong.der]],
            [server_name_indication: ~c"wrong.test"],
            [alpn_advertised_protocols: ["incompatible/1"]]
          ] do
        with_rejecting_peer(f, unquote(family), fn port ->
          warm_ticket(port, f, unquote(family))

          assert {:error, reason} =
                   rejected_client(
                     unquote(family),
                     port,
                     Keyword.merge(ssl(f, unquote(family)), change)
                   )

          refute reason in [:timeout, :connect_timeout, :request_timeout]
        end)
      end
    end
  end

  defp ssl(f, family) do
    [
      versions: [:"tlsv1.3"],
      verify: :verify_peer,
      cacerts: [f.ca.der],
      server_name_indication: ~c"exssl.test",
      alpn_advertised_protocols: [if(family == :http2, do: "h2", else: "http/1.1")],
      session_tickets: :auto
    ]
  end

  defp rejected_client(family, port, options) when family in [:http1, :http2] do
    HTTP.fetch("https://127.0.0.1:#{port}/policy",
      http_version: family,
      tls_backend: :ex_ssl,
      ssl: options,
      timeout: @timeout,
      connect_timeout: @timeout
    )
    |> HTTP.Promise.await(@timeout + 1_000)
  end

  defp rejected_client(:wss, port, options) do
    socket =
      WebSocket.new("wss://127.0.0.1:#{port}/policy", [],
        tls_backend: :ex_ssl,
        ssl: options,
        timeout: @timeout,
        connect_timeout: @timeout
      )

    monitor = Process.monitor(socket.pid)

    try do
      assert_receive {WebSocket, ^socket, %HTTP.WebSocket.Event.Error{reason: reason}}, @timeout
      assert_receive {:DOWN, ^monitor, :process, _, down_reason}, @timeout
      assert down_reason in [:normal, :noproc]
      refute_receive {WebSocket, ^socket, %HTTP.WebSocket.Event.Open{}}, 0
      {:error, reason}
    after
      if Process.alive?(socket.pid), do: Process.exit(socket.pid, :kill)
    end
  end

  defp rejected_client(:sse, port, options) do
    source =
      EventSource.new("https://127.0.0.1:#{port}/policy",
        tls_backend: :ex_ssl,
        ssl: options,
        connect_timeout: @timeout,
        reconnect_time: 60_000,
        max_reconnect_time: 60_000
      )

    monitor = Process.monitor(source.pid)

    try do
      assert_receive {EventSource, ^source, %HTTP.EventSource.Event.Error{reason: reason}},
                     @timeout

      assert :ok = EventSource.close(source)
      assert_receive {:DOWN, ^monitor, :process, _, down_reason}, @timeout
      assert down_reason in [:normal, :noproc]
      refute_receive {EventSource, ^source, %HTTP.EventSource.Event.Open{}}, 0
      refute_receive {EventSource, ^source, %HTTP.EventSource.Event.Message{}}, 0
      {:error, reason}
    after
      if Process.alive?(source.pid), do: Process.exit(source.pid, :kill)
    end
  end

  defp warm_ticket(port, f, family) do
    # Ticket partitioning is a TLS policy boundary, independent of HTTP Upgrade
    # or SSE semantics. Warm through the public fetch API with identical TLS
    # settings, then test the selected family's public API on the same endpoint.
    response =
      HTTP.fetch("https://127.0.0.1:#{port}/warm",
        http_version: if(family == :http2, do: :http2, else: :http1),
        tls_backend: :ex_ssl,
        ssl: ssl(f, family),
        timeout: @timeout
      )
      |> HTTP.Promise.await(@timeout + 1_000)

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "barrier"
  end

  defp with_rejecting_peer(f, family, client) do
    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        versions: [:"tlsv1.3"],
        session_tickets: :stateful,
        alpn_preferred_protocols: [if(family == :http2, do: "h2", else: "http/1.1")],
        certfile: f.server.certificate,
        keyfile: f.server.key
      )

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, @timeout)
        {:ok, socket} = :ssl.handshake(tcp, @timeout)

        assert {:ok, [session_resumption: false]} =
                 :ssl.connection_information(socket, [:session_resumption])

        warm_response(socket, family)
        :ssl.close(socket)
        {:ok, tcp} = :ssl.transport_accept(listener, @timeout)

        case :ssl.handshake(tcp, @timeout) do
          {:ok, socket} ->
            # A resumed handshake would bypass the changed policy and is forbidden,
            # even if the client later failed for an unrelated HTTP reason.
            assert {:ok, [session_resumption: false]} =
                     :ssl.connection_information(socket, [:session_resumption])

            assert {:error, reason} = :ssl.recv(socket, 0, @timeout)
            refute reason == :timeout
            :ssl.close(socket)

          {:error, reason} ->
            refute reason == :timeout
        end

        :ok
      end)

    try do
      client.(port)
      assert :ok = Task.await(peer, @timeout + 1_000)
      assert {:error, :timeout} = :ssl.transport_accept(listener, 0)
    after
      Task.shutdown(peer, :brutal_kill)
      :ssl.close(listener)
    end

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1_000)
  end

  defp warm_response(socket, :http2) do
    preface = HTTP.HTTP2.connection_preface()
    assert {:ok, ^preface} = :ssl.recv(socket, byte_size(preface), @timeout)
    assert %Frame{type: :settings} = frame(socket)
    assert %Frame{type: :headers} = frame(socket)

    :ok =
      :ssl.send(socket, [
        Frame.encode(:settings, 0, 0, ""),
        Frame.encode(
          :headers,
          4,
          1,
          HPACK.encode_headers([{":status", "200"}, {"content-length", "7"}])
        ),
        Frame.encode(:data, 1, 1, "barrier")
      ])

    assert %Frame{type: :settings, flags: 1} = frame(socket)
  end

  defp warm_response(socket, _) do
    assert headers(socket, "") =~ "GET /warm HTTP/1.1"

    :ok =
      :ssl.send(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nbarrier"
      )
  end

  defp headers(socket, buffer) when byte_size(buffer) < 16_384 do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, bytes} = :ssl.recv(socket, 0, @timeout)
      headers(socket, buffer <> bytes)
    end
  end

  defp frame(socket) do
    assert {:ok, <<size::24, _::binary>> = header} = :ssl.recv(socket, 9, @timeout)
    assert size <= 16_384
    payload = if size == 0, do: "", else: elem(:ssl.recv(socket, size, @timeout), 1)
    assert {:ok, frame, ""} = Frame.decode(header <> payload)
    frame
  end
end
