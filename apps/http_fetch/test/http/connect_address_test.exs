defmodule HTTP.ConnectAddressTest do
  use ExUnit.Case, async: false

  alias HTTP.FetchOptions
  alias HTTP.HTTP2.{PoolKey, WireProfile}
  @ipv4 {127, 0, 0, 1}
  @ipv6 {0, 0, 0, 0, 0, 0, 0, 1}
  @fixtures Path.expand("../support/fixtures", __DIR__)
  @timeout 5000

  test "pin options normalize flat keys and require manual redirects and supported routes" do
    for key <- [:connect_address, "connect_address", "connectAddress"] do
      assert %{connect_address: @ipv4} = FetchOptions.new(%{key => @ipv4, :redirect => :manual})
    end

    for bad <- [
          "127.0.0.1",
          ~c"127.0.0.1",
          [{127, 0, 0, 1}],
          {127, 0, 0, 256},
          {0, 0, 0},
          {0, 0, 0, 0, 0, 0, 0, 65_536}
        ] do
      assert_raise ArgumentError, ~r/invalid connect_address/, fn ->
        FetchOptions.new(connect_address: bad, redirect: :manual)
      end
    end

    for route <- [
          [redirect: :follow],
          [http_version: :http3, redirect: :manual],
          [unix_socket: "/tmp/pinned.sock", redirect: :manual],
          [proxy: "http://localhost:1", redirect: :manual]
        ] do
      assert_raise ArgumentError, ~r/connect_address/, fn ->
        FetchOptions.new([connect_address: @ipv4] ++ route)
      end
    end

    assert %{connect_address: @ipv6} = FetchOptions.new(connect_address: @ipv6, redirect: :error)
  end

  test "low-level requests reject unsupported pin routes and automatic redirects before I/O" do
    base = %HTTP.Request{
      url: URI.parse("https://pinned.invalid:1/"),
      transport_options: [connect_address: @ipv4, redirect: :manual, timeout: 100]
    }

    for {options, unix} <- [
          {[http_version: :http3], nil},
          {[proxy: "http://localhost:1"], nil},
          {[], "/tmp/pin.sock"}
        ] do
      request = %{base | transport_options: Keyword.merge(base.transport_options, options)}

      assert {:error, :connect_address_unsupported_route} =
               HTTP.SocketClient.request(request, nil, unix)
    end

    request = %{base | transport_options: Keyword.put(base.transport_options, :redirect, :follow)}

    assert {:error, :connect_address_requires_manual_redirect} =
             HTTP.SocketClient.request(request)
  end

  test "conflicting SNI and explicit certificate identities reject pinned routes before I/O" do
    {:ok, listener} = listen(@ipv4)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    for backend <- [:ssl, :ex_ssl] do
      assert {:error, :connect_address_sni_conflict} =
               HTTP.fetch("https://pinned.invalid:#{port}/",
                 connect_address: @ipv4,
                 redirect: :manual,
                 tls_backend: backend,
                 ssl: [server_name_indication: ~c"wrong.invalid"]
               )
               |> HTTP.Promise.await(@timeout)
    end

    for identity <- [
          {:ip, {127, 0, 0, 2}},
          {:ip, "127.0.0.2"},
          {:dns_id, "localhost"},
          {:ip, "invalid"},
          {:ip, <<255>>},
          nil
        ] do
      assert {:error, :connect_address_identity_conflict} =
               HTTP.fetch("https://127.0.0.1:#{port}/",
                 connect_address: @ipv4,
                 redirect: :manual,
                 tls_backend: :ex_ssl,
                 ssl: [ex_ssl: [reference_identity: identity]]
               )
               |> HTTP.Promise.await(@timeout)
    end

    assert {:error, :connect_address_identity_conflict} =
             HTTP.fetch("https://pinned.invalid:#{port}/",
               connect_address: @ipv4,
               redirect: :manual,
               tls_backend: :ex_ssl,
               ssl: [ex_ssl: [reference_identity: {:dns_id, "wrong.invalid"}]]
             )
             |> HTTP.Promise.await(@timeout)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
  end

  test "pinned and DNS connections and distinct pins have separate pooled identities" do
    request = %HTTP.Request{url: URI.parse("https://pinned.invalid/")}

    keys =
      for pin <- [nil, @ipv4, {127, 0, 0, 2}, @ipv6] do
        request = %{request | transport_options: if(pin, do: [connect_address: pin], else: [])}
        assert {:ok, key} = PoolKey.build(request, WireProfile.native_v1(), :h2)
        key
      end

    assert length(Enum.uniq(keys)) == 4
  end

  for address <- [@ipv4, @ipv6] do
    test "HTTP literal #{inspect(address)} dialing preserves original Host without DNS" do
      address = unquote(Macro.escape(address))
      parent = self()

      {port, _peer} =
        tcp_peer(address, fn socket ->
          request = recv_head(:gen_tcp, socket)
          send(parent, {:request, request})
          :ok = :gen_tcp.send(socket, response("pinned"))
        end)

      result =
        HTTP.fetch("http://pinned.invalid:#{port}/literal",
          connect_address: address,
          redirect: :manual
        )
        |> HTTP.Promise.await(@timeout)

      assert %HTTP.Response{status: 200} = result
      assert HTTP.Response.read_all(result) == "pinned"
      assert_receive {:request, request}, @timeout
      assert request =~ "Host: pinned.invalid:#{port}\r\n"
    end
  end

  for backend <- [:ssl, :ex_ssl], address <- [@ipv4, @ipv6] do
    test "#{backend} pin #{inspect(address)} retains SNI and hostname verification" do
      address = unquote(Macro.escape(address))
      backend = unquote(backend)
      parent = self()

      {port, _} =
        tls_peer(address, fn socket ->
          assert {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
          send(parent, {:sni, info[:sni_hostname], recv_head(:ssl, socket)})
          :ok = :ssl.send(socket, response("verified"))
        end)

      result =
        HTTP.fetch("https://pinned.invalid:#{port}/verified",
          connect_address: address,
          redirect: :manual,
          tls_backend: backend,
          ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")]
        )
        |> HTTP.Promise.await(@timeout)

      assert %HTTP.Response{status: 200} = result
      assert HTTP.Response.read_all(result) == "verified"
      assert_receive {:sni, ~c"pinned.invalid", request}, @timeout
      assert request =~ "Host: pinned.invalid:#{port}\r\n"
    end
  end

  for backend <- [:ssl, :ex_ssl] do
    test "#{backend} pin keeps default trust and rejects wrong URL certificate identity" do
      for {host, ssl} <- [
            {"pinned.invalid", []},
            {"wrong.invalid", [cacertfile: Path.join(@fixtures, "pinned-ca.pem")]}
          ] do
        {port, peer} =
          tls_peer(@ipv4, fn _socket -> flunk("invalid TLS identity reached HTTP") end)

        assert {:error, _} =
                 HTTP.fetch("https://#{host}:#{port}/",
                   connect_address: @ipv4,
                   redirect: :manual,
                   tls_backend: unquote(backend),
                   ssl: ssl
                 )
                 |> HTTP.Promise.await(@timeout)

        assert_receive {:tls_handshake, ^peer, {:error, _}}, @timeout
      end
    end
  end

  for address <- [{127, 0, 0, 2}, @ipv6], identity <- [nil, {:ip, @ipv4}, {:ip, "127.0.0.1"}] do
    test "ExSSL original IP #{inspect(identity)} survives dialing a distinct pin #{inspect(address)}" do
      parent = self()

      {port, _} =
        tls_peer(
          unquote(Macro.escape(address)),
          fn socket ->
            assert {:ok, info} = :ssl.connection_information(socket, [:sni_hostname])
            send(parent, {:ip_request, info[:sni_hostname], recv_head(:ssl, socket)})
            :ok = :ssl.send(socket, response("ip verified"))
          end,
          "localhost"
        )

      identity = unquote(Macro.escape(identity))
      ssl = [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]

      ssl =
        if identity,
          do: ssl ++ [server_name_indication: :disable, ex_ssl: [reference_identity: identity]],
          else: ssl

      result =
        HTTP.fetch("https://127.0.0.1:#{port}/verified",
          connect_address: unquote(Macro.escape(address)),
          redirect: :manual,
          tls_backend: :ex_ssl,
          ssl: ssl
        )
        |> HTTP.Promise.await(@timeout)

      assert %HTTP.Response{status: 200} = result
      assert HTTP.Response.read_all(result) == "ip verified"
      assert_receive {:ip_request, nil, request}, @timeout
      assert request =~ "Host: 127.0.0.1:#{port}\r\n"
    end
  end

  for host <- ["127.0.0.2", "[::1]"] do
    test "ExSSL pin verifies original #{host} instead of the dialed certificate IP" do
      {port, peer} =
        tls_peer(
          @ipv4,
          fn _socket -> flunk("mismatched IP identity reached HTTP") end,
          "localhost"
        )

      assert {:error, _} =
               HTTP.fetch("https://#{unquote(host)}:#{port}/",
                 connect_address: @ipv4,
                 redirect: :manual,
                 tls_backend: :ex_ssl,
                 ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
               )
               |> HTTP.Promise.await(@timeout)

      assert_receive {:tls_handshake, ^peer, {:error, _}}, @timeout
    end
  end

  test "refused pin never falls back to DNS or repeats a mutation after peer failure" do
    {:ok, listener} = listen(@ipv4)
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    assert {:error, :econnrefused} =
             HTTP.fetch("http://localhost:#{port}/",
               connect_address: {127, 0, 0, 2},
               redirect: :manual,
               method: :post,
               body: "mutation"
             )
             |> HTTP.Promise.await(@timeout)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 0)
    parent = self()

    {port, peer} =
      tcp_peer(@ipv4, fn socket ->
        request = recv_head(:gen_tcp, socket)
        send(parent, {:mutation, request})
        :ok = :gen_tcp.close(socket)
        receive do: (:stop -> :ok)
      end)

    assert {:error, _} =
             HTTP.fetch("http://pinned.invalid:#{port}/",
               connect_address: @ipv4,
               redirect: :manual,
               method: :post,
               body: "mutation"
             )
             |> HTTP.Promise.await(@timeout)

    assert_receive {:mutation, request}, @timeout
    assert request =~ "POST / HTTP/1.1"
    refute_receive {:mutation, _}, 0
    send(peer, :stop)
  end

  test "a permitted redirect is returned and the next hop needs a new caller pin" do
    {port, _} =
      tcp_peer(@ipv4, fn socket ->
        _ = recv_head(:gen_tcp, socket)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 302 Found\r\nLocation: http://other.invalid/path\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
          )
      end)

    result =
      HTTP.fetch("http://pinned.invalid:#{port}/", connect_address: @ipv4, redirect: :manual)
      |> HTTP.Promise.await(@timeout)

    assert %HTTP.Response{status: 302} = result
    assert HTTP.Headers.get(result.headers, "location") == "http://other.invalid/path"
  end

  for backend <- [:ssl, :ex_ssl], stop <- [:abort, :deadline] do
    test "#{backend} pinned TLS establishment cleanup on #{stop}" do
      parent = self()

      {port, peer} =
        tcp_peer(@ipv4, fn socket ->
          assert {:ok, _client_hello} = :gen_tcp.recv(socket, 0, @timeout)
          send(parent, {:tls_started, self()})
          await_tls_transport_close(socket)
          send(parent, {:tls_closed, self()})
        end)

      controller = HTTP.AbortController.new()
      on_exit(fn -> if Process.alive?(controller), do: Agent.stop(controller) end)
      timeout = if unquote(stop) == :deadline, do: 300, else: @timeout

      promise =
        HTTP.fetch("https://pinned.invalid:#{port}/",
          connect_address: @ipv4,
          redirect: :manual,
          tls_backend: unquote(backend),
          signal: controller,
          timeout: timeout,
          connect_timeout: @timeout
        )

      assert_receive {:tls_started, ^peer}, @timeout
      if unquote(stop) == :abort, do: HTTP.AbortController.abort(controller)
      assert {:error, reason} = HTTP.Promise.await(promise, @timeout)
      assert reason in [:aborted, :request_timeout, :connect_timeout]
      assert_receive {:tls_closed, ^peer}, @timeout
    end
  end

  test "HTTP2 pools cannot reuse a live connection established for a different pin" do
    parent = self()
    {:ok, listener} = listen({0, 0, 0, 0})
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn(fn ->
        for _ <- 1..2 do
          {:ok, socket} = :gen_tcp.accept(listener, @timeout)
          {:ok, {address, _}} = :inet.sockname(socket)
          body = if address == @ipv4, do: "first", else: "second"
          spawn_link(fn -> h2_peer(parent, body, address).(socket) end)
        end

        receive do: (:stop -> :ok)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    scope = "pin-#{System.unique_integer([:positive])}"

    for {pin, body} <- [{@ipv4, "first"}, {{127, 0, 0, 2}, "second"}] do
      result =
        HTTP.fetch("http://pool-pin.invalid:#{port}/",
          connect_address: pin,
          redirect: :manual,
          http_version: :h2c,
          http2_scope: scope
        )
        |> HTTP.Promise.await(@timeout)

      assert %HTTP.Response{status: 200} = result
      assert HTTP.Response.read_all(result) == body
      assert_receive {:h2_request, ^body, ^pin, headers}, @timeout
      assert {":authority", "pool-pin.invalid:#{port}"} in headers
    end
  end

  defp h2_peer(parent, body, address) do
    fn socket ->
      preface = HTTP.HTTP2.connection_preface()
      assert {:ok, ^preface} = :gen_tcp.recv(socket, byte_size(preface), @timeout)
      :ok = :gen_tcp.send(socket, HTTP.HTTP2.Frame.encode(:settings, 0, 0, <<>>))
      {id, block} = h2_headers(socket)
      assert {:ok, _, headers} = HTTP.HTTP2.HPACK.decode(HTTP.HTTP2.HPACK.new_decoder(), block)

      :ok =
        :gen_tcp.send(socket, [
          HTTP.HTTP2.Frame.encode(:headers, 4, id, <<0x88>>),
          HTTP.HTTP2.Frame.encode(:data, 1, id, body)
        ])

      send(parent, {:h2_request, body, address, headers})
      receive do: (:stop -> :ok)
    end
  end

  defp h2_headers(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, @timeout)

    payload =
      if size == 0 do
        <<>>
      else
        assert {:ok, bytes} = :gen_tcp.recv(socket, size, @timeout)
        bytes
      end

    case type do
      1 ->
        {id, payload}

      4 ->
        if flags == 0, do: :gen_tcp.send(socket, HTTP.HTTP2.Frame.encode(:settings, 1, 0, <<>>))
        h2_headers(socket)

      _ ->
        h2_headers(socket)
    end
  end

  test "pinned OTP streaming connection retains cancellable TCP ownership" do
    {port, _} =
      tls_peer(@ipv4, fn socket ->
        assert {:error, :closed} = :ssl.recv(socket, 0, @timeout)
      end)

    request = %HTTP.Request{
      url: URI.parse("https://pinned.invalid:#{port}/"),
      body: self(),
      transport_options: [
        tls_backend: :ssl,
        connect_address: @ipv4,
        redirect: :manual,
        ssl: [cacertfile: Path.join(@fixtures, "pinned-ca.pem")]
      ]
    }

    assert {:ok, HTTP.Transport.SSL, socket, _} = HTTP.Runtime.Dialer.open(request, nil, @timeout)
    assert HTTP.Transport.SSL.cancellable?(socket)
    assert :ok = HTTP.Transport.SSL.close(socket)
  end

  defp await_tls_transport_close(socket, alerts \\ <<>>) do
    case :gen_tcp.recv(socket, 0, @timeout) do
      {:error, reason} when reason in [:closed, :econnreset] ->
        assert_tls_alerts(alerts)

      {:ok, bytes} ->
        assert byte_size(alerts) + byte_size(bytes) <= 64
        await_tls_transport_close(socket, alerts <> bytes)

      other ->
        flunk("TLS establishment did not close: #{inspect(other)}")
    end
  end

  defp assert_tls_alerts(<<>>), do: :ok

  defp assert_tls_alerts(<<21, 3, _minor, size::16, _alert::binary-size(size), rest::binary>>),
    do: assert_tls_alerts(rest)

  defp listen(address) do
    family = if tuple_size(address) == 8, do: :inet6, else: :inet
    :gen_tcp.listen(0, [family, :binary, active: false, reuseaddr: true, ip: address])
  end

  defp tcp_peer(address, handler) do
    {:ok, listener} = listen(address)
    {:ok, {_, port}} = :inet.sockname(listener)
    parent = self()

    peer =
      spawn(fn ->
        with {:ok, socket} <- :gen_tcp.accept(listener, @timeout) do
          try do
            handler.(socket)
          rescue
            error -> send(parent, {:peer_error, error})
          after
            :gen_tcp.close(socket)
          end
        end
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {port, peer}
  end

  defp tls_peer(address, handler, fixture \\ "pinned") do
    family = if tuple_size(address) == 8, do: :inet6, else: :inet

    {:ok, listener} =
      :ssl.listen(0, [
        family,
        :binary,
        active: false,
        reuseaddr: true,
        ip: address,
        versions: [:"tlsv1.3"],
        certfile: Path.join(@fixtures, fixture <> ".pem"),
        keyfile: Path.join(@fixtures, fixture <> ".key")
      ])

    {:ok, {_, port}} = :ssl.sockname(listener)
    parent = self()

    peer =
      spawn(fn ->
        with {:ok, tcp} <- :ssl.transport_accept(listener, @timeout),
             result = :ssl.handshake(tcp, @timeout),
             _ = send(parent, {:tls_handshake, self(), result}),
             {:ok, socket} <- result do
          try do
            handler.(socket)
          rescue
            error -> send(parent, {:peer_error, error})
          after
            :ssl.close(socket)
          end
        end
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :ssl.close(listener)
    end)

    {port, peer}
  end

  defp recv_head(transport, socket, buffer \\ <<>>) do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      assert {:ok, data} = transport.recv(socket, 0, @timeout)
      recv_head(transport, socket, buffer <> data)
    else
      buffer
    end
  end

  defp response(body),
    do:
      "HTTP/1.1 200 OK\r\nContent-Length: #{byte_size(body)}\r\nConnection: close\r\n\r\n#{body}"
end
