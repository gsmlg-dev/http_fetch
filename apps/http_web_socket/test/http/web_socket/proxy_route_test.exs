defmodule HTTP.WebSocket.ProxyRouteTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  import Bitwise
  alias HTTP.{ClientCompletion, WebSocket}
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}

  @timeout 5_000
  @fixtures Path.expand("../../support/fixtures", __DIR__)
  @credential "Basic cHJveHktdXNlcjpzZWNyZXQ="

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssl)
    :ok
  end

  test "plain WS uses absolute HTTP form and proxy authentication with ACK delivery" do
    parent = self()

    {port, peer} =
      peer(fn socket ->
        request = request(:gen_tcp, socket)
        send(parent, {:request, self(), request})
        exchange(:gen_tcp, socket, request)
      end)

    client = client("ws://unresolvable.invalid:8081/chat?q=1", proxy(port))
    assert_receive {:request, ^peer, request}, @timeout

    assert String.starts_with?(
             request,
             "GET http://unresolvable.invalid:8081/chat?q=1 HTTP/1.1\r\n"
           )

    assert header(request, "host") == "unresolvable.invalid:8081"
    assert header(request, "proxy-authorization") == @credential
    complete_exchange(client)
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{version} WSS uses CONNECT and preserves target TLS identity and inner headers" do
      version = unquote(version)
      parent = self()

      {origin_port, origin} =
        tls_origin(version, fn socket ->
          request = request(:ssl, socket)
          send(parent, {:origin_request, self(), request})
          exchange(:ssl, socket, request)
        end)

      {port, peer} = tunnel_proxy(origin_port)

      client =
        client("wss://localhost:#{origin_port}/chat?q=1", proxy(port),
          ssl: [cacertfile: fixture("localhost-ca.pem"), versions: [version]],
          headers: [
            {"Proxy-Authorization", "must-not-reach-origin"},
            {"Authorization", "Bearer target"}
          ]
        )

      assert_receive {:connect, ^peer, connect}, @timeout
      assert String.starts_with?(connect, "CONNECT localhost:#{origin_port} HTTP/1.1\r\n")
      assert header(connect, "host") == "localhost:#{origin_port}"
      assert header(connect, "proxy-authorization") == @credential
      refute connect =~ "Bearer target"
      assert_receive {:sni, "localhost"}, @timeout
      assert_receive {:origin_request, ^origin, request}, @timeout
      assert String.starts_with?(request, "GET /chat?q=1 HTTP/1.1\r\n")
      assert header(request, "host") == "localhost:#{origin_port}"
      assert header(request, "authorization") == "Bearer target"
      assert header(request, "proxy-authorization") == nil
      complete_exchange(client)
      assert_receive {:proxy_closed, ^peer}, @timeout
    end
  end

  test "a tunneled target with the wrong certificate hostname fails before Upgrade" do
    {origin_port, origin} = tls_origin(:"tlsv1.3", fn _ -> flunk("unverified origin opened") end)
    {port, peer} = tunnel_proxy(origin_port)

    client =
      client("wss://wrong.invalid:#{origin_port}/chat", proxy(port),
        ssl: [cacertfile: fixture("localhost-ca.pem")]
      )

    assert_receive {:connect, ^peer, connect}, @timeout
    assert connect =~ "CONNECT wrong.invalid:#{origin_port} HTTP/1.1"
    assert_receive {:sni, "wrong.invalid"}, @timeout
    assert_receive {WebSocket, ^client, %Error{handshake: nil}}, @timeout
    assert_cleanup(client)
    assert_receive {:tls_rejected, ^origin}, @timeout
    assert_receive {:proxy_closed, ^peer}, @timeout
  end

  test "a refused proxy never dials a reachable origin" do
    {listener, origin_port} = listener()
    {refused, proxy_port} = listener()
    :ok = :gen_tcp.close(refused)
    client = client("ws://127.0.0.1:#{origin_port}/socket", proxy(proxy_port))
    assert_receive {WebSocket, ^client, %Error{reason: :econnrefused}}, @timeout
    assert_cleanup(client)
    assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
  end

  test "a rejected CONNECT neither leaks credentials nor falls back to the origin" do
    {listener, origin_port} = listener()
    parent = self()

    {port, peer} =
      peer(fn socket ->
        send(parent, {:connect, self(), request(:gen_tcp, socket)})

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
          )

        closed(socket)
        send(parent, {:proxy_closed, self()})
      end)

    client = client("wss://localhost:#{origin_port}/socket", proxy(port))
    assert_receive {:connect, ^peer, _}, @timeout

    assert_receive {WebSocket, ^client, %Error{reason: {:proxy_connect_status, 407}} = error},
                   @timeout

    refute inspect(error) =~ @credential
    assert error.handshake == nil
    assert_cleanup(client)
    assert_receive {:proxy_closed, ^peer}, @timeout
    assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
  end

  test "proxy credentials stay out of diagnostics, telemetry and safe Upgrade metadata" do
    parent = self()
    id = {__MODULE__, make_ref()}

    :ok =
      :telemetry.attach_many(
        id,
        [[:http_web_socket, :connect, :start], [:http_web_socket, :connect, :exception]],
        &__MODULE__.observe/4,
        parent
      )

    on_exit(fn -> :telemetry.detach(id) end)

    {port, peer} =
      peer(fn socket ->
        _ = request(:gen_tcp, socket)
        send(parent, {:held, self()})
        receive do: (:reject -> :ok)

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 403 Forbidden\r\nRetry-After: 3\r\nSet-Cookie: ",
            @credential,
            "\r\nX-Codex-WebSocket-Max-Unfragmented-Message-Bytes: ",
            String.duplicate("x", 1_025),
            "\r\n\r\n"
          ])

        closed(socket)
      end)

    client = client("ws://unresolvable.invalid/socket", proxy(port))
    assert_receive {:held, ^peer}, @timeout
    refute inspect(:sys.get_status(client.pid), limit: :infinity) =~ @credential
    send(peer, :reject)

    assert_receive {WebSocket, ^client,
                    %Error{
                      reason: {:unexpected_status, 403},
                      handshake: %{status: 403, truncated?: true, headers: headers}
                    } = error},
                   @timeout

    assert HTTP.Headers.to_list(headers) == [{"retry-after", "3"}]
    refute inspect(error) =~ @credential
    assert_cleanup(client)

    for _ <- 1..2 do
      assert_receive {:proxy_telemetry, metadata}, @timeout
      refute inspect(metadata) =~ @credential
    end
  end

  def observe(_event, _measurements, metadata, parent),
    do: send(parent, {:proxy_telemetry, metadata})

  for phase <- [:connect, :tls], terminal <- [:cancel, :opening_timeout, :owner_exit] do
    test "#{terminal} during #{phase} releases the exact proxy socket" do
      cancellation_scenario(unquote(phase), unquote(terminal))
    end
  end

  defp cancellation_scenario(phase, terminal) do
    parent = self()

    {port, peer} =
      peer(fn socket ->
        _ = request(:gen_tcp, socket)

        if phase == :tls do
          :ok = :gen_tcp.send(socket, "HTTP/1.1 200 Connection Established\r\n\r\n")
          assert {:ok, <<22, _::binary>>} = :gen_tcp.recv(socket, 0, @timeout)
        end

        send(parent, {:held, self()})
        closed(socket)
        send(parent, {:proxy_closed, self()})
      end)

    timeout = if terminal == :opening_timeout, do: 250, else: @timeout
    url = "wss://localhost:8443/socket"

    {client, owner} =
      if terminal == :owner_exit do
        owner =
          spawn(fn ->
            client = WebSocket.new(url, [], proxy: proxy(port), opening_timeout: timeout)
            send(parent, {:client, self(), client})
            receive do: (:stop -> :ok)
          end)

        assert_receive {:client, ^owner, client}, @timeout
        {client, owner}
      else
        {client(url, proxy(port), opening_timeout: timeout), nil}
      end

    receipt = WebSocket.completion(client)
    assert_receive {:held, ^peer}, @timeout

    case terminal do
      :cancel -> assert :ok = WebSocket.close(client)
      :owner_exit -> Process.exit(owner, :kill)
      :opening_timeout -> assert_receive {WebSocket, ^client, %Error{}}, @timeout
    end

    assert :ok = ClientCompletion.await(receipt, @timeout)
    assert_receive {:proxy_closed, ^peer}, @timeout
    refute Process.alive?(client.pid)
    refute_receive {WebSocket, ^client, %Open{}}, 0
  end

  test "proxy tunnel timeout is independently bounded by its tuple" do
    parent = self()

    {port, peer} =
      peer(fn socket ->
        _ = request(:gen_tcp, socket)
        send(parent, {:held, self()})
        closed(socket)
        send(parent, {:proxy_closed, self()})
      end)

    client = client("wss://localhost:8443/socket", {:http, "127.0.0.1", port, [timeout: 250]})
    assert_receive {:held, ^peer}, @timeout
    assert_receive {WebSocket, ^client, %Error{reason: :proxy_tunnel_timeout}}, 2_000
    assert_cleanup(client)
    assert_receive {:proxy_closed, ^peer}, @timeout
  end

  test "explicit proxy nil makes a direct selection for caller-resolved NO_PROXY" do
    {port, _peer} =
      peer(fn socket ->
        request = request(:gen_tcp, socket)
        assert String.starts_with?(request, "GET /direct HTTP/1.1\r\n")
        assert header(request, "proxy-authorization") == nil
        exchange(:gen_tcp, socket, request)
      end)

    complete_exchange(client("ws://127.0.0.1:#{port}/direct", nil))
  end

  defp client(url, proxy, extra \\ []) do
    client =
      WebSocket.new(
        url,
        [],
        Keyword.merge(
          [
            proxy: proxy,
            delivery: :ack,
            opening_timeout: @timeout,
            connect_timeout: @timeout,
            write_timeout: 1_000,
            close_timeout: 1_000
          ],
          extra
        )
      )

    on_exit(fn -> WebSocket.close(client) end)
    client
  end

  defp proxy(port),
    do: {:http, "127.0.0.1", port, [headers: [{"Proxy-Authorization", @credential}]]}

  defp complete_exchange(client) do
    assert_receive {WebSocket, ^client, %Open{handshake: %{status: 101}}}, @timeout
    assert_receive {WebSocket, ^client, %Message{data: "hello"}, ref}, @timeout
    assert :ok = WebSocket.acknowledge(client, ref)
    assert {:ok, write} = WebSocket.send_ack(client, "proof")
    assert_receive {WebSocket, ^client, {:send_result, ^write, :ok}}, @timeout
    assert_receive {WebSocket, ^client, %Message{data: "echo:proof"}, echo}, @timeout
    assert :ok = WebSocket.acknowledge(client, echo)
    assert :ok = WebSocket.close(client, 1000)
    assert_receive {WebSocket, ^client, %Close{code: 1000, was_clean: true}}, @timeout
    assert :ok = ClientCompletion.await(WebSocket.completion(client), @timeout)
  end

  defp assert_cleanup(client) do
    assert_receive {WebSocket, ^client, %Close{code: 1006, was_clean: false}}, @timeout
    assert :ok = ClientCompletion.await(WebSocket.completion(client), @timeout)
  end

  defp listener do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    {listener, port}
  end

  defp peer(fun) do
    {listener, port} = listener()

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @timeout)
        fun.(socket)
        :gen_tcp.close(socket)
      end)

    on_exit(fn -> Process.exit(peer, :kill) end)
    {port, peer}
  end

  defp tls_origin(version, fun) do
    parent = self()

    peer(fn socket ->
      opts = [
        certfile: fixture("localhost.pem"),
        keyfile: fixture("localhost.key"),
        versions: [version],
        alpn_preferred_protocols: ["http/1.1"],
        sni_fun: fn host ->
          send(parent, {:sni, to_string(host)})
          []
        end
      ]

      case :ssl.handshake(socket, opts, @timeout) do
        {:ok, tls} ->
          assert {:ok, "http/1.1"} = :ssl.negotiated_protocol(tls)
          fun.(tls)
          :ssl.close(tls)

        {:error, _} ->
          send(parent, {:tls_rejected, self()})
      end
    end)
  end

  defp tunnel_proxy(origin_port) do
    parent = self()

    peer(fn socket ->
      send(parent, {:connect, self(), request(:gen_tcp, socket)})

      {:ok, origin} =
        :gen_tcp.connect({127, 0, 0, 1}, origin_port, [:binary, active: false], @timeout)

      :ok = :gen_tcp.send(socket, "HTTP/1.1 200 Connection Established\r\n\r\n")
      :ok = :inet.setopts(socket, active: :once)
      :ok = :inet.setopts(origin, active: :once)
      relay(socket, origin)
      send(parent, {:proxy_closed, self()})
    end)
  end

  defp relay(left, right) do
    receive do
      {:tcp, socket, bytes} when socket == left or socket == right ->
        other = if socket == left, do: right, else: left

        case :gen_tcp.send(other, bytes) do
          :ok ->
            :inet.setopts(socket, active: :once)
            relay(left, right)

          {:error, _} ->
            :ok
        end

      {:tcp_closed, _} ->
        :ok

      {:tcp_error, _, _} ->
        :ok
    after
      @timeout -> flunk("proxy relay did not close")
    end

    :gen_tcp.close(left)
    :gen_tcp.close(right)
  end

  defp exchange(transport, socket, request) do
    key = header(request, "sec-websocket-key")
    accept = Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

    :ok =
      transport.send(socket, [
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept}\r\n\r\n",
        <<0x81, 5, "hello">>
      ])

    assert {1, "proof"} = frame(transport, socket)
    :ok = transport.send(socket, <<0x81, 10, "echo:proof">>)
    assert {8, <<1000::16>>} = frame(transport, socket)
    :ok = transport.send(socket, <<0x88, 2, 1000::16>>)
  end

  defp request(transport, socket, buffer \\ "") do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      {:ok, bytes} = transport.recv(socket, 0, @timeout)
      request(transport, socket, buffer <> bytes)
    else
      buffer
    end
  end

  defp header(request, name) do
    request
    |> String.split("\r\n")
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [key, value] -> if String.downcase(key) == name, do: String.trim(value)
        _ -> nil
      end
    end)
  end

  defp frame(transport, socket) do
    {:ok, <<first, 1::1, size::7>>} = transport.recv(socket, 2, @timeout)

    {:ok, <<mask::binary-size(4), payload::binary-size(size)>>} =
      transport.recv(socket, 4 + size, @timeout)

    bytes =
      for {byte, index} <- Enum.with_index(:binary.bin_to_list(payload)),
          do: bxor(byte, :binary.at(mask, rem(index, 4)))

    {first &&& 15, :erlang.list_to_binary(bytes)}
  end

  defp closed(socket) do
    case :gen_tcp.recv(socket, 0, @timeout) do
      {:ok, _} -> closed(socket)
      {:error, reason} when reason in [:closed, :econnreset] -> :ok
      other -> flunk("proxy socket did not close: #{inspect(other)}")
    end
  end

  defp fixture(name), do: Path.join(@fixtures, name)
end
