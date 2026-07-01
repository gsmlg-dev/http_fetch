defmodule HTTP.SocketClientHTTP2Test do
  use ExUnit.Case, async: true

  import Bitwise

  alias HTTP.HTTP2.Frame
  alias HTTP.HTTP2.HPACK

  @certfile Path.expand("../support/fixtures/localhost.pem", __DIR__)
  @keyfile Path.expand("../support/fixtures/localhost.key", __DIR__)

  @ack 0x1
  @end_stream 0x1
  @end_headers 0x4

  test "fetches an explicit h2c prior-knowledge response" do
    test_pid = self()

    url =
      start_h2c_server!(fn socket, transport ->
        {request_headers, buffer} = recv_client_h2_request(socket, transport)
        send(test_pid, {:h2_request, request_headers})

        send_h2_response(socket, transport, "h2c")
        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :h2c)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Headers.get(response.headers, "x-protocol") == "h2"
    assert HTTP.Response.read_all(response) == "h2c"

    assert_receive {:h2_request, headers}
    assert {":method", "GET"} in headers
    assert {":scheme", "http"} in headers
    assert {":path", "/test"} in headers
  end

  test "auto over https negotiates h2 with ALPN" do
    test_pid = self()

    url =
      start_https_h2_server!([<<"h2">>, <<"http/1.1">>], fn socket, transport ->
        send(test_pid, {:negotiated, negotiated_protocol(socket)})
        {_request_headers, buffer} = recv_client_h2_request(socket, transport)

        send_h2_response(socket, transport, "tls-h2")
        assert_settings_ack(socket, transport, buffer)
      end)

    response =
      url
      |> HTTP.fetch(http_version: :auto, ssl: [verify: :verify_none])
      |> HTTP.Promise.await()

    assert_receive {:negotiated, "h2"}
    assert response.status == 200
    assert HTTP.Response.read_all(response) == "tls-h2"
  end

  test "forced https http2 fails when ALPN does not negotiate h2" do
    url =
      start_https_h2_server!([], fn socket, _transport ->
        :timer.sleep(100)
        :ssl.close(socket)
      end)

    assert {:error, {:http2_not_negotiated, nil}} =
             url
             |> HTTP.fetch(http_version: :http2, ssl: [verify: :verify_none])
             |> HTTP.Promise.await()
  end

  defp start_h2c_server!(handler) do
    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        handler.(socket, :gen_tcp)
        :gen_tcp.close(socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp start_https_h2_server!(alpn_protocols, handler) do
    alpn_opts =
      if alpn_protocols == [] do
        []
      else
        [alpn_preferred_protocols: alpn_protocols]
      end

    {:ok, listen_socket} =
      :ssl.listen(
        0,
        [
          :binary,
          packet: :raw,
          active: false,
          ip: {127, 0, 0, 1},
          reuseaddr: true,
          certfile: @certfile,
          keyfile: @keyfile
        ] ++ alpn_opts
      )

    {:ok, {{127, 0, 0, 1}, port}} = :ssl.sockname(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, transport_socket} = :ssl.transport_accept(listen_socket, 5_000)

        case :ssl.handshake(transport_socket) do
          {:ok, socket} ->
            handler.(socket, :ssl)
            :ssl.close(socket)

          {:error, _reason} ->
            :ok
        end

        :ssl.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :ssl.close(listen_socket)
    end)

    "https://127.0.0.1:#{port}/test"
  end

  defp recv_client_h2_request(socket, transport) do
    {preface, buffer} =
      recv_exact(socket, transport, byte_size(HTTP.HTTP2.connection_preface()), <<>>)

    assert preface == HTTP.HTTP2.connection_preface()

    {:ok, %Frame{type: :settings, stream_id: 0}, buffer} =
      recv_frame(socket, transport, buffer)

    {:ok, %Frame{type: :headers, stream_id: 1, flags: flags, payload: header_block}, buffer} =
      recv_frame(socket, transport, buffer)

    assert (flags &&& @end_headers) == @end_headers

    {:ok, _decoder, headers} = HPACK.decode(HPACK.new_decoder(), header_block)
    {headers, buffer}
  end

  defp send_h2_response(socket, transport, body) do
    headers =
      HPACK.encode_headers([
        {":status", "200"},
        {"content-length", Integer.to_string(byte_size(body))},
        {"x-protocol", "h2"}
      ])

    send_all(socket, transport, [
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, @end_headers, 1, headers),
      Frame.encode(:data, @end_stream, 1, body)
    ])
  end

  defp assert_settings_ack(socket, transport, buffer) do
    assert {:ok, %Frame{type: :settings, flags: flags, stream_id: 0, payload: ""}, _buffer} =
             recv_frame(socket, transport, buffer)

    assert (flags &&& @ack) == @ack
  end

  defp recv_frame(socket, transport, buffer) do
    case Frame.decode(buffer) do
      {:ok, frame, rest} ->
        {:ok, frame, rest}

      :more ->
        {:ok, data} = apply(transport, :recv, [socket, 0, 5_000])
        recv_frame(socket, transport, buffer <> data)
    end
  end

  defp recv_exact(_socket, _transport, size, acc) when byte_size(acc) >= size do
    <<data::binary-size(size), rest::binary>> = acc
    {data, rest}
  end

  defp recv_exact(socket, transport, size, acc) do
    {:ok, data} = apply(transport, :recv, [socket, 0, 5_000])
    recv_exact(socket, transport, size, acc <> data)
  end

  defp send_all(socket, transport, iodata) do
    :ok = apply(transport, :send, [socket, iodata])
  end

  defp negotiated_protocol(socket) do
    case :ssl.negotiated_protocol(socket) do
      {:ok, protocol} when is_binary(protocol) -> protocol
      {:ok, protocol} when is_list(protocol) -> List.to_string(protocol)
      {:error, :protocol_not_negotiated} -> nil
    end
  end
end
