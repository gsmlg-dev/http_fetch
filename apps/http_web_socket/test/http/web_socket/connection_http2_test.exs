defmodule HTTP.WebSocket.ConnectionHTTP2Test do
  use ExUnit.Case, async: true
  import Bitwise
  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Open, Message, Close, Error}
  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  test "2xx opens a duplex masked WebSocket, ACK delivery and close half-close are ordered" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, id, <<0x88>>),
            frame(0, 0, id, <<0x81>>),
            frame(0, 0, id, <<2, "hi", 0x82, 2, 0, 255>>)
          ])

        assert {1, "from-client"} = websocket_frame(socket, id)
        send(parent, {:client_masked, self()})
        receive do: (:peer_close -> :ok)
        :ok = :gen_tcp.send(socket, frame(0, 1, id, <<0x88, 2, 1000::16>>))
        assert {8, <<1000::16>>} = websocket_frame(socket, id)
        assert {0, 1, ^id, ""} = next_frame(socket, 0, id)
        send(parent, {:close_wire, self()})
      end)

    ws = websocket(url, delivery: :ack)
    assert_receive {WebSocket, ^ws, %Open{}}, 5_000
    assert WebSocket.http_version(ws) == :http2
    assert WebSocket.protocol(ws) == ""
    assert_receive {WebSocket, ^ws, %Message{data: "hi"}, first}, 5_000
    assert WebSocket.send(ws, "from-client") == :ok
    assert_receive {:client_masked, ^peer}, 5_000
    assert %{queued_events: 2, inflight?: true} = WebSocket.status(ws)
    refute_receive {WebSocket, ^ws, %Message{}, _}, 0
    assert :ok = WebSocket.acknowledge(ws, first)
    assert_receive {WebSocket, ^ws, %Message{data: %HTTP.Blob{data: <<0, 255>>}}, second}, 5_000
    assert :ok = WebSocket.acknowledge(ws, first)
    assert :ok = WebSocket.acknowledge(ws, second)
    send(peer, :peer_close)
    assert_receive {WebSocket, ^ws, %Close{code: 1000, was_clean: true}}, 5_000
    assert_receive {:close_wire, ^peer}, 5_000
  end

  test "zero send credit keeps send/status/cancel responsive and leaves ordinary siblings usable" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          {id, 4} = request(socket)
          :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
          {sibling, 5} = request(socket)

          :ok =
            :gen_tcp.send(socket, [frame(1, 4, sibling, <<0x88>>), frame(0, 1, sibling, "ok")])

          assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
          send(parent, {:reset_wire, self()})
        end,
        <<3::16, 10::32, 8::16, 1::32, 4::16, 0::32>>
      )

    scope = "ws-sibling-#{System.unique_integer([:positive])}"
    ws = websocket(url, http2_scope: scope, close_timeout: 50)
    assert_receive {WebSocket, ^ws, %Open{}}, 5_000
    assert :ok = WebSocket.send(ws, "blocked")
    assert WebSocket.buffered_amount(ws) == 7
    assert %{pending_send_frames: 1} = WebSocket.status(ws)
    uri = HTTP.Runtime.Options.origin_uri(URI.parse(url))

    response =
      HTTP.fetch(uri, http_version: :h2c, http2_scope: scope, connect_timeout: 30_000)
      |> HTTP.Promise.await(5_000)

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "ok"
    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{was_clean: false}}, 5_000
    assert_receive {:reset_wire, ^peer}, 5_000
  end

  test "END_STREAM after local Close without peer Close is abnormal and never sends 1006" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)
        :ok = :gen_tcp.send(socket, frame(1, 4, id, <<0x88>>))
        assert {8, <<1000::16>>} = websocket_frame(socket, id)
        :ok = :gen_tcp.send(socket, frame(0, 1, id, ""))
        assert {3, 0, ^id, <<8::32>>} = next_frame(socket, 3, id)
        send(parent, {:abnormal_wire, self()})
      end)

    ws = websocket(url)
    assert_receive {WebSocket, ^ws, %Open{}}, 5_000
    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, 5_000
    assert_receive {:abnormal_wire, ^peer}, 5_000
  end

  test "valid messages preceding a malformed frame drain before protocol error and Close" do
    parent = self()

    {url, peer} =
      peer(fn socket ->
        {id, 4} = request(socket)

        :ok =
          :gen_tcp.send(socket, [
            frame(1, 4, id, <<0x88>>),
            frame(0, 0, id, <<0x81, 4, "good", 0x83, 0>>)
          ])

        assert {8, <<1002::16, _reason::binary>>} = websocket_frame(socket, id)
        send(parent, {:protocol_close, self()})
      end)

    ws = websocket(url, delivery: :ack)
    assert_receive {WebSocket, ^ws, %Open{}}, 5_000
    assert_receive {WebSocket, ^ws, %Message{data: "good"}, ref}, 5_000
    assert %{queued_events: 1} = WebSocket.status(ws)
    refute_receive {WebSocket, ^ws, %Error{}}, 0
    assert :ok = WebSocket.acknowledge(ws, ref)
    assert_receive {WebSocket, ^ws, %Error{reason: :unknown_opcode}}, 5_000
    assert_receive {WebSocket, ^ws, %Close{code: 1002, was_clean: false}}, 5_000
    assert_receive {:protocol_close, ^peer}, 5_000
  end

  test "strict H2 capability refusal opens no CONNECT and retains owner for an ordinary request" do
    parent = self()

    {url, peer} =
      peer(
        fn socket ->
          {id, 5} = request(socket)
          :ok = :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 1, id, "ordinary")])
          send(parent, {:ordinary_wire, self()})
        end,
        <<3::16, 10::32>>
      )

    scope = "ws-refusal-#{System.unique_integer([:positive])}"
    ws = websocket(url, http2_scope: scope)
    assert_receive {WebSocket, ^ws, %Error{reason: :extended_connect_not_supported}}, 5_000
    assert_receive {WebSocket, ^ws, %Close{code: 1006, was_clean: false}}, 5_000
    refute_receive {WebSocket, ^ws, %Open{}}, 0

    response =
      HTTP.fetch(HTTP.Runtime.Options.origin_uri(URI.parse(url)),
        http_version: :h2c,
        http2_scope: scope,
        connect_timeout: 30_000
      )
      |> HTTP.Promise.await(5_000)

    assert HTTP.Response.read_all(response) == "ordinary"
    assert_receive {:ordinary_wire, ^peer}, 5_000
  end

  defp websocket(url, options \\ []) do
    ws = WebSocket.new(url, [], [http_version: :h2c, timeout: 5_000] ++ options)
    assert %WebSocket{} = ws
    on_exit(fn -> if Process.alive?(ws.pid), do: Process.exit(ws.pid, :kill) end)
    ws
  end

  # Literal short RFC6455 client-frame oracle, independent from the frame codec.
  defp websocket_frame(socket, id) do
    {0, 0, ^id, bytes} = next_frame(socket, 0, id)
    <<first, 1::1, length::7, key::binary-size(4), payload::binary-size(length)>> = bytes

    decoded =
      for <<byte <- payload>>, reduce: {0, []} do
        {index, acc} -> {index + 1, [bxor(byte, :binary.at(key, rem(index, 4))) | acc]}
      end

    {first &&& 15, decoded |> elem(1) |> Enum.reverse() |> :erlang.list_to_binary()}
  end

  defp peer(script, settings \\ <<3::16, 10::32, 8::16, 1::32>>) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)

        assert {:ok, @preface} = :gen_tcp.recv(socket, byte_size(@preface), 5_000)
        :ok = :gen_tcp.send(socket, frame(4, 0, 0, settings))

        script.(socket)
        receive do: (:stop -> :gen_tcp.close(socket))
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {"ws://127.0.0.1:#{port}/chat", peer}
  end

  defp frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  defp receive_frame(socket) do
    assert {:ok, <<size::24, type, flags, 0::1, id::31>>} = :gen_tcp.recv(socket, 9, 5_000)
    payload = if size == 0, do: <<>>, else: recv_payload(socket, size)
    {type, flags, id, payload}
  end

  defp recv_payload(socket, size) do
    assert {:ok, payload} = :gen_tcp.recv(socket, size, 5_000)
    payload
  end

  defp request(socket) do
    case receive_frame(socket) do
      {1, flags, id, _payload} ->
        {id, flags}

      {4, 0, 0, _payload} ->
        :ok = :gen_tcp.send(socket, frame(4, 1, 0, <<>>))
        request(socket)

      _frame ->
        request(socket)
    end
  end

  defp next_frame(socket, type, id) do
    case receive_frame(socket) do
      {^type, _flags, ^id, _payload} = observed -> observed
      _frame -> next_frame(socket, type, id)
    end
  end
end
