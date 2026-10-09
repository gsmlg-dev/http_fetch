defmodule HTTP.WebSocket.ProxyFrameTest do
  use ExUnit.Case, async: true
  import Bitwise
  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.{Open, Close}
  @timeout 5_000

  test "proxy options retain browser defaults and reject HTTP2 and invalid pong configuration" do
    assert {:ok, %{mode: :browser, automatic_pong: true}} =
             WebSocket.Options.new("ws://example.com")

    assert {:ok, %{mode: :proxy, automatic_pong: false}} =
             WebSocket.Options.new("ws://example.com", [], %{
               "mode" => :proxy,
               "automaticPong" => false
             })

    for version <- [:http2, :h2c, :auto] do
      assert {:error, :proxy_requires_http1} =
               WebSocket.new("ws://example.com", [], mode: :proxy, http_version: version)
    end

    assert {:error, {:invalid_option, :mode}} =
             WebSocket.new("ws://example.com", [], mode: :invalid)

    assert {:error, {:invalid_option, :automatic_pong}} =
             WebSocket.new("ws://example.com", [], mode: :proxy, automatic_pong: :disabled)

    assert {:error, :automatic_pong_requires_proxy} =
             WebSocket.new("ws://example.com", [], automatic_pong: false)
  end

  test "proxy delivers bounded FIFO text binary ping pong and sends explicit frames before close" do
    {url, _} =
      peer(fn socket, key ->
        :ok =
          :gen_tcp.send(socket, [
            head(key),
            <<0x81, 1, "t", 0x82, 1, 255, 0x89, 1, "p", 0x8A, 1, "q">>
          ])

        assert {1, "text"} = frame(socket)
        assert {2, <<255>>} = frame(socket)
        assert {9, "ping"} = frame(socket)
        assert {10, "pong"} = frame(socket)
        assert {8, <<1001::16, "Going Away">>} = frame(socket)
        :ok = :gen_tcp.send(socket, <<0x88, 12, 1001::16, "Going Away">>)
      end)

    ws =
      WebSocket.new(url, [],
        mode: :proxy,
        automatic_pong: false,
        delivery: :ack,
        max_message_size: 1,
        max_queue_bytes: 132,
        max_queue_events: 1
      )

    assert_receive {WebSocket, ^ws, %Open{}}, @timeout

    for {opcode, data} <- [text: "t", binary: <<255>>, ping: "p", pong: "q"] do
      assert_receive {WebSocket, ^ws,
                      %{__struct__: HTTP.WebSocket.Event.Frame, opcode: ^opcode, data: ^data},
                      ref},
                     @timeout

      assert %{queued_events: 1, queued_bytes: 8} = WebSocket.status(ws)
      refute_receive {WebSocket, ^ws, %{__struct__: HTTP.WebSocket.Event.Frame}, _}, 0
      assert :ok = WebSocket.acknowledge(ws, ref)
    end

    for outgoing <- [text: "text", binary: <<255>>, ping: "ping", pong: "pong"] do
      assert {:ok, ref} = WebSocket.send_frame_ack(ws, outgoing)
      assert_receive {WebSocket, ^ws, {:send_result, ^ref, :ok}}, @timeout
    end

    assert :ok = WebSocket.close(ws, 1001, "Going Away")

    assert_receive {WebSocket, ^ws, %Close{code: 1001, reason: "Going Away", was_clean: true}},
                   @timeout
  end

  test "proxy automatic pong remains opt-in configurable while delivering controls" do
    {url, _} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, [head(key), <<0x89, 1, "p", 0x8A, 1, "q">>])
        assert {10, "p"} = frame(socket)
        assert {8, <<1000::16>>} = frame(socket)
        :ok = :gen_tcp.send(socket, <<0x88, 2, 1000::16>>)
      end)

    ws = WebSocket.new(url, [], mode: :proxy)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout

    assert_receive {WebSocket, ^ws,
                    %{__struct__: HTTP.WebSocket.Event.Frame, opcode: :ping, data: "p"}},
                   @timeout

    assert_receive {WebSocket, ^ws,
                    %{__struct__: HTTP.WebSocket.Event.Frame, opcode: :pong, data: "q"}},
                   @timeout

    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
  end

  test "full-size controls retain ACK byte bounds even with a smaller message limit" do
    payload = :binary.copy("p", 125)

    {url, _} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, [head(key), <<0x89, 125, payload::binary, 0x8A, 0>>])
        assert {8, <<1000::16>>} = frame(socket)
        :ok = :gen_tcp.send(socket, <<0x88, 2, 1000::16>>)
      end)

    ws =
      WebSocket.new(url, [],
        mode: :proxy,
        automatic_pong: false,
        delivery: :ack,
        max_message_size: 1,
        max_queue_bytes: 132,
        max_queue_events: 2
      )

    assert_receive {WebSocket, ^ws, %Open{}}, @timeout

    assert_receive {WebSocket, ^ws, %{__struct__: HTTP.WebSocket.Event.Frame, data: ^payload},
                    ref},
                   @timeout

    assert %{queued_events: 1, queued_bytes: 132, raw_bytes: 2} = WebSocket.status(ws)
    assert :ok = WebSocket.acknowledge(ws, ref)

    assert_receive {WebSocket, ^ws, %{__struct__: HTTP.WebSocket.Event.Frame, opcode: :pong},
                    ref},
                   @timeout

    assert :ok = WebSocket.acknowledge(ws, ref)
    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
  end

  test "proxy ACK capacity must admit a full RFC control payload" do
    assert {:error, :message_limit_exceeds_delivery_limit} =
             WebSocket.new("ws://example.com", [],
               mode: :proxy,
               delivery: :ack,
               max_message_size: 1,
               max_queue_bytes: 131
             )
  end

  test "explicit frame validation rejects invalid UTF8 oversized controls and reserved close codes" do
    {url, _} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, head(key))
        assert {9, ""} = frame(socket)
        assert {8, <<1008::16, "policy">>} = frame(socket)
        :ok = :gen_tcp.send(socket, <<0x88, 8, 1008::16, "policy">>)
      end)

    ws = WebSocket.new(url, [], mode: :proxy, max_send_queue: 2)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert {:error, :invalid_text_data} = WebSocket.send_frame(ws, {:text, <<255>>})

    assert {:error, :control_payload_too_large} =
             WebSocket.send_frame(ws, {:ping, :binary.copy("p", 126)})

    assert {:error, :send_queue_full} = WebSocket.send_frame(ws, {:pong, "big"})
    assert {:error, :invalid_frame} = WebSocket.send_frame(ws, {:close, <<1000::16>>})

    for code <- [999, 1004, 1005, 1006, 1015, 2000, 5000] do
      assert {:error, :invalid_close_code} = WebSocket.close(ws, code)
    end

    assert {:error, :invalid_close_reason} = WebSocket.close(ws, 1008, <<255>>)
    assert {:error, :close_reason_too_long} = WebSocket.close(ws, 1011, :binary.copy("r", 124))
    assert :ok = WebSocket.send_frame(ws, {:ping, ""})
    assert :ok = WebSocket.close(ws, 1008, "policy")
    assert_receive {WebSocket, ^ws, %Close{code: 1008, was_clean: true}}, @timeout
    assert {:error, :closed} = WebSocket.send_frame_ack(ws, {:pong, ""})
  end

  test "browser rejects explicit frame sends and non-browser close codes" do
    {url, _} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, head(key))
        assert {8, <<1000::16>>} = frame(socket)
        :ok = :gen_tcp.send(socket, <<0x88, 2, 1000::16>>)
      end)

    ws = WebSocket.new(url)
    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    assert {:error, :proxy_mode_required} = WebSocket.send_frame(ws, {:ping, ""})
    assert {:error, :proxy_mode_required} = WebSocket.send_frame_ack(ws, {:pong, ""})
    assert {:error, :invalid_close_code} = WebSocket.close(ws, 1001)
    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{was_clean: true}}, @timeout
  end

  test "proxy close emits every supported wire status and an empty close" do
    for code <- [
          nil,
          1000,
          1001,
          1002,
          1003,
          1007,
          1008,
          1009,
          1010,
          1011,
          1012,
          1013,
          1014,
          3000,
          4999
        ] do
      payload = if code, do: <<code::16, "reason">>, else: <<>>
      reason = if code, do: "reason", else: ""

      {url, _} =
        peer(fn socket, key ->
          :ok = :gen_tcp.send(socket, head(key))
          assert {8, ^payload} = frame(socket)
          :ok = :gen_tcp.send(socket, <<0x88, byte_size(payload), payload::binary>>)
        end)

      ws = WebSocket.new(url, [], mode: :proxy)
      assert_receive {WebSocket, ^ws, %Open{}}, @timeout
      assert :ok = WebSocket.close(ws, code, reason)
      event_code = code

      assert_receive {WebSocket, ^ws,
                      %Close{code: ^event_code, reason: ^reason, was_clean: true}},
                     @timeout
    end
  end

  test "proxy empty control sends count toward bounded queue and close deadline cancels pending sends" do
    parent = self()

    {url, peer} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, head(key))
        receive do: (:drain -> drain(socket))
        send(parent, {:closed, self()})
      end)

    ws =
      WebSocket.new(url, [],
        mode: :proxy,
        max_send_frames: 2,
        max_send_queue: 16 * 1024 * 1024,
        close_timeout: 100,
        socket_opts: [sndbuf: 1024, high_watermark: 1024, low_watermark: 512]
      )

    assert_receive {WebSocket, ^ws, %Open{}}, @timeout
    data = :binary.copy(<<1>>, 8 * 1024 * 1024)
    assert {:ok, _} = WebSocket.send_frame_ack(ws, {:binary, data})
    assert {:ok, pending} = WebSocket.send_frame_ack(ws, {:binary, data})
    assert {:ok, control} = WebSocket.send_frame_ack(ws, {:ping, ""})
    assert {:error, :send_queue_full} = WebSocket.send_frame_ack(ws, {:pong, ""})
    assert %{pending_send_frames: 2} = WebSocket.status(ws)
    monitor = Process.monitor(ws.pid)
    assert :ok = WebSocket.close(ws, 1011, "cancelled")
    assert_receive {WebSocket, ^ws, {:send_result, ^control, {:error, :closed}}}, @timeout
    assert_receive {WebSocket, ^ws, {:send_result, ^pending, {:error, :closed}}}, @timeout
    assert_receive {:DOWN, ^monitor, :process, _, :normal}, 1000
    send(peer, :drain)
    assert_receive {:closed, ^peer}, @timeout
  end

  test "owner death closes proxy transport despite an unacknowledged control event" do
    parent = self()

    {url, peer} =
      peer(fn socket, key ->
        :ok = :gen_tcp.send(socket, [head(key), <<0x89, 0>>])
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, @timeout)
        send(parent, {:owner_closed, self()})
      end)

    owner =
      spawn(fn ->
        ws = WebSocket.new(url, [], mode: :proxy, automatic_pong: false, delivery: :ack)

        receive do
          {WebSocket, ^ws, %{__struct__: HTTP.WebSocket.Event.Frame, opcode: :ping}, _ref} ->
            send(parent, {:owned, ws})
        end

        receive do: (:stop -> :ok)
      end)

    on_exit(fn -> if Process.alive?(owner), do: Process.exit(owner, :kill) end)
    assert_receive {:owned, ws}, @timeout
    monitor = Process.monitor(ws.pid)
    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 1000
    assert_receive {:owner_closed, ^peer}, @timeout
  end

  defp peer(fun) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, recbuf: 1_024])
    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, @timeout)
        request = request(socket, "")

        key = request_key(request)

        fun.(socket, key)
        :gen_tcp.close(socket)
      end)

    on_exit(fn ->
      Process.exit(peer, :kill)
      :gen_tcp.close(listener)
    end)

    {"ws://127.0.0.1:#{port}/proxy", peer}
  end

  defp request(socket, buffer) do
    if :binary.match(buffer, "\r\n\r\n") == :nomatch do
      {:ok, data} = :gen_tcp.recv(socket, 0, @timeout)
      request(socket, buffer <> data)
    else
      buffer
    end
  end

  defp request_key(request) do
    request
    |> String.split("\r\n")
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] -> if String.downcase(name) == "sec-websocket-key", do: String.trim(value)
        _ -> nil
      end
    end)
  end

  defp head(key) do
    accept = Base.encode64(:crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))

    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept}\r\n\r\n"
  end

  defp frame(socket) do
    {:ok, <<first, 1::1, size::7>>} = :gen_tcp.recv(socket, 2, @timeout)

    {:ok, <<mask::binary-size(4), payload::binary-size(size)>>} =
      :gen_tcp.recv(socket, 4 + size, @timeout)

    bytes =
      for {byte, index} <- Enum.with_index(:binary.bin_to_list(payload)),
          do: bxor(byte, :binary.at(mask, rem(index, 4)))

    {first &&& 15, :erlang.list_to_binary(bytes)}
  end

  defp drain(socket) do
    case :gen_tcp.recv(socket, 0, @timeout) do
      {:ok, _} -> drain(socket)
      {:error, reason} when reason in [:closed, :econnreset] -> :ok
      other -> flunk("expected closed, got #{inspect(other)}")
    end
  end
end
