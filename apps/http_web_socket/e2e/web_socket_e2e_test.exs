defmodule HTTP.WebSocketE2ETest do
  use ExUnit.Case, async: true

  alias HTTP.WebSocket
  alias HTTP.WebSocket.Event.Close
  alias HTTP.WebSocket.Event.Message
  alias HTTP.WebSocket.Event.Open

  test "round trips text messages through a local WebSocket server" do
    {:ok, _server, port} = HTTPWebSocket.TestServer.start_link(open_message: "ready")

    socket = WebSocket.new("ws://127.0.0.1:#{port}/chat")

    assert_receive {WebSocket, ^socket, %Open{}}, 1_000
    assert_receive {WebSocket, ^socket, %Message{data: "ready"}}, 1_000

    assert :ok = WebSocket.send(socket, "hello from e2e")
    assert_receive {:websocket_server_received, :text, "hello from e2e"}, 1_000
    assert_receive {WebSocket, ^socket, %Message{data: "echo:hello from e2e"}}, 1_000

    assert :ok = WebSocket.close(socket, 1000, "done")

    assert_receive {WebSocket, ^socket, %Close{code: 1000, reason: "done", was_clean: true}},
                   1_000
  end

  test "sends custom headers, negotiates protocol, and sends binary payloads" do
    {:ok, _server, port} = HTTPWebSocket.TestServer.start_link(protocol: "chat.v1")

    socket =
      WebSocket.new("ws://127.0.0.1:#{port}/socket", ["chat.v1"],
        headers: [{"X-Trace-Id", "e2e-123"}]
      )

    assert_receive {:websocket_server_handshake, request}, 1_000
    assert request =~ "Sec-WebSocket-Protocol: chat.v1\r\n"
    assert request =~ "X-Trace-Id: e2e-123\r\n"

    assert_receive {WebSocket, ^socket, %Open{}}, 1_000
    assert WebSocket.protocol(socket) == "chat.v1"

    assert :ok = WebSocket.send(socket, WebSocket.array_buffer(<<0, 1, 2, 3>>))
    assert_receive {:websocket_server_received, :binary, <<0, 1, 2, 3>>}, 1_000

    assert :ok = WebSocket.send(socket, HTTP.Blob.new(<<4, 5, 6, 7>>))
    assert_receive {:websocket_server_received, :binary, <<4, 5, 6, 7>>}, 1_000

    assert :ok = WebSocket.close(socket, 1000, "binary done")

    assert_receive {WebSocket, ^socket,
                    %Close{code: 1000, reason: "binary done", was_clean: true}},
                   1_000
  end

  test "emits close event when the peer closes first" do
    {:ok, _server, port} =
      HTTPWebSocket.TestServer.start_link(close_after_open: {1000, "server done"})

    socket = WebSocket.new("ws://127.0.0.1:#{port}/socket")

    assert_receive {WebSocket, ^socket, %Open{}}, 1_000

    assert_receive {WebSocket, ^socket,
                    %Close{code: 1000, reason: "server done", was_clean: true}},
                   1_000

    assert WebSocket.ready_state(socket) == WebSocket.closed()
  end
end
