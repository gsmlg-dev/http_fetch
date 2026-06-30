defmodule HTTP.WebSocketTest do
  use ExUnit.Case, async: true

  alias HTTP.WebSocket
  alias HTTP.WebSocket.ArrayBuffer
  alias HTTP.WebSocket.Event.Close
  alias HTTP.WebSocket.Event.Error
  alias HTTP.WebSocket.Event.Message
  alias HTTP.WebSocket.Event.Open

  test "defines browser ready state constants" do
    assert WebSocket.connecting() == 0
    assert WebSocket.open() == 1
    assert WebSocket.closing() == 2
    assert WebSocket.closed() == 3
  end

  test "wraps explicit binary data as array buffer" do
    assert %ArrayBuffer{data: <<1, 2>>, byte_length: 2} = WebSocket.array_buffer(<<1, 2>>)
    assert {:error, :invalid_array_buffer} = WebSocket.array_buffer(:bad)
  end

  test "defines browser-compatible event structs" do
    assert %Open{type: "open"} = %Open{}
    assert %Message{type: "message"} = %Message{}
    assert %Error{type: "error"} = %Error{}
    assert %Close{type: "close"} = %Close{}
  end

  test "connects, receives messages, sends text, and closes cleanly" do
    {:ok, _server, port} = HTTPWebSocket.TestServer.start_link(open_message: "welcome")

    socket = WebSocket.new("ws://127.0.0.1:#{port}/socket?room=1")

    assert %WebSocket{} = socket
    assert WebSocket.url(socket) == "ws://127.0.0.1:#{port}/socket?room=1"

    assert_receive {WebSocket, ^socket, %Open{}}, 1_000
    assert WebSocket.ready_state(socket) == WebSocket.open()
    assert WebSocket.protocol(socket) == ""
    assert WebSocket.extensions(socket) == ""
    assert WebSocket.binary_type(socket) == :blob

    assert_receive {WebSocket, ^socket, %Message{data: "welcome"}}, 1_000

    assert :ok = WebSocket.send(socket, "hello")
    assert_receive {:websocket_server_received, :text, "hello"}, 1_000
    assert_receive {WebSocket, ^socket, %Message{data: "echo:hello"}}, 1_000

    assert :ok = WebSocket.close(socket, 1000, "done")

    assert_receive {WebSocket, ^socket, %Close{code: 1000, reason: "done", was_clean: true}},
                   1_000
  end

  test "supports selected subprotocols and array buffer receive mode" do
    {:ok, _server, port} =
      HTTPWebSocket.TestServer.start_link(protocol: "chat", open_message: {:binary, <<1, 2, 3>>})

    socket = WebSocket.new("ws://127.0.0.1:#{port}/socket", ["chat"], binary_type: :array_buffer)

    assert_receive {WebSocket, ^socket, %Open{}}, 1_000
    assert WebSocket.protocol(socket) == "chat"
    assert WebSocket.binary_type(socket) == :array_buffer

    assert_receive {WebSocket, ^socket,
                    %Message{data: %ArrayBuffer{data: <<1, 2, 3>>, byte_length: 3}}},
                   1_000
  end

  test "sends array buffer and blob payloads as binary frames" do
    {:ok, _server, port} = HTTPWebSocket.TestServer.start_link()
    socket = WebSocket.new("ws://127.0.0.1:#{port}/socket")

    assert_receive {WebSocket, ^socket, %Open{}}, 1_000

    assert :ok = WebSocket.send(socket, WebSocket.array_buffer(<<1, 2, 3>>))
    assert_receive {:websocket_server_received, :binary, <<1, 2, 3>>}, 1_000

    assert :ok = WebSocket.send(socket, HTTP.Blob.new(<<4, 5, 6>>))
    assert_receive {:websocket_server_received, :binary, <<4, 5, 6>>}, 1_000
  end

  test "rejects invalid constructor input synchronously" do
    assert {:error, :fragment_not_allowed} = WebSocket.new("ws://example.com/socket#frag")
  end

  test "validates close arguments synchronously" do
    assert {:error, :invalid_close_code} =
             WebSocket.close(%WebSocket{pid: self()}, 1005, "")

    assert {:error, :close_reason_too_long} =
             WebSocket.close(%WebSocket{pid: self()}, 1000, :binary.copy("a", 124))
  end
end
