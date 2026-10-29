defmodule HTTP.WebSocket.SecureUnixSocketTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias HTTP.{ClientCompletion, WebSocket}
  alias HTTP.WebSocket.Event.{Close, Message, Open}

  setup do
    path = Path.join(System.tmp_dir!(), "ws-unix-#{System.unique_integer([:positive])}.sock")

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ifaddr: {:local, String.to_charlist(path)}])

    on_exit(fn ->
      :gen_tcp.close(listener)
      File.rm!(path)
    end)

    {:ok, path: path, listener: listener}
  end

  test "WSS and the HTTPS alias reject without a Unix connection", %{
    path: path,
    listener: listener
  } do
    for scheme <- ["wss", "https"], backend <- [nil, :ex_ssl] do
      assert {:error, :tls_over_unix_socket_not_supported} =
               WebSocket.new("#{scheme}://localhost/socket", [],
                 unix_socket: path,
                 tls_backend: backend
               )

      assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
    end
  end

  test "plain WS still upgrades and exchanges a frame over Unix", %{
    path: path,
    listener: listener
  } do
    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 1_000)
        request = recv_head(socket)
        [_, key] = Regex.run(~r/\r\nsec-websocket-key: ([^\r]+)\r\n/i, request)

        accept =
          :crypto.hash(:sha, key <> "258EAFA5-E914-47DA-95CA-C5AB0DC85B11") |> Base.encode64()

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: #{accept}\r\n\r\n",
            <<0x81, 4, "unix">>
          ])

        assert {:ok, <<0x88, _::binary>>} = :gen_tcp.recv(socket, 0, 1_000)
        :ok = :gen_tcp.send(socket, <<0x88, 2, 1000::16>>)
        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
        :gen_tcp.close(socket)
        request
      end)

    ws = WebSocket.new("ws://localhost/socket", [], unix_socket: path)
    on_exit(fn -> WebSocket.close(ws) end)
    assert_receive {WebSocket, ^ws, %Open{}}, 1_000
    assert_receive {WebSocket, ^ws, %Message{data: "unix"}}, 1_000
    assert :ok = WebSocket.close(ws, 1000)
    assert_receive {WebSocket, ^ws, %Close{code: 1000, was_clean: true}}, 1_000
    assert :ok = ClientCompletion.await(WebSocket.completion(ws), 1_000)
    assert Task.await(peer, 1_000) =~ "GET /socket HTTP/1.1\r\n"
  end

  defp recv_head(socket, buffer \\ "") do
    assert byte_size(buffer) <= 8_192

    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      assert {:ok, data} = :gen_tcp.recv(socket, 0, 1_000)
      recv_head(socket, buffer <> data)
    end
  end
end
