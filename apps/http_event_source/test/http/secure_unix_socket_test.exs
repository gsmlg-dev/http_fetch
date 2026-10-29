defmodule HTTP.EventSource.SecureUnixSocketTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias HTTP.{ClientCompletion, EventSource}
  alias HTTP.EventSource.Event.{Error, Message, Open}

  setup do
    path = Path.join(System.tmp_dir!(), "sse-unix-#{System.unique_integer([:positive])}.sock")

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ifaddr: {:local, String.to_charlist(path)}])

    on_exit(fn ->
      :gen_tcp.close(listener)
      File.rm!(path)
    end)

    {:ok, path: path, listener: listener}
  end

  test "HTTPS rejects before creating a client or Unix connection", %{
    path: path,
    listener: listener
  } do
    for backend <- [nil, :ex_ssl], version <- [:http1, :auto] do
      assert {:error, :tls_over_unix_socket_not_supported} =
               EventSource.new("https://localhost/events",
                 unix_socket: path,
                 tls_backend: backend,
                 http_version: version
               )

      assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
    end
  end

  test "a secure redirect closes the plain stream without another Unix connection", %{
    path: path,
    listener: listener
  } do
    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 1_000)
        request = recv_head(socket)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://localhost/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
          )

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
        :gen_tcp.close(socket)
        request
      end)

    source = EventSource.new("http://localhost/events", unix_socket: path)
    on_exit(fn -> EventSource.close(source) end)

    assert_receive {EventSource, ^source, %Error{reason: :tls_over_unix_socket_not_supported}},
                   1_000

    assert EventSource.ready_state(source) == EventSource.closed()
    assert :ok = ClientCompletion.await(EventSource.completion(source), 1_000)
    assert Task.await(peer, 1_000) =~ "GET /events HTTP/1.1\r\n"
    assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
    refute_receive {EventSource, ^source, %Open{}}, 0
  end

  test "plain HTTP still delivers events over Unix", %{path: path, listener: listener} do
    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 1_000)
        request = recv_head(socket)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: unix\n\n"
          )

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
        :gen_tcp.close(socket)
        request
      end)

    source = EventSource.new("http://localhost/events", unix_socket: path)
    on_exit(fn -> EventSource.close(source) end)
    assert_receive {EventSource, ^source, %Open{}}, 1_000
    assert_receive {EventSource, ^source, %Message{data: "unix"}}, 1_000
    assert :ok = EventSource.close(source)
    assert :ok = ClientCompletion.await(EventSource.completion(source), 1_000)
    assert Task.await(peer, 1_000) =~ "GET /events HTTP/1.1\r\n"
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
