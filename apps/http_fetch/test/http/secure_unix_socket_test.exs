defmodule HTTP.SecureUnixSocketTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias HTTP.{Promise, Response}

  setup do
    path = Path.join(System.tmp_dir!(), "fetch-unix-#{System.unique_integer([:positive])}.sock")

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, ifaddr: {:local, String.to_charlist(path)}])

    on_exit(fn ->
      :gen_tcp.close(listener)
      File.rm!(path)
    end)

    {:ok, path: path, listener: listener}
  end

  test "HTTPS never connects to a plaintext Unix socket", %{path: path, listener: listener} do
    for backend <- [nil, :ex_ssl], version <- [:http1, :auto] do
      assert {:error, :tls_over_unix_socket_not_supported} =
               HTTP.fetch("https://localhost/private",
                 unix_socket: path,
                 tls_backend: backend,
                 http_version: version
               )
               |> Promise.await(1_000)

      assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
    end
  end

  test "a redirect to HTTPS rejects before a second Unix connection", %{
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
            "HTTP/1.1 302 Found\r\nLocation: https://localhost/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
          )

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
        :gen_tcp.close(socket)
        request
      end)

    assert {:error, :tls_over_unix_socket_not_supported} =
             HTTP.fetch("http://localhost/start", unix_socket: path) |> Promise.await(1_000)

    assert Task.await(peer, 1_000) =~ "GET /start HTTP/1.1\r\n"
    assert {:error, :timeout} = :gen_tcp.accept(listener, 25)
  end

  test "plain HTTP still exchanges a response over Unix", %{path: path, listener: listener} do
    peer =
      Task.async(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 1_000)
        request = recv_head(socket)

        :ok =
          :gen_tcp.send(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nunix"
          )

        assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1_000)
        :gen_tcp.close(socket)
        request
      end)

    assert %Response{status: 200, body: "unix"} =
             HTTP.fetch("http://localhost/plain", unix_socket: path) |> Promise.await(1_000)

    assert Task.await(peer, 1_000) =~ "GET /plain HTTP/1.1\r\n"
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
