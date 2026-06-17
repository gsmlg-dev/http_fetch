defmodule HTTP.SSLTransportTest do
  use ExUnit.Case, async: true

  @certfile Path.expand("../support/fixtures/localhost.pem", __DIR__)
  @cacertfile Path.expand("../support/fixtures/localhost-ca.pem", __DIR__)
  @keyfile Path.expand("../support/fixtures/localhost.key", __DIR__)

  describe "https transport" do
    test "rejects self-signed certificates by default" do
      url = start_https_server!(fn socket -> send_response(socket, "secure") end)

      assert {:error, _reason} = url |> HTTP.fetch() |> HTTP.Promise.await()
    end

    test "fetches responses over ssl" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, request} = recv_headers(socket, <<>>)
          assert request =~ "GET /secure HTTP/1.1\r\n"

          send_response(socket, "secure")
        end)

      response =
        url
        |> HTTP.fetch(options: [ssl: [verify: :verify_none]])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert HTTP.Response.read_all(response) == "secure"
    end

    test "honors caller cacertfile with verify peer" do
      url =
        start_https_server!(fn socket ->
          assert {:ok, request} = recv_headers(socket, <<>>)
          assert request =~ "GET /secure HTTP/1.1\r\n"

          send_response(socket, "trusted")
        end)

      response =
        url
        |> HTTP.fetch(options: [ssl: [cacertfile: @cacertfile]])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert HTTP.Response.read_all(response) == "trusted"
    end

    test "streams large responses over ssl" do
      body = String.duplicate("s", HTTP.Config.streaming_threshold() + 1)

      url =
        start_https_server!(fn socket ->
          assert {:ok, _request} = recv_headers(socket, <<>>)
          send_response(socket, body)
        end)

      response =
        url
        |> HTTP.fetch(options: [ssl: [verify: :verify_none]])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert response.body == nil
      assert is_pid(response.stream)
      assert HTTP.Response.read_all(response) == body
    end
  end

  defp start_https_server!(handler) when is_function(handler, 1) do
    {:ok, listen_socket} =
      :ssl.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        certfile: @certfile,
        keyfile: @keyfile
      ])

    {:ok, {{127, 0, 0, 1}, port}} = :ssl.sockname(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, transport_socket} = :ssl.transport_accept(listen_socket, 5_000)

        case :ssl.handshake(transport_socket) do
          {:ok, socket} ->
            handler.(socket)
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

    "https://127.0.0.1:#{port}/secure"
  end

  defp recv_headers(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      {:ok, acc}
    else
      case :ssl.recv(socket, 0, 5_000) do
        {:ok, data} -> recv_headers(socket, acc <> data)
        {:error, reason} -> {:error, reason}
      end
    end
  end

  defp send_response(socket, body) do
    :ok =
      :ssl.send(socket, [
        "HTTP/1.1 200 OK\r\n",
        "Content-Length: ",
        Integer.to_string(byte_size(body)),
        "\r\n",
        "Connection: close\r\n",
        "\r\n",
        body
      ])

    :ssl.close(socket)
  end
end
