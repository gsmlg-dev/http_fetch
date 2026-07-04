defmodule HTTP.RequestStreamTest do
  use ExUnit.Case, async: true

  test "uploads a duplex half stream as an HTTP/1.1 chunked request body" do
    test_pid = self()

    url =
      start_raw_http_server!(fn listen_socket ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        request = recv_request(socket)
        send(test_pid, {:request, request})

        :ok =
          :gen_tcp.send(socket, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])

        :gen_tcp.close(socket)
      end)

    {:ok, stream} = HTTP.Stream.from_enumerable(["hello", " ", "stream"])

    response =
      url
      |> HTTP.fetch(method: :post, body: stream, duplex: "half", content_type: "text/plain")
      |> HTTP.Promise.await()

    assert response.status == 200
    assert HTTP.Response.read_all(response) == "ok"

    assert_receive {:request,
                    %{
                      request_line: "POST /test HTTP/1.1",
                      headers: headers,
                      body: "hello stream"
                    }}

    assert headers["content-type"] == "text/plain"
    assert headers["transfer-encoding"] == "chunked"
    refute Map.has_key?(headers, "content-length")
  end

  defp start_raw_http_server!(handler) when is_function(handler, 1) do
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
        handler.(listen_socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp recv_request(socket) do
    {head, rest} = recv_header_block(socket, <<>>)
    [request_line | header_lines] = String.split(head, "\r\n")

    headers =
      header_lines
      |> Enum.flat_map(fn line ->
        case String.split(line, ":", parts: 2) do
          [name, value] -> [{String.downcase(name), String.trim(value)}]
          _ -> []
        end
      end)
      |> Map.new()

    body =
      case Map.get(headers, "transfer-encoding") do
        "chunked" -> recv_chunked_body(socket, rest)
        _other -> recv_content_length_body(socket, rest, headers)
      end

    %{request_line: request_line, headers: headers, body: body}
  end

  defp recv_header_block(socket, acc) do
    case :binary.match(acc, "\r\n\r\n") do
      {index, 4} ->
        head = binary_part(acc, 0, index)
        rest = binary_part(acc, index + 4, byte_size(acc) - index - 4)
        {head, rest}

      :nomatch ->
        {:ok, data} = :gen_tcp.recv(socket, 0, 5_000)
        recv_header_block(socket, acc <> data)
    end
  end

  defp recv_chunked_body(socket, data) do
    data = recv_until(socket, data, "0\r\n\r\n")
    parse_chunked_body(data, [])
  end

  defp recv_until(socket, data, marker) do
    if String.contains?(data, marker) do
      data
    else
      {:ok, more} = :gen_tcp.recv(socket, 0, 5_000)
      recv_until(socket, data <> more, marker)
    end
  end

  defp parse_chunked_body(data, acc) do
    {line, rest} = take_line(data)
    size = String.to_integer(line, 16)

    if size == 0 do
      acc |> Enum.reverse() |> IO.iodata_to_binary()
    else
      <<chunk::binary-size(size), "\r\n", rest::binary>> = rest
      parse_chunked_body(rest, [chunk | acc])
    end
  end

  defp take_line(data) do
    {index, 2} = :binary.match(data, "\r\n")
    line = binary_part(data, 0, index)
    rest = binary_part(data, index + 2, byte_size(data) - index - 2)
    {line, rest}
  end

  defp recv_content_length_body(socket, data, headers) do
    content_length =
      headers
      |> Map.get("content-length", "0")
      |> String.to_integer()

    recv_body(socket, data, content_length)
  end

  defp recv_body(_socket, data, content_length) when byte_size(data) >= content_length do
    binary_part(data, 0, content_length)
  end

  defp recv_body(socket, data, content_length) do
    {:ok, more} = :gen_tcp.recv(socket, content_length - byte_size(data), 5_000)
    recv_body(socket, data <> more, content_length)
  end
end
