defmodule HTTPEventSource.TestServer do
  @moduledoc false

  def start_link(opts \\ []) do
    parent = self()
    responses = Keyword.get(opts, :responses, [opts])

    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1}
      ])

    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listen_socket)

    pid =
      spawn_link(fn ->
        accept_loop(listen_socket, parent, responses)
      end)

    {:ok, pid, port}
  end

  defp accept_loop(listen_socket, _parent, []) do
    :gen_tcp.close(listen_socket)
  end

  defp accept_loop(listen_socket, parent, [response | rest]) do
    case :gen_tcp.accept(listen_socket, 5_000) do
      {:ok, socket} ->
        serve(socket, parent, response)
        accept_loop(listen_socket, parent, rest)

      {:error, reason} ->
        send(parent, {:event_source_server_error, reason})
        :gen_tcp.close(listen_socket)
    end
  end

  defp serve(socket, parent, response) do
    case recv_until(socket, "\r\n\r\n", <<>>) do
      {:ok, request} ->
        send(parent, {:event_source_server_request, request})
        :ok = :gen_tcp.send(socket, response_head(response))
        :ok = send_body(socket, Keyword.get(response, :body, ""))

        if Keyword.get(response, :close, true) do
          :gen_tcp.close(socket)
        else
          wait_for_close(socket, parent)
        end

      {:error, reason} ->
        send(parent, {:event_source_server_error, reason})
        :gen_tcp.close(socket)
    end
  end

  defp recv_until(socket, marker, buffer) do
    if :binary.match(buffer, marker) == :nomatch do
      with {:ok, data} <- :gen_tcp.recv(socket, 0, 1_000) do
        recv_until(socket, marker, buffer <> data)
      end
    else
      {:ok, buffer}
    end
  end

  defp response_head(response) do
    status = Keyword.get(response, :status, 200)
    reason = reason_phrase(status)
    headers = Keyword.get(response, :headers, [])
    content_type = Keyword.get(response, :content_type, "text/event-stream")

    content_type_header =
      if content_type do
        [{"Content-Type", content_type}]
      else
        []
      end

    [
      "HTTP/1.1 ",
      Integer.to_string(status),
      " ",
      reason,
      "\r\n",
      header_lines(content_type_header ++ headers),
      "Connection: close\r\n",
      "\r\n"
    ]
  end

  defp header_lines(headers) do
    Enum.map(headers, fn {name, value} -> [to_string(name), ": ", to_string(value), "\r\n"] end)
  end

  defp send_body(_socket, ""), do: :ok

  defp send_body(socket, chunks) when is_list(chunks) do
    Enum.each(chunks, fn chunk ->
      :ok = :gen_tcp.send(socket, chunk)
    end)
  end

  defp send_body(socket, body), do: :gen_tcp.send(socket, body)

  defp wait_for_close(socket, parent) do
    case :gen_tcp.recv(socket, 0, 2_000) do
      {:error, :closed} ->
        send(parent, :event_source_server_closed)

      {:error, reason} ->
        send(parent, {:event_source_server_error, reason})

      {:ok, _data} ->
        wait_for_close(socket, parent)
    end
  end

  defp reason_phrase(200), do: "OK"
  defp reason_phrase(204), do: "No Content"
  defp reason_phrase(404), do: "Not Found"
  defp reason_phrase(_status), do: "Unknown"
end
