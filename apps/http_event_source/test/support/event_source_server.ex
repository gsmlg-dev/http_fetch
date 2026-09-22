defmodule HTTPEventSource.TestServer do
  @moduledoc false

  def start_link(opts \\ []) do
    parent = self()
    responses = Keyword.get(opts, :responses, [opts])
    tls? = Keyword.get(opts, :tls, false)
    transport = socket_module(tls?)
    {:ok, listen_socket} = listen(tls?, opts)
    {:ok, {{127, 0, 0, 1}, port}} = sockname(tls?, listen_socket)

    pid = spawn_link(fn -> accept_loop(tls?, transport, listen_socket, parent, responses) end)
    {:ok, pid, port}
  end

  defp listen(false, _opts) do
    :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])
  end

  defp listen(true, opts) do
    :ssl.listen(0,
      mode: :binary,
      packet: :raw,
      active: false,
      reuseaddr: true,
      ip: {127, 0, 0, 1},
      versions: [:"tlsv1.3"],
      certfile: Keyword.fetch!(opts, :certfile),
      keyfile: Keyword.fetch!(opts, :keyfile)
    )
  end

  defp accept_loop(_tls?, transport, listen_socket, _parent, []),
    do: transport.close(listen_socket)

  defp accept_loop(tls?, transport, listen_socket, parent, [response | rest]) do
    case accept(tls?, listen_socket) do
      {:ok, socket} ->
        serve(transport, socket, parent, response)
        accept_loop(tls?, transport, listen_socket, parent, rest)

      {:error, reason} ->
        send(parent, {:event_source_server_error, reason})
        transport.close(listen_socket)
    end
  end

  defp accept(false, listen_socket), do: :gen_tcp.accept(listen_socket, 5_000)

  defp accept(true, listen_socket) do
    with {:ok, transport_socket} <- :ssl.transport_accept(listen_socket, 5_000),
         do: :ssl.handshake(transport_socket)
  end

  defp socket_module(false), do: :gen_tcp
  defp socket_module(true), do: :ssl
  defp sockname(false, listen_socket), do: :inet.sockname(listen_socket)
  defp sockname(true, listen_socket), do: :ssl.sockname(listen_socket)

  defp serve(transport, socket, parent, response) do
    case recv_until(transport, socket, "\r\n\r\n", <<>>) do
      {:ok, request} ->
        send(parent, {:event_source_server_request, request})
        :ok = transport.send(socket, response_head(response))
        :ok = send_body(transport, socket, Keyword.get(response, :body, ""))

        close_response(transport, socket, parent, response)

      {:error, reason} ->
        send(parent, {:event_source_server_error, reason})
        transport.close(socket)
    end
  end

  defp recv_until(transport, socket, marker, buffer) do
    if :binary.match(buffer, marker) == :nomatch do
      with {:ok, data} <- transport.recv(socket, 0, 1_000),
           do: recv_until(transport, socket, marker, buffer <> data)
    else
      {:ok, buffer}
    end
  end

  defp response_head(response) do
    status = Keyword.get(response, :status, 200)
    headers = Keyword.get(response, :headers, [])
    content_type = Keyword.get(response, :content_type, "text/event-stream")
    content_type_header = if content_type, do: [{"Content-Type", content_type}], else: []

    [
      "HTTP/1.1 ",
      Integer.to_string(status),
      " ",
      reason_phrase(status),
      "\r\n",
      header_lines(content_type_header ++ headers),
      "Connection: close\r\n\r\n"
    ]
  end

  defp header_lines(headers),
    do:
      Enum.map(headers, fn {name, value} -> [to_string(name), ": ", to_string(value), "\r\n"] end)

  defp send_body(_transport, _socket, ""), do: :ok

  defp send_body(transport, socket, body) when is_function(body, 0),
    do: send_body(transport, socket, body.())

  defp send_body(transport, socket, chunks) when is_list(chunks),
    do: Enum.each(chunks, &transport.send(socket, &1))

  defp send_body(transport, socket, body), do: transport.send(socket, body)

  defp close_response(transport, socket, parent, response) do
    case Keyword.get(response, :wait_for) do
      wait_for when is_atom(wait_for) and not is_nil(wait_for) ->
        receive do
          ^wait_for -> transport.close(socket)
        end

      nil ->
        if Keyword.get(response, :close, true) do
          transport.close(socket)
        else
          wait_for_close(transport, socket, parent)
        end
    end
  end

  defp wait_for_close(transport, socket, parent) do
    case transport.recv(socket, 0, 2_000) do
      {:error, :closed} -> send(parent, :event_source_server_closed)
      {:error, reason} -> send(parent, {:event_source_server_error, reason})
      {:ok, _data} -> wait_for_close(transport, socket, parent)
    end
  end

  defp reason_phrase(200), do: "OK"
  defp reason_phrase(204), do: "No Content"
  defp reason_phrase(404), do: "Not Found"
  defp reason_phrase(_status), do: "Unknown"
end
