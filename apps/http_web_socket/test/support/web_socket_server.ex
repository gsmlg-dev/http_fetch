defmodule HTTPWebSocket.TestServer do
  @moduledoc false

  import Bitwise

  @guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  def start_link(opts \\ []) do
    parent = self()
    tls? = Keyword.get(opts, :tls, false)
    transport = socket_module(tls?)
    {:ok, listen_socket} = listen(tls?, opts)
    {:ok, {{127, 0, 0, 1}, port}} = sockname(tls?, listen_socket)

    pid =
      spawn_link(fn ->
        with {:ok, socket} <- accept(tls?, listen_socket),
             :ok <- transport.close(listen_socket) do
          serve(socket, parent, opts, transport)
        else
          {:error, reason} -> send(parent, {:websocket_server_error, reason})
        end
      end)

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

  defp accept(false, listen_socket), do: :gen_tcp.accept(listen_socket)

  defp accept(true, listen_socket) do
    with {:ok, transport_socket} <- :ssl.transport_accept(listen_socket),
         do: :ssl.handshake(transport_socket)
  end

  defp socket_module(false), do: :gen_tcp
  defp socket_module(true), do: :ssl
  defp sockname(false, listen_socket), do: :inet.sockname(listen_socket)
  defp sockname(true, listen_socket), do: :ssl.sockname(listen_socket)

  defp serve(socket, parent, opts, transport) do
    with {:ok, request} <- recv_until(transport, socket, "\r\n\r\n", <<>>),
         {:ok, key} <- request_header(request, "sec-websocket-key") do
      :ok =
        transport.send(socket, [
          handshake_response(key, Keyword.get(opts, :protocol)),
          Keyword.get(opts, :upgrade_frames, <<>>)
        ])

      send(parent, {:websocket_server_handshake, request})

      if Keyword.get(opts, :close_after_upgrade, false) do
        receive do
          :close_tls -> transport.close(socket)
        after
          5_000 -> transport.close(socket)
        end
      else
        maybe_send_open_message(transport, socket, Keyword.get(opts, :open_message))

        case maybe_send_close(transport, socket, Keyword.get(opts, :close_after_open)) do
          :closed -> :ok
          :open -> loop(transport, socket, parent, <<>>)
        end
      end
    else
      {:error, reason} ->
        send(parent, {:websocket_server_error, reason})
        transport.close(socket)
    end
  end

  defp loop(transport, socket, parent, buffer) do
    case take_client_frame(buffer) do
      {:ok, opcode, payload, rest} ->
        handle_frame(transport, socket, parent, opcode, payload)
        loop(transport, socket, parent, rest)

      :more ->
        case transport.recv(socket, 0, 1_000) do
          {:ok, data} -> loop(transport, socket, parent, buffer <> data)
          {:error, :closed} -> send(parent, :websocket_server_closed)
          {:error, reason} -> send(parent, {:websocket_server_error, reason})
        end
    end
  end

  defp handle_frame(transport, socket, parent, 0x1, payload) do
    send(parent, {:websocket_server_received, :text, payload})
    :ok = send_server_frame(transport, socket, 0x1, "echo:" <> payload)
  end

  defp handle_frame(_transport, _socket, parent, 0x2, payload),
    do: send(parent, {:websocket_server_received, :binary, payload})

  defp handle_frame(transport, socket, parent, 0x8, payload) do
    send(parent, {:websocket_server_received, :close, payload})
    :ok = send_server_frame(transport, socket, 0x8, payload)
    transport.close(socket)
  end

  defp handle_frame(_transport, _socket, parent, opcode, payload),
    do: send(parent, {:websocket_server_received, opcode, payload})

  defp maybe_send_open_message(_transport, _socket, nil), do: :ok

  defp maybe_send_open_message(transport, socket, {:binary, payload}),
    do: send_server_frame(transport, socket, 0x2, payload)

  defp maybe_send_open_message(transport, socket, message) when is_binary(message),
    do: send_server_frame(transport, socket, 0x1, message)

  defp maybe_send_close(_transport, _socket, nil), do: :open

  defp maybe_send_close(transport, socket, {code, reason}) do
    :ok = send_server_frame(transport, socket, 0x8, <<code::16, reason::binary>>)
    transport.close(socket)
    :closed
  end

  defp recv_until(transport, socket, marker, buffer) do
    if :binary.match(buffer, marker) == :nomatch do
      with {:ok, data} <- transport.recv(socket, 0, 1_000),
           do: recv_until(transport, socket, marker, buffer <> data)
    else
      {:ok, buffer}
    end
  end

  defp request_header(request, wanted_name) do
    request
    |> String.split("\r\n")
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] -> if String.downcase(name) == wanted_name, do: {:ok, String.trim(value)}
        _ -> nil
      end
    end)
    |> case do
      nil -> {:error, {:missing_header, wanted_name}}
      result -> result
    end
  end

  defp handshake_response(key, protocol) do
    [
      "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
      accept_key(key),
      if(protocol, do: ["\r\nSec-WebSocket-Protocol: ", protocol], else: []),
      "\r\n\r\n"
    ]
  end

  defp accept_key(key), do: :crypto.hash(:sha, key <> @guid) |> Base.encode64()
  defp take_client_frame(buffer) when byte_size(buffer) < 6, do: :more

  defp take_client_frame(<<first, second, rest::binary>>) do
    opcode = first &&& 0x0F
    masked? = (second &&& 0x80) != 0
    length_code = second &&& 0x7F

    with true <- masked?,
         {:ok, length, rest} <- take_length(length_code, rest),
         {:ok, mask_key, payload, rest} <- take_masked_payload(rest, length) do
      {:ok, opcode, unmask(payload, mask_key), rest}
    else
      false -> {:ok, :unmasked_client_frame, <<>>, <<>>}
      :more -> :more
    end
  end

  defp take_length(length, rest) when length <= 125, do: {:ok, length, rest}
  defp take_length(126, <<length::16, rest::binary>>), do: {:ok, length, rest}
  defp take_length(126, _rest), do: :more
  defp take_length(127, <<length::64, rest::binary>>), do: {:ok, length, rest}
  defp take_length(127, _rest), do: :more
  defp take_masked_payload(rest, length) when byte_size(rest) < 4 + length, do: :more

  defp take_masked_payload(<<mask_key::binary-size(4), rest::binary>>, length) do
    <<payload::binary-size(^length), remaining::binary>> = rest
    {:ok, mask_key, payload, remaining}
  end

  defp send_server_frame(transport, socket, opcode, payload),
    do: transport.send(socket, server_frame(opcode, payload))

  defp server_frame(opcode, payload) when byte_size(payload) <= 125,
    do: <<0x80 ||| opcode, byte_size(payload), payload::binary>>

  defp unmask(payload, <<a, b, c, d>>) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {byte, index} -> bxor(byte, Enum.at([a, b, c, d], rem(index, 4))) end)
    |> :binary.list_to_bin()
  end
end
