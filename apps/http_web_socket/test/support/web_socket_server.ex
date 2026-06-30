defmodule HTTPWebSocket.TestServer do
  @moduledoc false

  import Bitwise

  @guid "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

  def start_link(opts \\ []) do
    parent = self()

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
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        :ok = :gen_tcp.close(listen_socket)
        serve(socket, parent, opts)
      end)

    {:ok, pid, port}
  end

  defp serve(socket, parent, opts) do
    with {:ok, request} <- recv_until(socket, "\r\n\r\n", <<>>),
         {:ok, key} <- request_header(request, "sec-websocket-key") do
      protocol = Keyword.get(opts, :protocol)
      :ok = :gen_tcp.send(socket, handshake_response(key, protocol))
      send(parent, {:websocket_server_handshake, request})

      maybe_send_open_message(socket, Keyword.get(opts, :open_message))

      case maybe_send_close(socket, Keyword.get(opts, :close_after_open)) do
        :closed -> :ok
        :open -> loop(socket, parent, <<>>)
      end
    else
      {:error, reason} ->
        send(parent, {:websocket_server_error, reason})
        :gen_tcp.close(socket)
    end
  end

  defp loop(socket, parent, buffer) do
    case take_client_frame(buffer) do
      {:ok, opcode, payload, rest} ->
        handle_frame(socket, parent, opcode, payload)
        loop(socket, parent, rest)

      :more ->
        case :gen_tcp.recv(socket, 0, 1_000) do
          {:ok, data} ->
            loop(socket, parent, buffer <> data)

          {:error, :closed} ->
            send(parent, :websocket_server_closed)

          {:error, reason} ->
            send(parent, {:websocket_server_error, reason})
        end
    end
  end

  defp handle_frame(socket, parent, 0x1, payload) do
    send(parent, {:websocket_server_received, :text, payload})
    :ok = send_server_frame(socket, 0x1, "echo:" <> payload)
  end

  defp handle_frame(_socket, parent, 0x2, payload) do
    send(parent, {:websocket_server_received, :binary, payload})
  end

  defp handle_frame(socket, parent, 0x8, payload) do
    send(parent, {:websocket_server_received, :close, payload})
    :ok = send_server_frame(socket, 0x8, payload)
    :gen_tcp.close(socket)
  end

  defp handle_frame(_socket, parent, opcode, payload) do
    send(parent, {:websocket_server_received, opcode, payload})
  end

  defp maybe_send_open_message(_socket, nil), do: :ok

  defp maybe_send_open_message(socket, {:binary, payload}) do
    send_server_frame(socket, 0x2, payload)
  end

  defp maybe_send_open_message(socket, message) when is_binary(message) do
    send_server_frame(socket, 0x1, message)
  end

  defp maybe_send_close(_socket, nil), do: :open

  defp maybe_send_close(socket, {code, reason}) do
    :ok = send_server_frame(socket, 0x8, <<code::16, reason::binary>>)
    :gen_tcp.close(socket)
    :closed
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

  defp request_header(request, wanted_name) do
    request
    |> String.split("\r\n")
    |> Enum.find_value(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] ->
          if String.downcase(name) == wanted_name, do: {:ok, String.trim(value)}

        _ ->
          nil
      end
    end)
    |> case do
      nil -> {:error, {:missing_header, wanted_name}}
      result -> result
    end
  end

  defp handshake_response(key, nil) do
    [
      "HTTP/1.1 101 Switching Protocols\r\n",
      "Upgrade: websocket\r\n",
      "Connection: Upgrade\r\n",
      "Sec-WebSocket-Accept: ",
      accept_key(key),
      "\r\n\r\n"
    ]
  end

  defp handshake_response(key, protocol) do
    [
      "HTTP/1.1 101 Switching Protocols\r\n",
      "Upgrade: websocket\r\n",
      "Connection: Upgrade\r\n",
      "Sec-WebSocket-Accept: ",
      accept_key(key),
      "\r\n",
      "Sec-WebSocket-Protocol: ",
      protocol,
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
    <<payload::binary-size(length), remaining::binary>> = rest
    {:ok, mask_key, payload, remaining}
  end

  defp send_server_frame(socket, opcode, payload) do
    :gen_tcp.send(socket, server_frame(opcode, payload))
  end

  defp server_frame(opcode, payload) when byte_size(payload) <= 125 do
    <<0x80 ||| opcode, byte_size(payload), payload::binary>>
  end

  defp unmask(payload, <<a, b, c, d>>) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {byte, index} ->
      bxor(byte, Enum.at([a, b, c, d], rem(index, 4)))
    end)
    |> :binary.list_to_bin()
  end
end
