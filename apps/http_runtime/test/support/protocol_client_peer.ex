defmodule HTTP.ProtocolClientPeer do
  @moduledoc false
  alias HTTP.HTTP2.{Frame, HPACK, Settings}

  def start(protocol, test) do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true, ip: {127, 0, 0, 1}])

    {:ok, {_, port}} = :inet.sockname(listener)

    peer =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        :gen_tcp.close(listener)
        send(test, {:peer_accepted, self()})

        case protocol do
          :http1 ->
            h1(socket, test, <<>>, 0)

          :http2 ->
            {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)
            :ok = :gen_tcp.send(socket, Frame.encode(:settings, 0, 0, <<>>))
            :ok = :inet.setopts(socket, active: :once)

            h2(socket, test, %{
              buffer: <<>>,
              decoder: HPACK.new_decoder(),
              encoder: HPACK.new_encoder(),
              blocked: nil,
              ack_waiter: nil
            })
        end
      end)

    {peer, "http://127.0.0.1:#{port}", listener}
  end

  defp h1(socket, test, buffer, count) do
    case :binary.match(buffer, "\r\n\r\n") do
      {offset, 4} ->
        <<head::binary-size(offset), _::binary-size(4), rest::binary>> = buffer
        send(test, {:peer_request, self(), count + 1, head})

        cond do
          String.contains?(head, " /oversize ") ->
            _ =
              :gen_tcp.send(socket, [
                "HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\n\r\n",
                :binary.copy("x", 2_097_152)
              ])

          String.contains?(head, " /close ") ->
            :ok =
              :gen_tcp.send(
                socket,
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
              )

          String.contains?(head, " /hang ") ->
            :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")

          true ->
            :ok = :gen_tcp.send(socket, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        end

        h1(socket, test, rest, count + 1)

      :nomatch ->
        case :gen_tcp.recv(socket, 0, 5_000) do
          {:ok, data} -> h1(socket, test, buffer <> data, count)
          {:error, :closed} -> send(test, {:peer_closed, self(), count})
        end
    end
  end

  defp h2(socket, test, state) do
    receive do
      {:tcp, ^socket, bytes} ->
        state = frames(socket, test, %{state | buffer: state.buffer <> bytes})
        :ok = :inet.setopts(socket, active: :once)
        h2(socket, test, state)

      {:tcp_closed, ^socket} ->
        send(test, {:peer_closed, self(), :http2})

      {:tcp_error, ^socket, reason} ->
        send(test, {:peer_error, self(), reason})

      {:expire, id} ->
        :ok = :gen_tcp.send(socket, Frame.encode(:rst_stream, 0, id, <<8::32>>))
        send(test, {:peer_expired, self(), id})
        h2(socket, test, %{state | blocked: nil})
    after
      5_000 ->
        :gen_tcp.close(socket)
        send(test, {:peer_timeout, self()})
    end
  end

  defp frames(socket, test, state) do
    case Frame.decode(state.buffer) do
      :more ->
        state

      {:ok, frame, rest} ->
        send(test, {:peer_frame, self(), frame})
        state = frame(socket, test, %{state | buffer: rest}, frame)
        frames(socket, test, state)
    end
  end

  defp frame(socket, test, state, %{type: :settings, flags: 0, payload: payload}) do
    {:ok, settings} = Settings.decode(payload)
    :ok = :gen_tcp.send(socket, Frame.encode(:settings, 1, 0, <<>>))
    send(test, {:peer_settings, self(), settings})

    if state.blocked &&
         List.keyfind(settings, :initial_window_size, 0) == {:initial_window_size, 65_535} do
      id = state.blocked
      :ok = :gen_tcp.send(socket, Frame.encode(:data, 1, id, "y"))
      %{state | blocked: nil}
    else
      state
    end
  end

  defp frame(socket, test, state, %{type: :headers, stream_id: id, payload: block}) do
    {:ok, decoder, headers} = HPACK.decode(state.decoder, block)
    path = List.keyfind(headers, ":path", 0) |> elem(1)
    send(test, {:peer_request, self(), id, path})

    {encoder, block} =
      HPACK.encode_headers(state.encoder, [{":status", "200"}, {"content-length", "2"}])

    :ok = :gen_tcp.send(socket, Frame.encode(:headers, 4, id, block))

    case path do
      "/health" ->
        :ok = :gen_tcp.send(socket, Frame.encode(:data, 1, id, "ok"))
        %{state | encoder: encoder, decoder: decoder}

      "/expire" ->
        :ok = :gen_tcp.send(socket, Frame.encode(:data, 0, id, "x"))
        Process.send_after(self(), {:expire, id}, 100)
        send(test, {:peer_blocked, self(), id})
        %{state | encoder: encoder, decoder: decoder}

      "/ack" ->
        :ok = :gen_tcp.send(socket, Frame.encode(:data, 0, id, "x"))
        send(test, {:peer_blocked, self(), id})
        %{state | encoder: encoder, decoder: decoder, ack_waiter: id}

      "/restore" ->
        :ok = :gen_tcp.send(socket, Frame.encode(:data, 0, id, "x"))
        send(test, {:peer_blocked, self(), id})
        %{state | encoder: encoder, decoder: decoder, blocked: id}

      "/reset" ->
        :ok = :gen_tcp.send(socket, Frame.encode(:data, 0, id, "x"))
        %{state | encoder: encoder, decoder: decoder}
    end
  end

  defp frame(socket, _test, %{ack_waiter: id} = state, %{type: :window_update, stream_id: id})
       when id != nil do
    :ok = :gen_tcp.send(socket, Frame.encode(:data, 1, id, "y"))
    %{state | ack_waiter: nil}
  end

  defp frame(_socket, _test, state, _frame), do: state
end
