defmodule HTTP.Test.HTTP2ScriptedPeer do
  @moduledoc false
  import Bitwise

  def frame(type, flags, id, payload),
    do: <<byte_size(payload)::24, type, flags, 0::1, id::31, payload::binary>>

  def start(test, script, opts \\ []) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])
    {:ok, {_, port}} = :inet.sockname(listener)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listener, 5_000)
        {:ok, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"} = :gen_tcp.recv(socket, 24, 5_000)
        :ok = :gen_tcp.send(socket, frame(4, 0, 0, Keyword.get(opts, :settings, <<>>)))
        script.(socket)
        send(test, {:peer_complete, self()})

        receive do
          :close -> :gen_tcp.close(socket)
        after
          5_000 -> :gen_tcp.close(socket)
        end

        :gen_tcp.close(listener)
      end)

    :ok = :gen_tcp.controlling_process(listener, pid)

    {"http://localhost:#{port}/test", pid}
  end

  def recv(socket) do
    {:ok, <<length::24, type, flags, _::1, id::31>>} = :gen_tcp.recv(socket, 9, 5_000)
    payload = if length == 0, do: <<>>, else: elem(:gen_tcp.recv(socket, length, 5_000), 1)
    {type, flags, id, payload}
  end

  def request(socket) do
    case recv(socket) do
      {1, flags, id, _} -> {id, (flags &&& 1) == 1}
      _ -> request(socket)
    end
  end

  def body(socket, id, acc \\ []) do
    case recv(socket) do
      {0, flags, ^id, bytes} ->
        if byte_size(bytes) > 0 do
          :ok =
            :gen_tcp.send(socket, [
              frame(8, 0, 0, <<byte_size(bytes)::32>>),
              frame(8, 0, id, <<byte_size(bytes)::32>>)
            ])
        end

        if (flags &&& 1) == 1,
          do: IO.iodata_to_binary(Enum.reverse([bytes | acc])),
          else: body(socket, id, [bytes | acc])

      _ ->
        body(socket, id, acc)
    end
  end

  def response(socket, id, body) do
    :gen_tcp.send(socket, [frame(1, 4, id, <<0x88>>), frame(0, 1, id, body)])
  end
end
