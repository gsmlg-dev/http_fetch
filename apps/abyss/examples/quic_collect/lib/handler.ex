defmodule AbyssCollectExample.Handler do
  @behaviour Abyss.QUIC.Handler

  @impl true
  def init(connection, metadata, opts) do
    if opts[:observer], do: send(opts[:observer], {:bound, self(), connection, metadata})
    {:ok, %{connection: connection, streams: %{}, delay: opts[:delay] || 0}}
  end

  @impl true
  def handle_event({:stream_open, stream, kind}, state) do
    # End only our sending direction before collecting the peer's data.
    if kind == :bidi do
      {:ok, _} = Abyss.QUIC.send_stream(stream, <<>>, true)
    end

    {:ok, %{state | streams: Map.put(state.streams, stream, {0, :crypto.hash_init(:sha256)})}}
  end

  def handle_event(event, state) when event == :tick or event == :writable,
    do: {:ok, collect(state)}

  def handle_event({:readable, _}, state), do: {:ok, collect(state)}
  def handle_event(_, state), do: {:ok, state}

  defp collect(state) do
    if state.delay > 0, do: Process.sleep(state.delay)

    Enum.reduce(state.streams, state, fn {stream, _}, acc ->
      {:ok, items} = Abyss.QUIC.read(stream, 1024)

      Enum.reduce(items, acc, fn
        {:data, _, bytes}, s ->
          {count, hash} = s.streams[stream]

          %{
            s
            | streams:
                Map.put(
                  s.streams,
                  stream,
                  {count + byte_size(bytes), :crypto.hash_update(hash, bytes)}
                )
          }

        {:fin, _}, s ->
          {count, hash} = s.streams[stream]
          {:ok, report} = Abyss.QUIC.open_stream(s.connection, :uni)

          {:ok, _} =
            Abyss.QUIC.send_stream(report, <<count::64, :crypto.hash_final(hash)::binary>>, true)

          %{s | streams: Map.delete(s.streams, stream)}

        {:reset, _, _, _}, s ->
          %{s | streams: Map.delete(s.streams, stream)}
      end)
    end)
  end
end
