defmodule AbyssEchoExample.Handler do
  @behaviour Abyss.QUIC.Handler

  @impl true
  def init(connection, metadata, opts) do
    {:ok, bidi} = Abyss.QUIC.open_stream(connection, :bidi)
    {:ok, uni} = Abyss.QUIC.open_stream(connection, :uni)
    if opts[:observer], do: send(opts[:observer], {:bound, self(), connection, metadata})

    {:ok,
     %{
       streams: %{bidi => :bidi, uni => :uni},
       # This write starts at offset zero and exercises engine packetization.
       pending: %{bidi => {:binary.copy("x", 16_384), true}, uni => {"server-uni", true}},
       local: bidi,
       observer: opts[:observer]
     }}
  end

  @impl true
  def handle_event({:stream_open, stream, kind}, state),
    do: {:ok, %{state | streams: Map.put(state.streams, stream, kind)}}

  def handle_event(event, state) when event == :tick or event == :writable,
    do: progress(state)

  def handle_event({:readable, _}, state), do: progress(state)
  def handle_event(_, state), do: {:ok, state}

  defp progress(state) do
    Enum.reduce_while(state.streams, {:ok, state}, fn {stream, kind}, {:ok, acc} ->
      with {:ok, next} <- read(acc, stream, kind),
           {:ok, next} <- flush(next, stream) do
        {:cont, {:ok, next}}
      else
        failure -> {:halt, failure}
      end
    end)
  end

  defp read(state, stream, kind) do
    if Map.has_key?(state.pending, stream) do
      {:ok, state}
    else
      # Writes are atomic admissions. Small echo chunks can use residual peer
      # credit after fragmented reads; an entire 16KiB chunk might not fit it.
      case Abyss.QUIC.read(stream, 1024) do
        {:ok, items} ->
          {:ok,
           Enum.reduce(items, state, fn
             {:data, _, bytes}, s when kind == :bidi and stream != s.local ->
               put_pending(s, stream, bytes, false)

             {:fin, _}, s when kind == :bidi and stream != s.local ->
               put_pending(s, stream, <<>>, true)

             {:fin, _}, s ->
               if s.observer, do: send(s.observer, {:received_fin, stream})
               %{s | streams: Map.delete(s.streams, stream)}

             {:reset, _, code, _}, s ->
               if s.observer, do: send(s.observer, {:reset, stream, code})
               %{s | streams: Map.delete(s.streams, stream)}

             _, s ->
               s
           end)}

        failure ->
          {:stop, {:read_failed, failure}, state}
      end
    end
  end

  defp put_pending(state, stream, bytes, fin) do
    {previous, _} = Map.get(state.pending, stream, {<<>>, false})
    %{state | pending: Map.put(state.pending, stream, {previous <> bytes, fin})}
  end

  defp flush(state, stream) do
    case state.pending[stream] do
      nil ->
        {:ok, state}

      {bytes, fin} ->
        case Abyss.QUIC.send_stream(stream, bytes, fin) do
          {:ok, _} ->
            streams =
              if fin and stream != state.local,
                do: Map.delete(state.streams, stream),
                else: state.streams

            {:ok, %{state | pending: Map.delete(state.pending, stream), streams: streams}}

          {:blocked, _} ->
            {:ok, state}

          failure ->
            {:stop, {:write_failed, failure}, state}
        end
    end
  end
end
