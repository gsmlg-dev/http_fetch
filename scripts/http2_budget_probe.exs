defmodule HTTP2BudgetProbe do
  import Bitwise

  alias HTTP.HTTP2.BodyBridge

  @chunk_count 2_000
  @max_chunk_bytes 16_384

  def run do
    stream = spawn(fn -> producer(1) end)

    {:ok, bridge} =
      BodyBridge.start_link(stream, self(),
        max_chunk_bytes: @max_chunk_bytes,
        max_buffer_bytes: @max_chunk_bytes
      )

    :ok = BodyBridge.credit(bridge, @chunk_count * @max_chunk_bytes)
    collect(bridge, 0, 0, 0, 0)
  end

  defp producer(index) when index <= @chunk_count do
    receive do
      {:read_chunk, bridge, :ack} ->
        size = rem(index * 7_919, @max_chunk_bytes) + 1
        ref = make_ref()
        send(bridge, {:stream_chunk, self(), :binary.copy(<<index &&& 255>>, size), ref})
        producer(index + 1)

      {:stream_chunk_ack, _ref} ->
        producer(index)
    end
  end

  defp producer(_index) do
    receive do
      {:read_chunk, bridge, :ack} ->
        send(bridge, {:stream_end, self()})
    end
  end

  defp collect(bridge, chunks, peak_memory, peak_queue, peak_buffered) do
    memory = :erlang.process_info(bridge, :memory) |> elem(1)
    queue = :erlang.process_info(bridge, :message_queue_len) |> elem(1)
    status = BodyBridge.status(bridge)

    peak_memory = max(peak_memory, memory)
    peak_queue = max(peak_queue, queue)
    peak_buffered = max(peak_buffered, status.peak_buffered_bytes)

    receive do
      {:body_chunk, ^bridge, _chunk, ref} ->
        :ok = BodyBridge.ack(bridge, ref)
        collect(bridge, chunks + 1, peak_memory, peak_queue, peak_buffered)

      {:body_eof, ^bridge} ->
        final_memory = :erlang.process_info(bridge, :memory) |> elem(1)

        IO.puts(
          :io_lib.format(
            "chunks=~p peak_buffered_bytes=~p max_buffer_bytes=~p peak_memory_words=~p final_memory_words=~p peak_queue_len=~p~n",
            [
              chunks,
              peak_buffered,
              status.max_buffer_bytes,
              peak_memory,
              final_memory,
              peak_queue
            ]
          )
        )
    end
  end
end

HTTP2BudgetProbe.run()
