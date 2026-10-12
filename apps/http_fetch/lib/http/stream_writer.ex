defmodule HTTP.Stream.Writer do
  @moduledoc false

  # One owner, one stream, one monitor and one outstanding acknowledged chunk.
  # A timed-out/aborted write permanently closes this session's credit. Its
  # chunk remains owned until the stream consumes stop or its lifecycle ends.
  defstruct [:stream, :owner, :token, :monitor, :credit]

  def new(stream, token) do
    %__MODULE__{
      stream: stream,
      owner: self(),
      token: token,
      monitor: Process.monitor(stream),
      credit: :atomics.new(1, [])
    }
  end

  def chunk(%__MODULE__{owner: owner} = writer, chunk, timeout)
      when is_binary(chunk) and is_integer(timeout) and timeout >= 0 do
    cond do
      owner != self() ->
        {:error, :wrong_writer}

      :atomics.compare_exchange(writer.credit, 1, 0, 1) != :ok ->
        {:error, :writer_closed}

      true ->
        ref = make_ref()
        send(writer.stream, {:writer_chunk, self(), writer.token, ref, chunk})
        await_chunk(writer, ref, timeout)
    end
  end

  def close(%__MODULE__{} = writer) do
    if writer.owner == self() do
      :atomics.put(writer.credit, 1, 2)
      Process.demonitor(writer.monitor, [:flush])
    end

    :ok
  end

  defp await_chunk(writer, ref, timeout) do
    monitor = writer.monitor
    stream = writer.stream

    receive do
      {:chunk_ack, ^ref} ->
        :atomics.put(writer.credit, 1, 0)
        :ok

      {:chunk_error, ^ref, reason} ->
        stop(writer, reason)

      {:DOWN, ^monitor, :process, ^stream, reason} ->
        :atomics.put(writer.credit, 1, 2)
        {:error, {:stream_down, reason}}

      :abort ->
        stop(writer, :aborted)

      :deadline ->
        stop(writer, :request_timeout)
    after
      timeout -> stop(writer, :timeout)
    end
  end

  defp stop(writer, reason) do
    :atomics.put(writer.credit, 1, 2)
    send(writer.stream, {:writer_stop, self(), writer.token, reason})
    {:error, reason}
  end
end
