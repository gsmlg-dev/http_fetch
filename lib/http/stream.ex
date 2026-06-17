defmodule HTTP.Stream do
  @moduledoc false

  defstruct reader: nil,
            chunks: [],
            done?: false,
            error: nil,
            total_bytes: 0,
            start_time: nil

  @spec start_link(non_neg_integer()) :: {:ok, pid()}
  def start_link(content_length) do
    start_time = System.monotonic_time(:microsecond)
    HTTP.Telemetry.streaming_start(content_length)

    Task.start_link(fn ->
      loop(%__MODULE__{start_time: start_time})
    end)
  end

  @spec chunk(pid(), binary()) :: :ok
  def chunk(pid, chunk) when is_pid(pid) and is_binary(chunk) do
    send(pid, {:chunk, chunk})
    :ok
  end

  @spec finish(pid()) :: :ok
  def finish(pid) when is_pid(pid) do
    send(pid, :finish)
    :ok
  end

  @spec error(pid(), term()) :: :ok
  def error(pid, reason) when is_pid(pid) do
    send(pid, {:error, reason})
    :ok
  end

  defp loop(%__MODULE__{} = state) do
    receive do
      {:read_chunk, reader} when is_pid(reader) ->
        state
        |> Map.put(:reader, reader)
        |> flush()
        |> loop()

      {:chunk, chunk} ->
        chunk_size = byte_size(chunk)
        total_bytes = state.total_bytes + chunk_size
        HTTP.Telemetry.streaming_chunk(chunk_size, total_bytes)

        state
        |> Map.put(:total_bytes, total_bytes)
        |> push_chunk(chunk)
        |> loop()

      :finish ->
        duration = System.monotonic_time(:microsecond) - state.start_time
        HTTP.Telemetry.streaming_stop(state.total_bytes, duration)

        state
        |> Map.put(:done?, true)
        |> flush()
        |> loop()

      {:error, reason} ->
        state
        |> Map.put(:error, reason)
        |> flush()
        |> loop()
    after
      HTTP.Config.streaming_timeout() ->
        duration = System.monotonic_time(:microsecond) - state.start_time
        HTTP.Telemetry.streaming_stop(state.total_bytes, duration)

        state
        |> Map.put(:error, :timeout)
        |> flush()
        |> loop()
    end
  end

  defp push_chunk(%__MODULE__{reader: nil, chunks: chunks} = state, chunk) do
    %{state | chunks: [chunk | chunks]}
  end

  defp push_chunk(%__MODULE__{reader: reader} = state, chunk) do
    send(reader, {:stream_chunk, self(), chunk})
    state
  end

  defp flush(%__MODULE__{reader: nil} = state), do: state

  defp flush(%__MODULE__{reader: reader, chunks: chunks, done?: done?, error: error} = state) do
    chunks
    |> Enum.reverse()
    |> Enum.each(fn chunk -> send(reader, {:stream_chunk, self(), chunk}) end)

    cond do
      error ->
        send(reader, {:stream_error, self(), error})
        %{state | chunks: []}

      done? ->
        send(reader, {:stream_end, self()})
        %{state | chunks: []}

      true ->
        %{state | chunks: []}
    end
  end
end
