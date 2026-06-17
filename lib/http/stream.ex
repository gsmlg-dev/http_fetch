defmodule HTTP.Stream do
  @moduledoc false

  defstruct reader: nil,
            reader_ack?: false,
            chunks: [],
            pending_ack: nil,
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

  @spec chunk(pid(), binary(), timeout()) :: :ok | {:error, term()}
  def chunk(pid, chunk, timeout \\ HTTP.Config.streaming_timeout())
      when is_pid(pid) and is_binary(chunk) do
    ref = make_ref()
    monitor_ref = Process.monitor(pid)
    send(pid, {:chunk, self(), ref, chunk})

    receive do
      {:chunk_ack, ^ref} ->
        Process.demonitor(monitor_ref, [:flush])
        :ok

      {:chunk_error, ^ref, reason} ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, reason}

      {:DOWN, ^monitor_ref, :process, ^pid, reason} ->
        {:error, {:stream_down, reason}}

      :abort ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, :aborted}

      :deadline ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, :request_timeout}
    after
      timeout ->
        Process.demonitor(monitor_ref, [:flush])
        {:error, :timeout}
    end
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
        |> Map.put(:reader_ack?, false)
        |> flush()
        |> maybe_continue()

      {:read_chunk, reader, :ack} when is_pid(reader) ->
        state
        |> Map.put(:reader, reader)
        |> Map.put(:reader_ack?, true)
        |> flush()
        |> maybe_continue()

      {:stream_chunk_ack, ref} ->
        state
        |> ack_reader_chunk(ref)
        |> flush()
        |> maybe_continue()

      {:chunk, sender, ref, chunk} ->
        chunk_size = byte_size(chunk)
        total_bytes = state.total_bytes + chunk_size
        HTTP.Telemetry.streaming_chunk(chunk_size, total_bytes)

        state
        |> Map.put(:total_bytes, total_bytes)
        |> push_chunk(chunk, {sender, ref})
        |> loop()

      :finish ->
        duration = System.monotonic_time(:microsecond) - state.start_time
        HTTP.Telemetry.streaming_stop(state.total_bytes, duration)

        state
        |> Map.put(:done?, true)
        |> flush()
        |> maybe_continue()

      {:error, reason} ->
        state
        |> Map.put(:error, reason)
        |> flush()
        |> maybe_continue()
    after
      HTTP.Config.streaming_timeout() ->
        timeout(state)
    end
  end

  defp maybe_continue(%__MODULE__{done?: true, reader: reader, chunks: [], pending_ack: nil})
       when is_pid(reader),
       do: :ok

  defp maybe_continue(%__MODULE__{error: error, reader: reader, chunks: [], pending_ack: nil})
       when not is_nil(error) and is_pid(reader),
       do: :ok

  defp maybe_continue(%__MODULE__{} = state), do: loop(state)

  defp timeout(%__MODULE__{done?: true}), do: :ok
  defp timeout(%__MODULE__{error: error}) when not is_nil(error), do: :ok

  defp timeout(%__MODULE__{} = state) do
    duration = System.monotonic_time(:microsecond) - state.start_time
    HTTP.Telemetry.streaming_stop(state.total_bytes, duration)

    _state =
      state
      |> Map.put(:error, :timeout)
      |> flush()
      |> reply_pending({:error, :timeout})

    :ok
  end

  defp push_chunk(%__MODULE__{reader: nil, chunks: chunks} = state, chunk, ack) do
    %{state | chunks: [chunk | chunks], pending_ack: ack}
  end

  defp push_chunk(%__MODULE__{reader: reader, reader_ack?: true} = state, chunk, ack) do
    {_sender, ref} = ack
    send(reader, {:stream_chunk, self(), chunk, ref})
    %{state | pending_ack: ack}
  end

  defp push_chunk(%__MODULE__{reader: reader} = state, chunk, ack) do
    send(reader, {:stream_chunk, self(), chunk})
    reply_pending(%{state | pending_ack: ack}, :ok)
  end

  defp flush(%__MODULE__{reader: nil} = state), do: state

  defp flush(
         %__MODULE__{
           reader: reader,
           reader_ack?: true,
           chunks: [chunk],
           pending_ack: {_sender, ref}
         } =
           state
       ) do
    send(reader, {:stream_chunk, self(), chunk, ref})
    %{state | chunks: []}
  end

  defp flush(%__MODULE__{reader_ack?: true, pending_ack: {_sender, _ref}} = state), do: state

  defp flush(%__MODULE__{reader: reader, chunks: chunks, done?: done?, error: error} = state) do
    chunks
    |> Enum.reverse()
    |> Enum.each(fn chunk -> send(reader, {:stream_chunk, self(), chunk}) end)

    state = reply_pending(state, :ok)

    cond do
      error ->
        send(reader, {:stream_error, self(), error})
        %{state | chunks: [], pending_ack: nil}

      done? ->
        send(reader, {:stream_end, self()})
        %{state | chunks: [], pending_ack: nil}

      true ->
        %{state | chunks: [], pending_ack: nil}
    end
  end

  defp ack_reader_chunk(%__MODULE__{pending_ack: {_sender, ref}} = state, ref) do
    reply_pending(state, :ok)
  end

  defp ack_reader_chunk(%__MODULE__{} = state, _ref), do: state

  defp reply_pending(%__MODULE__{pending_ack: nil} = state, _reply), do: state

  defp reply_pending(%__MODULE__{pending_ack: {sender, ref}} = state, :ok) do
    send(sender, {:chunk_ack, ref})
    %{state | pending_ack: nil}
  end

  defp reply_pending(%__MODULE__{pending_ack: {sender, ref}} = state, {:error, reason}) do
    send(sender, {:chunk_error, ref, reason})
    %{state | pending_ack: nil}
  end
end
