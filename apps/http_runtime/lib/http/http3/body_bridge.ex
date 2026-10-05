defmodule HTTP.HTTP3.BodyBridge do
  @moduledoc "Bounded upload reader using producer messages and definitive admission acknowledgements."
  use GenServer

  def start_link(source, owner, opts \\ []),
    do: GenServer.start_link(__MODULE__, {source, owner, opts})

  def credit(pid, bytes), do: GenServer.call(pid, {:credit, bytes})
  def ack(pid, ref), do: GenServer.call(pid, {:ack, ref})
  def cancel(pid), do: GenServer.call(pid, :cancel)
  def early_response(pid), do: GenServer.call(pid, :early_response)
  def status(pid), do: GenServer.call(pid, :status)

  @impl true
  def init({source, owner, opts}) do
    chunk = Keyword.get(opts, :max_chunk_bytes, 16_384)
    buffer = Keyword.get(opts, :max_buffer_bytes, 65_536)

    if is_pid(source) and is_pid(owner) and is_integer(chunk) and chunk in 1..16_384 and
         is_integer(buffer) and buffer >= chunk and buffer <= 65_536 do
      {:ok,
       %{
         source: source,
         owner: owner,
         source_monitor: Process.monitor(source),
         owner_monitor: Process.monitor(owner),
         credit: 0,
         pending: nil,
         inflight: nil,
         reading?: false,
         stopped?: false,
         eof?: false,
         buffered_bytes: 0,
         peak_buffered_bytes: 0,
         max_chunk_bytes: Keyword.get(opts, :max_chunk_bytes, 16_384),
         max_buffer_bytes: buffer
       }}
    else
      {:stop, :invalid_body_bridge_options}
    end
  end

  @impl true
  def handle_call(:status, _from, state),
    do:
      {:reply, Map.take(state, [:buffered_bytes, :peak_buffered_bytes, :inflight, :stopped?]),
       state}

  def handle_call({:credit, bytes}, _from, state) when is_integer(bytes) and bytes > 0,
    do:
      {:reply, :ok, advance(%{state | credit: min(state.credit + bytes, state.max_chunk_bytes)})}

  def handle_call({:ack, ref}, _from, %{inflight: {ref, size}} = state) do
    {rest, producer_ref} = state.pending

    state = %{
      state
      | inflight: nil,
        buffered_bytes: state.buffered_bytes - size,
        credit: min(state.credit + size, state.max_chunk_bytes)
    }

    state =
      if rest == <<>> do
        send(state.source, {:stream_chunk_ack, producer_ref})
        %{state | pending: nil}
      else
        state
      end

    {:reply, :ok, advance(state)}
  end

  def handle_call({:ack, _ref}, _from, state), do: {:reply, {:error, :unknown_ack}, state}

  def handle_call(kind, _from, %{stopped?: true} = state) when kind in [:cancel, :early_response],
    do: {:reply, :ok, state}

  def handle_call(kind, _from, state) when kind in [:cancel, :early_response] do
    send(state.source, {:error, kind})
    {:reply, :ok, %{state | stopped?: true, pending: nil, inflight: nil, buffered_bytes: 0}}
  end

  @impl true
  def handle_info(
        {:stream_chunk, source, bytes, ref},
        %{source: source, reading?: true, pending: nil, stopped?: false} = state
      )
      when is_binary(bytes) do
    if byte_size(bytes) <= state.max_buffer_bytes do
      next = %{
        state
        | reading?: false,
          pending: {bytes, ref},
          buffered_bytes: byte_size(bytes),
          peak_buffered_bytes: max(state.peak_buffered_bytes, byte_size(bytes))
      }

      if bytes == <<>> do
        send(source, {:stream_chunk_ack, ref})
        {:noreply, advance(%{next | pending: nil})}
      else
        {:noreply, advance(next)}
      end
    else
      send(state.owner, {:body_error, self(), :body_buffer_limit})
      send(source, {:error, :body_buffer_limit})
      {:stop, :normal, state}
    end
  end

  def handle_info({:stream_end, source}, %{source: source} = state) do
    {:noreply, advance(%{state | eof?: true, reading?: false})}
  end

  def handle_info({:stream_error, source, reason}, %{source: source} = state) do
    send(state.owner, {:body_error, self(), reason})
    {:stop, :normal, state}
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, state) do
    if ref == state.source_monitor and not state.stopped?,
      do: send(state.owner, {:body_error, self(), {:source_down, reason}})

    if ref == state.owner_monitor and not state.stopped?,
      do: send(state.source, {:error, :cancel})

    {:stop, :normal, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp advance(%{stopped?: true} = state), do: state

  defp advance(%{eof?: true, pending: nil, inflight: nil} = state) do
    send(state.owner, {:body_eof, self()})
    %{state | stopped?: true}
  end

  defp advance(%{pending: {bytes, producer_ref}, inflight: nil, credit: credit} = state)
       when credit > 0 and byte_size(bytes) > 0 do
    size = min(byte_size(bytes), min(credit, state.max_chunk_bytes))
    <<chunk::binary-size(^size), rest::binary>> = bytes
    ref = make_ref()
    send(state.owner, {:body_chunk, self(), :binary.copy(chunk), ref})

    %{
      state
      | pending: {:binary.copy(rest), producer_ref},
        inflight: {ref, size},
        credit: credit - size
    }
  end

  defp advance(%{pending: nil, inflight: nil, reading?: false, credit: credit} = state)
       when credit > 0 do
    send(state.source, {:read_chunk, self(), :ack})
    %{state | reading?: true}
  end

  defp advance(state), do: state
end
