defmodule HTTP.HTTP2.BodyBridge do
  @moduledoc """
  Bounded credit bridge for an `HTTP.Stream` upload producer.

  The bridge owns at most one outstanding reader request and one bounded source
  chunk. It never calls a producer synchronously and never aggregates the body.
  """
  use GenServer

  @default_max_chunk 16_384
  @default_max_buffer 65_536

  @type t :: pid()

  def start_link(stream, owner, opts \\ []) when is_pid(stream) and is_pid(owner) do
    GenServer.start_link(__MODULE__, {stream, owner, opts})
  end

  def credit(bridge, bytes) when is_pid(bridge) and is_integer(bytes) and bytes > 0,
    do: GenServer.call(bridge, {:credit, bytes})

  def ack(bridge, ref) when is_pid(bridge), do: GenServer.call(bridge, {:ack, ref})
  def cancel(bridge), do: GenServer.call(bridge, :cancel)
  def discard(bridge), do: GenServer.call(bridge, :discard)
  def early_response(bridge), do: GenServer.call(bridge, :early_response)
  def status(bridge), do: GenServer.call(bridge, :status)

  @impl true
  def init({stream, owner, opts}) do
    monitor = Process.monitor(stream)
    owner_monitor = Process.monitor(owner)

    {:ok,
     %{
       stream: stream,
       owner: owner,
       monitor: monitor,
       owner_monitor: owner_monitor,
       credit: 0,
       read_pending?: false,
       inflight: nil,
       pending_chunk: nil,
       source_ref: nil,
       first_slice?: false,
       buffered_bytes: 0,
       max_chunk_bytes: Keyword.get(opts, :max_chunk_bytes, @default_max_chunk),
       max_buffer_bytes: Keyword.get(opts, :max_buffer_bytes, @default_max_buffer),
       eof?: false,
       stopped?: false,
       started_at: System.monotonic_time(),
       bytes: 0,
       content_length: Keyword.get(opts, :content_length),
       peak_buffered_bytes: 0
     }}
  end

  @impl true
  def handle_call({:credit, _bytes}, _from, %{stopped?: true} = state),
    do: {:reply, :ok, state}

  def handle_call({:credit, bytes}, _from, state) do
    credit = min(state.credit + bytes, state.max_buffer_bytes - state.buffered_bytes)
    {:reply, :ok, advance(%{state | credit: credit})}
  end

  def handle_call({:ack, _ref}, _from, %{stopped?: true} = state), do: {:reply, :ok, state}

  def handle_call({:ack, ref}, _from, %{inflight: {ref, size}} = state) do
    {:reply, :ok, settle_slice(state, size)}
  end

  def handle_call({:ack, _ref}, _from, state), do: {:reply, {:error, :unknown_ack}, state}

  def handle_call(:cancel, _from, state), do: {:reply, :ok, stop_stream(state, :cancelled)}

  def handle_call(:discard, _from, state),
    do: {:stop, :normal, :ok, stop_stream(state, :cancelled, false)}

  def handle_call(:early_response, _from, state),
    do: {:reply, :ok, stop_stream(state, :early_response, false)}

  def handle_call(:status, _from, state) do
    {:reply,
     Map.take(state, [
       :credit,
       :inflight,
       :buffered_bytes,
       :max_buffer_bytes,
       :peak_buffered_bytes,
       :eof?,
       :stopped?,
       :bytes
     ]), state}
  end

  @impl true
  def handle_cast(:early_response, state),
    do: {:noreply, stop_stream(state, :early_response, false)}

  def handle_cast(:stop, state) do
    _ = stop_stream(state, :cancelled, false)
    {:stop, :normal, state}
  end

  @impl true
  def handle_info({:stream_chunk, stream, chunk, ack_ref}, %{stream: stream} = state)
      when is_binary(chunk) do
    cond do
      state.stopped? ->
        {:noreply, state}

      not state.read_pending? or state.source_ref != nil ->
        {:stop, :protocol_error, finish(state, :protocol_error)}

      byte_size(chunk) > state.max_buffer_bytes ->
        {:noreply, stop_stream(state, :buffer_limit)}

      state.content_length != nil and state.bytes + byte_size(chunk) > state.content_length ->
        {:noreply, stop_stream(state, :content_length_mismatch)}

      chunk == <<>> ->
        send(stream, {:stream_chunk_ack, ack_ref})
        {:noreply, advance(%{state | read_pending?: false})}

      true ->
        size = byte_size(chunk)

        {:noreply,
         advance(%{
           state
           | read_pending?: false,
             pending_chunk: chunk,
             source_ref: ack_ref,
             first_slice?: true,
             buffered_bytes: size,
             peak_buffered_bytes: max(state.peak_buffered_bytes, size),
             bytes: state.bytes + size
         })}
    end
  end

  def handle_info({:stream_end, stream}, %{stream: stream} = state) do
    cond do
      state.stopped? ->
        {:noreply, state}

      state.content_length != nil and state.bytes != state.content_length ->
        {:noreply, stop_stream(state, :content_length_mismatch)}

      true ->
        send(state.owner, {:body_eof, self()})
        {:noreply, finish(%{state | eof?: true, read_pending?: false}, :eof)}
    end
  end

  def handle_info({:stream_error, stream, reason}, %{stream: stream} = state) do
    if state.stopped? do
      {:noreply, state}
    else
      send(state.owner, {:body_error, self(), reason})
      {:noreply, finish(%{state | read_pending?: false}, :source_error)}
    end
  end

  def handle_info({:body_ack, ref}, %{inflight: {ref, size}} = state) do
    {:noreply, settle_slice(state, size)}
  end

  def handle_info({:body_ack, _ref}, state), do: {:noreply, state}

  def handle_info({:DOWN, monitor, :process, _owner, _reason}, %{owner_monitor: monitor} = state) do
    _ = stop_stream(state, :owner_down, false)
    {:stop, :normal, state}
  end

  def handle_info({:DOWN, monitor, :process, _stream, reason}, %{monitor: monitor} = state) do
    if state.eof? or state.stopped? do
      {:noreply, state}
    else
      send(state.owner, {:body_error, self(), {:stream_down, reason}})
      {:stop, :normal, finish(state, :source_down)}
    end
  end

  defp settle_slice(state, size) do
    buffered_bytes = state.buffered_bytes - size
    credit = min(state.credit + size, state.max_buffer_bytes - buffered_bytes)
    state = %{state | inflight: nil, buffered_bytes: buffered_bytes, credit: credit}

    if state.pending_chunk == <<>> and buffered_bytes == 0 do
      send(state.stream, {:stream_chunk_ack, state.source_ref})
      advance(%{state | source_ref: nil, pending_chunk: nil})
    else
      advance(state)
    end
  end

  defp advance(%{stopped?: true} = state), do: state

  defp advance(%{inflight: nil, pending_chunk: chunk, credit: credit} = state)
       when is_binary(chunk) and byte_size(chunk) > 0 and credit > 0 do
    size = min(min(byte_size(chunk), state.max_chunk_bytes), credit)
    <<slice::binary-size(^size), rest::binary>> = chunk
    ref = if state.first_slice?, do: state.source_ref, else: make_ref()
    send(state.owner, {:body_chunk, self(), slice, ref})

    %{
      state
      | inflight: {ref, size},
        pending_chunk: rest,
        first_slice?: false,
        credit: credit - size
    }
  end

  defp advance(state), do: maybe_read(state)

  defp maybe_read(%{credit: credit, inflight: nil, source_ref: nil, read_pending?: false} = state)
       when credit > 0 do
    send(state.stream, {:read_chunk, self(), :ack})
    %{state | read_pending?: true}
  end

  defp maybe_read(state), do: state

  defp stop_stream(state, reason, notify_owner? \\ true) do
    if not state.stopped? do
      HTTP.Stream.error(state.stream, reason)

      if is_reference(state.source_ref),
        do: send(state.stream, {:stream_chunk_ack, state.source_ref})
    end

    if notify_owner?, do: send(state.owner, {:body_error, self(), reason})
    finish(state, bridge_outcome(reason))
  end

  defp finish(%{stopped?: true} = state, _outcome), do: state

  defp finish(state, outcome) do
    duration_us =
      System.convert_time_unit(System.monotonic_time() - state.started_at, :native, :microsecond)

    HTTP.Telemetry.http2_body_bridge(outcome, %{
      duration_us: duration_us,
      bytes: state.bytes,
      peak_buffered_bytes: state.peak_buffered_bytes
    })

    %{
      state
      | stopped?: true,
        credit: 0,
        inflight: nil,
        pending_chunk: nil,
        source_ref: nil,
        read_pending?: false,
        buffered_bytes: 0
    }
  end

  defp bridge_outcome(:cancelled), do: :cancelled
  defp bridge_outcome(:early_response), do: :early_response
  defp bridge_outcome(:owner_down), do: :owner_down
  defp bridge_outcome(:buffer_limit), do: :buffer_limit
  defp bridge_outcome(:content_length_mismatch), do: :content_length_mismatch
end
