defmodule HTTP.HTTP2.BodyBridge do
  @moduledoc """
  Bounded credit bridge for an `HTTP.Stream` upload producer.

  The bridge owns at most one outstanding reader request and one unacknowledged
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
  def early_response(bridge), do: GenServer.call(bridge, :early_response)
  def status(bridge), do: GenServer.call(bridge, :status)

  @impl true
  def init({stream, owner, opts}) do
    monitor = Process.monitor(stream)

    {:ok,
     %{
       stream: stream,
       owner: owner,
       monitor: monitor,
       credit: 0,
       inflight: nil,
       buffered_bytes: 0,
       max_chunk_bytes: Keyword.get(opts, :max_chunk_bytes, @default_max_chunk),
       max_buffer_bytes: Keyword.get(opts, :max_buffer_bytes, @default_max_buffer),
       eof?: false,
       stopped?: false,
       bytes: 0
     }}
  end

  @impl true
  def handle_call({:credit, bytes}, _from, state) do
    {:reply, :ok, maybe_read(%{state | credit: state.credit + bytes})}
  end

  def handle_call({:ack, ref}, _from, %{inflight: {ref, size}} = state) do
    send(state.stream, {:stream_chunk_ack, ref})

    {:reply, :ok,
     maybe_read(%{state | inflight: nil, buffered_bytes: state.buffered_bytes - size})}
  end

  def handle_call({:ack, _ref}, _from, state), do: {:reply, {:error, :unknown_ack}, state}

  def handle_call(:cancel, _from, state), do: {:reply, :ok, stop_stream(state, :cancelled)}

  def handle_call(:early_response, _from, state),
    do: {:reply, :ok, stop_stream(state, :early_response)}

  def handle_call(:status, _from, state) do
    {:reply, Map.take(state, [:credit, :inflight, :buffered_bytes, :eof?, :stopped?, :bytes]),
     state}
  end

  @impl true
  def handle_info({:stream_chunk, stream, chunk, ack_ref}, %{stream: stream} = state)
      when is_binary(chunk) do
    cond do
      state.stopped? ->
        {:noreply, state}

      state.inflight != nil ->
        {:stop, :protocol_error, state}

      byte_size(chunk) > state.max_chunk_bytes ->
        {:noreply, stop_stream(state, :chunk_too_large)}

      chunk == <<>> ->
        send(stream, {:stream_chunk_ack, ack_ref})
        {:noreply, maybe_read(state)}

      state.buffered_bytes + byte_size(chunk) > state.max_buffer_bytes ->
        {:noreply, stop_stream(state, :buffer_limit)}

      true ->
        send(state.owner, {:body_chunk, self(), chunk, ack_ref})
        size = byte_size(chunk)

        {:noreply,
         %{
           state
           | inflight: {ack_ref, size},
             buffered_bytes: state.buffered_bytes + size,
             credit: state.credit - size,
             bytes: state.bytes + size
         }}
    end
  end

  def handle_info({:stream_end, stream}, %{stream: stream} = state) do
    send(state.owner, {:body_eof, self()})
    {:noreply, %{state | eof?: true, stopped?: true}}
  end

  def handle_info({:stream_error, stream, reason}, %{stream: stream} = state) do
    send(state.owner, {:body_error, self(), reason})
    {:noreply, %{state | stopped?: true}}
  end

  def handle_info({:body_ack, ref}, %{inflight: {ref, size}} = state) do
    send(state.stream, {:stream_chunk_ack, ref})
    {:noreply, maybe_read(%{state | inflight: nil, buffered_bytes: state.buffered_bytes - size})}
  end

  def handle_info({:DOWN, monitor, :process, _stream, reason}, %{monitor: monitor} = state) do
    if state.eof? or state.stopped? do
      {:noreply, state}
    else
      send(state.owner, {:body_error, self(), {:stream_down, reason}})
      {:stop, :normal, %{state | stopped?: true}}
    end
  end

  defp maybe_read(%{stopped?: true} = state), do: state

  defp maybe_read(%{credit: credit, inflight: nil} = state) when credit > 0 do
    send(state.stream, {:read_chunk, self(), :ack})
    state
  end

  defp maybe_read(state), do: state

  defp stop_stream(state, reason) do
    if not state.stopped?, do: HTTP.Stream.error(state.stream, reason)
    send(state.owner, {:body_error, self(), reason})
    %{state | stopped?: true}
  end
end
