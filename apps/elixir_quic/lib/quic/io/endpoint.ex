defmodule Quic.IO.Endpoint do
  @moduledoc """
  Pure bounded endpoint state for QUIC external IO.

  The first UDP adapter binds a concrete local address. Wildcard and
  ancillary destination/interface metadata are intentionally unsupported.
  `enqueue/4` is admission only; `local_send/4` reports the later local
  writer result. Peer ACKs belong to `Quic.Recovery`, never this IO budget.
  """

  defstruct generation: 0,
            queue: :queue.new(),
            queue_bytes: 0,
            max_queue: 128,
            max_queue_bytes: 1_048_576,
            in_flight: %{},
            bytes_received: 0,
            bytes_pending: 0,
            bytes_sent: 0,
            address_validated: false,
            closed: false,
            handshake_deadline: nil,
            idle_deadline: nil,
            timers: %{}

  defmodule Send do
    @enforce_keys [:ref, :generation, :bytes, :remote]
    defstruct [:ref, :generation, :bytes, :remote, :completed_at, :error, status: :queued]
  end

  defmodule Timer do
    @enforce_keys [:ref, :generation, :kind, :deadline]
    defstruct [:ref, :generation, :kind, :deadline]
  end

  @type t :: %__MODULE__{}
  @type send_ref :: reference()

  def new(opts \\ []) do
    with {:ok, max_queue} <- positive(opts, :max_queue, 128),
         {:ok, max_bytes} <- positive(opts, :max_queue_bytes, 1_048_576) do
      {:ok,
       %__MODULE__{
         max_queue: max_queue,
         max_queue_bytes: max_bytes,
         handshake_deadline: Keyword.get(opts, :handshake_deadline),
         idle_deadline: Keyword.get(opts, :idle_deadline)
       }}
    end
  end

  def receive_bytes(%__MODULE__{} = state, bytes) when is_integer(bytes) and bytes >= 0 do
    {:ok, %{state | bytes_received: state.bytes_received + bytes}}
  end

  def validate_address(%__MODULE__{} = state), do: {:ok, %{state | address_validated: true}}

  def enqueue(%__MODULE__{closed: true}, _bytes, _remote, _now), do: {:error, :closed}

  def enqueue(%__MODULE__{} = state, bytes, remote, _now)
      when is_binary(bytes) and byte_size(bytes) > 0 do
    size = byte_size(bytes)

    cond do
      :queue.len(state.queue) + map_size(state.in_flight) >= state.max_queue ->
        {:error, :queue_limit}

      state.bytes_pending + size > state.max_queue_bytes ->
        {:error, :queue_bytes_limit}

      not state.address_validated and
          state.bytes_sent + state.bytes_pending + size > 3 * state.bytes_received ->
        {:error, :anti_amplification}

      true ->
        send = %Send{ref: make_ref(), generation: state.generation, bytes: bytes, remote: remote}
        next = :queue.in(send, state.queue)

        {:ok,
         %{
           state
           | queue: next,
             queue_bytes: state.queue_bytes + size,
             bytes_pending: state.bytes_pending + size
         }, send}
    end
  end

  def enqueue(_state, _bytes, _remote, _now), do: {:error, :invalid_datagram}

  def dequeue(%__MODULE__{} = state) do
    case :queue.out(state.queue) do
      {{:value, %Send{} = send}, queue} ->
        next = %{
          state
          | queue: queue,
            queue_bytes: state.queue_bytes - byte_size(send.bytes),
            in_flight: Map.put(state.in_flight, send.ref, send)
        }

        {:ok, next, send}

      {:empty, _queue} ->
        :empty
    end
  end

  def local_send(%__MODULE__{} = state, %Send{ref: ref, generation: generation}, result, at)
      when generation == state.generation and is_integer(at) do
    case Map.get(state.in_flight, ref) do
      %Send{} = send ->
        local_send_in_flight(state, send, result, at)

      nil ->
        {:error, :unknown_send}
    end
  end

  def local_send(_state, %Send{}, _result, _at), do: {:error, :stale_generation}

  defp local_send_in_flight(state, %Send{} = send, result, at) do
    in_flight = Map.delete(state.in_flight, send.ref)

    case result do
      :ok ->
        {:ok,
         %{
           state
           | in_flight: in_flight,
             bytes_pending: state.bytes_pending - byte_size(send.bytes),
             bytes_sent: state.bytes_sent + byte_size(send.bytes)
         }, %Send{send | status: :sent, completed_at: at}}

      {:error, reason} ->
        {:ok,
         %{
           state
           | in_flight: in_flight,
             bytes_pending: state.bytes_pending - byte_size(send.bytes)
         }, %Send{send | status: :failed, completed_at: at, error: reason}}

      _ ->
        {:error, :invalid_send_result}
    end
  end

  def timer(%__MODULE__{closed: true}, _kind, _deadline), do: {:error, :closed}

  def timer(%__MODULE__{} = state, kind, deadline)
      when kind in [:handshake, :idle] and is_integer(deadline) do
    timer = %Timer{ref: make_ref(), generation: state.generation, kind: kind, deadline: deadline}
    {:ok, %{state | timers: Map.put(state.timers, kind, timer)}, timer}
  end

  def timer_expired?(%__MODULE__{} = state, %Timer{} = timer, now)
      when is_integer(now),
      do:
        not state.closed and timer.generation == state.generation and
          Map.get(state.timers, timer.kind) == timer and now >= timer.deadline

  def bump_generation(%__MODULE__{} = state) do
    # An outstanding writer may already have sent before its receipt becomes
    # stale. Conservatively retain its reservation as spent path credit.
    {:ok,
     %{
       state
       | generation: state.generation + 1,
         timers: %{},
         queue: :queue.new(),
         queue_bytes: 0,
         in_flight: %{},
         bytes_sent: state.bytes_sent + state.bytes_pending,
         bytes_pending: 0
     }}
  end

  def shutdown(%__MODULE__{} = state) do
    {:ok, next} = bump_generation(state)
    {:ok, %{next | closed: true}}
  end

  defp positive(opts, key, default) do
    value = Keyword.get(opts, key, default)
    if is_integer(value) and value > 0, do: {:ok, value}, else: {:error, {key, :must_be_positive}}
  end
end
