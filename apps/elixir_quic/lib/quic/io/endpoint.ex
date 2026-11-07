defmodule Quic.IO.Endpoint do
  @moduledoc """
  Pure bounded endpoint state for QUIC external IO.

  The first UDP adapter binds a concrete local address. Wildcard and
  ancillary destination/interface metadata are intentionally unsupported.
  `enqueue/4` is admission only; `local_send/4` reports the later local
  writer result. Peer ACKs belong to `Quic.Recovery`, never this IO budget.

  At most two paths retain independent received, reserved, and spent byte
  ledgers. The legacy arities use the selected path, while top-level byte
  counters remain lifetime totals across paths. Send receipts retain the path
  chosen at admission even if the selected path subsequently changes.
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
            active_path: :default,
            paths: %{},
            closed: false,
            handshake_deadline: nil,
            idle_deadline: nil,
            timers: %{}

  defmodule Send do
    @enforce_keys [:ref, :generation, :bytes, :remote]
    defstruct [
      :ref,
      :generation,
      :bytes,
      :remote,
      :path_id,
      :completed_at,
      :error,
      status: :queued
    ]
  end

  defmodule Timer do
    @enforce_keys [:ref, :generation, :kind, :deadline]
    defstruct [:ref, :generation, :kind, :deadline]
  end

  @type t :: %__MODULE__{
          address_validated: boolean(),
          bytes_received: non_neg_integer(),
          paths: %{optional(path_id()) => path_ledger()}
        }
  @type send_ref :: reference()
  @type path_id :: term()
  @type path_ledger :: %{
          bytes_received: non_neg_integer(),
          bytes_pending: non_neg_integer(),
          bytes_sent: non_neg_integer(),
          address_validated: boolean()
        }

  @type initial_state :: %__MODULE__{
          active_path: path_id(),
          address_validated: false,
          bytes_pending: 0,
          bytes_received: 0,
          bytes_sent: 0,
          closed: false,
          generation: 0,
          handshake_deadline: term(),
          idle_deadline: term(),
          in_flight: %{},
          max_queue: pos_integer(),
          max_queue_bytes: pos_integer(),
          paths: %{path_id() => path_ledger()},
          queue: {[], []},
          queue_bytes: 0,
          timers: %{}
        }

  @spec new(keyword()) ::
          {:ok, initial_state()}
          | {:error, {:max_queue | :max_queue_bytes, :must_be_positive}}
  def new(opts \\ []) do
    with {:ok, max_queue} <- positive(opts, :max_queue, 128),
         {:ok, max_bytes} <- positive(opts, :max_queue_bytes, 1_048_576) do
      {:ok,
       %__MODULE__{
         max_queue: max_queue,
         max_queue_bytes: max_bytes,
         active_path: Keyword.get(opts, :path, :default),
         paths: %{Keyword.get(opts, :path, :default) => fresh_path(false)},
         handshake_deadline: Keyword.get(opts, :handshake_deadline),
         idle_deadline: Keyword.get(opts, :idle_deadline)
       }}
    end
  end

  @doc "Selected path used by the legacy IO arities."
  @spec selected_path(t()) :: path_id()
  def selected_path(%__MODULE__{} = state), do: state.active_path

  @doc "The path's independent amplification ledger, or nil after retirement."
  @spec path(t(), path_id()) :: path_ledger() | nil
  def path(%__MODULE__{} = state, id), do: Map.get(state.paths, id)

  @spec add_path(t(), path_id(), boolean()) :: {:ok, t()} | {:error, :path_limit}
  def add_path(%__MODULE__{} = state, id, validated \\ false) when is_boolean(validated) do
    cond do
      Map.has_key?(state.paths, id) -> {:ok, state}
      map_size(state.paths) >= 2 -> {:error, :path_limit}
      true -> {:ok, %{state | paths: Map.put(state.paths, id, fresh_path(validated))}}
    end
  end

  @spec select_path(t(), path_id()) :: {:ok, t()} | {:error, :unknown_path}
  def select_path(%__MODULE__{} = state, id) do
    case path(state, id) do
      nil -> {:error, :unknown_path}
      ledger -> {:ok, %{state | active_path: id, address_validated: ledger.address_validated}}
    end
  end

  @spec drop_path(t(), path_id()) ::
          {:ok, t()} | {:error, :active_path | :unknown_path | :path_busy}
  def drop_path(%__MODULE__{} = state, id) do
    cond do
      id == state.active_path -> {:error, :active_path}
      path(state, id) == nil -> {:error, :unknown_path}
      path(state, id).bytes_pending > 0 -> {:error, :path_busy}
      true -> {:ok, %{state | paths: Map.delete(state.paths, id)}}
    end
  end

  def receive_bytes(%__MODULE__{} = state, bytes),
    do: receive_bytes(state, bytes, state.active_path)

  @spec receive_bytes(t(), non_neg_integer(), path_id()) :: {:ok, t()} | {:error, :unknown_path}
  def receive_bytes(%__MODULE__{} = state, bytes, id) when is_integer(bytes) and bytes >= 0 do
    case path(state, id) do
      nil ->
        {:error, :unknown_path}

      ledger ->
        next = %{ledger | bytes_received: ledger.bytes_received + bytes}

        {:ok,
         %{
           state
           | paths: Map.put(state.paths, id, next),
             bytes_received: state.bytes_received + bytes
         }}
    end
  end

  def validate_address(%__MODULE__{} = state), do: validate_address(state, state.active_path)

  @spec validate_address(t(), path_id()) :: {:ok, t()} | {:error, :unknown_path}
  def validate_address(%__MODULE__{} = state, id) do
    case path(state, id) do
      nil ->
        {:error, :unknown_path}

      ledger ->
        paths = Map.put(state.paths, id, %{ledger | address_validated: true})

        {:ok,
         %{
           state
           | paths: paths,
             address_validated: state.address_validated or id == state.active_path
         }}
    end
  end

  def enqueue(%__MODULE__{} = state, bytes, remote, now),
    do: enqueue(state, bytes, remote, now, state.active_path)

  def enqueue(_state, _bytes, _remote, _now), do: {:error, :invalid_datagram}

  @spec enqueue(t(), binary(), term(), integer(), path_id()) ::
          {:ok, t(), %Send{}} | {:error, atom()}
  def enqueue(%__MODULE__{closed: true}, _bytes, _remote, _now, _id), do: {:error, :closed}

  def enqueue(%__MODULE__{} = state, bytes, remote, _now, id)
      when is_binary(bytes) and byte_size(bytes) > 0 do
    size = byte_size(bytes)
    ledger = path(state, id)

    cond do
      ledger == nil ->
        {:error, :unknown_path}

      :queue.len(state.queue) + map_size(state.in_flight) >= state.max_queue ->
        {:error, :queue_limit}

      state.bytes_pending + size > state.max_queue_bytes ->
        {:error, :queue_bytes_limit}

      not ledger.address_validated and
          ledger.bytes_sent + ledger.bytes_pending + size > 3 * ledger.bytes_received ->
        {:error, :anti_amplification}

      true ->
        send = %Send{
          ref: make_ref(),
          generation: state.generation,
          bytes: bytes,
          remote: remote,
          path_id: id
        }

        next = :queue.in(send, state.queue)
        ledger = %{ledger | bytes_pending: ledger.bytes_pending + size}

        {:ok,
         %{
           state
           | queue: next,
             queue_bytes: state.queue_bytes + size,
             bytes_pending: state.bytes_pending + size,
             paths: Map.put(state.paths, id, ledger)
         }, send}
    end
  end

  def enqueue(_state, _bytes, _remote, _now, _id), do: {:error, :invalid_datagram}

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
    ledger = path(state, send.path_id)

    case result do
      :ok ->
        {:ok,
         %{
           state
           | in_flight: in_flight,
             bytes_pending: state.bytes_pending - byte_size(send.bytes),
             bytes_sent: state.bytes_sent + byte_size(send.bytes),
             paths:
               Map.put(state.paths, send.path_id, %{
                 ledger
                 | bytes_pending: ledger.bytes_pending - byte_size(send.bytes),
                   bytes_sent: ledger.bytes_sent + byte_size(send.bytes)
               })
         }, %Send{send | status: :sent, completed_at: at}}

      {:error, reason} ->
        {:ok,
         %{
           state
           | in_flight: in_flight,
             bytes_pending: state.bytes_pending - byte_size(send.bytes),
             paths:
               Map.put(state.paths, send.path_id, %{
                 ledger
                 | bytes_pending: ledger.bytes_pending - byte_size(send.bytes)
               })
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
         bytes_pending: 0,
         paths:
           Map.new(state.paths, fn {id, ledger} ->
             {id,
              %{ledger | bytes_sent: ledger.bytes_sent + ledger.bytes_pending, bytes_pending: 0}}
           end)
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

  defp fresh_path(validated),
    do: %{bytes_received: 0, bytes_pending: 0, bytes_sent: 0, address_validated: validated}
end
