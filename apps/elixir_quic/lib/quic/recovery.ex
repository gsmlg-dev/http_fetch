defmodule Quic.Recovery do
  @moduledoc """
  Explicit-time QUIC packet-number spaces and loss recovery state.

  Packet numbers are allocated by `reserve/4` and are never reused. A packet
  moves through `:reserved`, `:queued`, `:sent`, then `:acked`, `:lost`, or
  `:failed`. ACKs received before a local send receipt are retained as a bounded
  pending acknowledgement and resolved when the receipt arrives.

  Receive ACK history retains the newest `max_ack_ranges` (1..256) ranges per
  space. A monotonic receive floor discards older packet numbers, including
  previously unseen delayed packets; reliable data can be retransmitted under
  a fresh packet number. Discarding an encryption space resets its receive epoch.

  Packet-number spaces stay global across migration. Each reserved packet pins
  its send path, and at most two independent RTT/congestion controllers remain
  live. The selected controller occupies `rtt`/`congestion` for compatibility;
  `paths` stores only its one inactive peer. Cross-path ACKs do not sample RTT.
  """

  alias Quic.Congestion.NewReno

  @spaces [:initial, :handshake, :application]
  @default_rtt 333_000
  defstruct spaces: %{},
            rtt: nil,
            congestion: nil,
            active_path: :default,
            paths: %{},
            path_defaults: nil,
            pto_grants: %{},
            max_sent_packets: 4096,
            max_ack_ranges: 256,
            timer_generation: 0,
            deadline: nil

  defmodule Packet do
    @moduledoc false
    defstruct [
      :number,
      :space,
      :status,
      :bytes,
      :sent_at,
      :metadata,
      :acked_at,
      :lost_at,
      path_id: :default
    ]

    @type t :: %__MODULE__{}
  end

  defmodule Space do
    @moduledoc false
    defstruct retired: false,
              next: 0,
              largest_received: -1,
              receive_floor: 0,
              largest_acked: -1,
              ack_ranges: [],
              sent: %{},
              pending_acks: MapSet.new()
  end

  defmodule RTT do
    @moduledoc false
    defstruct latest: nil,
              smoothed: nil,
              variance: nil,
              min: nil,
              max_ack_delay: 25_000,
              ack_delay_exponent: 3,
              pto_count: 0

    @type t :: %__MODULE__{}
  end

  @type initial_state :: %Quic.Recovery{
          active_path: path_id(),
          congestion: %Quic.Congestion.NewReno{
            acked_bytes: 0,
            bytes_in_flight: 0,
            cwnd: term(),
            max_datagram_size: term(),
            mss: number(),
            ssthresh: term()
          },
          deadline: nil,
          max_ack_ranges: 1..256,
          max_sent_packets: term(),
          path_defaults: %{rtt: RTT.t(), congestion: NewReno.initial_state()},
          paths: %{},
          pto_grants: %{},
          rtt: %Quic.Recovery.RTT{
            ack_delay_exponent: term(),
            latest: nil,
            max_ack_delay: term(),
            min: nil,
            pto_count: 0,
            smoothed: nil,
            variance: nil
          },
          spaces: map(),
          timer_generation: 0
        }

  @spec new(keyword()) :: initial_state()
  def new(opts \\ []) do
    max_ack_ranges = Keyword.get(opts, :max_ack_ranges, 256)

    unless is_integer(max_ack_ranges) and max_ack_ranges in 1..256,
      do: raise(ArgumentError, "max_ack_ranges must be in 1..256")

    rtt = %RTT{
      max_ack_delay: Keyword.get(opts, :max_ack_delay, 25_000),
      ack_delay_exponent: Keyword.get(opts, :ack_delay_exponent, 3)
    }

    spaces = Map.new(@spaces, &{&1, %Space{}})

    congestion = NewReno.new(opts)

    %__MODULE__{
      spaces: spaces,
      rtt: rtt,
      congestion: congestion,
      active_path: Keyword.get(opts, :path, :default),
      path_defaults: %{rtt: rtt, congestion: congestion},
      max_sent_packets: Keyword.get(opts, :max_sent_packets, 4096),
      max_ack_ranges: max_ack_ranges
    }
  end

  @type t :: %__MODULE__{
          path_defaults: path_controller(),
          pto_grants: %{optional({packet_space(), non_neg_integer()}) => path_id()}
        }
  @type path_id :: term()
  @type packet_space :: :initial | :handshake | :application
  @type path_controller :: %{rtt: RTT.t(), congestion: NewReno.t()}
  @type ack_result :: %{
          acked: [non_neg_integer()],
          lost: [{packet_space(), non_neg_integer()}],
          rtt_sample: pos_integer() | nil
        }

  @doc "The selected send path; packet-number spaces are shared by all paths."
  @spec selected_path(t()) :: path_id()
  def selected_path(%__MODULE__{} = state), do: state.active_path

  @doc "An independent path controller, or nil after retirement."
  @spec path(t(), path_id()) :: path_controller() | nil
  def path(%__MODULE__{active_path: id} = state, id),
    do: %{rtt: state.rtt, congestion: state.congestion}

  def path(%__MODULE__{} = state, id), do: Map.get(state.paths, id)

  @doc "Install connection-wide peer ACK parameters without copying RTT estimates."
  @spec configure_peer_ack(t(), non_neg_integer(), 0..20) ::
          {:ok, t()} | {:error, :invalid_ack_parameters}
  def configure_peer_ack(%__MODULE__{} = state, max_delay, exponent)
      when is_integer(max_delay) and max_delay >= 0 and exponent in 0..20 do
    configure = fn controller ->
      %{
        controller
        | rtt: %{controller.rtt | max_ack_delay: max_delay, ack_delay_exponent: exponent}
      }
    end

    state =
      Enum.reduce([state.active_path | Map.keys(state.paths)], state, fn id, state ->
        update_path(state, id, configure)
      end)

    {:ok, arm(%{state | path_defaults: configure.(state.path_defaults)})}
  end

  def configure_peer_ack(_state, _max_delay, _exponent), do: {:error, :invalid_ack_parameters}

  @spec add_path(t(), path_id()) :: {:ok, t()} | {:error, :path_limit}
  def add_path(%__MODULE__{} = state, id) do
    rtt = %{
      state.path_defaults.rtt
      | max_ack_delay: state.rtt.max_ack_delay,
        ack_delay_exponent: state.rtt.ack_delay_exponent
    }

    defaults = %{state.path_defaults | rtt: rtt}

    cond do
      path(state, id) != nil -> {:ok, state}
      map_size(state.paths) >= 1 -> {:error, :path_limit}
      true -> {:ok, %{state | paths: Map.put(state.paths, id, defaults)}}
    end
  end

  @spec select_path(t(), path_id()) :: {:ok, t()} | {:error, :unknown_path}
  def select_path(%__MODULE__{active_path: id} = state, id), do: {:ok, state}

  def select_path(%__MODULE__{} = state, id) do
    case Map.pop(state.paths, id) do
      {nil, _} ->
        {:error, :unknown_path}

      {controller, paths} ->
        paths = Map.put(paths, state.active_path, path(state, state.active_path))

        {:ok,
         arm(%{
           state
           | paths: paths,
             active_path: id,
             rtt: controller.rtt,
             congestion: controller.congestion
         })}
    end
  end

  @spec drop_path(t(), path_id()) ::
          {:ok, t()} | {:error, :active_path | :unknown_path | :path_busy}
  def drop_path(%__MODULE__{} = state, id) do
    cond do
      id == state.active_path ->
        {:error, :active_path}

      path(state, id) == nil ->
        {:error, :unknown_path}

      live_path_packets?(state, id) ->
        {:error, :path_busy}

      true ->
        spaces =
          Map.new(state.spaces, fn {space, s} ->
            packets =
              Map.new(s.sent, fn {number, packet} ->
                {number, retire_path_packet(packet, id)}
              end)

            {space, %{s | sent: packets}}
          end)

        {:ok, arm(%{state | paths: Map.delete(state.paths, id), spaces: spaces})}
    end
  end

  defp retire_path_packet(%Packet{path_id: id, status: :sent} = packet, id),
    do: %{packet | status: :discarded, metadata: terminal_metadata(packet.metadata)}

  defp retire_path_packet(packet, _id), do: packet

  @doc "Current probe timeout duration in microseconds, before PTO backoff."
  @spec pto_duration(t()) :: pos_integer()
  def pto_duration(state), do: pto_duration(state, state.active_path)

  @spec pto_duration(t(), path_id()) :: pos_integer()
  def pto_duration(state, id) do
    controller = path(state, id)

    (controller.rtt.smoothed || @default_rtt) +
      max(1000, 4 * (controller.rtt.variance || div(@default_rtt, 2))) +
      if(Enum.any?(state.spaces, fn {space, _} -> space == :application end),
        do: controller.rtt.max_ack_delay,
        else: 0
      )
  end

  @spec reserve(t(), atom(), map(), non_neg_integer()) ::
          {:ok, t(), Packet.t()} | {:error, atom()}
  def reserve(state, space, metadata \\ %{}, bytes \\ 0)

  def reserve(state, space, metadata, bytes)
      when space in @spaces and is_map(metadata) and is_integer(bytes) and bytes >= 0 do
    reserve_packet(state, space, metadata, bytes, nil)
  end

  def reserve(_, _, _, _), do: {:error, :invalid_reservation}

  @doc """
  Reserve one fresh packet for an original selected by the latest expired PTO.

  The one-shot grant is tied to the original packet and its send path. Probe
  bytes count as additional flight without increasing the congestion window;
  ordinary reservations cannot use this allowance. The caller supplies the
  actual protected-packet size limit and only the selected retry may use it.
  """
  @spec reserve_probe(t(), packet_space(), non_neg_integer(), map(), integer(), integer()) ::
          {:ok, t(), Packet.t()} | {:error, atom()}
  def reserve_probe(state, space, original, metadata, bytes, packet_limit)
      when space in @spaces and is_integer(original) and original >= 0 and is_map(metadata) do
    grant = {space, original}
    id = Map.get(metadata, :path_id, state.active_path)

    cond do
      state.spaces[space].retired ->
        {:error, :retired_space}

      not (is_integer(bytes) and bytes > 0 and is_integer(packet_limit) and
             packet_limit > 0 and bytes <= packet_limit) ->
        {:error, :invalid_probe_size}

      Map.get(metadata, :ack_eliciting, true) != true ->
        {:error, :invalid_probe_packet}

      not Map.has_key?(state.pto_grants, grant) ->
        {:error, :probe_not_authorized}

      not valid_probe_grant?(state, grant, state.pto_grants[grant]) ->
        {:error, :probe_not_authorized}

      state.pto_grants[grant] != id ->
        {:error, :probe_path_mismatch}

      true ->
        reserve_packet(state, space, metadata, bytes, grant)
    end
  end

  def reserve_probe(_, _, _, _, _, _), do: {:error, :invalid_probe_reservation}

  defp reserve_packet(state, space, metadata, bytes, grant) do
    s = state.spaces[space]

    if s.retired do
      {:error, :retired_space}
    else
      s = prune_terminal_history(s, state.max_sent_packets)

      if map_size(s.sent) >= state.max_sent_packets do
        {:error, :sent_history_limit}
      else
        id = Map.get(metadata, :path_id, state.active_path)

        with %{congestion: congestion} = controller <- path(state, id),
             {:ok, congestion} <- reserve_congestion(congestion, bytes, grant) do
          packet = %Packet{
            number: s.next,
            space: space,
            status: :reserved,
            bytes: bytes,
            metadata: Map.put(metadata, :path_id, id),
            path_id: id
          }

          state = put_path(state, id, %{controller | congestion: congestion})
          state = %{state | pto_grants: Map.delete(state.pto_grants, grant)}
          {:ok, put_packet(state, space, packet, %{s | next: s.next + 1}), packet}
        else
          nil -> {:error, :unknown_path}
          error -> error
        end
      end
    end
  end

  defp reserve_congestion(congestion, bytes, nil), do: NewReno.reserve(congestion, bytes)

  defp reserve_congestion(congestion, bytes, _grant),
    do: {:ok, %{congestion | bytes_in_flight: congestion.bytes_in_flight + bytes}}

  defp valid_probe_grant?(state, {space, number}, id) do
    case state.spaces[space].sent[number] do
      %Packet{status: :sent, path_id: ^id, metadata: metadata} ->
        not state.spaces[space].retired and path(state, id) != nil and
          Map.get(metadata, :ack_eliciting, true) == true

      _ ->
        false
    end
  end

  @doc false
  def supersede(state, space, number) when space in @spaces and is_integer(number) do
    with {:ok, %Packet{status: :lost, metadata: metadata} = packet} <-
           fetch_packet(state, space, number),
         true <- Map.has_key?(metadata, :crypto) or Map.has_key?(metadata, :control) do
      {:ok, put_packet(state, space, %{packet | status: :superseded}, state.spaces[space])}
    else
      _ -> {:error, :invalid_supersession}
    end
  end

  @doc false
  def abort_reservations_since(state, before) do
    {spaces, released} =
      Enum.reduce(@spaces, {%{}, %{}}, fn space, {spaces, released} ->
        cutoff = before.spaces[space].next
        current = state.spaces[space]

        {sent, {bytes, aborted}} =
          Enum.map_reduce(current.sent, {%{}, []}, fn {number, packet}, {bytes, aborted} ->
            if number >= cutoff and packet.status in [:reserved, :queued] do
              {{number,
                %{packet | status: :failed, metadata: terminal_metadata(packet.metadata)}},
               {add_bytes(bytes, packet.path_id, packet.bytes), [number | aborted]}}
            else
              {{number, packet}, {bytes, aborted}}
            end
          end)

        pending = Enum.reduce(aborted, current.pending_acks, &MapSet.delete(&2, &1))
        next = %{current | sent: Map.new(sent), pending_acks: pending}
        {Map.put(spaces, space, next), merge_bytes(released, bytes)}
      end)

    arm(apply_congestion(%{state | spaces: spaces}, released, :release))
  end

  @spec transition(t(), atom(), non_neg_integer(), atom()) :: {:ok, t()} | {:error, atom()}
  def transition(state, space, number, status) when status in [:queued, :sent],
    do: update_status(state, space, number, status)

  def transition(_, _, _, _), do: {:error, :invalid_status}

  @spec local_send(t(), atom(), non_neg_integer(), :ok | {:error, term()}, integer()) ::
          {:ok, t(), [atom()]} | {:error, atom()}
  def local_send(
        %{spaces: %{initial: %{retired: true}}} = state,
        :initial,
        _number,
        _result,
        _at
      ),
      do: {:ok, state, [:retired]}

  def local_send(
        %{spaces: %{handshake: %{retired: true}}} = state,
        :handshake,
        _number,
        _result,
        _at
      ),
      do: {:ok, state, [:retired]}

  def local_send(state, space, number, :ok, at) when is_integer(at) do
    with {:ok, packet} <- fetch_packet(state, space, number),
         true <- packet.status in [:reserved, :queued] do
      packet = %{packet | status: :sent, sent_at: at}
      s = state.spaces[space]

      {status, pending} =
        if MapSet.member?(s.pending_acks, number),
          do: {:acked, MapSet.delete(s.pending_acks, number)},
          else: {:sent, s.pending_acks}

      packet = %{
        packet
        | status: status,
          acked_at: if(status == :acked, do: at, else: nil),
          metadata:
            if(status == :acked, do: terminal_metadata(packet.metadata), else: packet.metadata)
      }

      state = put_packet(state, space, packet, %{s | pending_acks: pending})

      state =
        if status == :acked,
          do: apply_congestion(state, %{packet.path_id => packet.bytes}, :on_ack),
          else: state

      {:ok, arm(state), [status]}
    else
      false ->
        case fetch_packet(state, space, number) do
          {:ok, %Packet{status: status}}
          when status in [:sent, :acked, :lost, :superseded, :failed, :discarded] ->
            {:ok, state, []}

          _ ->
            {:error, :invalid_packet_state}
        end

      error ->
        error
    end
  end

  def local_send(state, space, number, {:error, _reason}, _at) do
    with {:ok, packet} <- fetch_packet(state, space, number),
         true <- packet.status in [:reserved, :queued] do
      s = state.spaces[space]
      s = %{s | pending_acks: MapSet.delete(s.pending_acks, number)}
      state = put_packet(state, space, %{packet | status: :failed}, s)
      {:ok, apply_congestion(state, %{packet.path_id => packet.bytes}, :release), [:failed]}
    else
      false -> {:error, :invalid_packet_state}
      error -> error
    end
  end

  @spec receive_ack(t(), packet_space(), map(), integer()) ::
          {:ok, t(), ack_result()} | {:error, atom()}
  def receive_ack(state, space, ack, at),
    do: receive_ack(state, space, ack, at, state.active_path)

  @spec receive_ack(t(), packet_space(), map(), integer(), path_id()) ::
          {:ok, t(), ack_result()} | {:error, atom()}
  def receive_ack(%{spaces: %{initial: %{retired: true}}}, :initial, _ack, _at, _path),
    do: {:error, :retired_space}

  def receive_ack(%{spaces: %{handshake: %{retired: true}}}, :handshake, _ack, _at, _path),
    do: {:error, :retired_space}

  def receive_ack(state, space, ack, at, receive_path)
      when space in @spaces and is_map(ack) and is_integer(at) do
    with {:ok, ranges} <-
           normalize_ranges(ack[:ranges] || [], state.max_ack_ranges),
         {:ok, largest} <- validate_largest(ack[:largest], ranges),
         :ok <- known_ack?(state.spaces[space], largest, ranges) do
      {space_state, acked, newly_acked_bytes} = acknowledge(state.spaces[space], ranges, at)

      space_state = %{space_state | largest_acked: max(space_state.largest_acked, largest)}
      state = %{state | spaces: Map.put(state.spaces, space, space_state)}
      {state, sample} = update_rtt(state, space, ack, acked, at, receive_path)
      state = apply_congestion(state, newly_acked_bytes, :on_ack)
      {state, threshold_lost} = detect_packet_threshold(state, space, largest)
      {:ok, arm(state), %{acked: acked, lost: threshold_lost, rtt_sample: sample}}
    end
  end

  @doc "Record an authenticated packet number received in a packet-number space."
  @spec note_received(t(), atom(), non_neg_integer()) :: {:ok, t()} | {:error, atom()}
  def note_received(%{spaces: %{initial: %{retired: true}}}, :initial, _number),
    do: {:error, :retired_space}

  def note_received(%{spaces: %{handshake: %{retired: true}}}, :handshake, _number),
    do: {:error, :retired_space}

  def note_received(state, space, number)
      when space in @spaces and is_integer(number) and number >= 0 do
    current = state.spaces[space]

    if number < current.receive_floor do
      {:ok, state}
    else
      ranges = merge_ranges(current.ack_ranges, [{number, number}])
      {retired, ranges} = Enum.split(ranges, max(0, length(ranges) - state.max_ack_ranges))

      floor =
        case List.last(retired) do
          nil -> current.receive_floor
          {_low, high} -> max(current.receive_floor, high + 1)
        end

      next = %{
        current
        | largest_received: max(number, current.largest_received),
          receive_floor: floor,
          ack_ranges: ranges
      }

      {:ok, %{state | spaces: Map.put(state.spaces, space, next)}}
    end
  end

  def note_received(_, _, _), do: {:error, :invalid_received_packet}

  @doc false
  def received?(state, space, number) do
    Enum.any?(state.spaces[space].ack_ranges, fn {low, high} ->
      number >= low and number <= high
    end)
  end

  @doc "Discard an encryption space's outstanding work while preserving allocated packet numbers."
  def discard_space(state, space) when space in @spaces do
    current = state.spaces[space]

    {sent, released} =
      Enum.reduce(current.sent, {%{}, %{}}, fn {number, packet}, {packets, bytes} ->
        if packet.status in [:reserved, :queued, :sent] do
          {Map.put(packets, number, %{packet | status: :discarded}),
           add_bytes(bytes, packet.path_id, packet.bytes)}
        else
          {Map.put(packets, number, packet), bytes}
        end
      end)

    next = %{
      current
      | sent: sent,
        pending_acks: MapSet.new(),
        ack_ranges: [],
        receive_floor: 0,
        largest_received: -1
    }

    state = %{state | spaces: Map.put(state.spaces, space, next)}
    state |> apply_congestion(released, :release) |> reset_pto_counts() |> arm()
  end

  @doc "Permanently retire Initial/Handshake recovery, preserving the next packet number."
  @spec retire_space(t(), :initial | :handshake) :: t()
  def retire_space(state, space) when space in [:initial, :handshake] do
    current = state.spaces[space]

    if current.retired do
      state
    else
      released =
        Enum.reduce(current.sent, %{}, fn {_number, packet}, acc ->
          if packet.status in [:reserved, :queued, :sent],
            do: add_bytes(acc, packet.path_id, packet.bytes),
            else: acc
        end)

      next = %Space{next: current.next, retired: true}

      state = %{state | spaces: Map.put(state.spaces, space, next)}
      state |> apply_congestion(released, :release) |> reset_pto_counts() |> arm()
    end
  end

  @doc "Recompute the next deadline from actual sent packets, without advancing time."
  def arm(state) do
    loss_times =
      for {_space, s} <- state.spaces,
          {number, p} <- s.sent,
          p.status == :sent and is_integer(p.sent_at) and number <= s.largest_acked,
          do: p.sent_at + loss_delay(state, p.path_id)

    deadline =
      case loss_times do
        [] ->
          case pto_candidates(state) do
            [] -> nil
            candidates -> candidates |> Enum.map(&elem(&1, 0)) |> Enum.min()
          end

        times ->
          Enum.min(times)
      end

    grants =
      Map.filter(state.pto_grants, fn {grant, id} -> valid_probe_grant?(state, grant, id) end)

    %{
      state
      | deadline: deadline,
        timer_generation: state.timer_generation + 1,
        pto_grants: grants
    }
  end

  @spec on_time(t(), integer()) :: {:ok, t(), map()}
  def on_time(state, now) when is_integer(now) do
    expired = is_integer(state.deadline) and now >= state.deadline
    {state, lost} = detect_loss(state, now)

    probes =
      if expired and lost == [] do
        case Enum.sort(pto_candidates(state)) do
          [{_deadline, space, number} | _] -> [{space, number}]
          [] -> []
        end
      else
        []
      end

    state =
      if expired do
        grants =
          probes
          |> Enum.take(2)
          |> Map.new(fn {space, number} ->
            {{space, number}, state.spaces[space].sent[number].path_id}
          end)

        %{state | pto_grants: grants}
      else
        state
      end

    state =
      Enum.reduce(probes, state, fn {space, number}, state ->
        id = state.spaces[space].sent[number].path_id

        update_path(state, id, fn controller ->
          %{
            controller
            | rtt: %{controller.rtt | pto_count: min(16, controller.rtt.pto_count + 1)}
          }
        end)
      end)

    next = arm(state)

    {:ok, next,
     %{lost: lost, probes: probes, pto: next.deadline, generation: next.timer_generation}}
  end

  @spec timer_expired?(t(), non_neg_integer(), integer()) :: boolean()
  def timer_expired?(%__MODULE__{deadline: deadline, timer_generation: generation}, token, now),
    do: token == generation and is_integer(deadline) and now >= deadline

  defp put_packet(state, space, packet, space_state),
    do: %{
      state
      | spaces:
          Map.put(state.spaces, space, %{
            space_state
            | sent: Map.put(space_state.sent, packet.number, packet)
          })
    }

  defp prune_terminal_history(space, limit) do
    if map_size(space.sent) < limit do
      space
    else
      retained =
        Enum.reject(space.sent, fn {_number, packet} ->
          packet.status in [:acked, :failed, :discarded, :superseded]
        end)

      %{space | sent: Map.new(retained)}
    end
  end

  defp fetch_packet(state, space, number) do
    case state.spaces[space].sent[number] do
      nil -> {:error, :unknown_packet}
      packet -> {:ok, packet}
    end
  end

  defp update_status(state, space, number, status) do
    with {:ok, packet} <- fetch_packet(state, space, number),
         true <-
           packet.status in [:reserved, :queued] or (status == :sent and packet.status == :sent) do
      {:ok, put_packet(state, space, %{packet | status: status}, state.spaces[space])}
    else
      false -> {:error, :invalid_packet_state}
      error -> error
    end
  end

  defp validate_largest(nil, _), do: {:error, :invalid_ack}

  defp validate_largest(largest, ranges) when is_integer(largest) and largest >= 0 do
    if ranges != [] and Enum.max(Enum.map(ranges, &elem(&1, 1))) == largest,
      do: {:ok, largest},
      else: {:error, :invalid_ack_ranges}
  end

  defp validate_largest(_, _), do: {:error, :invalid_ack}

  defp normalize_ranges(ranges, max) when is_list(ranges) and length(ranges) <= max do
    result =
      Enum.reduce_while(ranges, {:ok, []}, fn range, {:ok, acc} ->
        case range_bounds(range) do
          {:ok, {lo, hi}} when lo <= hi ->
            {:cont, {:ok, [{lo, hi} | acc]}}

          _ ->
            {:halt, {:error, :invalid_ack_ranges}}
        end
      end)

    case result do
      {:ok, xs} -> {:ok, Enum.sort(xs)}
      error -> error
    end
  end

  defp normalize_ranges(_, _), do: {:error, :ack_range_limit}

  defp range_bounds({lo, hi}) when is_integer(lo) and is_integer(hi) and lo >= 0 and hi >= 0,
    do: {:ok, {lo, hi}}

  defp range_bounds(%{start: lo, end: hi}), do: range_bounds({lo, hi})
  defp range_bounds(_), do: {:error, :invalid_ack_range}

  defp known_ack?(space, largest, ranges) do
    issued = space.next

    if largest >= issued or Enum.any?(ranges, fn {_lo, hi} -> hi >= issued end),
      do: {:error, :ack_never_issued},
      else: :ok
  end

  defp acknowledge(space, ranges, at) do
    # Range widths grow with connection lifetime; work is bounded by retained
    # packet records and the validated range count, never by the numeric span.
    {space, acked, bytes} =
      Enum.reduce(space.sent, {space, [], %{}}, fn {n, packet}, {s, nums, bytes} = acc ->
        if Enum.any?(ranges, fn {lo, hi} -> n >= lo and n <= hi end) do
          case packet do
            %Packet{status: :sent} = p ->
              p = %{p | status: :acked, acked_at: at, metadata: terminal_metadata(p.metadata)}

              {%{s | sent: Map.put(s.sent, n, p)}, [n | nums],
               add_bytes(bytes, p.path_id, p.bytes)}

            %Packet{status: status} = p when status in [:lost, :superseded] ->
              p = %{p | status: :acked, acked_at: at, metadata: terminal_metadata(p.metadata)}
              {%{s | sent: Map.put(s.sent, n, p)}, [n | nums], bytes}

            %Packet{status: status} when status in [:reserved, :queued] ->
              {%{s | pending_acks: MapSet.put(s.pending_acks, n)}, nums, bytes}

            _ ->
              acc
          end
        else
          acc
        end
      end)

    # Map traversal has no packet-number order; RTT selection expects largest first.
    {space, Enum.sort(acked, :desc), bytes}
  end

  defp terminal_metadata(metadata), do: Map.drop(metadata, [:bytes, :control])

  defp merge_ranges(existing, incoming) do
    (existing ++ incoming)
    |> Enum.sort()
    |> Enum.reduce([], fn
      {lo, hi}, [{previous_lo, previous_hi} | rest] when lo <= previous_hi + 1 ->
        [{previous_lo, max(previous_hi, hi)} | rest]

      range, acc ->
        [range | acc]
    end)
    |> Enum.reverse()
  end

  defp update_rtt(state, space, ack, acked, at, receive_path) do
    controller = path(state, receive_path)

    {latest, sample} =
      case Enum.find(acked, fn n ->
             packet = state.spaces[space].sent[n]
             controller != nil and packet.path_id == receive_path and packet.sent_at != nil
           end) do
        nil ->
          {nil, nil}

        n ->
          latest = max(1, at - state.spaces[space].sent[n].sent_at)
          min_rtt = if controller.rtt.min, do: min(controller.rtt.min, latest), else: latest

          delay =
            if space == :application do
              min(
                max(0, ack[:delay] || 0) * Integer.pow(2, controller.rtt.ack_delay_exponent),
                controller.rtt.max_ack_delay
              )
            else
              0
            end

          sample = if latest >= min_rtt + delay, do: latest - delay, else: latest
          {latest, sample}
      end

    if sample == nil,
      do: {state, nil},
      else:
        {put_path(state, receive_path, %{
           controller
           | rtt: update_rtt_sample(controller.rtt, latest, sample)
         }), latest}
  end

  defp update_rtt_sample(rtt, latest, sample) do
    min = if rtt.min, do: min(rtt.min, latest), else: latest

    {smoothed, variance} =
      if rtt.smoothed,
        do:
          {div(7 * rtt.smoothed + sample, 8),
           div(3 * rtt.variance + abs(rtt.smoothed - sample), 4)},
        else: {sample, div(sample, 2)}

    %{rtt | latest: latest, min: min, smoothed: smoothed, variance: variance, pto_count: 0}
  end

  defp detect_loss(state, now) do
    Enum.reduce(@spaces, {state, []}, fn space, {st, lost} ->
      s = st.spaces[space]

      {s, nums, bytes} =
        Enum.reduce(s.sent, {s, [], %{}}, fn {n, p}, {ss, ns, b} ->
          if p.status == :sent and is_integer(p.sent_at) and n <= s.largest_acked and
               now - p.sent_at >= loss_delay(st, p.path_id),
             do:
               {%{ss | sent: Map.put(ss.sent, n, %{p | status: :lost, lost_at: now})}, [n | ns],
                add_bytes(b, p.path_id, p.bytes)},
             else: {ss, ns, b}
        end)

      st = apply_congestion(%{st | spaces: Map.put(st.spaces, space, s)}, bytes, :on_loss)
      {st, lost ++ Enum.map(nums, &{space, &1})}
    end)
  end

  defp detect_packet_threshold(state, space, largest) do
    threshold = largest - 3
    s = state.spaces[space]

    {s, nums, bytes} =
      Enum.reduce(s.sent, {s, [], %{}}, fn {n, p}, {ss, ns, b} ->
        if p.status == :sent and threshold >= 0 and n <= threshold,
          do:
            {%{ss | sent: Map.put(ss.sent, n, %{p | status: :lost})}, [n | ns],
             add_bytes(b, p.path_id, p.bytes)},
          else: {ss, ns, b}
      end)

    state = apply_congestion(%{state | spaces: Map.put(state.spaces, space, s)}, bytes, :on_loss)
    {state, Enum.map(nums, &{space, &1})}
  end

  defp loss_delay(state, id) do
    rtt = path(state, id).rtt

    max(
      1000,
      div(max(rtt.latest || @default_rtt, rtt.smoothed || @default_rtt) * 9 + 7, 8)
    )
  end

  defp pto_candidates(state) do
    Enum.flat_map(@spaces, fn space ->
      sent =
        state.spaces[space].sent
        |> Map.values()
        |> Enum.filter(
          &(&1.status == :sent and is_integer(&1.sent_at) and
              Map.get(&1.metadata, :ack_eliciting, true))
        )

      sent
      |> Enum.group_by(& &1.path_id)
      |> Enum.map(fn {id, packets} ->
        rtt = path(state, id).rtt

        base =
          (rtt.smoothed || @default_rtt) +
            max(1000, 4 * (rtt.variance || div(@default_rtt, 2))) +
            if(space == :application, do: rtt.max_ack_delay, else: 0)

        latest = packets |> Enum.map(& &1.sent_at) |> Enum.max()
        oldest = Enum.min_by(packets, & &1.sent_at)
        {latest + base * Integer.pow(2, rtt.pto_count), space, oldest.number}
      end)
    end)
  end

  defp live_path_packets?(state, id) do
    Enum.any?(state.spaces, fn {_space, s} ->
      Enum.any?(s.sent, fn {_number, packet} ->
        packet.path_id == id and
          (packet.status in [:reserved, :queued] or
             (packet.status == :sent and
                (packet.bytes > 0 or Map.get(packet.metadata, :ack_eliciting, true))))
      end)
    end)
  end

  defp put_path(%{active_path: id} = state, id, controller),
    do: %{state | rtt: controller.rtt, congestion: controller.congestion}

  defp put_path(state, id, controller),
    do: %{state | paths: Map.put(state.paths, id, controller)}

  defp update_path(state, id, fun) do
    case path(state, id) do
      nil -> state
      controller -> put_path(state, id, fun.(controller))
    end
  end

  defp apply_congestion(state, by_path, operation) do
    Enum.reduce(by_path, state, fn {id, bytes}, state ->
      update_path(state, id, fn controller ->
        %{controller | congestion: apply(NewReno, operation, [controller.congestion, bytes])}
      end)
    end)
  end

  defp add_bytes(by_path, _id, 0), do: by_path
  defp add_bytes(by_path, id, bytes), do: Map.update(by_path, id, bytes, &(&1 + bytes))
  defp merge_bytes(left, right), do: Map.merge(left, right, fn _id, a, b -> a + b end)

  defp reset_pto_counts(state) do
    Enum.reduce([state.active_path | Map.keys(state.paths)], state, fn id, state ->
      update_path(state, id, fn controller ->
        %{controller | rtt: %{controller.rtt | pto_count: 0}}
      end)
    end)
  end
end
