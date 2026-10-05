defmodule Quic.HandshakeScheduler do
  @moduledoc """
  Deterministic handshake packet scheduler.

  This module is deliberately socket-free.  TLS emissions become retained
  CRYPTO ranges and protected send effects; local send receipts and peer ACKs
  are applied separately through `Quic.Recovery`.
  """

  import Bitwise

  alias Quic.{Codec, Protection, Recovery, TLSDriver, PeerCIDs, Streams, TransportParameters}
  alias SSL.Crypto.HKDF

  @levels [:initial, :handshake, :application]
  @spaces [:initial, :handshake, :application]
  @default_max_packet 1350

  defstruct role: nil,
            dcid: <<>>,
            scid: <<>>,
            original_dcid: <<>>,
            retry_scid: nil,
            retry_token: <<>>,
            peer_initial_scid: nil,
            peer_cids: nil,
            tls: nil,
            recovery: nil,
            keys: %{},
            read_keys: %{},
            key_update: %{
              phase: 0,
              generation: 0,
              first_received: nil,
              previous_largest: -1,
              previous_read: nil,
              previous_until: nil,
              ack_sent: true
            },
            pending: [],
            pending_acks: %{},
            pending_control: %{},
            effects: [],
            max_packet_size: @default_max_packet,
            peer_idle_timeout: 0,
            local_max_datagram_frame_size: 0,
            peer_max_datagram_frame_size: 0,
            min_initial_size: 1200,
            max_queue: 64,
            queued: 0,
            queued_bytes: 0,
            max_queue_bytes: 1_048_576,
            acked_stream_ranges: %{},
            acked_stream_fins: MapSet.new(),
            streams: nil

  @type t :: %__MODULE__{}

  @spec new(:client | :server, keyword()) ::
          {:ok, t(), list()} | {:error, term()} | {:error, term(), t()}
  def new(role, opts \\ [])

  def new(role, opts) when role in [:client, :server] do
    with {:ok, dcid} <- required_cid(opts, :dcid),
         {:ok, scid} <- required_cid(opts, :scid),
         {:ok, initial} <-
           initial_keys(
             opts,
             Keyword.get(opts, :initial_key_dcid, Keyword.get(opts, :original_dcid, dcid)),
             role
           ),
         {:ok, tls, tls_effects} <- TLSDriver.new(role, tls_options(opts)) do
      recovery = Keyword.get(opts, :recovery, Recovery.new())

      state = %__MODULE__{
        role: role,
        dcid: dcid,
        scid: scid,
        original_dcid: Keyword.get(opts, :original_dcid, dcid),
        retry_scid: Keyword.get(opts, :retry_scid),
        tls: tls,
        recovery: recovery,
        keys: Map.put(Keyword.get(opts, :keys, %{}), :initial, initial),
        read_keys:
          initial_read_keys(
            opts,
            Keyword.get(opts, :initial_key_dcid, Keyword.get(opts, :original_dcid, dcid)),
            role,
            initial
          ),
        max_packet_size: Keyword.get(opts, :max_packet_size, @default_max_packet),
        min_initial_size: Keyword.get(opts, :min_initial_size, 1200),
        max_queue: Keyword.get(opts, :max_queue, 64),
        max_queue_bytes: Keyword.get(opts, :max_queue_bytes, 1_048_576),
        local_max_datagram_frame_size: Keyword.get(opts, :max_datagram_frame_size, 0),
        streams: Streams.new(role, Keyword.get(opts, :streams, []))
      }

      with {:ok, state, sends} <- ingest_tls_effects(state, tls_effects),
           {:ok, state, sends2} <- schedule(state) do
        {:ok, state, sends ++ sends2}
      end
    end
  end

  def new(_, _), do: {:error, :invalid_role}

  @doc "Fold TLS driver effects returned from a CRYPTO receive into the scheduler."
  @spec feed(t(), atom(), non_neg_integer(), binary()) ::
          {:ok, t(), list()} | {:error, term(), t(), list()}
  def feed(%__MODULE__{} = state, level, offset, bytes)
      when level in @levels and is_integer(offset) and offset >= 0 and is_binary(bytes) do
    case TLSDriver.feed(state.tls, level, offset, bytes) do
      {:ok, tls, effects} ->
        state = %{state | tls: tls}

        case ingest_tls_effects(state, effects) do
          {:ok, state, generated} ->
            case schedule(state) do
              {:ok, state, sends} -> {:ok, state, generated ++ sends}
              {:error, reason, state} -> {:error, reason, state, []}
            end

          {:error, reason, state} ->
            {:error, reason, state, []}
        end

      {:error, reason, tls, effects} ->
        state = %{state | tls: tls}

        case ingest_tls_effects(state, effects) do
          {:ok, state, generated} -> {:error, reason, state, generated}
          {:error, fold_error, state} -> {:error, fold_error, state, []}
        end
    end
  end

  def feed(state, _, _, _), do: {:error, :invalid_crypto_input, state, []}

  @doc "Admit one application stream frame into the bounded scheduler queue."
  @spec send_stream(t(), non_neg_integer(), binary(), boolean()) ::
          {:ok, t(), list()}
          | {:blocked, map() | :send_queue_limit | :send_queue_bytes_limit}
          | {:error, term()}
          | {:error, term(), t()}
  def send_stream(%__MODULE__{streams: streams} = state, id, data, fin \\ false) do
    retained =
      for {_pn, packet} <- state.recovery.spaces.application.sent,
          frame <- Map.get(packet.metadata, :control, []),
          frame.type == :stream,
          do: byte_size(frame.data)

    cond do
      not is_binary(data) or not is_boolean(fin) ->
        {:error, :invalid_stream_frame}

      byte_size(data) > 16_384 ->
        {:error, :chunk_too_large}

      state.queued_bytes + Enum.sum(retained) + byte_size(data) > state.max_queue_bytes ->
        {:blocked, :send_queue_bytes_limit}

      length(Map.get(state.pending_control, :application, [])) >= state.max_queue ->
        {:blocked, :send_queue_limit}

      true ->
        with {:ok, next_streams, frame} <- Streams.send(streams, id, data, fin),
             true <- Map.has_key?(state.keys, :application) do
          state = %{
            state
            | streams: next_streams,
              queued_bytes: state.queued_bytes + byte_size(data)
          }

          controls = Map.get(state.pending_control, :application, []) ++ [frame]

          schedule(%{
            state
            | pending_control: Map.put(state.pending_control, :application, controls)
          })
        else
          false -> {:error, :application_unavailable}
          {:blocked, frame} -> {:blocked, frame}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  @doc "Admit one unreliable application DATAGRAM frame; loss never requeues it."
  def send_datagram(%__MODULE__{} = state, data) when is_binary(data) do
    frame = %{type: :datagram, data: data}

    with true <- state.peer_max_datagram_frame_size > 0,
         true <- byte_size(data) + 2 <= effective_datagram_frame_size(state),
         {:ok, wire} <- Codec.encode_frames([frame]),
         true <- byte_size(wire) <= effective_datagram_frame_size(state) do
      controls = Map.get(state.pending_control, :application, [])

      cond do
        length(controls) >= state.max_queue ->
          {:blocked, :send_queue_limit}

        state.queued_bytes + byte_size(data) > state.max_queue_bytes ->
          {:blocked, :send_queue_bytes_limit}

        not Map.has_key?(state.keys, :application) ->
          {:error, :application_unavailable}

        true ->
          next = %{state | queued_bytes: state.queued_bytes + byte_size(data)}
          pending = Map.put(next.pending_control, :application, controls ++ [frame])
          schedule(%{next | pending_control: pending})
      end
    else
      false when state.peer_max_datagram_frame_size == 0 -> {:error, :datagram_unsupported}
      false -> {:error, :datagram_too_large}
      {:error, reason} -> {:error, reason}
    end
  end

  def send_datagram(_, _), do: {:error, :invalid_datagram}

  @doc "Effective frame ceiling after peer negotiation and worst-case packet overhead."
  def effective_datagram_frame_size(state) do
    # Packet numbers and an authenticated replacement CID can grow while queued.
    packet_overhead = 1 + 20 + 4 + 16

    max(0, min(state.peer_max_datagram_frame_size, state.max_packet_size - packet_overhead))
  end

  @doc "Install the semantic values of authenticated, validated peer parameters."
  def install_peer_parameters(state, values) do
    rtt = %{
      state.recovery.rtt
      | max_ack_delay: Map.get(values, :max_ack_delay, 25) * 1000,
        ack_delay_exponent: Map.get(values, :ack_delay_exponent, 3)
    }

    %{
      state
      | streams: Streams.install_peer_parameters(state.streams, values),
        peer_max_datagram_frame_size: Map.get(values, :max_datagram_frame_size, 0),
        max_packet_size:
          min(state.max_packet_size, Map.get(values, :max_udp_payload_size, 65_527)),
        recovery: %{state.recovery | rtt: rtt},
        peer_idle_timeout: Map.get(values, :max_idle_timeout, 0)
    }
  end

  @doc "Open a locally initiated stream without creating a process per stream."
  @spec open_stream(t(), :bidi | :uni) ::
          {:ok, t(), non_neg_integer()} | {:blocked, map()} | {:error, term()}
  def open_stream(%__MODULE__{streams: streams} = state, kind) when kind in [:bidi, :uni] do
    with true <- Map.has_key?(state.keys, :application),
         {:ok, next_streams, id} <- Streams.open(streams, kind) do
      {:ok, %{state | streams: next_streams}, id}
    else
      false -> {:error, :application_unavailable}
      {:blocked, frame} -> {:blocked, frame}
    end
  end

  def open_stream(_, _), do: {:error, :invalid_stream_kind}

  @doc "Consume queued stream events for a manual-delivery stream policy."
  def consume_stream(%__MODULE__{streams: streams} = state, id, max_bytes) do
    case Streams.consume(streams, id, max_bytes) do
      {:ok, streams, events} ->
        {streams, frames} = Streams.take_credit(streams)
        {:ok, queue_control(%{state | streams: streams}, :application, frames), events}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Reset only the local send direction and discard its pending data ranges."
  def reset_stream(state, id, code) do
    with {:ok, streams, frame} <- Streams.reset_send(state.streams, id, code) do
      state = discard_stream_send(%{state | streams: streams}, id)
      schedule(queue_control(state, :application, if(frame, do: [frame], else: [])))
    end
  end

  @doc "Request cancellation of the receive direction, preserving the send half."
  def stop_stream(state, id, code) do
    with {:ok, streams, frame} <- Streams.stop_sending(state.streams, id, code) do
      {streams, credit} = Streams.take_credit(streams)
      schedule(queue_control(%{state | streams: streams}, :application, [frame | credit]))
    end
  end

  defp discard_stream_send(state, id) do
    keep = fn frame -> not (frame.type == :stream and frame.stream_id == id) end
    frames = Enum.filter(Map.get(state.pending_control, :application, []), keep)

    pending =
      if frames == [],
        do: Map.delete(state.pending_control, :application),
        else: Map.put(state.pending_control, :application, frames)

    sent =
      Map.new(state.recovery.spaces.application.sent, fn {number, packet} ->
        control = Map.get(packet.metadata, :control, [])
        remaining = Enum.filter(control, keep)

        metadata =
          if remaining == control,
            do: packet.metadata,
            else: packet.metadata |> Map.delete(:bytes) |> Map.put(:control, remaining)

        {number, %{packet | metadata: metadata}}
      end)

    state = put_in(state.recovery.spaces.application.sent, sent)
    %{state | pending_control: pending, queued_bytes: control_data_bytes(frames)}
  end

  @doc "Queue reliable control information, coalescing monotonic credit updates."
  def queue_control(state, level, frames) do
    controls =
      Enum.reduce(frames, Map.get(state.pending_control, level, []), fn frame, acc ->
        if frame.type in [:max_data, :max_stream_data, :max_streams_bidi, :max_streams_uni] do
          key = {frame.type, Map.get(frame, :stream_id)}
          {same, rest} = Enum.split_with(acc, &({&1.type, Map.get(&1, :stream_id)} == key))
          value = Enum.reduce(same, frame.value, &max(&1.value, &2))
          rest ++ [%{frame | value: value}]
        else
          if frame in acc, do: acc, else: acc ++ [frame]
        end
      end)

    if controls == [],
      do: state,
      else: %{state | pending_control: Map.put(state.pending_control, level, controls)}
  end

  @doc "Queue an ACK frame for the next packet in a packet-number space."
  def queue_ack(%__MODULE__{} = state, space, ack) when space in @spaces and is_map(ack) do
    if retired?(state, space),
      do: state,
      else: %{state | pending_acks: Map.put(state.pending_acks, space, [ack])}
  end

  def queue_ack(state, _, _), do: state

  @doc "Apply a local writer result; this is distinct from packet admission."
  def local_send(%__MODULE__{} = state, space, number, result, at)
      when space in @spaces and is_integer(number) do
    case Recovery.local_send(state.recovery, space, number, result, at) do
      {:ok, recovery, statuses} ->
        if statuses == [:retired] do
          {:ok, state, statuses}
        else
          next = %{
            state
            | recovery: recovery,
              queued: max(0, state.queued - if(statuses == [], do: 0, else: 1))
          }

          next =
            if state.role == :client and space == :handshake and result == :ok,
              do: retire_level(next, :initial),
              else: next

          next = note_key_update_ack(next, space, number, result, statuses)

          next =
            if statuses == [:acked] do
              frames = Map.get(state.recovery.spaces[space].sent[number].metadata, :control, [])

              Enum.reduce(frames, next, &acknowledge_stream_frame/2)
              |> prune_acknowledged_streams()
            else
              next
            end

          {:ok, next, statuses}
        end

      error ->
        error
    end
  end

  @doc "Whether the packet-number space is permanently retired."
  @spec retired?(t(), :initial | :handshake | :application) :: boolean()
  def retired?(state, level), do: state.recovery.spaces[level].retired

  @doc "Drop the QUIC keys, retained packets and CRYPTO storage for an obsolete level."
  @spec retire_level(t(), :initial | :handshake) :: t()
  def retire_level(state, level) when level in [:initial, :handshake] do
    if retired?(state, level) do
      state
    else
      queued =
        Enum.count(state.recovery.spaces[level].sent, fn {_, packet} ->
          packet.status in [:reserved, :queued]
        end)

      %{
        state
        | keys: Map.delete(state.keys, level),
          read_keys: if(level == :initial, do: %{}, else: state.read_keys),
          tls: TLSDriver.retire_level(state.tls, level),
          recovery: Recovery.retire_space(state.recovery, level),
          pending: Enum.reject(state.pending, &(&1.level == level)),
          pending_acks: Map.delete(state.pending_acks, level),
          pending_control: Map.delete(state.pending_control, level),
          effects: Enum.reject(state.effects, &(&1.level == level)),
          queued: max(0, state.queued - queued)
      }
    end
  end

  @doc "Confirm QUIC and retire Handshake after role-specific confirmation."
  @spec confirm_handshake(t()) :: t()
  def confirm_handshake(state) do
    state = %{state | tls: TLSDriver.mark_quic_confirmed(state.tls)}
    retire_level(state, :handshake)
  end

  @doc "Apply an authenticated peer ACK to Recovery."
  def receive_ack(%__MODULE__{} = state, space, ack, at) when space in @spaces do
    with {:ok, recovery, result} <- Recovery.receive_ack(state.recovery, space, ack, at) do
      frames =
        Enum.flat_map(result.acked, fn number ->
          Map.get(state.recovery.spaces[space].sent[number].metadata, :control, [])
        end)

      next = Enum.reduce(frames, %{state | recovery: recovery}, &acknowledge_stream_frame/2)
      {:ok, prune_acknowledged_streams(next), result}
    end
  end

  defp acknowledge_stream_frame(%{type: :stream} = frame, state) do
    ranges = Map.get(state.acked_stream_ranges, frame.stream_id, [])
    ranges = merge_stream_ranges(ranges ++ [{frame.offset, frame.offset + byte_size(frame.data)}])

    fins =
      if frame.fin,
        do: MapSet.put(state.acked_stream_fins, frame.stream_id),
        else: state.acked_stream_fins

    %{
      state
      | acked_stream_ranges: Map.put(state.acked_stream_ranges, frame.stream_id, ranges),
        acked_stream_fins: fins
    }
  end

  defp acknowledge_stream_frame(_, state), do: state

  defp merge_stream_ranges(ranges) do
    ranges
    |> Enum.sort()
    |> Enum.reduce([], fn {lo, hi}, acc ->
      case acc do
        [{left, right} | rest] when lo <= right -> [{left, max(right, hi)} | rest]
        _ -> [{lo, hi} | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp unacknowledged_frames(state, frames),
    do: Enum.flat_map(frames, &unacknowledged_frame(state, &1))

  defp unacknowledged_frame(state, %{type: :stream} = frame) do
    finish = frame.offset + byte_size(frame.data)

    ranges =
      Enum.reduce(
        Map.get(state.acked_stream_ranges, frame.stream_id, []),
        [{frame.offset, finish}],
        fn {a, b}, ranges ->
          Enum.flat_map(ranges, fn {lo, hi} ->
            subtract_acknowledged_range(a, b, lo, hi)
          end)
        end
      )

    fin = frame.fin and not MapSet.member?(state.acked_stream_fins, frame.stream_id)

    frames =
      for {lo, hi} <- ranges,
          hi > lo,
          do: %{
            frame
            | offset: lo,
              data: binary_part(frame.data, lo - frame.offset, hi - lo),
              fin: fin and hi == finish
          }

    if fin and not Enum.any?(frames, & &1.fin),
      do: frames ++ [%{frame | offset: finish, data: <<>>}],
      else: frames
  end

  defp unacknowledged_frame(_, frame), do: [frame]

  defp prune_acknowledged_streams(state) do
    control = unacknowledged_frames(state, Map.get(state.pending_control, :application, []))

    pending =
      if control == [],
        do: Map.delete(state.pending_control, :application),
        else: Map.put(state.pending_control, :application, control)

    sent =
      Map.new(state.recovery.spaces.application.sent, fn {number, packet} ->
        original = Map.get(packet.metadata, :control, [])
        remaining = unacknowledged_frames(state, original)

        packet =
          if original != [] and remaining == [] do
            metadata = Map.drop(packet.metadata, [:bytes, :control])

            %{
              packet
              | metadata: metadata,
                status: if(packet.status == :lost, do: :acked, else: packet.status)
            }
          else
            if original == remaining,
              do: packet,
              else: %{packet | metadata: Map.put(packet.metadata, :control, remaining)}
          end

        {number, packet}
      end)

    state = put_in(state.recovery.spaces.application.sent, sent)
    %{state | pending_control: pending, queued_bytes: control_data_bytes(control)}
  end

  @doc "Process bounded coalesced packets in order, preserving an accepted prefix."
  @spec receive_datagram(t(), binary(), integer()) ::
          {:ok, t(), [map()]} | {:error, term(), t()}
  def receive_datagram(state, datagram, at \\ 0)

  def receive_datagram(%__MODULE__{} = state, <<first, _::binary>> = datagram, at)
      when (first &&& 0xF0) == 0xF0 and is_integer(at) do
    case apply_retry(state, datagram) do
      {:ok, next, sends} -> {:ok, next, [%{type: :retry, generated: sends}]}
      {:error, reason} -> {:error, reason, state}
      {:error, reason, _} -> {:error, reason, state}
    end
  end

  def receive_datagram(%__MODULE__{} = state, datagram, at)
      when is_binary(datagram) and is_integer(at) and byte_size(datagram) > 0 do
    if byte_size(datagram) > 65_527,
      do: {:error, :datagram_size_limit, state},
      else: receive_coalesced(state, datagram, at, [], 0)
  end

  def receive_datagram(state, _datagram, _at), do: {:error, :invalid_datagram, state}

  defp apply_retry(%{recovery: %{spaces: %{initial: %{retired: true}}}}, _packet),
    do: {:error, :unexpected_retry}

  defp apply_retry(
         %{role: :client, retry_scid: nil, peer_initial_scid: nil} = state,
         <<_first, 1::32, rest::binary>> = packet
       )
       when byte_size(packet) <= 4096 do
    with {:ok, dcid, rest} <- take_cid(rest),
         true <- dcid == state.scid,
         {:ok, scid, rest} <- take_cid(rest),
         true <- byte_size(scid) > 0 and scid != state.dcid and byte_size(rest) > 16,
         :ok <- Protection.validate_retry(state.original_dcid, packet),
         {:ok, write_keys} <- Protection.initial_secrets(scid, :client),
         {:ok, read_keys} <- Protection.initial_secrets(scid, :server) do
      token = binary_part(rest, 0, byte_size(rest) - 16)

      pending =
        Enum.map(state.tls.levels.initial.sent, fn emission ->
          %{level: :initial, offset: emission.offset, bytes: emission.bytes}
        end)

      next = %{
        state
        | dcid: scid,
          retry_scid: scid,
          retry_token: token,
          keys: Map.put(state.keys, :initial, write_keys),
          read_keys: read_keys,
          recovery: Recovery.discard_space(state.recovery, :initial),
          pending_acks: Map.delete(state.pending_acks, :initial),
          pending: pending,
          queued: 0
      }

      schedule(next)
    else
      false -> {:error, :invalid_retry}
      {:error, _} = error -> error
    end
  end

  defp apply_retry(_state, _packet), do: {:error, :unexpected_retry}

  defp receive_coalesced(state, <<>>, _at, events, _count), do: {:ok, state, events}

  defp receive_coalesced(state, _rest, _at, events, 32),
    do: {:ok, state, events ++ [%{type: :discard, reason: :packet_count_limit}]}

  defp receive_coalesced(state, bytes, at, events, count) do
    result =
      with {:ok, packet, authenticated} <- decode_protected_packet(state, bytes, at),
           :ok <- validate_packet_frames(packet.plaintext, packet.level),
           {:ok, recovery} <-
             Recovery.note_received(authenticated.recovery, packet.space, packet.number),
           {:ok, next, generated} <-
             dispatch_inbound(
               learn_peer_cid(%{authenticated | recovery: recovery}, packet),
               packet,
               at
             ) do
        next =
          if next.role == :server and packet.level == :handshake do
            next = %{next | tls: TLSDriver.mark_address_validated(next.tls)}
            retire_level(next, :initial)
          else
            next
          end

        {:ok, next, generated, packet.packet_length}
      end

    case result do
      {:retired, length} ->
        <<_packet::binary-size(^length), rest::binary>> = bytes

        receive_coalesced(
          state,
          rest,
          at,
          events ++ [%{type: :discard, reason: :retired_level}],
          count + 1
        )

      {:ok, next, generated, length} ->
        <<_packet::binary-size(^length), rest::binary>> = bytes
        receive_coalesced(next, rest, at, events ++ generated, count + 1)

      {:error, reason} ->
        coalesced_error(state, events, count, reason)
    end
  end

  defp coalesced_error(state, _events, 0, reason), do: {:error, reason, state}

  defp coalesced_error(state, events, _count, reason),
    do: {:ok, state, events ++ [%{type: :discard, reason: reason}]}

  @doc "Alias for callers that process one packet rather than a datagram batch."
  def receive_packet(state, packet, at \\ 0), do: receive_datagram(state, packet, at)

  @doc "Return the exact retained datagram for retransmission."
  def retransmit(%__MODULE__{} = state, space, number) when space in @spaces do
    case state.recovery.spaces[space].sent[number] do
      %Recovery.Packet{metadata: %{bytes: bytes, level: level, packet_number: ^number}} ->
        {:ok,
         %{space: space, level: level, packet_number: number, bytes: bytes, retransmit: true}}

      %Recovery.Packet{metadata: %{bytes: bytes, level: level}} when is_binary(bytes) ->
        {:ok,
         %{space: space, level: level, packet_number: number, bytes: bytes, retransmit: true}}

      _ ->
        {:error, :unknown_packet}
    end
  end

  @doc "Repacketize retained CRYPTO under a fresh packet number without calling TLS."
  def retry_crypto(%__MODULE__{} = state, space, number) when space in @spaces do
    case state.recovery.spaces[space].sent[number] do
      %Recovery.Packet{status: status, metadata: %{level: level, crypto: {offset, length}}}
      when status in [:sent, :lost, :failed] and length > 0 ->
        with {:ok, bytes} <- TLSDriver.retransmit(state.tls, level, offset, length) do
          if Enum.any?(
               state.pending,
               &(&1.level == level and &1.offset == offset and &1.bytes == bytes)
             ) do
            {:ok, state, []}
          else
            next = %{
              state
              | pending: state.pending ++ [%{level: level, offset: offset, bytes: bytes}]
            }

            with {:ok, recovery} <- handoff_lost_packet(next.recovery, space, number) do
              schedule(%{next | recovery: recovery})
            end
          end
        end

      %Recovery.Packet{status: status, metadata: %{control: [_ | _] = frames}}
      when status in [:sent, :lost, :failed] ->
        reliable = Enum.reject(frames, &(&1.type == :datagram))
        probe = if reliable == [], do: [%{type: :ping}], else: []
        next = queue_control(state, space, reliable ++ probe)

        with {:ok, recovery} <- handoff_lost_packet(next.recovery, space, number) do
          schedule(%{next | recovery: recovery})
        end

      nil ->
        {:error, :unknown_packet}

      _ ->
        {:error, :not_retransmittable}
    end
  end

  defp handoff_lost_packet(recovery, space, number) do
    case recovery.spaces[space].sent[number] do
      %Recovery.Packet{status: :lost} -> Recovery.supersede(recovery, space, number)
      %Recovery.Packet{} -> {:ok, recovery}
      nil -> {:error, :unknown_packet}
    end
  end

  @doc "Send HANDSHAKE_DONE after the server completes its TLS handshake."
  def handshake_done(%{role: :server, tls: %{facts: %{tls_complete: true}}} = state) do
    schedule(%{
      state
      | pending_control: Map.put(state.pending_control, :application, [%{type: :handshake_done}])
    })
  end

  def handshake_done(_), do: {:error, :handshake_not_complete}

  @doc "Schedule all currently pending emissions and queued ACKs."
  @spec schedule(t()) :: {:ok, t(), list()} | {:error, term(), t()}
  def schedule(%__MODULE__{} = state), do: do_schedule(state, state.recovery)

  defp do_schedule(%__MODULE__{} = state, before) do
    case state.pending do
      [] ->
        case Enum.find(
               @spaces,
               &(Map.has_key?(state.pending_acks, &1) or Map.has_key?(state.pending_control, &1))
             ) do
          nil ->
            {:ok, state, []}

          space ->
            emission = %{
              level: space,
              offset: state.tls.levels[space].next_send,
              bytes: <<>>,
              ack_only: true
            }

            do_schedule(%{state | pending: [emission]}, before)
        end

      [emission | rest] ->
        case fragment_pending(state, emission) do
          {:split, first, second} ->
            do_schedule(%{state | pending: [first, second | rest]}, before)

          {:error, reason} ->
            {:error, reason, state}

          :ok ->
            schedule_fragment(state, emission, rest, before)
        end
    end
  end

  # Fit each CRYPTO range against the actual protected packet.  The probe does
  # not reserve a packet number or call TLS, and therefore cannot consume
  # congestion credit or alter retransmission state.
  defp fragment_pending(_state, %{bytes: <<>>}), do: :ok

  defp fragment_pending(state, %{level: level, offset: offset, bytes: bytes} = emission)
       when is_binary(bytes) do
    key_context = Map.get(state.keys, level)

    case build_protected(state, level, offset, bytes, key_context) do
      {:ok, packet} when byte_size(packet) <= state.max_packet_size ->
        :ok

      {:ok, _oversize} ->
        fit = largest_fitting_fragment(state, emission, key_context)

        if fit > 0 and fit < byte_size(bytes) do
          first = %{emission | bytes: binary_part(bytes, 0, fit)}

          second = %{
            emission
            | offset: offset + fit,
              bytes: binary_part(bytes, fit, byte_size(bytes) - fit)
          }

          {:split, first, second}
        else
          {:error, :packet_size_limit}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp largest_fitting_fragment(state, %{level: level, offset: offset, bytes: bytes}, keys) do
    do_largest_fitting(state, level, offset, bytes, keys, 1, byte_size(bytes), 0)
  end

  defp do_largest_fitting(_state, _level, _offset, _bytes, _keys, low, high, best)
       when low > high,
       do: best

  defp do_largest_fitting(state, level, offset, bytes, keys, low, high, best) do
    mid = div(low + high, 2)
    candidate = binary_part(bytes, 0, mid)

    case build_protected(state, level, offset, candidate, keys) do
      {:ok, packet} when byte_size(packet) <= state.max_packet_size ->
        do_largest_fitting(state, level, offset, bytes, keys, mid + 1, high, mid)

      _ ->
        do_largest_fitting(state, level, offset, bytes, keys, low, mid - 1, best)
    end
  end

  defp ingest_tls_effects(state, effects) when is_list(effects) do
    with :ok <- preflight_authenticated_parameters(state, effects) do
      Enum.reduce_while(effects, {:ok, state, []}, fn
        {:emit, level, bytes}, {:ok, state, generated}
        when level in @levels and is_binary(bytes) ->
          offset = emitted_offset(state, level, bytes)
          emission = %{level: level, offset: offset, bytes: bytes}
          {:cont, {:ok, %{state | pending: state.pending ++ [emission]}, generated}}

        {%SSL.QUIC.Secret{}, _}, acc ->
          {:cont, acc}

        %SSL.QUIC.Secret{} = secret, {:ok, state, generated} ->
          case install_secret(state, secret) do
            {:ok, state} -> {:cont, {:ok, state, generated}}
            {:error, reason} -> {:halt, {:error, reason, state}}
          end

        {:handshake_complete, _}, acc ->
          {:cont, acc}

        :handshake_complete, acc ->
          {:cont, acc}

        {:peer_authenticated, _}, acc ->
          {:cont, acc}

        {:peer_transport_parameters, bytes, :authenticated}, {:ok, state, generated} ->
          case validate_peer_transport_parameters(state, bytes) do
            :ok -> {:cont, {:ok, state, generated}}
            {:error, reason} -> {:halt, {:error, {:transport_parameters, reason}, state}}
          end

        {:peer_transport_parameters, _, _}, acc ->
          {:cont, acc}

        {:negotiated_alpn, _}, acc ->
          {:cont, acc}

        {:error, error}, _ ->
          {:halt, {:error, error, state}}

        _, _ ->
          {:halt, {:error, :invalid_tls_action, state}}
      end)
    end
  end

  defp preflight_authenticated_parameters(state, effects) do
    Enum.reduce_while(effects, :ok, fn
      {:peer_transport_parameters, bytes, :authenticated}, :ok ->
        case validate_peer_transport_parameters(state, bytes) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, {:transport_parameters, reason}, state}}
        end

      _, :ok ->
        {:cont, :ok}
    end)
  end

  defp validate_peer_transport_parameters(%{peer_initial_scid: nil}, _bytes), do: :ok

  defp validate_peer_transport_parameters(state, bytes) do
    peer_role = if state.role == :client, do: :server, else: :client

    with {:ok, parameters} <- TransportParameters.decode(bytes) do
      TransportParameters.validate(parameters,
        role: peer_role,
        initial_source_connection_id: state.peer_initial_scid,
        retry_source_connection_id: if(peer_role == :server, do: state.retry_scid),
        original_destination_connection_id: if(peer_role == :server, do: state.original_dcid)
      )
    end
  end

  defp protect_and_reserve(state, %{level: level, offset: offset, bytes: bytes} = emission) do
    with {:ok, packet_state, remaining} <- fit_controls(state, emission),
         control <- Map.get(packet_state.pending_control, level, []),
         ack_eliciting <- bytes != <<>> or control != [],
         {:ok, packet} <-
           build_protected(packet_state, level, offset, bytes, Map.get(state.keys, level)),
         true <- byte_size(packet) <= state.max_packet_size,
         {:ok, recovery, reserved} <-
           Recovery.reserve(
             state.recovery,
             level,
             %{
               level: level,
               crypto: {offset, byte_size(bytes)},
               bytes: packet,
               control: control,
               acks: Map.get(state.pending_acks, level, []),
               key_phase: if(level == :application, do: state.key_update.phase, else: nil),
               ack_eliciting: ack_eliciting
             },
             if(ack_eliciting or level == :initial, do: byte_size(packet), else: 0)
           ),
         {:ok, recovery} <- Recovery.transition(recovery, level, reserved.number, :queued) do
      metadata = Map.put(reserved.metadata, :packet_number, reserved.number)
      recovery = put_in(recovery.spaces[level].sent[reserved.number].metadata, metadata)

      pending_control =
        if remaining == [],
          do: Map.delete(state.pending_control, level),
          else: Map.put(state.pending_control, level, remaining)

      next = %{
        state
        | recovery: recovery,
          pending_acks: Map.delete(state.pending_acks, level),
          pending_control: pending_control,
          queued_bytes: max(0, state.queued_bytes - control_data_bytes(control))
      }

      {:ok, next,
       %{type: :send, space: level, level: level, packet_number: reserved.number, bytes: packet}}
    else
      false -> {:error, :packet_size_limit, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  # Each application packet carries at most one control/STREAM/DATAGRAM frame.
  # Size probes include ACKs, CID, packet number, varints, padding and AEAD tag.
  defp fit_controls(state, %{level: :application, bytes: <<>>} = emission) do
    case Map.get(state.pending_control, :application, []) do
      [] ->
        {:ok, state, []}

      [frame | rest] ->
        candidate = %{
          state
          | pending_control: Map.put(state.pending_control, :application, [frame])
        }

        case build_protected(
               candidate,
               :application,
               emission.offset,
               <<>>,
               state.keys.application
             ) do
          {:ok, bytes} when byte_size(bytes) <= state.max_packet_size ->
            {:ok, candidate, rest}

          {:ok, _} when frame.type == :stream and byte_size(frame.data) > 0 ->
            count =
              fitting_stream_bytes(candidate, frame, emission.offset, 1, byte_size(frame.data), 0)

            if count == 0 do
              {:error, :packet_size_limit}
            else
              first = %{frame | data: binary_part(frame.data, 0, count), fin: false}

              tail = %{
                frame
                | offset: frame.offset + count,
                  data: binary_part(frame.data, count, byte_size(frame.data) - count)
              }

              {:ok,
               %{
                 candidate
                 | pending_control: Map.put(candidate.pending_control, :application, [first])
               }, [tail | rest]}
            end

          {:ok, _} when frame.type == :datagram ->
            case Map.get(state.pending_acks, :application, []) do
              [] ->
                {:error, :packet_size_limit}

              [_ | _] ->
                # Send the ACK separately; an admitted DATAGRAM cannot be split.
                ack_only = %{
                  candidate
                  | pending_control: Map.delete(candidate.pending_control, :application)
                }

                {:ok, ack_only, [frame | rest]}
            end

          {:ok, _} ->
            {:error, :packet_size_limit}

          {:error, reason} ->
            {:error, reason}
        end
    end
  end

  defp fit_controls(state, _), do: {:ok, state, []}

  defp fitting_stream_bytes(_, _, _, low, high, best) when low > high, do: best

  defp fitting_stream_bytes(state, frame, offset, low, high, best) do
    mid = div(low + high, 2)
    first = %{frame | data: binary_part(frame.data, 0, mid), fin: false}
    candidate = %{state | pending_control: Map.put(state.pending_control, :application, [first])}

    case build_protected(candidate, :application, offset, <<>>, state.keys.application) do
      {:ok, bytes} when byte_size(bytes) <= state.max_packet_size ->
        fitting_stream_bytes(state, frame, offset, mid + 1, high, mid)

      _ ->
        fitting_stream_bytes(state, frame, offset, low, mid - 1, best)
    end
  end

  defp control_data_bytes(frames) do
    Enum.reduce(frames, 0, fn
      %{type: type, data: data}, total when type in [:stream, :datagram] and is_binary(data) ->
        total + byte_size(data)

      _, total ->
        total
    end)
  end

  defp build_protected(_state, level, _offset, _bytes, nil),
    do: {:error, {:unsupported_level, level}}

  defp build_protected(state, :initial, offset, bytes, keys) do
    ack_frames = Map.get(state.pending_acks, :initial, [])
    control = Map.get(state.pending_control, :initial, [])
    crypto = %{type: :crypto, offset: offset, data: bytes}

    with {:ok, ack_bytes} <- Codec.encode_frames(ack_frames ++ control),
         {:ok, crypto_bytes} <-
           if(bytes == <<>>, do: {:ok, <<>>}, else: Codec.encode_frames([crypto])) do
      plaintext = crypto_bytes <> ack_bytes
      plaintext = pad_initial(state, plaintext, keys)
      pn = state.recovery.spaces.initial.next
      pn_len = packet_number_length(pn)
      encrypt_initial(state, keys, pn, pn_len, plaintext)
    end
  end

  defp build_protected(state, level, offset, bytes, keys)
       when level in [:handshake, :application] and is_map(keys) do
    write_keys = Map.get(keys, :write)

    if is_map(write_keys) do
      ack_frames =
        Map.get(state.pending_acks, level, []) ++ Map.get(state.pending_control, level, [])

      crypto = %{type: :crypto, offset: offset, data: bytes}

      with {:ok, ack_bytes} <- Codec.encode_frames(ack_frames),
           {:ok, crypto_bytes} <-
             if(bytes == <<>>, do: {:ok, <<>>}, else: Codec.encode_frames([crypto])) do
        plaintext = crypto_bytes <> ack_bytes
        pn = state.recovery.spaces[level].next
        pn_len = packet_number_length(pn)
        encrypt_protected(state, level, write_keys, pn, pn_len, plaintext)
      end
    else
      {:error, {:missing_write_key, level}}
    end
  end

  defp build_protected(_state, level, _offset, _bytes, _keys),
    do: {:error, {:unsupported_level, level}}

  defp encrypt_initial(state, keys, pn, pn_len, plaintext) do
    dummy_cipher = <<0::size((byte_size(plaintext) + 16) * 8)>>

    with {:ok, unprotected} <-
           Codec.build_initial(%{
             dcid: state.dcid,
             scid: state.scid,
             token: state.retry_token,
             packet_number: pn,
             packet_number_length: pn_len,
             payload: dummy_cipher
           }),
         header_size <- byte_size(unprotected) - byte_size(dummy_cipher),
         aad <- binary_part(unprotected, 0, header_size),
         {:ok, ciphertext} <-
           Protection.aead_encrypt(
             keys.key,
             keys.iv,
             pn,
             aad,
             plaintext,
             Map.get(keys, :aead, :aes_128_gcm)
           ),
         packet <- aad <> ciphertext,
         pn_offset <- header_size - pn_len,
         {:ok, mask} <-
           Protection.header_protection_mask(
             keys.hp,
             binary_part(packet, pn_offset + 4, 16),
             :aes_128_gcm
           ),
         prefix_size <- pn_offset - 1,
         <<first, prefix::binary-size(^prefix_size), pn_wire::binary-size(^pn_len), tail::binary>> <-
           packet do
      masked_first = bxor(first, :binary.at(mask, 0) &&& 0x0F)
      masked_pn = mask_packet_number(pn_wire, mask, 1)
      {:ok, <<masked_first, prefix::binary, masked_pn::binary, tail::binary>>}
    else
      {:error, _} = error -> error
      _ -> {:error, :protection_failed}
    end
  end

  defp encrypt_protected(state, :handshake, keys, pn, pn_len, plaintext) do
    encrypt_long(state, keys, 2, pn, pn_len, plaintext)
  end

  defp encrypt_protected(state, :application, keys, pn, pn_len, plaintext) do
    encrypt_short(state, keys, pn, pn_len, plaintext)
  end

  defp encrypt_long(state, keys, packet_type, pn, pn_len, plaintext) do
    plaintext = sample_padding(plaintext, pn_len)
    dummy_cipher = <<0::size((byte_size(plaintext) + 16) * 8)>>

    with {:ok, length} <- Codec.encode_varint(byte_size(dummy_cipher) + pn_len),
         header <-
           <<0xC0 ||| packet_type <<< 4 ||| pn_len - 1, 1::32, byte_size(state.dcid),
             state.dcid::binary, byte_size(state.scid), state.scid::binary, length::binary>>,
         aad <- header <> <<pn::unsigned-big-integer-size(pn_len * 8)>>,
         {:ok, ciphertext} <-
           Protection.aead_encrypt(
             keys.key,
             keys.iv,
             pn,
             aad,
             plaintext,
             Map.get(keys, :aead, :aes_128_gcm)
           ),
         packet <- aad <> ciphertext,
         pn_offset <- byte_size(header),
         {:ok, mask} <-
           Protection.header_protection_mask(
             keys.hp,
             binary_part(packet, pn_offset + 4, 16),
             keys.hp_algorithm
           ),
         prefix_size <- byte_size(header) - 1,
         <<first, prefix::binary-size(^prefix_size), pn_wire::binary-size(^pn_len), tail::binary>> <-
           packet do
      masked_first = bxor(first, :binary.at(mask, 0) &&& 0x0F)
      masked_pn = mask_packet_number(pn_wire, mask, 1)
      {:ok, <<masked_first, prefix::binary, masked_pn::binary, tail::binary>>}
    else
      {:error, _} = error -> error
      _ -> {:error, :protection_failed}
    end
  end

  defp encrypt_short(state, keys, pn, pn_len, plaintext) do
    plaintext = sample_padding(plaintext, pn_len)

    with header <- <<0x40 ||| state.key_update.phase <<< 2 ||| pn_len - 1, state.dcid::binary>>,
         aad <- header <> <<pn::unsigned-big-integer-size(pn_len * 8)>>,
         {:ok, ciphertext} <-
           Protection.aead_encrypt(
             keys.key,
             keys.iv,
             pn,
             aad,
             plaintext,
             Map.get(keys, :aead, :aes_128_gcm)
           ),
         packet <- aad <> ciphertext,
         pn_offset <- byte_size(header),
         {:ok, mask} <-
           Protection.header_protection_mask(
             keys.hp,
             binary_part(packet, pn_offset + 4, 16),
             keys.hp_algorithm
           ),
         prefix_size <- byte_size(header) - 1,
         <<first, prefix::binary-size(^prefix_size), pn_wire::binary-size(^pn_len), tail::binary>> <-
           packet do
      masked_first = bxor(first, :binary.at(mask, 0) &&& 0x1F)
      masked_pn = mask_packet_number(pn_wire, mask, 1)
      {:ok, <<masked_first, prefix::binary, masked_pn::binary, tail::binary>>}
    else
      {:error, _} = error -> error
      _ -> {:error, :protection_failed}
    end
  end

  defp sample_padding(bytes, pn_len) do
    bytes <> :binary.copy(<<0>>, max(0, 4 - pn_len - byte_size(bytes)))
  end

  defp learn_peer_cid(%{peer_initial_scid: nil} = state, %{level: :initial, scid: scid}),
    do: %{state | peer_initial_scid: scid, dcid: scid, peer_cids: PeerCIDs.new(scid)}

  defp learn_peer_cid(state, _), do: state

  defp mask_packet_number(bytes, mask, index) do
    for {byte, i} <- Enum.with_index(:binary.bin_to_list(bytes)), into: <<>> do
      <<bxor(byte, :binary.at(mask, i + index))>>
    end
  end

  defp pad_initial(state, plaintext, _keys) do
    target = max(0, state.min_initial_size)
    pn = state.recovery.spaces.initial.next

    size_for = fn length ->
      {:ok, packet} =
        Codec.build_initial(%{
          dcid: state.dcid,
          scid: state.scid,
          token: state.retry_token,
          packet_number: pn,
          packet_number_length: packet_number_length(pn),
          payload: :binary.copy(<<0>>, length + 16)
        })

      byte_size(packet)
    end

    length = byte_size(plaintext)
    candidate = length + max(0, target - size_for.(length))
    padded_length = max(length, candidate - max(0, size_for.(candidate) - target))
    plaintext <> :binary.copy(<<0>>, padded_length - length)
  end

  defp packet_number_length(pn) when pn < 256, do: 1
  defp packet_number_length(pn) when pn < 65_536, do: 2
  defp packet_number_length(pn) when pn < 16_777_216, do: 3
  defp packet_number_length(_), do: 4

  defp emitted_offset(state, level, bytes) do
    existing = Enum.filter(state.pending, &(&1.level == level))

    case Enum.find(Enum.reverse(state.tls.levels[level].sent), fn emission ->
           emission.bytes == bytes and
             not Enum.any?(existing, &(&1.offset == emission.offset))
         end) do
      %{offset: offset} -> offset
      _ -> state.tls.levels[level].next_send - byte_size(bytes)
    end
  end

  defp required_cid(opts, key) do
    case Keyword.get(opts, key) do
      cid when is_binary(cid) and byte_size(cid) <= 20 -> {:ok, cid}
      _ -> {:error, {:missing_or_invalid, key}}
    end
  end

  defp install_secret(state, %SSL.QUIC.Secret{
         level: level,
         direction: direction,
         cipher_suite: cipher_suite,
         aead: aead,
         hkdf: hkdf,
         secret: secret
       })
       when level in [:handshake, :application] and direction in [:read, :write] do
    with false <- retired?(state, level),
         {:ok, derived} <- Protection.packet_keys(level, cipher_suite, aead, hkdf, secret) do
      context = Map.put(derived, :direction, direction)
      context = if level == :application, do: Map.put(context, :secret, secret), else: context
      existing = get_in(state.keys, [level, direction])

      cond do
        is_nil(existing) ->
          keys =
            Map.put(
              state.keys,
              level,
              Map.put(Map.get(state.keys, level, %{}), direction, context)
            )

          {:ok, %{state | keys: keys}}

        existing == context ->
          {:error, {:duplicate_secret, level, direction}}

        true ->
          {:error, {:conflicting_secret, level, direction}}
      end
    else
      true -> {:error, :retired_level}
      {:error, _} = error -> error
    end
  end

  defp install_secret(_state, %SSL.QUIC.Secret{level: level}),
    do: {:error, {:unsupported_secret_level, level}}

  defp initial_keys(opts, dcid, role) do
    case Keyword.get(opts, :initial_keys) do
      %{key: _, iv: _, hp: _} = keys -> {:ok, keys}
      nil -> Protection.initial_secrets(dcid, role)
      _ -> {:error, :invalid_initial_context}
    end
  end

  defp initial_read_keys(opts, dcid, role, initial) do
    case Keyword.get(opts, :initial_read_keys) do
      %{key: _, iv: _, hp: _} = keys ->
        keys

      nil ->
        case Protection.initial_secrets(dcid, opposite_role(role)) do
          {:ok, keys} -> keys
          _ -> initial
        end

      _ ->
        initial
    end
  end

  defp opposite_role(:client), do: :server
  defp opposite_role(:server), do: :client

  defp tls_options(opts) do
    Keyword.drop(opts, [
      :dcid,
      :original_dcid,
      :initial_key_dcid,
      :retry_scid,
      :scid,
      :initial_keys,
      :keys,
      :recovery,
      :max_packet_size,
      :min_initial_size,
      :max_queue,
      :max_queue_bytes,
      :max_datagram_frame_size,
      :streams,
      :initial_read_keys
    ])
  end

  defp dispatch_inbound(
         state,
         %{level: level, space: space, number: number, plaintext: plaintext},
         at
       ) do
    case Codec.decode_frames(plaintext) do
      {:ok, frames, <<>>} ->
        state =
          if Enum.any?(
               frames,
               &(&1.type not in [:ack, :padding, :connection_close, :application_close])
             ) do
            received = state.recovery.spaces[space]

            queue_ack(state, space, %{
              type: :ack,
              largest: received.largest_received,
              delay: 0,
              ranges: Enum.reverse(received.ack_ranges)
            })
          else
            state
          end

        dispatch_frames(state, level, space, number, frames, at, [])

      {:ok, _frames, _tail} ->
        {:error, :trailing_frame_bytes}

      {:error, reason} ->
        {:error, {:malformed_frame, reason}}
    end
  end

  defp validate_packet_frames(plaintext, level) do
    with {:ok, frames, <<>>} <- Codec.decode_frames(plaintext),
         :ok <- Codec.validate_frame_levels(frames, level) do
      :ok
    else
      {:ok, _frames, _tail} -> {:error, :trailing_frame_bytes}
      {:wrong_encryption_level, _, _} = reason -> {:error, reason}
      {:error, reason} when is_tuple(reason) -> {:error, reason}
      {:error, reason} -> {:error, {:malformed_frame, reason}}
    end
  end

  defp dispatch_frames(state, _level, _space, _number, [], _at, events),
    do: {:ok, state, Enum.reverse(events)}

  defp dispatch_frames(state, level, space, number, [frame | rest], at, events) do
    dispatch_frame(state, level, space, number, frame, rest, at, events)
  end

  defp dispatch_frame(
         state,
         level,
         space,
         number,
         %{type: :crypto, offset: offset, data: bytes},
         rest,
         at,
         events
       )
       when level in [:initial, :handshake, :application] do
    case feed(state, level, offset, bytes) do
      {:ok, next, generated} ->
        dispatch_frames(next, level, space, number, rest, at, [
          %{type: :crypto, level: level, offset: offset, bytes: bytes, generated: generated}
          | events
        ])

      {:error, reason, _next, _generated} ->
        {:error, reason}
    end
  end

  defp dispatch_frame(_state, level, _space, _number, %{type: :crypto}, _rest, _at, _events) do
    {:error, {:wrong_encryption_level, :crypto, level}}
  end

  defp dispatch_frame(state, level, space, number, %{type: :ack} = ack, rest, at, events) do
    case receive_ack(state, space, ack, at) do
      {:ok, next, result} ->
        dispatch_frames(next, level, space, number, rest, at, [
          %{type: :ack, result: result} | events
        ])

      {:error, reason} ->
        {:error, {:invalid_ack, reason}}
    end
  end

  defp dispatch_frame(state, level, space, number, %{type: :stream} = frame, rest, at, events)
       when level == :application do
    case Streams.receive(state.streams, frame) do
      {:ok, streams, stream_events} ->
        {streams, credit} = Streams.take_credit(streams)
        next = queue_control(%{state | streams: streams}, :application, credit)

        dispatch_frames(next, level, space, number, rest, at, [
          %{type: :stream, frame: frame, events: stream_events} | events
        ])

      {:error, reason} ->
        {:error, {:stream, reason}}
    end
  end

  defp dispatch_frame(_state, level, _space, _number, %{type: :stream}, _rest, _at, _events) do
    {:error, {:wrong_encryption_level, :stream, level}}
  end

  defp dispatch_frame(
         state,
         level,
         space,
         number,
         %{type: :datagram, wire_size: _} = frame,
         rest,
         at,
         events
       )
       when level == :application do
    if state.local_max_datagram_frame_size > 0 and
         frame.wire_size <= state.local_max_datagram_frame_size do
      dispatch_frames(state, level, space, number, rest, at, [frame | events])
    else
      {:error, {:protocol_violation, 0x0A, frame.wire_type}}
    end
  end

  defp dispatch_frame(_state, level, _space, _number, %{type: :datagram}, _rest, _at, _events) do
    {:error, {:wrong_encryption_level, :datagram, level}}
  end

  defp dispatch_frame(
         state,
         level,
         space,
         number,
         %{type: :reset_stream} = frame,
         rest,
         at,
         events
       )
       when level == :application do
    case Streams.receive_reset(
           state.streams,
           frame.stream_id,
           frame.error_code,
           frame.final_size
         ) do
      {:ok, streams, stream_events} ->
        {streams, credit} = Streams.take_credit(streams)
        next = queue_control(%{state | streams: streams}, :application, credit)

        dispatch_frames(next, level, space, number, rest, at, [
          %{type: :reset_stream, frame: frame, events: stream_events} | events
        ])

      {:error, reason} ->
        {:error, {:stream, reason}}
    end
  end

  defp dispatch_frame(_state, level, _space, _number, %{type: :reset_stream}, _rest, _at, _events) do
    {:error, {:wrong_encryption_level, :reset_stream, level}}
  end

  defp dispatch_frame(
         state,
         level,
         space,
         number,
         %{type: :stop_sending} = frame,
         rest,
         at,
         events
       )
       when level == :application do
    case Streams.peer_stop_sending(state.streams, frame.stream_id, frame.error_code) do
      {:ok, streams, reset} ->
        next = discard_stream_send(%{state | streams: streams}, frame.stream_id)
        next = queue_control(next, :application, if(reset, do: [reset], else: []))
        dispatch_frames(next, level, space, number, rest, at, [frame | events])

      {:error, reason} ->
        {:error, {:stream, reason}}
    end
  end

  defp dispatch_frame(_state, level, _space, _number, %{type: :stop_sending}, _rest, _at, _events) do
    {:error, {:wrong_encryption_level, :stop_sending, level}}
  end

  defp dispatch_frame(state, level, space, number, %{type: type} = frame, rest, at, events)
       when type in [:max_data, :max_stream_data, :max_streams_bidi, :max_streams_uni] and
              level == :application do
    case Streams.update_credit(state.streams, frame) do
      {:ok, streams, _status} ->
        dispatch_frames(%{state | streams: streams}, level, space, number, rest, at, [
          frame | events
        ])

      {:error, reason} ->
        {:error, {:stream, reason}}
    end
  end

  defp dispatch_frame(_state, level, _space, _number, %{type: type}, _rest, _at, _events)
       when type in [:max_data, :max_stream_data, :max_streams_bidi, :max_streams_uni] do
    {:error, {:wrong_encryption_level, type, level}}
  end

  defp dispatch_frame(state, level, space, number, %{type: type} = frame, rest, at, events)
       when type in [
              :data_blocked,
              :stream_data_blocked,
              :streams_blocked_bidi,
              :streams_blocked_uni
            ] and level == :application do
    dispatch_frames(state, level, space, number, rest, at, [frame | events])
  end

  defp dispatch_frame(_state, level, _space, _number, %{type: type}, _rest, _at, _events)
       when type in [
              :data_blocked,
              :stream_data_blocked,
              :streams_blocked_bidi,
              :streams_blocked_uni
            ] do
    {:error, {:wrong_encryption_level, type, level}}
  end

  defp dispatch_frame(
         state,
         level,
         space,
         number,
         %{type: :new_connection_id} = frame,
         rest,
         at,
         events
       )
       when level == :application do
    if state.peer_cids do
      with {:ok, cids, retired} <- PeerCIDs.receive_id(state.peer_cids, frame) do
        frames = Enum.map(retired, &%{type: :retire_connection_id, sequence: &1})
        control = Enum.uniq(Map.get(state.pending_control, :application, []) ++ frames)

        if length(control) <= state.max_queue do
          next = %{
            state
            | peer_cids: cids,
              dcid: PeerCIDs.current(cids),
              pending_control: Map.put(state.pending_control, :application, control)
          }

          next =
            if control == [],
              do: %{next | pending_control: Map.delete(next.pending_control, :application)},
              else: next

          dispatch_frames(next, level, space, number, rest, at, [frame | events])
        else
          {:error, :control_queue_limit}
        end
      end
    else
      {:error, :missing_peer_connection_id}
    end
  end

  defp dispatch_frame(
         _state,
         level,
         _space,
         _number,
         %{type: :new_connection_id},
         _rest,
         _at,
         _events
       ) do
    {:error, {:wrong_encryption_level, :new_connection_id, level}}
  end

  defp dispatch_frame(
         _state,
         _level,
         _space,
         _number,
         %{type: :retire_connection_id},
         _rest,
         _at,
         _events
       ) do
    # Only local sequence zero is currently issued. Its retirement on a
    # packet addressed to that same CID is forbidden by RFC 9000 19.16.
    {:error, :invalid_connection_id_retirement}
  end

  defp dispatch_frame(state, level, space, number, %{type: :handshake_done}, rest, at, events)
       when level == :application do
    if state.role == :client and state.tls.facts.tls_complete do
      next = confirm_handshake(state)

      dispatch_frames(next, level, space, number, rest, at, [
        %{type: :handshake_done} | events
      ])
    else
      {:error, :unexpected_handshake_done}
    end
  end

  defp dispatch_frame(
         %{role: :client} = state,
         :application,
         space,
         number,
         %{type: :new_token},
         rest,
         at,
         events
       ) do
    # RFC 9000 permits discarding NEW_TOKEN when future token reuse is unsupported.
    dispatch_frames(state, :application, space, number, rest, at, events)
  end

  defp dispatch_frame(
         _state,
         :application,
         _space,
         _number,
         %{type: :new_token},
         _rest,
         _at,
         _events
       ),
       do: {:error, :unexpected_new_token}

  defp dispatch_frame(_state, level, _space, _number, %{type: :new_token}, _rest, _at, _events),
    do: {:error, {:wrong_encryption_level, :new_token, level}}

  defp dispatch_frame(
         _state,
         level,
         _space,
         _number,
         %{type: :handshake_done},
         _rest,
         _at,
         _events
       ) do
    {:error, {:wrong_encryption_level, :handshake_done, level}}
  end

  defp dispatch_frame(state, level, space, number, %{type: type} = frame, rest, at, events)
       when type in [:connection_close, :application_close, :ping] do
    dispatch_frames(state, level, space, number, rest, at, [frame | events])
  end

  defp dispatch_frame(state, level, space, number, frame, rest, at, events) do
    dispatch_frames(state, level, space, number, rest, at, [frame | events])
  end

  defp decode_protected_packet(state, datagram, at) do
    with {:ok, parsed} <- parse_protected_header(state, datagram),
         false <- retired?(state, parsed.level) && {:retired, parsed.packet_length},
         keys when is_map(keys) <- read_key(state, parsed.level),
         packet <- binary_part(datagram, 0, parsed.packet_length),
         {:ok, unprotected, pn_len} <-
           Protection.remove_header_protection(
             packet,
             parsed.pn_offset,
             keys.hp,
             keys.hp_algorithm
           ),
         pn_offset <- parsed.pn_offset,
         <<_first, _prefix::binary-size(^pn_offset - 1), pn_bytes::binary-size(^pn_len),
           ciphertext::binary>> <- unprotected,
         truncated <- :binary.decode_unsigned(pn_bytes),
         largest <- state.recovery.spaces[parsed.space].largest_received,
         {:ok, number} <- reconstruct_inbound(truncated, largest, pn_len),
         aad_size <- parsed.pn_offset + pn_len,
         aad <- binary_part(unprotected, 0, aad_size),
         {:ok, plaintext, authenticated} <-
           decrypt_packet(state, parsed.level, keys, number, aad, ciphertext, at),
         :ok <- validate_unprotected_header(unprotected, parsed.level) do
      {:ok, Map.merge(parsed, %{number: number, plaintext: plaintext}), authenticated}
    else
      {:retired, length} -> {:retired, length}
      nil -> {:error, :missing_read_key}
      {:error, reason} -> {:error, reason}
      _ -> {:error, :malformed_protected_packet}
    end
  end

  defp decrypt_packet(state, :application, keys, number, <<first, _::binary>> = aad, bytes, at) do
    update = state.key_update
    phase = first >>> 2 &&& 1

    cond do
      phase == update.phase ->
        with {:ok, plaintext} <- decrypt_with(keys, number, aad, bytes),
             true <- number > update.previous_largest do
          update = expire_previous_read(update, at)
          first_received = min(update.first_received || number, number)
          {:ok, plaintext, %{state | key_update: %{update | first_received: first_received}}}
        else
          false -> {:error, {:key_update_error, :packet_number}}
          error -> error
        end

      update.generation > 0 and is_integer(update.first_received) and
          number < update.first_received ->
        with previous when is_map(previous) <- previous_read(update, at),
             {:ok, plaintext} <- decrypt_with(previous, number, aad, bytes) do
          {:ok, plaintext, state}
        else
          nil -> {:error, :bad_tag}
          error -> error
        end

      true ->
        decrypt_next_phase(state, keys, number, aad, bytes, at)
    end
  end

  defp decrypt_packet(state, _level, keys, number, aad, bytes, _at) do
    with {:ok, plaintext} <- decrypt_with(keys, number, aad, bytes),
         do: {:ok, plaintext, state}
  end

  defp decrypt_with(keys, number, aad, bytes) do
    Protection.aead_decrypt(
      keys.key,
      keys.iv,
      number,
      aad,
      bytes,
      Map.get(keys, :aead, :aes_128_gcm)
    )
  end

  defp decrypt_next_phase(state, keys, number, aad, bytes, at) do
    with {:ok, read} <- next_application_key(keys),
         {:ok, plaintext} <- decrypt_with(read, number, aad, bytes),
         :ok <- validate_key_update(state, number),
         {:ok, write} <- next_application_key(state.keys.application.write) do
      update = %{
        state.key_update
        | phase: bxor(state.key_update.phase, 1),
          generation: state.key_update.generation + 1,
          previous_largest: state.recovery.spaces.application.largest_received,
          first_received: number,
          previous_read: keys,
          previous_until: at + 3 * Recovery.pto_duration(state.recovery),
          ack_sent: false
      }

      application = %{state.keys.application | read: read, write: write}

      {:ok, plaintext,
       %{state | keys: Map.put(state.keys, :application, application), key_update: update}}
    end
  end

  defp validate_key_update(state, number) do
    cond do
      not state.tls.facts.quic_confirmed ->
        {:error, {:key_update_error, :handshake_unconfirmed}}

      not state.key_update.ack_sent ->
        {:error, {:key_update_error, :update_unacknowledged}}

      number <= state.recovery.spaces.application.largest_received ->
        {:error, {:key_update_error, :packet_number}}

      true ->
        :ok
    end
  end

  defp next_application_key(%{secret: secret} = keys) do
    next = HKDF.expand_label(keys.hkdf, secret, "quic ku", <<>>, byte_size(secret))

    with true <- is_binary(next),
         {:ok, derived} <-
           Protection.packet_keys(:application, keys.cipher_suite, keys.aead, keys.hkdf, next) do
      # RFC9001 section6: header protection never changes during a key update.
      {:ok, %{derived | hp: keys.hp} |> Map.merge(%{secret: next, direction: keys.direction})}
    else
      false -> {:error, :invalid_key_update_secret}
      error -> error
    end
  end

  defp next_application_key(_), do: {:error, :bad_tag}

  defp previous_read(update, at) do
    if is_integer(update.previous_until) and at < update.previous_until,
      do: update.previous_read
  end

  defp expire_previous_read(update, at) do
    if is_integer(update.previous_until) and at >= update.previous_until,
      do: %{update | previous_read: nil, previous_until: nil},
      else: update
  end

  defp note_key_update_ack(state, :application, number, :ok, statuses)
       when statuses in [[:sent], [:acked]] do
    metadata = state.recovery.spaces.application.sent[number].metadata
    first = state.key_update.first_received

    acknowledged =
      metadata[:key_phase] == state.key_update.phase and is_integer(first) and
        Enum.any?(Map.get(metadata, :acks, []), fn ack ->
          Enum.any?(ack.ranges, fn {_lo, hi} -> hi >= first end)
        end)

    if acknowledged,
      do: %{state | key_update: %{state.key_update | ack_sent: true}},
      else: state
  end

  defp note_key_update_ack(state, _space, _number, _result, _statuses), do: state

  defp reconstruct_inbound(truncated, -1, _pn_len), do: {:ok, truncated}

  defp reconstruct_inbound(truncated, largest, pn_len),
    do: Codec.reconstruct_packet_number(truncated, largest, pn_len)

  defp read_key(state, :initial) do
    case state.read_keys[:initial] || state.read_keys do
      %{key: _, iv: _, hp: _} = keys -> Map.put_new(keys, :hp_algorithm, :aes_128_gcm)
      keys -> keys
    end
  end

  defp read_key(state, level), do: get_in(state.keys, [level, :read])

  defp parse_protected_header(state, <<first, version::32, rest::binary>> = packet)
       when (first &&& 0x80) != 0 do
    if version != 1,
      do: {:error, :unsupported_version},
      else: parse_long_header(state, first, rest, packet)
  end

  defp parse_protected_header(state, <<first, _rest::binary>> = packet)
       when (first &&& 0x80) == 0 do
    dcid_len = byte_size(state.scid)
    pn_offset = 1 + dcid_len

    cond do
      byte_size(packet) < pn_offset + 4 + 16 ->
        {:error, :truncated_header}

      (first &&& 0x40) == 0 ->
        {:error, :invalid_header_fixed_bit}

      true ->
        {:ok,
         %{
           level: :application,
           space: :application,
           pn_offset: pn_offset,
           packet_length: byte_size(packet)
         }}
    end
  end

  defp parse_protected_header(_, _), do: {:error, :truncated_header}

  defp validate_unprotected_header(<<first, _rest::binary>>, :application) do
    cond do
      (first &&& 0x40) == 0 -> {:error, :invalid_header_fixed_bit}
      (first &&& 0x18) != 0 -> {:error, :invalid_header_reserved_bits}
      true -> :ok
    end
  end

  defp validate_unprotected_header(<<first, _rest::binary>>, level)
       when level in [:initial, :handshake] do
    cond do
      (first &&& 0x80) == 0 or (first &&& 0x40) == 0 ->
        {:error, :invalid_header_fixed_bit}

      (first &&& 0x0C) != 0 ->
        {:error, :invalid_header_reserved_bits}

      true ->
        :ok
    end
  end

  defp validate_unprotected_header(_, _), do: {:error, :truncated_header}

  defp parse_long_header(state, first, rest, packet) do
    type = first >>> 4 &&& 0x03

    with {:ok, dcid, rest} <- take_cid(rest),
         {:ok, scid, rest} <- take_cid(rest),
         :ok <- validate_cids(state, dcid, scid),
         {:ok, rest} <- maybe_skip_token(type, rest),
         {:ok, length, after_length} <- Codec.decode_varint(rest),
         true <- length >= 1 and byte_size(after_length) >= length,
         pn_offset <- byte_size(packet) - byte_size(after_length),
         {:ok, level} <- long_level(type) do
      {:ok,
       %{
         level: level,
         space: level,
         dcid: dcid,
         scid: scid,
         pn_offset: pn_offset,
         packet_length: pn_offset + length
       }}
    else
      false -> {:error, :truncated_packet}
      {:error, _} = error -> error
    end
  end

  defp take_cid(<<length, rest::binary>>) when length <= 20 and byte_size(rest) >= length,
    do: {:ok, binary_part(rest, 0, length), binary_part(rest, length, byte_size(rest) - length)}

  defp take_cid(_), do: {:error, :malformed_connection_id}

  defp maybe_skip_token(0, rest) do
    with {:ok, length, rest} <- Codec.decode_varint(rest), true <- byte_size(rest) >= length do
      {:ok, binary_part(rest, length, byte_size(rest) - length)}
    else
      false -> {:error, :truncated_token}
      error -> error
    end
  end

  defp maybe_skip_token(2, rest), do: {:ok, rest}
  defp maybe_skip_token(_, _), do: {:error, :unsupported_packet_type}

  defp long_level(0), do: {:ok, :initial}
  defp long_level(2), do: {:ok, :handshake}
  defp long_level(_), do: {:error, :unsupported_packet_type}

  defp validate_cids(state, dcid, scid) do
    valid_destinations =
      [state.scid, state.dcid, state.original_dcid, state.retry_scid]
      |> Enum.reject(&is_nil/1)

    if dcid in valid_destinations and byte_size(dcid) <= 20 and byte_size(scid) <= 20,
      do: :ok,
      else: {:error, :wrong_connection_id}
  end

  defp subtract_acknowledged_range(a, b, lo, hi) do
    if b <= lo or a >= hi do
      [{lo, hi}]
    else
      if(lo < a, do: [{lo, a}], else: []) ++ if b < hi, do: [{b, hi}], else: []
    end
  end

  defp schedule_reserved(state, emission, rest, before) do
    case protect_and_reserve(state, emission) do
      {:ok, state, effect} ->
        case do_schedule(
               %{state | pending: rest, queued: state.queued + 1},
               before
             ) do
          {:ok, state, effects} ->
            {:ok, state, [effect | effects]}

          {:error, reason, state} ->
            recovery = Recovery.abort_reservations_since(state.recovery, before)
            {:error, reason, %{state | recovery: recovery, queued: state.queued - 1}}
        end

      {:error, reason, state}
      when reason in [:congestion_limited, :sent_history_limit] ->
        {:ok, state, []}

      {:error, reason, state} ->
        {:error, reason, state}
    end
  end

  defp schedule_fragment(state, emission, rest, before) do
    if state.queued >= state.max_queue do
      if state.max_queue <= 0,
        do: {:error, :send_queue_limit, state},
        else: {:ok, state, []}
    else
      schedule_reserved(state, emission, rest, before)
    end
  end
end
