defmodule QuicHttp3.WebTransportRouter do
  @moduledoc """
  Pure, bounded single-session draft-17 association and delivery-credit primitive.

  This module performs no transport IO and enables no capability. Its owner must
  validate negotiated requirements before register/2, execute returned reset
  actions through reliable-prefix-aware transport operations, and include these
  retained bytes in its total application budget. Events are exposed only after
  accept/2 and retain credit until acknowledge/2. Unknown acknowledgements fail.
  """
  alias HTTP.H3.{Datagram, WebTransport.Draft17}
  @buffered_rejected 0x3994BD84
  @session_gone 0x170D7B68

  defstruct session_id: nil,
            phase: :new,
            streams: %{},
            pending: [],
            outstanding: %{},
            retained_bytes: 0,
            max_bytes: 262_144,
            max_items: 128,
            max_streams: 32,
            max_datagram_bytes: 1200

  def new(opts \\ []) do
    state = struct!(__MODULE__, opts)

    if Enum.all?(
         [state.max_bytes, state.max_items, state.max_streams, state.max_datagram_bytes],
         &(is_integer(&1) and &1 > 0)
       ) and state.max_bytes <= 262_144,
       do: {:ok, state},
       else: {:error, :invalid_router_limits}
  end

  def register(%{phase: :new} = state, id) do
    if Draft17.valid_session_id?(id),
      do: {:ok, %{state | session_id: id, phase: :pending}},
      else: {:error, :invalid_session_id}
  end

  def register(_, _), do: {:error, :session_capacity}

  def accept(%{phase: :pending, session_id: id} = state, id),
    do: {:ok, %{state | phase: :accepted, pending: []}, state.pending}

  def accept(_, _), do: {:error, :unknown_session}

  def close(%{session_id: id, phase: phase} = state, id) when phase in [:pending, :accepted] do
    actions = Enum.map(state.streams, fn {key, _} -> {:reset, key, @session_gone} end)

    {:ok,
     %{state | phase: :closed, streams: %{}, pending: [], outstanding: %{}, retained_bytes: 0},
     actions}
  end

  def close(%{session_id: id, phase: :closed} = state, id), do: {:ok, state, []}
  def close(_, _), do: {:error, :unknown_session}

  def acknowledge(state, receipt) do
    case Map.pop(state.outstanding, receipt) do
      {nil, _} ->
        {:error, :unknown_receipt}

      {size, rest} ->
        {:ok, %{state | outstanding: rest, retained_bytes: state.retained_bytes - size}}
    end
  end

  def stream_data(state, key, kind, bytes, fin)
      when kind in [:uni, :bidi] and is_binary(bytes) and is_boolean(fin) do
    stream = state.streams[key]

    cond do
      state.phase not in [:pending, :accepted] ->
        {:ok, state, [{:reset, key, @session_gone}]}

      stream == nil and map_size(state.streams) >= state.max_streams ->
        {:ok, state, [{:reset, key, @buffered_rejected}]}

      stream && stream.kind != kind ->
        {:error, :stream_direction_changed}

      stream && stream.fin? ->
        {:error, :data_after_fin}

      stream && stream.id != nil ->
        deliver_stream(state, key, stream, bytes, fin)

      true ->
        identify_stream(
          state,
          key,
          stream || %{kind: kind, id: nil, prefix: <<>>, fin?: false},
          bytes,
          fin
        )
    end
  end

  def datagram(%{phase: phase} = state, bytes) when phase in [:pending, :accepted] do
    case Datagram.decode(bytes, state.max_datagram_bytes) do
      {:ok, id, payload} when id == state.session_id ->
        retain(state, {:datagram, id, payload}, byte_size(payload), :drop)

      {:ok, _, _} ->
        {:ok, state, []}

      error ->
        error
    end
  end

  def datagram(state, _), do: {:ok, state, []}

  defp identify_stream(state, key, stream, bytes, fin) do
    input = stream.prefix <> bytes
    base = %{state | retained_bytes: state.retained_bytes - byte_size(stream.prefix)}

    case Draft17.decode_prefix(stream.kind, input) do
      :more when not fin ->
        if base.retained_bytes + byte_size(input) <= state.max_bytes do
          stream = %{stream | prefix: :binary.copy(input)}

          {:ok,
           %{
             base
             | streams: Map.put(base.streams, key, stream),
               retained_bytes: base.retained_bytes + byte_size(input)
           }, []}
        else
          reject_stream(base, key)
        end

      :more ->
        {:error, :truncated_webtransport_prefix}

      {:ok, id, payload} when id == state.session_id ->
        deliver_stream(base, key, %{stream | id: id, prefix: <<>>}, payload, fin)

      {:ok, _, _} ->
        reject_stream(base, key)

      error ->
        error
    end
  end

  defp deliver_stream(state, key, stream, bytes, fin) do
    next = %{state | streams: Map.put(state.streams, key, %{stream | fin?: fin})}

    retain(
      next,
      {:stream, stream.id, key, stream.kind, :binary.copy(bytes), fin},
      byte_size(bytes),
      {:reset, key}
    )
  end

  defp retain(state, event, size, overflow) do
    if state.retained_bytes + size > state.max_bytes or
         map_size(state.outstanding) >= state.max_items do
      case overflow do
        :drop -> {:ok, state, []}
        {:reset, key} -> reject_stream(state, key)
      end
    else
      receipt = make_ref()
      delivery = {receipt, event}

      next = %{
        state
        | outstanding: Map.put(state.outstanding, receipt, size),
          retained_bytes: state.retained_bytes + size
      }

      if state.phase == :accepted,
        do: {:ok, next, [delivery]},
        else: {:ok, %{next | pending: next.pending ++ [delivery]}, []}
    end
  end

  defp reject_stream(state, key) do
    # Previously retained events remain charged until their consumer receipt;
    # stream rejection never frees bytes still exposed to a subscriber.
    {:ok, %{state | streams: Map.delete(state.streams, key)}, [{:reset, key, @buffered_rejected}]}
  end
end
