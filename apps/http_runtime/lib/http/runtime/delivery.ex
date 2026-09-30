defmodule HTTP.Runtime.Delivery do
  @moduledoc """
  Finite application delivery state shared by stream adapters. Acknowledged mode
  charges the single in-flight delivery and its FIFO until opaque settlement.
  Legacy mode retains the established envelope and applies a conservative owner
  mailbox overload policy; it cannot bound unrelated producers in that mailbox.
  """

  def new(options) do
    options = if is_struct(options), do: Map.from_struct(options), else: Map.new(options)

    %{
      mode: Map.get(options, :delivery, :legacy),
      max_bytes: Map.get(options, :max_queue_bytes, 2_097_152),
      max_events: Map.get(options, :max_queue_events, 64),
      bytes: 0,
      events: 0,
      inflight: nil,
      queue: :queue.new()
    }
  end

  def push(%{mode: :legacy} = state, event, bytes, owner) do
    case Process.info(owner, :message_queue_len) do
      {:message_queue_len, count} when count < state.max_events and bytes <= state.max_bytes ->
        {:ok, state, [{event, nil}]}

      _ ->
        {:error, :consumer_overloaded}
    end
  end

  def push(state, event, bytes, _owner) do
    if state.events >= state.max_events or state.bytes + bytes > state.max_bytes do
      {:error, :consumer_overloaded}
    else
      state = %{state | bytes: state.bytes + bytes, events: state.events + 1}
      admit(state, event, bytes)
    end
  end

  def acknowledge(%{inflight: {ref, bytes}} = state, ref) do
    state = %{state | bytes: state.bytes - bytes, events: state.events - 1, inflight: nil}

    case :queue.out(state.queue) do
      {{:value, {event, next_bytes}}, rest} -> admit(%{state | queue: rest}, event, next_bytes)
      {:empty, _} -> {:ok, state, []}
    end
  end

  def acknowledge(state, _ref), do: {:ok, state, []}

  def status(state),
    do: %{
      queued_bytes: state.bytes,
      queued_events: state.events,
      inflight?: state.inflight != nil
    }

  def paused?(state), do: state.mode == :ack and state.inflight != nil
  def clear(state), do: %{state | bytes: 0, events: 0, inflight: nil, queue: :queue.new()}

  defp admit(%{inflight: nil} = state, event, bytes) do
    ref = make_ref()
    {:ok, %{state | inflight: {ref, bytes}}, [{event, ref}]}
  end

  defp admit(state, event, bytes),
    do: {:ok, %{state | queue: :queue.in({event, bytes}, state.queue)}, []}
end
