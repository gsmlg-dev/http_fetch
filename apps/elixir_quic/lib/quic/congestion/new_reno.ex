defmodule Quic.Congestion.NewReno do
  @moduledoc """
  Pure RFC 9002-style NewReno congestion controller.

  Admission is reservation based: queued datagrams consume congestion credit until
  they are definitively failed, acknowledged, or declared lost.
  """

  defstruct cwnd: 0,
            ssthresh: :infinity,
            bytes_in_flight: 0,
            mss: 1200,
            max_datagram_size: 1200,
            acked_bytes: 0,
            recovery_start: nil

  @type t :: %__MODULE__{}

  @type initial_state :: %Quic.Congestion.NewReno{
          acked_bytes: 0,
          bytes_in_flight: 0,
          cwnd: term(),
          max_datagram_size: term(),
          mss: number(),
          recovery_start: nil,
          ssthresh: term()
        }

  @spec new(keyword()) :: initial_state()
  def new(opts \\ []) do
    mss = Keyword.get(opts, :mss, 1200)
    initial_cwnd = Keyword.get(opts, :initial_cwnd, min(10 * mss, max(2 * mss, 14_720)))

    %__MODULE__{
      cwnd: initial_cwnd,
      ssthresh: Keyword.get(opts, :ssthresh, :infinity),
      mss: mss,
      max_datagram_size: Keyword.get(opts, :max_datagram_size, mss)
    }
  end

  @spec available?(t(), non_neg_integer()) :: boolean()
  def available?(%__MODULE__{cwnd: cwnd, bytes_in_flight: flight}, bytes)
      when is_integer(bytes) and bytes >= 0,
      do: flight + bytes <= cwnd

  @spec reserve(t(), non_neg_integer()) :: {:ok, t()} | {:error, :congestion_limited}
  def reserve(state, bytes) when is_integer(bytes) and bytes >= 0 do
    if available?(state, bytes),
      do: {:ok, %{state | bytes_in_flight: state.bytes_in_flight + bytes}},
      else: {:error, :congestion_limited}
  end

  def reserve(_, _), do: {:error, :invalid_bytes}

  @spec release(t(), non_neg_integer()) :: t()
  def release(state, bytes) when is_integer(bytes) and bytes >= 0,
    do: %{state | bytes_in_flight: max(0, state.bytes_in_flight - bytes)}

  @doc """
  Acknowledge packets given as `{bytes, sent_at}` pairs.

  Packets sent before the current recovery period started release their flight
  but do not grow the window (RFC 9002 section 7.3.2).
  """
  @spec on_packets_acked(t(), [{non_neg_integer(), integer() | nil}]) :: t()
  def on_packets_acked(state, packets) when is_list(packets) do
    {total, growth} =
      Enum.reduce(packets, {0, 0}, fn {bytes, sent_at}, {total, growth} ->
        if in_recovery?(state, sent_at),
          do: {total + bytes, growth},
          else: {total + bytes, growth + bytes}
      end)

    state = on_ack(state, growth)
    %{state | bytes_in_flight: max(0, state.bytes_in_flight - (total - growth))}
  end

  @doc """
  Declare lost bytes whose newest packet was sent at `largest_sent_at`.

  The window is reduced at most once per recovery period: losses of packets
  sent before the period started at `now` only release their flight
  (RFC 9002 section 7.3.2).
  """
  @spec on_packets_lost(t(), non_neg_integer(), integer() | nil, integer()) :: t()
  def on_packets_lost(state, bytes, largest_sent_at, now)
      when is_integer(bytes) and bytes >= 0 and is_integer(now) do
    if in_recovery?(state, largest_sent_at) do
      %{state | bytes_in_flight: max(0, state.bytes_in_flight - bytes)}
    else
      %{on_loss(state, bytes) | recovery_start: now}
    end
  end

  defp in_recovery?(%__MODULE__{recovery_start: start}, sent_at),
    do: is_integer(start) and is_integer(sent_at) and sent_at <= start

  @spec on_ack(t(), non_neg_integer()) :: t()
  def on_ack(state, 0), do: state

  def on_ack(state, bytes) when is_integer(bytes) and bytes >= 0 do
    flight = max(0, state.bytes_in_flight - bytes)

    cwnd =
      if state.ssthresh == :infinity or state.cwnd < state.ssthresh do
        min(state.cwnd + bytes, state.cwnd + state.max_datagram_size * 10)
      else
        state.cwnd + max(1, div(state.max_datagram_size * bytes, max(1, state.cwnd)))
      end

    %{state | bytes_in_flight: flight, cwnd: cwnd, acked_bytes: state.acked_bytes + bytes}
  end

  @spec on_loss(t(), non_neg_integer()) :: t()
  def on_loss(state, bytes) when is_integer(bytes) and bytes >= 0 do
    cwnd = max(2 * state.max_datagram_size, div(state.cwnd, 2))
    %{state | bytes_in_flight: max(0, state.bytes_in_flight - bytes), cwnd: cwnd, ssthresh: cwnd}
  end

  @spec pacing_delay(t(), non_neg_integer()) :: non_neg_integer()
  def pacing_delay(%__MODULE__{cwnd: cwnd, max_datagram_size: mss}, rtt_us)
      when is_integer(rtt_us) and rtt_us >= 0 do
    div(max(0, rtt_us) * mss, max(1, cwnd))
  end
end
