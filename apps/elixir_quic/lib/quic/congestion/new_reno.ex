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
            acked_bytes: 0

  @type t :: %__MODULE__{}

  @type initial_state :: %Quic.Congestion.NewReno{
          acked_bytes: 0,
          bytes_in_flight: 0,
          cwnd: term(),
          max_datagram_size: term(),
          mss: number(),
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
