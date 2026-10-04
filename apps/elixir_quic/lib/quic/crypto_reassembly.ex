defmodule Quic.CryptoReassembly do
  @moduledoc """
  Bounded sparse storage for one QUIC CRYPTO stream.

  Offsets are absolute and the store never allocates a buffer proportional to a
  future offset.  Overlapping bytes must agree; once bytes are delivered they
  are removed and cannot be delivered twice.
  """

  defstruct intervals: [], next: 0, buffered_bytes: 0, max_bytes: 262_144, max_intervals: 256

  @type t :: %__MODULE__{}

  @type initial_state :: %Quic.CryptoReassembly{
          buffered_bytes: 0,
          intervals: [],
          max_bytes: term(),
          max_intervals: term(),
          next: 0
        }

  @spec new(keyword()) :: initial_state()
  def new(opts \\ []) do
    %__MODULE__{
      max_bytes: Keyword.get(opts, :max_bytes, 262_144),
      max_intervals: Keyword.get(opts, :max_intervals, 256)
    }
  end

  @doc "Insert a sparse range and return newly contiguous bytes, if any."
  @spec put(t(), non_neg_integer(), binary()) ::
          {:ok, t(), binary()} | {:error, atom()}
  def put(%__MODULE__{} = state, offset, bytes)
      when is_integer(offset) and offset >= 0 and is_binary(bytes) do
    if bytes == <<>> do
      {:ok, state, <<>>}
    else
      end_offset = offset + byte_size(bytes)

      if end_offset <= state.next do
        {:ok, state, <<>>}
      else
        {offset, bytes} =
          if offset < state.next do
            trim = state.next - offset
            {state.next, binary_part(bytes, trim, byte_size(bytes) - trim)}
          else
            {offset, bytes}
          end

        with :ok <- validate_overlaps(state.intervals, offset, bytes) do
          new_bytes = uncovered_bytes(state.intervals, offset, offset + byte_size(bytes))
          intervals = insert_and_merge(state.intervals, offset, bytes)

          cond do
            state.buffered_bytes + new_bytes > state.max_bytes ->
              {:error, :crypto_buffer_limit}

            length(intervals) > state.max_intervals ->
              {:error, :crypto_interval_limit}

            true ->
              next_state = %{
                state
                | intervals: intervals,
                  buffered_bytes: state.buffered_bytes + new_bytes
              }

              {next_state, contiguous} = take_contiguous(next_state, <<>>)
              {:ok, next_state, contiguous}
          end
        end
      end
    end
  end

  def put(_, _, _), do: {:error, :invalid_crypto_range}

  @spec buffered_bytes(t()) :: non_neg_integer()
  def buffered_bytes(%__MODULE__{buffered_bytes: bytes}), do: bytes

  @spec next_offset(t()) :: non_neg_integer()
  def next_offset(%__MODULE__{next: next}), do: next

  @spec intervals(t()) :: [{non_neg_integer(), binary()}]
  def intervals(%__MODULE__{intervals: intervals}), do: intervals

  defp validate_overlaps(intervals, offset, bytes) do
    Enum.reduce_while(intervals, :ok, fn {start, existing}, :ok ->
      finish = start + byte_size(existing)
      overlap_start = max(start, offset)
      overlap_end = min(finish, offset + byte_size(bytes))

      if overlap_start < overlap_end do
        left = binary_part(existing, overlap_start - start, overlap_end - overlap_start)
        right = binary_part(bytes, overlap_start - offset, overlap_end - overlap_start)
        if left == right, do: {:cont, :ok}, else: {:halt, {:error, :conflicting_overlap}}
      else
        {:cont, :ok}
      end
    end)
  end

  defp uncovered_bytes(intervals, offset, finish) do
    covered =
      Enum.reduce(intervals, 0, fn {start, bytes}, total ->
        max(total, 0) + overlap_size(start, start + byte_size(bytes), offset, finish)
      end)

    # Intervals are non-overlapping, so the sum above is exact despite the
    # intentionally simple implementation.
    max(finish - offset - covered, 0)
  end

  defp overlap_size(a, b, c, d), do: max(min(b, d) - max(a, c), 0)

  defp insert_and_merge(intervals, offset, bytes) do
    (intervals ++ [{offset, bytes}])
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.reduce([], fn {start, data}, acc ->
      case acc do
        [{last_start, last_data} | rest] when last_start + byte_size(last_data) >= start ->
          last_end = last_start + byte_size(last_data)
          data_start = max(last_end - start, 0)

          suffix =
            if data_start < byte_size(data),
              do: binary_part(data, data_start, byte_size(data) - data_start),
              else: <<>>

          [{last_start, last_data <> suffix} | rest]

        _ ->
          [{start, data} | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp take_contiguous(%__MODULE__{intervals: [{start, bytes} | rest], next: next} = state, acc)
       when start == next do
    finish = next + byte_size(bytes)

    take_contiguous(
      %{
        state
        | intervals: rest,
          next: finish,
          buffered_bytes: state.buffered_bytes - byte_size(bytes)
      },
      acc <> bytes
    )
  end

  defp take_contiguous(state, acc), do: {state, acc}
end
