defmodule Quic.EarlyData do
  @moduledoc "Bounded, endpoint-owned admission for opt-in early transport data."
  alias Quic.TransportParameters
  @stream_bytes 65_536
  @datagram_bytes 65_536
  @payload_bytes 8_388_608
  @staging_bytes 1_048_576
  defstruct reservations: %{}, staging: MapSet.new()

  def policy(nil, _), do: {:ok, nil}
  def policy(false, _), do: {:ok, nil}

  def policy(opts, resumption) when is_list(opts) and not is_nil(resumption) do
    if Keyword.keyword?(opts) and Keyword.get(opts, :enabled) == true and
         is_binary(Keyword.get(opts, :application_profile)) and
         byte_size(Keyword.get(opts, :application_profile)) in 1..128,
       do: {:ok, %{profile: Keyword.fetch!(opts, :application_profile)}},
       else: {:error, :invalid_early_data_policy}
  end

  def policy(_, _), do: {:error, :early_data_requires_resumption}

  def cap_streams(opts) do
    for {name, limit} <- [
          max_data: @stream_bytes,
          max_stream_data: @stream_bytes,
          max_stream_data_bidi_local: @stream_bytes,
          max_stream_data_bidi_remote: @stream_bytes,
          max_stream_data_uni: @stream_bytes,
          max_streams_bidi: 8,
          max_streams_uni: 8
        ],
        reduce: opts do
      acc -> Keyword.put(acc, name, min(Keyword.get(opts, name, limit), limit))
    end
  end

  def reserve_staging(state, owner) do
    if MapSet.size(state.staging) * 32_768 < @staging_bytes do
      {%{state | staging: MapSet.put(state.staging, owner)}, 32_768}
    else
      {state, 0}
    end
  end

  def release_staging(state, owner), do: %{state | staging: MapSet.delete(state.staging, owner)}

  def reserve(state, owner, remembered, current) do
    with {:ok, old} <- TransportParameters.decode(remembered),
         {:ok, fresh} <- TransportParameters.decode(current),
         :ok <- compatible(old.values, fresh.values) do
      bytes =
        Map.get(old.values, :initial_max_data, 0) +
          if(Map.get(old.values, :max_datagram_frame_size, 0) > 0, do: @datagram_bytes, else: 0)

      used = Enum.sum(Map.values(state.reservations))

      if not Map.has_key?(state.reservations, owner) and used + bytes <= @payload_bytes,
        do: {:ok, %{state | reservations: Map.put(state.reservations, owner, bytes)}},
        else: {:error, :early_capacity}
    end
  end

  def compatible(old, fresh) do
    limits = [
      initial_max_data: @stream_bytes,
      initial_max_stream_data_bidi_local: @stream_bytes,
      initial_max_stream_data_bidi_remote: @stream_bytes,
      initial_max_stream_data_uni: @stream_bytes,
      initial_max_streams_bidi: 8,
      initial_max_streams_uni: 8,
      max_datagram_frame_size: 4_611_686_018_427_387_903,
      active_connection_id_limit: 8
    ]

    compatible_limits =
      Enum.all?(limits, fn {key, cap} ->
        previous = Map.get(old, key, 0)
        previous <= cap and previous <= Map.get(fresh, key, 0)
      end)

    if compatible_limits and
         (not Map.get(old, :reset_stream_at, false) or Map.get(fresh, :reset_stream_at, false)),
       do: :ok,
       else: {:error, :remembered_transport_limits}
  end

  def release(state, owner) do
    %{release_staging(state, owner) | reservations: Map.delete(state.reservations, owner)}
  end

  def stats(state),
    do: %{
      payload_reserved: Enum.sum(Map.values(state.reservations)),
      staging_reserved: MapSet.size(state.staging) * 32_768
    }
end
