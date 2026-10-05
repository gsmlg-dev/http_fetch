defmodule HTTP.HTTP3.ReceiveBudget do
  @moduledoc "Finite receive windows reserve capacity for every admitted request and peer stream."
  @window 65_536

  def normalize(options) do
    concurrency = Keyword.get(options, :max_streams, 32)
    streams = Keyword.get(options, :streams, [])

    if is_integer(concurrency) and concurrency in 1..128 and Keyword.keyword?(streams) do
      result =
        case options[:endpoint] do
          nil ->
            owned(options, streams, concurrency)

          %QuicHttp3.Transport.Quic.Endpoint{streams: actual} when is_map(actual) ->
            borrowed(options, streams, concurrency, actual)

          _ ->
            {:error, :http3_endpoint_receive_budget_mismatch}
        end

      with {:ok, normalized} <- result do
        normalize_rotation(normalized, concurrency)
      end
    else
      {:error, :invalid_http3_receive_budget}
    end
  end

  defp normalize_rotation(options, concurrency) do
    actual = QuicHttp3.Transport.Quic.stream_budget(options[:streams])
    records = actual.max_local_stream_records
    rotation = Keyword.get(options, :rotation_after, min(960, records))

    cond do
      records < concurrency + 1 ->
        {:error, :http3_stream_record_budget_too_small}

      not is_integer(rotation) or rotation < 2 or rotation > records ->
        {:error, :http3_rotation_budget_mismatch}

      true ->
        {:ok, Keyword.put(options, :rotation_after, rotation)}
    end
  end

  defp owned(options, streams, concurrency) do
    streams =
      streams |> Keyword.put_new(:max_streams_bidi, 0) |> Keyword.put_new(:max_streams_uni, 3)

    request =
      Keyword.get(
        streams,
        :max_stream_data_bidi_local,
        Keyword.get(streams, :max_stream_data, @window)
      )

    uni =
      Keyword.get(streams, :max_stream_data_uni, Keyword.get(streams, :max_stream_data, @window))

    count = streams[:max_streams_uni]

    if valid_windows?(request, uni, count) and streams[:max_streams_bidi] == 0 and
         Enum.all?([:max_data, :max_buffer, :max_ready_bytes, :max_receive_buffer], fn key ->
           not Keyword.has_key?(streams, key) or (is_integer(streams[key]) and streams[key] > 0)
         end) do
      required = concurrency * request + count * uni

      streams =
        streams
        |> Keyword.put_new(:max_stream_data, @window)
        |> Keyword.put_new(:max_data, required)
        |> Keyword.put_new(:max_buffer, required)
        |> Keyword.put_new(:max_ready_bytes, Keyword.get(streams, :max_receive_buffer, required))
        |> Keyword.put(:delivery, :manual)

      actual = QuicHttp3.Transport.Quic.stream_budget(streams)

      if sufficient?(actual, concurrency),
        do: {:ok, Keyword.put(options, :streams, streams)},
        else: {:error, :http3_receive_budget_too_small}
    else
      {:error, :invalid_http3_receive_budget}
    end
  end

  defp borrowed(options, streams, concurrency, actual) do
    matching = streams == [] or QuicHttp3.Transport.Quic.stream_budget(streams) == actual

    if matching and sufficient?(actual, concurrency) do
      {:ok, Keyword.put(options, :streams, Enum.sort(Map.to_list(actual)))}
    else
      {:error, :http3_endpoint_receive_budget_mismatch}
    end
  end

  defp sufficient?(actual, concurrency) do
    request = actual[:max_stream_data_bidi_local]
    uni = actual[:max_stream_data_uni]
    count = actual[:max_streams_uni]

    capacity =
      Enum.all?(
        [
          :max_data,
          :max_buffer,
          :max_ready_bytes,
          :max_stream_records,
          :max_local_stream_records
        ],
        fn field ->
          is_integer(actual[field]) and actual[field] > 0
        end
      )

    capacity and valid_windows?(request, uni, count) and actual[:max_streams_bidi] == 0 and
      actual[:delivery] == :manual and
      Enum.all?([:max_data, :max_buffer, :max_ready_bytes], fn key ->
        is_integer(actual[key]) and actual[key] > 0
      end) and
      actual[:max_data] >= concurrency * request + count * uni and
      actual[:max_buffer] >= concurrency * request + count * uni and
      actual[:max_ready_bytes] >= concurrency * request + count * uni
  end

  defp valid_windows?(request, uni, count),
    do:
      is_integer(request) and request in 1..@window and is_integer(uni) and uni in 1..@window and
        is_integer(count) and count in 3..16
end
