defmodule HTTP.HTTP3.ReceiveBudget do
  @moduledoc """
  Finite receive windows reserve capacity for every admitted request and peer stream.

  With `webtransport: true` an owned endpoint also admits peer-initiated
  WebTransport streams: by default 16 bidirectional and 16 unidirectional
  streams beyond the three H3 control/QPACK streams, each reserved at its
  receive window. Ordinary HTTP/3 owners keep peer bidirectional streams at 0.
  """
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
    wt? = Keyword.get(options, :webtransport, false) == true

    streams =
      streams
      |> Keyword.put_new(:max_streams_bidi, if(wt?, do: 16, else: 0))
      |> Keyword.put_new(:max_streams_uni, if(wt?, do: 19, else: 3))

    request =
      Keyword.get(
        streams,
        :max_stream_data_bidi_local,
        Keyword.get(streams, :max_stream_data, @window)
      )

    uni =
      Keyword.get(streams, :max_stream_data_uni, Keyword.get(streams, :max_stream_data, @window))

    count = streams[:max_streams_uni]
    bidi = streams[:max_streams_bidi]

    remote =
      Keyword.get(
        streams,
        :max_stream_data_bidi_remote,
        Keyword.get(streams, :max_stream_data, @window)
      )

    if valid_windows?(request, uni, count, wt?) and valid_peer_bidi?(bidi, remote, wt?) and
         Enum.all?([:max_data, :max_buffer, :max_ready_bytes, :max_receive_buffer], fn key ->
           not Keyword.has_key?(streams, key) or (is_integer(streams[key]) and streams[key] > 0)
         end) do
      required = concurrency * request + count * uni + bidi * remote

      streams =
        streams
        |> Keyword.put_new(:max_stream_data, @window)
        |> Keyword.put_new(:max_data, required)
        |> Keyword.put_new(:max_buffer, required)
        |> Keyword.put_new(:max_ready_bytes, Keyword.get(streams, :max_receive_buffer, required))
        |> Keyword.put(:delivery, :manual)

      actual = QuicHttp3.Transport.Quic.stream_budget(streams)

      if sufficient?(actual, concurrency, wt?),
        do: {:ok, Keyword.put(options, :streams, streams)},
        else: {:error, :http3_receive_budget_too_small}
    else
      {:error, :invalid_http3_receive_budget}
    end
  end

  defp borrowed(options, streams, concurrency, actual) do
    matching = streams == [] or QuicHttp3.Transport.Quic.stream_budget(streams) == actual

    if matching and sufficient?(actual, concurrency, false) do
      {:ok, Keyword.put(options, :streams, Enum.sort(Map.to_list(actual)))}
    else
      {:error, :http3_endpoint_receive_budget_mismatch}
    end
  end

  defp sufficient?(actual, concurrency, wt?) do
    request = actual[:max_stream_data_bidi_local]
    uni = actual[:max_stream_data_uni]
    count = actual[:max_streams_uni]
    bidi = actual[:max_streams_bidi]
    remote = Map.get(actual, :max_stream_data_bidi_remote, request)
    required = concurrency * request + count * uni + bidi * remote

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

    capacity and valid_windows?(request, uni, count, wt?) and
      valid_peer_bidi?(bidi, remote, wt?) and
      actual[:delivery] == :manual and
      Enum.all?([:max_data, :max_buffer, :max_ready_bytes], fn key ->
        is_integer(actual[key]) and actual[key] > 0
      end) and
      actual[:max_data] >= required and
      actual[:max_buffer] >= required and
      actual[:max_ready_bytes] >= required
  end

  defp valid_windows?(request, uni, count, wt?),
    do:
      is_integer(request) and request in 1..@window and is_integer(uni) and uni in 1..@window and
        is_integer(count) and count in 3..if(wt?, do: 67, else: 16)

  defp valid_peer_bidi?(0, _remote, _wt?), do: true

  defp valid_peer_bidi?(bidi, remote, true),
    do: is_integer(bidi) and bidi in 1..64 and is_integer(remote) and remote in 1..@window

  defp valid_peer_bidi?(_bidi, _remote, _wt?), do: false
end
