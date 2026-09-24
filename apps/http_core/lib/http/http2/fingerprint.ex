defmodule HTTP.HTTP2.Fingerprint do
  @moduledoc "Bounded, redacted observation and comparison of HTTP/2 wire bytes."

  alias HTTP.HTTP2.{Frame, HPACK}

  @preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

  @spec observe(binary(), keyword()) :: {:ok, map()} | {:error, term()}
  def observe(bytes, opts \\ []) when is_binary(bytes) do
    capture? = Keyword.get(opts, :raw_capture, false)
    max_raw = min(Keyword.get(opts, :max_raw_bytes, 65_536), 65_536)

    with {preface?, rest} <- split_preface(bytes),
         {:ok, frames} <- decode_frames(rest, []) do
      {settings, window_updates, priorities, headers, fragments} = summarize_frames(frames)

      observation = %{
        version: 1,
        source: :peer_observed,
        preface: preface?,
        frames: Enum.map(frames, &frame_summary/1),
        settings: settings,
        initial_window_updates: window_updates,
        priorities: priorities,
        headers: headers,
        continuation_fragments: fragments,
        summary: projection(settings, window_updates, priorities, headers, frames),
        raw: if(capture?, do: binary_part(bytes, 0, min(byte_size(bytes), max_raw)), else: nil)
      }

      {:ok, observation}
    end
  end

  @spec diff(map(), map()) :: map()
  def diff(left, right) do
    keys =
      (Map.keys(left) ++ Map.keys(right)) |> Enum.uniq() |> Enum.reject(&(&1 in [:raw, :summary]))

    %{
      version: 1,
      equal?: Enum.all?(keys, &(Map.get(left, &1) == Map.get(right, &1))),
      changes:
        Enum.reduce(keys, %{}, fn key, acc ->
          a = Map.get(left, key)
          b = Map.get(right, key)

          if a == b,
            do: acc,
            else: Map.put(acc, key, %{left: redact(key, a), right: redact(key, b)})
        end)
    }
  end

  @spec summarize(map()) :: map()
  def summarize(%{summary: summary}), do: summary

  defp split_preface(<<@preface, rest::binary>>), do: {true, rest}
  defp split_preface(bytes), do: {false, bytes}

  defp decode_frames(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_frames(bytes, acc) do
    case Frame.decode(bytes) do
      {:ok, frame, rest} -> decode_frames(rest, [frame | acc])
      :more -> {:error, :truncated_frame}
    end
  end

  defp summarize_frames(frames) do
    settings =
      Enum.flat_map(frames, fn
        %Frame{type: :settings, payload: payload} -> parse_settings(payload)
        _ -> []
      end)

    windows =
      Enum.flat_map(frames, fn
        %Frame{type: :window_update, stream_id: id, payload: <<0::1, increment::31>>} ->
          [{id, increment}]

        _ ->
          []
      end)

    priorities =
      Enum.filter(frames, &(&1.type in [:priority, :priority_update]))
      |> Enum.map(&frame_summary/1)

    {headers, fragments} = collect_headers(frames)
    {settings, windows, priorities, headers, fragments}
  end

  defp collect_headers(frames) do
    {headers, fragments, _decoder, _pending} =
      Enum.reduce(frames, {[], [], HPACK.new_decoder(), nil}, fn frame,
                                                                 {headers, fragments, decoder,
                                                                  pending} ->
        cond do
          frame.type == :headers ->
            if Frame.flag?(frame.flags, 0x4),
              do: decode_header(frame.payload, headers, decoder, fragments),
              else: {headers, [byte_size(frame.payload) | fragments], decoder, frame.payload}

          frame.type == :continuation and is_binary(pending) ->
            block = pending <> frame.payload

            if Frame.flag?(frame.flags, 0x4),
              do: decode_header(block, headers, decoder, fragments),
              else: {headers, [byte_size(frame.payload) | fragments], decoder, block}

          true ->
            {headers, fragments, decoder, pending}
        end
      end)

    {Enum.reverse(headers), Enum.reverse(fragments)}
  end

  defp decode_header(block, headers, decoder, fragments) do
    case HPACK.decode(decoder, block) do
      {:ok, decoder, values} ->
        {[Enum.map(values, &redact_header/1) | headers], fragments, decoder, nil}

      _ ->
        {headers, fragments, decoder, nil}
    end
  end

  defp redact_header({name, _value}) when name in ["authorization", "cookie", "set-cookie"],
    do: {name, "[REDACTED]"}

  defp redact_header(header), do: header

  defp redact(:headers, value),
    do:
      Enum.map(
        value || [],
        &Enum.map(&1, fn {name, v} ->
          if v == "[REDACTED]", do: {name, v}, else: {name, "[REDACTED]"}
        end)
      )

  defp redact(_key, value), do: value

  defp parse_settings(payload) when rem(byte_size(payload), 6) == 0,
    do: for(<<id::16, value::32 <- payload>>, do: {id, value})

  defp parse_settings(_), do: []

  defp frame_summary(%Frame{type: type, flags: flags, stream_id: stream_id, payload: payload}),
    do: %{type: type, flags: flags, stream_id: stream_id, length: byte_size(payload)}

  defp projection(settings, windows, priorities, headers, frames),
    do: %{
      projection_version: 1,
      settings: settings,
      windows: windows,
      priority_types: Enum.map(priorities, & &1.type),
      header_names: Enum.map(List.flatten(headers), &elem(&1, 0)),
      frame_types: Enum.map(frames, & &1.type)
    }
end
