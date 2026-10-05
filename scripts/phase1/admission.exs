defmodule Quic.Phase1.Admission do
  @moduledoc false
  @chunk 16_384
  @deadline 15_000

  def run(items, field, started, send_fun \\ &Quic.send_stream/4) do
    Enum.reduce(items, {[], nil, started, MapSet.new()}, fn {stream, bytes, final},
                                                            {acc, error, started, blocked} ->
      cond do
        not is_nil(error) or (bytes == <<>> and not final) ->
          {acc, error, started, blocked}

        MapSet.member?(blocked, stream.id) ->
          {acc ++ [{stream, bytes, final}], nil, started, blocked}

        true ->
          n = min(@chunk, byte_size(bytes))
          <<part::binary-size(^n), rest::binary>> = bytes
          bidi = Bitwise.band(stream.id, 2) == 0

          fin =
            final and rest == <<>> and (field != :sends or not bidi or MapSet.size(started) == 4)

          case send_fun.(stream, part, fin, deadline: @deadline) do
            {:ok, _} ->
              started =
                if field == :sends and bidi and part != <<>>,
                  do: MapSet.put(started, stream.id),
                  else: started

              remaining =
                if rest == <<>> and (not final or fin),
                  do: acc,
                  else: acc ++ [{stream, rest, final}]

              {remaining, nil, started, blocked}

            {:blocked, _} ->
              {acc ++ [{stream, bytes, final}], nil, started, MapSet.put(blocked, stream.id)}

            {:unknown, ref} ->
              {acc ++ [{stream, bytes, final}], {:unknown, ref}, started, blocked}

            {:error, reason} ->
              {acc ++ [{stream, bytes, final}], reason, started, blocked}
          end
      end
    end)
    |> then(fn {pending, error, started, _blocked} -> {pending, error, started} end)
  end
end
