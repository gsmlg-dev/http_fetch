defmodule Quic.Inspector do
  @moduledoc """
  Passive, bounded QUIC v1 Initial observation.

  `new/1` creates a flow table and `ingest/2` accepts a `Quic.Runtime.Datagram`
  (or an equivalent map containing `bytes`, `remote`, `generation` and
  `received_at`). It only emits observation maps; it never sends protocol
  packets or exposes TLS secrets. Each Initial key context has an independent
  packet-number reconstruction window and sparse CRYPTO interval store.
  """
  alias Quic.{Codec, Protection, Runtime}
  import Bitwise

  @default_limits [
    max_datagram: 65_535,
    max_intervals: 128,
    max_crypto_bytes: 131_072,
    max_hello_bytes: 65_539,
    max_contexts: 8,
    expiry: nil
  ]

  defstruct limits: Map.new(@default_limits), contexts: %{}, total_contexts: 0

  @type t :: %__MODULE__{}

  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(options \\ []) when is_list(options) do
    limits = Map.merge(Map.new(@default_limits), Map.new(options))

    if Enum.all?(limits, fn {_key, value} ->
         is_nil(value) or (is_integer(value) and value > 0)
       end),
       do: {:ok, %__MODULE__{limits: limits}},
       else: {:error, :invalid_limits}
  end

  @spec ingest(t(), Runtime.Datagram.t() | map()) :: {:ok, t(), [map()]} | {:error, term(), t()}
  def ingest(%__MODULE__{} = state, datagram) do
    with {:ok, bytes, flow, generation, received_at} <- metadata(datagram),
         :ok <- bound(:max_datagram, byte_size(bytes), state.limits),
         {:ok, state, events} <- expire(state, received_at),
         {:ok, packet, trailing} <- packet_bounds(bytes),
         {:ok, state, events2} <- decode_packet(state, packet, flow, generation, received_at) do
      if trailing == <<>>,
        do: {:ok, state, events ++ events2},
        else: {:ok, state, events ++ events2}
    else
      {:error, reason} -> {:error, reason, state}
      {:error, reason, next} -> {:error, reason, next}
    end
  end

  defp metadata(%Runtime.Datagram{
         bytes: bytes,
         remote: remote,
         generation: generation,
         received_at: at
       }),
       do: metadata(%{bytes: bytes, remote: remote, generation: generation, received_at: at})

  defp metadata(%{bytes: bytes, remote: remote, generation: generation, received_at: at})
       when is_binary(bytes) and is_integer(generation) and is_integer(at),
       do: {:ok, bytes, remote, generation, at}

  defp metadata(_), do: {:error, :invalid_datagram}

  defp packet_bounds(<<first, version::32, rest::binary>> = bytes) do
    if (first &&& 0x80) == 0 do
      {:error, :not_long_header}
    else
      if (first &&& 0x40) == 0 or (first >>> 4 &&& 3) != 0 do
        {:error, :not_initial}
      else
        with :ok <- if(version == 1, do: :ok, else: {:error, :unsupported_version}),
             {:ok, _dcid, rest} <- take_cid(rest),
             {:ok, _scid, rest} <- take_cid(rest),
             {:ok, token_len, rest} <- Codec.decode_varint(rest),
             true <- token_len <= byte_size(rest),
             <<_token::binary-size(^token_len), rest::binary>> <- rest,
             {:ok, length, rest} <- Codec.decode_varint(rest),
             true <- length <= byte_size(rest),
             true <- length >= 1 do
          packet_len = byte_size(bytes) - byte_size(rest) + length

          if packet_len <= byte_size(bytes) do
            {:ok, binary_part(bytes, 0, packet_len),
             binary_part(bytes, packet_len, byte_size(bytes) - packet_len)}
          else
            {:error, :truncated_payload}
          end
        else
          {:error, _} = error -> error
          _ -> {:error, :malformed_initial}
        end
      end
    end
  end

  defp packet_bounds(_), do: {:error, :truncated_header}

  defp decode_packet(state, packet, flow, generation, at) do
    <<_first, _version::32, rest::binary>> = packet

    with {:ok, dcid, rest} <- take_cid(rest),
         {:ok, scid, rest} <- take_cid(rest),
         {:ok, token_len, rest} <- Codec.decode_varint(rest),
         <<_token::binary-size(^token_len), rest::binary>> <- rest,
         {:ok, _length, rest} <- Codec.decode_varint(rest),
         pn_offset <- byte_size(packet) - byte_size(rest),
         context_key <- {flow, generation, dcid},
         {:ok, role, pn, frames} <- decrypt_frames(state, packet, pn_offset, context_key, dcid) do
      ctx =
        Map.get(state.contexts, {context_key, role}, %{
          largest: -1,
          intervals: [],
          crypto_bytes: 0,
          hellos: MapSet.new(),
          incomplete: MapSet.new(),
          last_seen: at,
          ordinal: 0,
          hello_cursor: 0
        })

      if not Map.has_key?(state.contexts, {context_key, role}) and
           map_size(state.contexts) >= state.limits.max_contexts do
        {:error, :resource_limited}
      else
        with {:ok, ctx, events} <-
               add_frames(ctx, frames, state.limits, %{
                 flow: flow,
                 generation: generation,
                 dcid: dcid,
                 scid: scid,
                 packet_number: pn,
                 key_context: {context_key, role},
                 at: at
               }) do
          contexts =
            Map.put(state.contexts, {context_key, role}, %{
              ctx
              | largest: max(ctx.largest, pn),
                last_seen: at
            })

          {:ok, %{state | contexts: contexts}, events}
        end
      end
    else
      {:error, :bad_tag} -> {:ok, state, []}
      {:error, _} = error -> error
      _ -> {:error, :malformed_packet}
    end
  end

  defp decrypt_frames(state, packet, pn_offset, context_key, dcid) do
    existing = Enum.find(state.contexts, fn {{ctx, _}, _} -> ctx == context_key end)

    roles =
      case existing do
        nil -> [:client, :server]
        {{_, role}, _} -> [role]
      end

    Enum.reduce_while(roles, {:error, :bad_tag}, fn role, _acc ->
      with {:ok, keys} <- Protection.initial_secrets(dcid, role),
           {:ok, unmasked, pn_len} <- unmask(packet, pn_offset, keys.hp),
           <<header::binary-size(^pn_offset), pn_bytes::binary-size(^pn_len), ciphertext::binary>> <-
             unmasked,
           truncated <- :binary.decode_unsigned(pn_bytes),
           largest <- if(existing, do: elem(existing, 1).largest, else: -1),
           {:ok, pn} <- reconstruct(truncated, largest, pn_len),
           {:ok, plaintext} <-
             Protection.aead_decrypt(keys.key, keys.iv, pn, header <> pn_bytes, ciphertext),
           {:ok, frames, <<>>} <-
             Codec.decode_frames(plaintext, max_frames: state.limits.max_intervals) do
        {:halt, {:ok, role, pn, frames}}
      else
        _ -> {:cont, {:error, :bad_tag}}
      end
    end)
  end

  defp unmask(packet, offset, hp) do
    case Protection.remove_header_protection(packet, offset, hp, :aes_128_gcm) do
      {:ok, packet, pn_len} -> {:ok, packet, pn_len}
      error -> error
    end
  end

  defp reconstruct(truncated, -1, _len), do: {:ok, truncated}

  defp reconstruct(truncated, largest, len),
    do: Codec.reconstruct_packet_number(truncated, largest, len)

  defp add_frames(ctx, frames, limits, provenance) do
    Enum.reduce_while(frames, {:ok, ctx, []}, fn
      %{type: :crypto, offset: offset, data: data}, {:ok, ctx, events} ->
        case insert(ctx, offset, data, limits) do
          {:ok, next} ->
            case observations(next, limits, provenance) do
              {:ok, observed, emitted} ->
                {:cont,
                 {:ok,
                  %{
                    observed
                    | hellos:
                        MapSet.union(
                          next.hellos,
                          emitted
                          |> Enum.flat_map(fn
                            %{hello_bytes: hello} -> [hello]
                            _ -> []
                          end)
                          |> MapSet.new()
                        )
                  }, events ++ emitted}}

              error ->
                {:halt, error}
            end

          error ->
            {:halt, error}
        end

      _, acc ->
        {:cont, acc}
    end)
  end

  defp insert(ctx, offset, data, limits) do
    cond do
      offset < 0 or byte_size(data) + ctx.crypto_bytes > limits.max_crypto_bytes ->
        {:error, :resource_limited}

      length(ctx.intervals) >= limits.max_intervals and data != <<>> ->
        {:error, :resource_limited}

      true ->
        if conflict?(ctx.intervals, offset, data),
          do: {:error, :conflicting_overlap},
          else: insert_merged(ctx, offset, data, limits)
    end
  end

  defp insert_merged(ctx, offset, data, limits) do
    ints = merge(ctx.intervals ++ [{offset, offset + byte_size(data), data}])
    bytes = Enum.reduce(ints, 0, fn {a, b, _}, n -> n + b - a end)

    if bytes > limits.max_crypto_bytes,
      do: {:error, :resource_limited},
      else: {:ok, %{ctx | intervals: ints, crypto_bytes: bytes}}
  end

  defp conflict?(_intervals, _offset, <<>>), do: false

  defp conflict?(intervals, offset, data) do
    Enum.any?(intervals, fn {start, finish, existing} ->
      left = max(start, offset)
      right = min(finish, offset + byte_size(data))

      if left < right do
        binary_part(existing, left - start, right - left) !=
          binary_part(data, left - offset, right - left)
      else
        false
      end
    end)
  end

  defp merge(intervals) do
    intervals
    |> Enum.sort_by(&elem(&1, 0))
    |> Enum.reduce([], fn {s, e, d}, acc ->
      case acc do
        [{ps, pe, pd} | rest] when s <= pe ->
          overlap = max(0, pe - s)

          tail =
            if byte_size(d) > overlap,
              do: binary_part(d, overlap, byte_size(d) - overlap),
              else: <<>>

          [{ps, max(pe, e), pd <> tail} | rest]

        _ ->
          [{s, e, d} | acc]
      end
    end)
    |> Enum.reverse()
  end

  defp observations(ctx, limits, provenance) do
    all = contiguous(ctx.intervals)

    binary =
      if byte_size(all) >= ctx.hello_cursor,
        do: binary_part(all, ctx.hello_cursor, byte_size(all) - ctx.hello_cursor),
        else: <<>>

    if byte_size(binary) < 4 do
      {:ok, ctx, []}
    else
      <<type, len::24, _::binary>> = binary

      cond do
        type != 1 ->
          {:ok, ctx, []}

        len > limits.max_hello_bytes ->
          {:error, :resource_limited}

        byte_size(binary) < 4 + len ->
          marker = {ctx.hello_cursor, len, byte_size(binary)}

          if MapSet.member?(ctx.incomplete, marker) do
            {:ok, ctx, []}
          else
            event = %{
              outcome: :incomplete,
              buffered_bytes: byte_size(binary),
              expected_bytes: 4 + len,
              provenance: provenance
            }

            {:ok, %{ctx | incomplete: MapSet.put(ctx.incomplete, marker)}, [event]}
          end

        true ->
          hello = binary_part(binary, 0, 4 + len)

          if MapSet.member?(ctx.hellos, hello) do
            {:ok, ctx, []}
          else
            observe_hello(hello, ctx, len, limits, provenance)
          end
      end
    end
  end

  defp contiguous([]), do: <<>>
  defp contiguous([{0, _e, d} | rest]), do: contiguous(rest, d, byte_size(d))
  defp contiguous(_), do: <<>>
  defp contiguous([{s, e, d} | rest], acc, pos) when s == pos, do: contiguous(rest, acc <> d, e)
  defp contiguous(_, acc, _), do: acc

  defp expire(state, now) do
    case state.limits.expiry do
      nil ->
        {:ok, state, []}

      ttl ->
        {:ok,
         %{
           state
           | contexts:
               Enum.filter(state.contexts, fn {_k, v} ->
                 Map.get(v, :last_seen, now) + ttl >= now
               end)
               |> Map.new()
         }, []}
    end
  end

  defp bound(key, value, limits),
    do: if(value <= limits[key], do: :ok, else: {:error, :resource_limited})

  defp take_cid(<<len, rest::binary>>) when len <= 20 and byte_size(rest) >= len,
    do: {:ok, binary_part(rest, 0, len), binary_part(rest, len, byte_size(rest) - len)}

  defp take_cid(_), do: {:error, :invalid_connection_id}

  defp observe_hello(hello, ctx, len, limits, provenance) do
    case SSL.Fingerprint.client_hello(hello, :quic) do
      {:ok, fp} ->
        event = %{
          outcome: :complete,
          hello_ordinal: ctx.ordinal + 1,
          hello_bytes: hello,
          fingerprint: fp,
          provenance: provenance
        }

        next = %{ctx | ordinal: ctx.ordinal + 1, hello_cursor: ctx.hello_cursor + 4 + len}

        with {:ok, final, more} <- observations(next, limits, provenance) do
          {:ok, final, [event | more]}
        end

      {:error, _} ->
        {:error, :malformed}
    end
  end
end
