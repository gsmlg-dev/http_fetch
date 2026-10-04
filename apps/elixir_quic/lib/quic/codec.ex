defmodule Quic.Codec do
  @moduledoc """
  Bounded QUIC v1 wire helpers.
  """
  import Bitwise

  @max_varint 0x3FFFFFFFFFFFFFFF
  @version 1

  @spec encode_varint(non_neg_integer()) :: {:ok, binary()} | {:error, :varint_overflow}
  def encode_varint(value) when is_integer(value) and value >= 0 and value <= @max_varint do
    cond do
      value < 1 <<< 6 -> {:ok, <<value>>}
      value < 1 <<< 14 -> {:ok, <<1::2, value::14>>}
      value < 1 <<< 30 -> {:ok, <<2::2, value::30>>}
      true -> {:ok, <<3::2, value::62>>}
    end
  end

  def encode_varint(_), do: {:error, :varint_overflow}

  @spec decode_varint(binary()) :: {:ok, non_neg_integer(), binary()} | {:error, atom()}
  def decode_varint(<<prefix, rest::binary>>) do
    bytes = 1 <<< (prefix >>> 6)
    value = prefix &&& 0x3F

    if byte_size(rest) < bytes - 1 do
      {:error, :truncated_varint}
    else
      tail_size = bytes - 1
      <<tail::binary-size(^tail_size), remainder::binary>> = rest
      {:ok, (value <<< (8 * (bytes - 1))) + :binary.decode_unsigned(tail), remainder}
    end
  end

  def decode_varint(_), do: {:error, :truncated_varint}

  @spec reconstruct_packet_number(non_neg_integer(), non_neg_integer(), pos_integer()) ::
          {:ok, non_neg_integer()} | {:error, atom()}
  def reconstruct_packet_number(truncated, largest, pn_len)
      when pn_len in [1, 2, 3, 4] and truncated >= 0 and truncated < 1 <<< (pn_len * 8) and
             largest >= 0 do
    expected = largest + 1
    window = 1 <<< (pn_len * 8)
    half = div(window, 2)
    candidate = (expected &&& bnot(window - 1)) ||| truncated

    candidate =
      cond do
        candidate + half <= expected -> candidate + window
        candidate > expected + half and candidate >= window -> candidate - window
        true -> candidate
      end

    {:ok, candidate}
  end

  def reconstruct_packet_number(_, _, _), do: {:error, :invalid_packet_number}

  @spec build_initial(map()) :: {:ok, binary()} | {:error, atom()}
  def build_initial(
        %{
          dcid: dcid,
          scid: scid,
          packet_number: pn,
          packet_number_length: pn_len,
          payload: payload
        } = fields
      )
      when is_binary(dcid) and is_binary(scid) and is_binary(payload) and byte_size(dcid) <= 20 and
             byte_size(scid) <= 20 and pn_len in [1, 2, 3, 4] and pn >= 0 and
             pn < 1 <<< (pn_len * 8) do
    token = Map.get(fields, :token, <<>>)
    version = Map.get(fields, :version, @version)

    with :ok <- valid_bytes(token, 0xFFFF),
         :ok <- valid_version(version),
         {:ok, token_len} <- encode_varint(byte_size(token)),
         {:ok, length} <- encode_varint(byte_size(payload) + pn_len),
         true <- byte_size(dcid) <= 255 and byte_size(scid) <= 255 do
      first = 0xC0 ||| 0 <<< 4 ||| pn_len - 1

      {:ok,
       <<first, version::32, byte_size(dcid), dcid::binary, byte_size(scid), scid::binary,
         token_len::binary, token::binary, length::binary,
         pn::unsigned-big-integer-size(pn_len * 8), payload::binary>>}
    else
      false -> {:error, :connection_id_too_long}
      error -> error
    end
  end

  def build_initial(_), do: {:error, :invalid_initial_fields}

  @spec parse_initial(binary()) :: {:ok, map()} | {:error, atom()}
  def parse_initial(<<first, version::32, rest::binary>> = packet) do
    with :ok <- validate_initial_first(first),
         :ok <- valid_version(version),
         {:ok, dcid, rest} <- take_cid(rest),
         {:ok, scid, rest} <- take_cid(rest),
         {:ok, token_len, rest} <- decode_varint(rest),
         :ok <- bound_length(token_len, byte_size(rest)),
         <<token::binary-size(^token_len), rest::binary>> <- rest,
         {:ok, length, rest} <- decode_varint(rest),
         :ok <- bound_length(length, byte_size(rest)),
         true <- length >= 1 do
      <<pn_and_payload::binary-size(^length), trailing::binary>> = rest
      pn_len = (first &&& 3) + 1

      if byte_size(pn_and_payload) < pn_len do
        {:error, :truncated_packet_number}
      else
        <<pn_bytes::binary-size(^pn_len), payload::binary>> = pn_and_payload

        {:ok,
         %{
           type: :initial,
           version: version,
           dcid: dcid,
           scid: scid,
           token: token,
           packet_number_length: pn_len,
           packet_number_bytes: pn_bytes,
           packet_number: :binary.decode_unsigned(pn_bytes),
           payload: payload,
           packet_length: byte_size(packet) - byte_size(trailing),
           trailing: trailing
         }}
      end
    else
      {:error, _} = error -> error
      _ -> {:error, :malformed_initial}
    end
  end

  def parse_initial(_), do: {:error, :truncated_header}

  @spec split_datagram(binary()) :: {:ok, [binary()]} | {:error, atom()}
  def split_datagram(datagram), do: split_datagram(datagram, [])

  defp split_datagram(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp split_datagram(data, acc) do
    case parse_initial(data) do
      {:ok, %{packet_length: length}} ->
        <<packet::binary-size(^length), rest::binary>> = data
        split_datagram(rest, [packet | acc])

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec encode_frames([map()]) :: {:ok, binary()} | {:error, atom()}
  def encode_frames(frames) when is_list(frames), do: encode_frames(frames, [])
  def encode_frames(_), do: {:error, :invalid_frames}

  defp encode_frames([], acc), do: {:ok, IO.iodata_to_binary(Enum.reverse(acc))}
  defp encode_frames([%{type: :ping} | rest], acc), do: encode_frames(rest, [<<1>> | acc])

  defp encode_frames([%{type: :crypto, offset: offset, data: data} | rest], acc)
       when is_integer(offset) and offset >= 0 and is_binary(data) do
    with {:ok, o} <- encode_varint(offset), {:ok, l} <- encode_varint(byte_size(data)) do
      encode_frames(rest, [data, l, o, <<6>> | acc])
    end
  end

  defp encode_frames(
         [%{type: :ack, largest: largest, delay: delay, ranges: ranges} = frame | rest],
         acc
       )
       when is_integer(largest) and is_integer(delay) and is_list(ranges) do
    with {:ok, a} <- encode_varint(largest),
         {:ok, d} <- encode_varint(delay),
         {:ok, encoded} <- encode_ack_ranges(largest, ranges) do
      case encode_ecn(frame[:ecn]) do
        {:ok, ecn, type} -> encode_frames(rest, [ecn, encoded, d, a, <<type>> | acc])
        {:error, _} = error -> error
      end
    end
  end

  defp encode_frames(
         [
           %{type: :connection_close, error_code: code, frame_type: frame_type, reason: reason}
           | rest
         ],
         acc
       )
       when is_integer(code) and is_integer(frame_type) and is_binary(reason) do
    with :ok <- bounded_reason_length(byte_size(reason)),
         {:ok, c} <- encode_varint(code),
         {:ok, f} <- encode_varint(frame_type),
         {:ok, l} <- encode_varint(byte_size(reason)) do
      encode_frames(rest, [reason, l, f, c, <<0x1C>> | acc])
    end
  end

  defp encode_frames([%{type: :application_close, error_code: code, reason: reason} | rest], acc)
       when is_integer(code) and is_binary(reason) do
    with :ok <- bounded_reason_length(byte_size(reason)),
         {:ok, c} <- encode_varint(code),
         {:ok, l} <- encode_varint(byte_size(reason)) do
      encode_frames(rest, [reason, l, c, <<0x1D>> | acc])
    end
  end

  defp encode_frames([%{type: :handshake_done} | rest], acc),
    do: encode_frames(rest, [<<0x1E>> | acc])

  defp encode_frames([%{type: :datagram, data: data} | rest], acc) when is_binary(data) do
    with {:ok, length} <- encode_varint(byte_size(data)) do
      encode_frames(rest, [data, length, <<0x31>> | acc])
    end
  end

  defp encode_frames(
         [%{type: :stream, stream_id: id, offset: offset, data: data} = frame | rest],
         acc
       )
       when is_integer(id) and id >= 0 and is_integer(offset) and offset >= 0 and is_binary(data) do
    type = 0x0E ||| if(Map.get(frame, :fin, false), do: 1, else: 0)

    with {:ok, stream} <- encode_varint(id),
         {:ok, off} <- encode_varint(offset),
         {:ok, length} <- encode_varint(byte_size(data)) do
      encode_frames(rest, [data, length, off, stream, <<type>> | acc])
    end
  end

  defp encode_frames(
         [%{type: :reset_stream, stream_id: id, error_code: code, final_size: final} | rest],
         acc
       )
       when is_integer(id) and id >= 0 and is_integer(code) and code >= 0 and is_integer(final) and
              final >= 0 do
    with {:ok, stream} <- encode_varint(id),
         {:ok, error} <- encode_varint(code),
         {:ok, size} <- encode_varint(final) do
      encode_frames(rest, [size, error, stream, <<4>> | acc])
    end
  end

  defp encode_frames([%{type: :stop_sending, stream_id: id, error_code: code} | rest], acc)
       when is_integer(id) and id >= 0 and is_integer(code) and code >= 0 do
    with {:ok, stream} <- encode_varint(id), {:ok, error} <- encode_varint(code) do
      encode_frames(rest, [error, stream, <<5>> | acc])
    end
  end

  defp encode_frames([%{type: type, value: value} | rest], acc)
       when type in [:max_data, :max_streams_bidi, :max_streams_uni] and is_integer(value) and
              value >= 0 do
    wire = %{max_data: 0x10, max_streams_bidi: 0x12, max_streams_uni: 0x13}[type]

    with {:ok, encoded} <- encode_varint(value),
         do: encode_frames(rest, [encoded, <<wire>> | acc])
  end

  defp encode_frames([%{type: :max_stream_data, stream_id: id, value: value} | rest], acc)
       when is_integer(id) and id >= 0 and is_integer(value) and value >= 0 do
    with {:ok, stream} <- encode_varint(id),
         {:ok, encoded} <- encode_varint(value),
         do: encode_frames(rest, [encoded, stream, <<0x11>> | acc])
  end

  defp encode_frames([%{type: type, value: value} | rest], acc)
       when type in [:data_blocked, :streams_blocked_bidi, :streams_blocked_uni] and
              is_integer(value) and value >= 0 do
    wire = %{data_blocked: 0x14, streams_blocked_bidi: 0x16, streams_blocked_uni: 0x17}[type]

    with {:ok, encoded} <- encode_varint(value),
         do: encode_frames(rest, [encoded, <<wire>> | acc])
  end

  defp encode_frames([%{type: :stream_data_blocked, stream_id: id, value: value} | rest], acc)
       when is_integer(id) and id >= 0 and is_integer(value) and value >= 0 do
    with {:ok, stream} <- encode_varint(id),
         {:ok, encoded} <- encode_varint(value),
         do: encode_frames(rest, [encoded, stream, <<0x15>> | acc])
  end

  defp encode_frames(
         [
           %{
             type: :new_connection_id,
             sequence: sequence,
             retire_prior_to: prior,
             cid: cid,
             token: token
           }
           | rest
         ],
         acc
       )
       when is_binary(cid) and byte_size(cid) in 1..20 and is_binary(token) and
              byte_size(token) == 16 do
    with {:ok, seq} <- encode_varint(sequence), {:ok, retire} <- encode_varint(prior) do
      encode_frames(rest, [
        <<0x18, seq::binary, retire::binary, byte_size(cid), cid::binary, token::binary>> | acc
      ])
    end
  end

  defp encode_frames([%{type: :retire_connection_id, sequence: sequence} | rest], acc) do
    with {:ok, seq} <- encode_varint(sequence),
         do: encode_frames(rest, [<<0x19, seq::binary>> | acc])
  end

  defp encode_frames([_ | _], _), do: {:error, :unsupported_frame}

  @spec decode_frames(binary(), keyword()) :: {:ok, [map()], binary()} | {:error, atom()}
  def decode_frames(data, opts \\ []) when is_binary(data) do
    max_frames = Keyword.get(opts, :max_frames, 1024)
    decode_frames(data, [], max_frames)
  end

  defp decode_frames(_rest, _acc, 0), do: {:error, :frame_limit}
  defp decode_frames(<<>>, acc, _), do: {:ok, Enum.reverse(acc), <<>>}

  defp decode_frames(<<0, rest::binary>>, acc, limit), do: decode_frames(rest, acc, limit)

  defp decode_frames(<<1, rest::binary>>, acc, limit),
    do: decode_frames(rest, [%{type: :ping} | acc], limit - 1)

  defp decode_frames(<<2, rest::binary>>, acc, limit) do
    with {:ok, largest, rest} <- decode_varint(rest),
         {:ok, delay, rest} <- decode_varint(rest),
         {:ok, count, rest} <- decode_varint(rest),
         {:ok, first_range, rest} <- decode_varint(rest),
         {:ok, ranges, tail} <- decode_ack_ranges(rest, largest, first_range, count) do
      decode_frames(
        tail,
        [%{type: :ack, largest: largest, delay: delay, ranges: ranges} | acc],
        limit - 1
      )
    else
      _ -> {:error, :malformed_ack_frame}
    end
  end

  defp decode_frames(<<3, rest::binary>>, acc, limit) do
    with {:ok, largest, rest} <- decode_varint(rest),
         {:ok, delay, rest} <- decode_varint(rest),
         {:ok, count, rest} <- decode_varint(rest),
         {:ok, first_range, rest} <- decode_varint(rest),
         {:ok, ranges, rest} <- decode_ack_ranges(rest, largest, first_range, count),
         {:ok, ect0, rest} <- decode_varint(rest),
         {:ok, ect1, rest} <- decode_varint(rest),
         {:ok, ce, tail} <- decode_varint(rest) do
      frame = %{
        type: :ack,
        largest: largest,
        delay: delay,
        ranges: ranges,
        ecn: %{ect0: ect0, ect1: ect1, ce: ce}
      }

      decode_frames(tail, [frame | acc], limit - 1)
    else
      _ -> {:error, :malformed_ack_frame}
    end
  end

  defp decode_frames(<<6, rest::binary>>, acc, limit) do
    with {:ok, offset, rest} <- decode_varint(rest),
         {:ok, length, rest} <- decode_varint(rest),
         :ok <- bound_length(length, byte_size(rest)),
         <<data::binary-size(^length), tail::binary>> <- rest do
      decode_frames(tail, [%{type: :crypto, offset: offset, data: data} | acc], limit - 1)
    else
      _ -> {:error, :malformed_crypto_frame}
    end
  end

  defp decode_frames(<<0x18, rest::binary>>, acc, limit) do
    with {:ok, sequence, rest} <- decode_varint(rest),
         {:ok, prior, <<length, rest::binary>>} <- decode_varint(rest),
         true <- length in 1..20,
         <<cid::binary-size(^length), token::binary-size(16), tail::binary>> <- rest do
      frame = %{
        type: :new_connection_id,
        sequence: sequence,
        retire_prior_to: prior,
        cid: cid,
        token: token
      }

      decode_frames(tail, [frame | acc], limit - 1)
    else
      _ -> {:error, :malformed_new_connection_id}
    end
  end

  defp decode_frames(<<0x19, rest::binary>>, acc, limit) do
    with {:ok, sequence, tail} <- decode_varint(rest),
         do:
           decode_frames(
             tail,
             [%{type: :retire_connection_id, sequence: sequence} | acc],
             limit - 1
           )
  end

  defp decode_frames(<<0x1C, rest::binary>>, acc, limit) do
    with {:ok, code, rest} <- decode_varint(rest),
         {:ok, frame_type, rest} <- decode_varint(rest),
         {:ok, length, rest} <- decode_varint(rest),
         :ok <- bounded_reason(length, rest),
         <<reason::binary-size(^length), tail::binary>> <- rest do
      frame = %{type: :connection_close, error_code: code, frame_type: frame_type, reason: reason}
      decode_frames(tail, [frame | acc], limit - 1)
    else
      _ -> {:error, :malformed_connection_close}
    end
  end

  defp decode_frames(<<0x1D, rest::binary>>, acc, limit) do
    with {:ok, code, rest} <- decode_varint(rest),
         {:ok, length, rest} <- decode_varint(rest),
         :ok <- bounded_reason(length, rest),
         <<reason::binary-size(^length), tail::binary>> <- rest do
      decode_frames(
        tail,
        [%{type: :application_close, error_code: code, reason: reason} | acc],
        limit - 1
      )
    else
      _ -> {:error, :malformed_connection_close}
    end
  end

  defp decode_frames(<<0x1E, rest::binary>>, acc, limit),
    do: decode_frames(rest, [%{type: :handshake_done} | acc], limit - 1)

  defp decode_frames(<<0x30, rest::binary>>, acc, limit),
    do: decode_datagram(0x30, rest, acc, limit, 1)

  defp decode_frames(<<0x31, rest::binary>>, acc, limit),
    do: decode_datagram(0x31, rest, acc, limit, 1)

  defp decode_frames(<<type, rest::binary>>, acc, limit) when type in 0x08..0x0F do
    fin = (type &&& 1) == 1
    has_length = (type &&& 2) == 2
    has_offset = (type &&& 4) == 4

    with {:ok, stream_id, rest} <- decode_varint(rest),
         {:ok, offset, rest} <- if(has_offset, do: decode_varint(rest), else: {:ok, 0, rest}),
         {:ok, length, rest} <-
           if(has_length, do: decode_varint(rest), else: {:ok, byte_size(rest), rest}),
         :ok <- bound_length(length, byte_size(rest)),
         <<data::binary-size(^length), tail::binary>> <- rest do
      frame = %{type: :stream, stream_id: stream_id, offset: offset, data: data, fin: fin}
      decode_frames(tail, [frame | acc], limit - 1)
    else
      _ -> {:error, :malformed_stream_frame}
    end
  end

  defp decode_frames(<<4, rest::binary>>, acc, limit) do
    with {:ok, stream_id, rest} <- decode_varint(rest),
         {:ok, error_code, rest} <- decode_varint(rest),
         {:ok, final_size, tail} <- decode_varint(rest) do
      decode_frames(
        tail,
        [
          %{
            type: :reset_stream,
            stream_id: stream_id,
            error_code: error_code,
            final_size: final_size
          }
          | acc
        ],
        limit - 1
      )
    else
      _ -> {:error, :malformed_reset_stream}
    end
  end

  defp decode_frames(<<5, rest::binary>>, acc, limit) do
    with {:ok, stream_id, rest} <- decode_varint(rest),
         {:ok, error_code, tail} <- decode_varint(rest) do
      decode_frames(
        tail,
        [%{type: :stop_sending, stream_id: stream_id, error_code: error_code} | acc],
        limit - 1
      )
    else
      _ -> {:error, :malformed_stop_sending}
    end
  end

  defp decode_frames(<<type, rest::binary>>, acc, limit) when type in 0x10..0x17 do
    with {:ok, first, rest} <- decode_varint(rest),
         {frame, tail} <- decode_flow_frame(type, first, rest) do
      decode_frames(tail, [frame | acc], limit - 1)
    else
      _ -> {:error, :malformed_flow_control}
    end
  end

  defp decode_frames(<<type, _::binary>>, _acc, _limit) when type >= 0x08 and type <= 0x0F,
    do: {:error, :unsupported_frame}

  defp decode_frames(<<type, _::binary>> = wire, acc, limit)
       when (type &&& 0xC0) != 0 do
    case decode_varint(wire) do
      {:ok, kind, rest} when kind in [0x30, 0x31] ->
        decode_datagram(kind, rest, acc, limit, byte_size(wire) - byte_size(rest))

      {:ok, kind, _} ->
        {:error, {:unknown_frame, kind}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp decode_frames(<<type, _::binary>>, _acc, _limit), do: {:error, {:unknown_frame, type}}
  defp decode_frames(_, _, _), do: {:error, :malformed_frame}

  defp decode_datagram(0x30, rest, acc, limit, type_size) do
    frame = %{
      type: :datagram,
      data: rest,
      wire_size: type_size + byte_size(rest),
      wire_type: 0x30
    }

    decode_frames(<<>>, [frame | acc], limit - 1)
  end

  defp decode_datagram(0x31, rest, acc, limit, type_size) do
    before_length = byte_size(rest)

    with {:ok, length, after_length} <- decode_varint(rest),
         :ok <- bound_length(length, byte_size(after_length)),
         <<data::binary-size(^length), tail::binary>> <- after_length do
      frame = %{
        type: :datagram,
        data: data,
        wire_size: type_size + before_length - byte_size(after_length) + length,
        wire_type: 0x31
      }

      decode_frames(tail, [frame | acc], limit - 1)
    else
      _ -> {:error, :malformed_datagram_frame}
    end
  end

  @doc "Validate encryption-level constraints that cannot be inferred from frame bytes."
  @spec validate_frame_levels([map()], :initial | :handshake | :application) ::
          :ok | {:error, term()} | {:wrong_encryption_level, atom(), atom()}
  def validate_frame_levels(frames, level)
      when is_list(frames) and level in [:initial, :handshake, :application] do
    Enum.reduce_while(frames, :ok, fn
      %{type: :crypto}, :ok when level in [:initial, :handshake, :application] ->
        {:cont, :ok}

      %{type: :crypto}, :ok ->
        {:halt, {:wrong_encryption_level, :crypto, level}}

      %{type: :handshake_done}, :ok when level == :application ->
        {:cont, :ok}

      %{type: :handshake_done}, :ok ->
        {:halt, {:wrong_encryption_level, :handshake_done, level}}

      %{type: :datagram}, :ok when level == :application ->
        {:cont, :ok}

      %{type: :datagram}, :ok ->
        {:halt, {:wrong_encryption_level, :datagram, level}}

      %{type: type}, :ok
      when type in [:new_connection_id, :retire_connection_id] and level == :application ->
        {:cont, :ok}

      %{type: type}, :ok when type in [:new_connection_id, :retire_connection_id] ->
        {:halt, {:wrong_encryption_level, type, level}}

      %{type: type}, :ok
      when type in [
             :stream,
             :reset_stream,
             :stop_sending,
             :max_data,
             :max_stream_data,
             :max_streams_bidi,
             :max_streams_uni,
             :data_blocked,
             :stream_data_blocked,
             :streams_blocked_bidi,
             :streams_blocked_uni
           ] and level == :application ->
        {:cont, :ok}

      %{type: type}, :ok
      when type in [
             :stream,
             :reset_stream,
             :stop_sending,
             :max_data,
             :max_stream_data,
             :max_streams_bidi,
             :max_streams_uni,
             :data_blocked,
             :stream_data_blocked,
             :streams_blocked_bidi,
             :streams_blocked_uni
           ] ->
        {:halt, {:wrong_encryption_level, type, level}}

      _, :ok ->
        {:cont, :ok}
    end)
  end

  def validate_frame_levels(_, _), do: {:error, :invalid_frame_level}

  defp encode_ack_ranges(largest, ranges) do
    with {:ok, normalized} <- normalize_ack_ranges(largest, ranges),
         [first | rest] <- normalized,
         {:ok, first_range} <- encode_varint(elem(first, 1) - elem(first, 0)),
         {:ok, range_count} <- encode_varint(length(rest)),
         {:ok, pairs} <- encode_ack_pairs(rest, first) do
      {:ok, <<range_count::binary, first_range::binary, pairs::binary>>}
    else
      _ -> {:error, :invalid_ack_ranges}
    end
  end

  defp normalize_ack_ranges(largest, ranges) when is_integer(largest) and largest >= 0 do
    if valid_ack_ranges?(ranges, largest), do: {:ok, ranges}, else: {:error, :invalid_ack_ranges}
  end

  defp normalize_ack_ranges(_, _), do: {:error, :invalid_ack_ranges}

  defp valid_ack_ranges?([{smallest, high} | rest], largest)
       when is_integer(smallest) and is_integer(high) and smallest >= 0 and high >= smallest and
              high == largest,
       do: valid_ack_tail?(rest, smallest)

  defp valid_ack_ranges?(_, _), do: false

  defp valid_ack_tail?([], _), do: true

  defp valid_ack_tail?([{smallest, high} | rest], previous_low)
       when is_integer(smallest) and is_integer(high) and smallest >= 0 and high >= smallest and
              high <= previous_low - 2,
       do: valid_ack_tail?(rest, smallest)

  defp valid_ack_tail?(_, _), do: false

  defp encode_ack_pairs([], _), do: {:ok, <<>>}

  defp encode_ack_pairs([{smallest, high} | rest], {previous_low, _}) do
    gap = previous_low - high - 2

    with true <- gap >= 0,
         {:ok, g} <- encode_varint(gap),
         {:ok, r} <- encode_varint(high - smallest),
         {:ok, tail} <- encode_ack_pairs(rest, {smallest, high}) do
      {:ok, <<g::binary, r::binary, tail::binary>>}
    else
      _ -> {:error, :invalid_ack_ranges}
    end
  end

  defp decode_ack_ranges(rest, largest, first_range, count) when count <= 64 do
    first_low = largest - first_range

    if first_low < 0 do
      {:error, :invalid_ack_ranges}
    else
      decode_ack_pairs(rest, [{first_low, largest}], first_low, count)
    end
  end

  defp decode_ack_ranges(_, _, _, _), do: {:error, :ack_range_limit}

  defp decode_ack_pairs(rest, ranges, _previous_low, 0), do: {:ok, Enum.reverse(ranges), rest}

  defp decode_ack_pairs(rest, ranges, previous_low, count) do
    with {:ok, gap, rest} <- decode_varint(rest),
         {:ok, range, rest} <- decode_varint(rest),
         high when high >= 0 <- previous_low - gap - 2,
         low when low >= 0 <- high - range do
      decode_ack_pairs(rest, [{low, high} | ranges], low, count - 1)
    else
      _ -> {:error, :invalid_ack_ranges}
    end
  end

  defp decode_flow_frame(0x10, value, rest), do: {%{type: :max_data, value: value}, rest}
  defp decode_flow_frame(0x12, value, rest), do: {%{type: :max_streams_bidi, value: value}, rest}
  defp decode_flow_frame(0x13, value, rest), do: {%{type: :max_streams_uni, value: value}, rest}
  defp decode_flow_frame(0x14, value, rest), do: {%{type: :data_blocked, value: value}, rest}

  defp decode_flow_frame(0x16, value, rest),
    do: {%{type: :streams_blocked_bidi, value: value}, rest}

  defp decode_flow_frame(0x17, value, rest),
    do: {%{type: :streams_blocked_uni, value: value}, rest}

  defp decode_flow_frame(type, stream_id, rest) when type in [0x11, 0x15] do
    case decode_varint(rest) do
      {:ok, value, tail} ->
        {if(type == 0x11,
           do: %{type: :max_stream_data, stream_id: stream_id, value: value},
           else: %{type: :stream_data_blocked, stream_id: stream_id, value: value}
         ), tail}

      _ ->
        {:error, :malformed_flow_control}
    end
  end

  defp encode_ecn(nil), do: {:ok, <<>>, 2}

  defp encode_ecn(%{ect0: ect0, ect1: ect1, ce: ce}) do
    with {:ok, a} <- encode_varint(ect0),
         {:ok, b} <- encode_varint(ect1),
         {:ok, c} <- encode_varint(ce) do
      {:ok, a <> b <> c, 3}
    end
  end

  defp encode_ecn(_), do: {:error, :invalid_ecn_counts}

  defp bounded_reason(length, rest) when length <= 1024 and byte_size(rest) >= length, do: :ok
  defp bounded_reason(_, _), do: {:error, :reason_too_large}

  defp bounded_reason_length(length) when is_integer(length) and length <= 1024, do: :ok
  defp bounded_reason_length(_), do: {:error, :reason_too_large}

  defp take_cid(<<len, rest::binary>>) when len <= 20 and byte_size(rest) >= len,
    do: {:ok, binary_part(rest, 0, len), binary_part(rest, len, byte_size(rest) - len)}

  defp take_cid(_), do: {:error, :invalid_connection_id}

  defp validate_initial_first(first)
       when (first &&& 0x80) != 0 and (first &&& 0x40) != 0 and (first >>> 4 &&& 3) == 0,
       do: :ok

  defp validate_initial_first(first) when (first &&& 0x40) == 0,
    do: {:error, :invalid_header_fixed_bit}

  defp validate_initial_first(_), do: {:error, :not_initial}
  defp valid_version(@version), do: :ok
  defp valid_version(_), do: {:error, :unsupported_version}
  defp valid_bytes(value, max) when is_binary(value) and byte_size(value) <= max, do: :ok
  defp valid_bytes(_, _), do: {:error, :length_exceeded}
  defp bound_length(length, available) when length >= 0 and length <= available, do: :ok
  defp bound_length(_, _), do: {:error, :truncated_payload}
end
