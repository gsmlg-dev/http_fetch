defmodule Quic.TransportParameters do
  @moduledoc """
  Bounded QUIC v1 transport-parameter wire and semantic helpers.

  The `ordered` list is the wire representation and is retained so callers can
  observe order and unknown extensions. `values` is the validated semantic view
  of parameters known to this version of Quic.
  """

  @max_parameter_bytes 65_535
  @max_parameters 64
  @max_cid_length 20

  @known %{
    0x00 => {:original_destination_connection_id, :cid},
    0x01 => {:max_idle_timeout, :varint},
    0x02 => {:stateless_reset_token, :token},
    0x03 => {:max_udp_payload_size, :varint},
    0x04 => {:initial_max_data, :varint},
    0x05 => {:initial_max_stream_data_bidi_local, :varint},
    0x06 => {:initial_max_stream_data_bidi_remote, :varint},
    0x07 => {:initial_max_stream_data_uni, :varint},
    0x08 => {:initial_max_streams_bidi, :varint},
    0x09 => {:initial_max_streams_uni, :varint},
    0x0A => {:ack_delay_exponent, :varint},
    0x0B => {:max_ack_delay, :varint},
    0x0C => {:disable_active_migration, :flag},
    0x0D => {:preferred_address, :preferred_address},
    0x0E => {:active_connection_id_limit, :varint},
    0x0F => {:initial_source_connection_id, :cid},
    0x10 => {:retry_source_connection_id, :cid},
    0x20 => {:max_datagram_frame_size, :varint}
  }

  @spec encode([map()] | map(), keyword()) :: {:ok, binary()} | {:error, atom()}
  def encode(ordered_or_map, opts \\ [])
  def encode(%{ordered: ordered}, opts), do: encode(ordered, opts)

  def encode(ordered, opts) when is_list(ordered) do
    with :ok <- bound_count(ordered),
         {:ok, wire} <- encode_entries(ordered, %{}, [], 0),
         :ok <- validate_wire_size(wire),
         {:ok, decoded} <- decode(wire, opts),
         :ok <- validate(decoded, opts) do
      {:ok, wire}
    end
  end

  def encode(_, _), do: {:error, :invalid_transport_parameters}

  @spec decode(binary(), keyword()) :: {:ok, map()} | {:error, atom()}
  def decode(data, opts \\ [])

  def decode(data, opts) when is_binary(data) do
    max_bytes = Keyword.get(opts, :max_bytes, @max_parameter_bytes)
    max_parameters = Keyword.get(opts, :max_parameters, @max_parameters)

    cond do
      not is_integer(max_bytes) or not is_integer(max_parameters) or max_bytes < 0 or
          max_parameters < 0 ->
        {:error, :invalid_bound}

      byte_size(data) > max_bytes ->
        {:error, :transport_parameters_too_large}

      true ->
        decode_entries(
          data,
          [],
          %{},
          [],
          %{},
          max_parameters
        )
    end
  end

  def decode(_, _), do: {:error, :invalid_transport_parameters}

  @spec validate(map() | [map()], keyword()) :: :ok | {:error, atom()}
  def validate(%{ordered: ordered, values: values}, opts) do
    with :ok <- validate_role(values, Keyword.get(opts, :role)),
         :ok <- validate_values(values),
         :ok <- validate_cids(values, opts) do
      validate_ordered(ordered)
    end
  end

  def validate(ordered, opts) when is_list(ordered) do
    with {:ok, wire} <- encode_entries(ordered, %{}, [], 0),
         {:ok, decoded} <- decode(wire, opts),
         do: validate(decoded, opts)
  end

  def validate(_, _), do: {:error, :invalid_transport_parameters}

  defp encode_entries([], _seen, acc, _total), do: {:ok, IO.iodata_to_binary(Enum.reverse(acc))}

  defp encode_entries([%{id: id, value: value} | rest], seen, acc, total)
       when is_integer(id) and id >= 0 and is_binary(value) do
    cond do
      Map.has_key?(seen, id) ->
        {:error, :duplicate_transport_parameter}

      byte_size(value) > @max_parameter_bytes ->
        {:error, :parameter_too_large}

      total + byte_size(value) > @max_parameter_bytes ->
        {:error, :transport_parameters_too_large}

      true ->
        with {:ok, id_wire} <- Quic.Codec.encode_varint(id),
             {:ok, len_wire} <- Quic.Codec.encode_varint(byte_size(value)) do
          wire = <<id_wire::binary, len_wire::binary, value::binary>>
          encode_entries(rest, Map.put(seen, id, true), [wire | acc], total + byte_size(wire))
        end
    end
  end

  defp encode_entries(_, _, _, _), do: {:error, :invalid_transport_parameter}

  defp decode_entries(<<>>, ordered, values, unknown, _seen, _limit) do
    {:ok, %{ordered: Enum.reverse(ordered), values: values, unknown: Enum.reverse(unknown)}}
  end

  defp decode_entries(_data, _ordered, _values, _unknown, _seen, 0),
    do: {:error, :parameter_count_limit}

  defp decode_entries(data, ordered, values, unknown, seen, limit) do
    with {:ok, id, rest} <- Quic.Codec.decode_varint(data),
         {:ok, length, rest} <- Quic.Codec.decode_varint(rest),
         true <- length <= @max_parameter_bytes,
         true <- byte_size(rest) >= length,
         <<value::binary-size(^length), tail::binary>> <- rest do
      if Map.has_key?(seen, id) do
        {:error, :duplicate_transport_parameter}
      else
        case Map.get(@known, id) do
          {key, kind} ->
            with {:ok, semantic} <- decode_value(kind, value) do
              decode_entries(
                tail,
                [%{id: id, value: value} | ordered],
                Map.put(values, key, semantic),
                unknown,
                Map.put(seen, id, true),
                limit - 1
              )
            end

          nil ->
            decode_entries(
              tail,
              [%{id: id, value: value} | ordered],
              values,
              [{id, value} | unknown],
              Map.put(seen, id, true),
              limit - 1
            )
        end
      end
    else
      false -> {:error, :truncated_transport_parameter}
      {:error, _} = error -> error
      _ -> {:error, :truncated_transport_parameter}
    end
  end

  defp decode_value(:varint, value) do
    case Quic.Codec.decode_varint(value) do
      {:ok, number, <<>>} -> {:ok, number}
      {:ok, _, _} -> {:error, :invalid_parameter_value}
      {:error, _} -> {:error, :invalid_parameter_value}
    end
  end

  defp decode_value(:flag, <<>>), do: {:ok, true}
  defp decode_value(:flag, _), do: {:error, :invalid_parameter_value}
  defp decode_value(:cid, value) when byte_size(value) <= @max_cid_length, do: {:ok, value}
  defp decode_value(:cid, _), do: {:error, :connection_id_too_long}
  defp decode_value(:token, <<_::binary-size(16)>> = value), do: {:ok, value}
  defp decode_value(:token, _), do: {:error, :invalid_stateless_reset_token}

  defp decode_value(
         :preferred_address,
         <<_ip4::binary-size(4), _port4::binary-size(2), _ip6::binary-size(16),
           _port6::binary-size(2), cid_len, rest::binary>> = value
       )
       when cid_len <= @max_cid_length and byte_size(rest) == cid_len + 16,
       do: {:ok, value}

  defp decode_value(:preferred_address, _), do: {:error, :invalid_preferred_address}

  defp validate_wire_size(wire) when byte_size(wire) <= @max_parameter_bytes, do: :ok
  defp validate_wire_size(_), do: {:error, :transport_parameters_too_large}

  defp bound_count(entries) when length(entries) <= @max_parameters, do: :ok
  defp bound_count(_), do: {:error, :parameter_count_limit}

  defp validate_ordered(entries) do
    with :ok <- bound_count(entries) do
      validate_unique_ids(entries, %{})
    end
  end

  defp validate_unique_ids([], _), do: :ok

  defp validate_unique_ids([%{id: id} | rest], seen) do
    if Map.has_key?(seen, id),
      do: {:error, :duplicate_transport_parameter},
      else: validate_unique_ids(rest, Map.put(seen, id, true))
  end

  defp validate_unique_ids(_, _), do: {:error, :invalid_transport_parameter}

  defp validate_values(values) do
    cond do
      Map.get(values, :max_udp_payload_size, 1200) < 1200 ->
        {:error, :invalid_max_udp_payload_size}

      Map.get(values, :max_udp_payload_size, 1200) > 65_527 ->
        {:error, :invalid_max_udp_payload_size}

      Map.get(values, :ack_delay_exponent, 3) > 20 ->
        {:error, :invalid_ack_delay_exponent}

      Map.get(values, :max_ack_delay, 0) > 0x3FFF ->
        {:error, :invalid_max_ack_delay}

      Map.get(values, :active_connection_id_limit, 2) < 2 ->
        {:error, :invalid_active_connection_id_limit}

      true ->
        :ok
    end
  end

  defp validate_role(_values, nil), do: :ok

  defp validate_role(values, role) when role in [:client, :server] do
    forbidden =
      if role == :client,
        do: [
          :original_destination_connection_id,
          :retry_source_connection_id,
          :stateless_reset_token,
          :preferred_address
        ],
        else: []

    if Enum.any?(forbidden, &Map.has_key?(values, &1)),
      do: {:error, :parameter_forbidden_for_role},
      else: :ok
  end

  defp validate_role(_, _), do: {:error, :invalid_role}

  defp validate_cids(values, opts) do
    with :ok <- require_cid(values, Keyword.get(opts, :role)),
         :ok <- validate_retry_cid(values, opts),
         :ok <-
           compare_cid(
             values,
             :original_destination_connection_id,
             Keyword.get(opts, :original_destination_connection_id)
           ) do
      compare_cid(
        values,
        :initial_source_connection_id,
        Keyword.get(opts, :initial_source_connection_id)
      )
    end
  end

  defp require_cid(_values, nil), do: :ok

  defp require_cid(values, :client) do
    if Map.has_key?(values, :initial_source_connection_id),
      do: :ok,
      else: {:error, :missing_initial_source_connection_id}
  end

  defp require_cid(values, :server) do
    cond do
      not Map.has_key?(values, :initial_source_connection_id) ->
        {:error, :missing_initial_source_connection_id}

      not Map.has_key?(values, :original_destination_connection_id) ->
        {:error, :missing_original_destination_connection_id}

      true ->
        :ok
    end
  end

  defp validate_retry_cid(values, opts) do
    if Keyword.has_key?(opts, :retry_source_connection_id) do
      case Keyword.get(opts, :retry_source_connection_id) do
        nil ->
          if Map.has_key?(values, :retry_source_connection_id),
            do: {:error, :unexpected_retry_source_connection_id},
            else: :ok

        expected ->
          compare_cid(values, :retry_source_connection_id, expected)
      end
    else
      :ok
    end
  end

  defp compare_cid(_values, _key, nil), do: :ok

  defp compare_cid(values, key, expected)
       when is_binary(expected) and byte_size(expected) <= @max_cid_length do
    if Map.get(values, key) == expected, do: :ok, else: {:error, :connection_id_mismatch}
  end

  defp compare_cid(_, _, _), do: {:error, :invalid_connection_id}
end
