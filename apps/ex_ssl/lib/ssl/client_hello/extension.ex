defmodule SSL.ClientHello.Extension do
  @moduledoc """
  Encodes fully materialized ClientHello extensions.
  """

  @ids %{
    server_name: 0,
    supported_groups: 10,
    ec_point_formats: 11,
    extended_master_secret: 23,
    renegotiation_info: 0xFF01,
    signature_algorithms: 13,
    alpn: 16,
    padding: 21,
    pre_shared_key: 41,
    supported_versions: 43,
    psk_key_exchange_modes: 45,
    signature_algorithms_cert: 50,
    key_share: 51
  }

  @spec encode(term()) :: {:ok, {0..0xFFFF, binary()}} | {:error, term()}
  def encode({:server_name, server_name}) when is_binary(server_name) do
    payload_size = byte_size(server_name) + 5

    if payload_size <= 0xFFFF do
      payload =
        <<byte_size(server_name) + 3::16, 0, byte_size(server_name)::16, server_name::binary>>

      {:ok, {@ids.server_name, payload}}
    else
      {:error, {:extension_payload_length_exceeded, :server_name, payload_size, 0xFFFF}}
    end
  end

  def encode({:supported_groups, groups}),
    do: uint16_vector(:supported_groups, @ids.supported_groups, groups)

  def encode({:ec_point_formats, formats}),
    do: uint8_vector(:ec_point_formats, @ids.ec_point_formats, formats)

  def encode({:extended_master_secret, <<>>}), do: {:ok, {@ids.extended_master_secret, <<>>}}
  def encode({:renegotiation_info, <<0>>}), do: {:ok, {@ids.renegotiation_info, <<0>>}}

  def encode({:signature_algorithms, algorithms}),
    do: uint16_vector(:signature_algorithms, @ids.signature_algorithms, algorithms)

  def encode({:signature_algorithms_cert, algorithms}),
    do: uint16_vector(:signature_algorithms_cert, @ids.signature_algorithms_cert, algorithms)

  def encode({:alpn, protocols} = extension) do
    if valid_alpn?(protocols) do
      protocols_payload =
        IO.iodata_to_binary(Enum.map(protocols, &<<byte_size(&1), &1::binary>>))

      bounded(:alpn, @ids.alpn, <<byte_size(protocols_payload)::16, protocols_payload::binary>>)
    else
      invalid(extension)
    end
  end

  def encode({:supported_versions, versions} = extension) do
    with :ok <- validate_uint16_values(versions, extension),
         :ok <- validate_vector_length(:supported_versions, 2 * length(versions), 0xFF) do
      payload = IO.iodata_to_binary(Enum.map(versions, &<<&1::16>>))

      bounded(
        :supported_versions,
        @ids.supported_versions,
        <<byte_size(payload), payload::binary>>
      )
    end
  end

  def encode({:psk_key_exchange_modes, modes}),
    do: uint8_vector(:psk_key_exchange_modes, @ids.psk_key_exchange_modes, modes)

  def encode({:key_share, entries} = extension) do
    if valid_key_share_entries?(entries) do
      entries_payload =
        IO.iodata_to_binary(
          Enum.map(entries, fn {group, public_key} ->
            <<group::16, byte_size(public_key)::16, public_key::binary>>
          end)
        )

      if byte_size(entries_payload) <= 0xFFFF - 2 do
        bounded(
          :key_share,
          @ids.key_share,
          <<byte_size(entries_payload)::16, entries_payload::binary>>
        )
      else
        {:error,
         {:extension_payload_length_exceeded, :key_share, byte_size(entries_payload) + 2, 0xFFFF}}
      end
    else
      invalid(extension)
    end
  end

  def encode({:padding, :none}), do: {:ok, {@ids.padding, <<>>}}

  def encode({:padding, size}) when is_integer(size) and size >= 0,
    do: bounded(:padding, @ids.padding, :binary.copy(<<0>>, size))

  def encode({:pre_shared_key, payload}) when is_binary(payload),
    do: bounded(:pre_shared_key, @ids.pre_shared_key, payload)

  def encode({:raw, extension_id, payload})
      when is_integer(extension_id) and extension_id in 0..0xFFFF and is_binary(payload),
      do: bounded(:raw, extension_id, payload)

  def encode(extension), do: invalid(extension)

  defp uint16_vector(tag, extension_id, values) do
    extension = {tag, values}

    with :ok <- validate_uint16_values(values, extension),
         :ok <- validate_vector_length(tag, 2 * length(values) + 2, 0xFFFF) do
      payload = IO.iodata_to_binary(Enum.map(values, &<<&1::16>>))
      bounded(tag, extension_id, <<byte_size(payload)::16, payload::binary>>)
    end
  end

  defp uint8_vector(tag, extension_id, values) do
    extension = {tag, values}

    with :ok <- validate_uint8_values(values, extension),
         :ok <- validate_vector_length(tag, length(values), 0xFF) do
      payload = :erlang.list_to_binary(values)
      bounded(tag, extension_id, <<byte_size(payload), payload::binary>>)
    end
  end

  defp validate_uint16_values(values, extension) when is_list(values) and values != [] do
    if Enum.all?(values, &valid_uint16?/1), do: :ok, else: invalid(extension)
  end

  defp validate_uint16_values(_values, extension), do: invalid(extension)

  defp validate_uint8_values(values, extension) when is_list(values) and values != [] do
    if Enum.all?(values, &valid_uint8?/1), do: :ok, else: invalid(extension)
  end

  defp validate_uint8_values(_values, extension), do: invalid(extension)

  defp validate_vector_length(_tag, length, maximum) when length <= maximum, do: :ok

  defp validate_vector_length(tag, length, maximum),
    do: {:error, {:extension_vector_length_exceeded, tag, length, maximum}}

  defp valid_alpn?(protocols) when is_list(protocols) and protocols != [] do
    Enum.all?(protocols, &(is_binary(&1) and byte_size(&1) in 1..255)) and
      Enum.reduce(protocols, 0, &(byte_size(&1) + 1 + &2)) <= 0xFFFF - 2
  end

  defp valid_alpn?(_protocols), do: false

  defp valid_key_share_entries?(entries) when is_list(entries) do
    Enum.all?(entries, fn
      {group, public_key} ->
        valid_uint16?(group) and is_binary(public_key) and byte_size(public_key) <= 0xFFFF

      _entry ->
        false
    end)
  end

  defp valid_key_share_entries?(_entries), do: false

  defp valid_uint16?(value), do: is_integer(value) and value in 0..0xFFFF
  defp valid_uint8?(value), do: is_integer(value) and value in 0..0xFF

  defp invalid(extension), do: {:error, {:invalid_materialized_extension, extension}}

  defp bounded(_tag, extension_id, payload) when byte_size(payload) <= 0xFFFF,
    do: {:ok, {extension_id, payload}}

  defp bounded(tag, _extension_id, payload),
    do: {:error, {:extension_payload_length_exceeded, tag, byte_size(payload), 0xFFFF}}
end
