defmodule SSL.Protocol.TLS12Codec do
  @moduledoc """
  Bounded codecs for complete TLS 1.2 handshake messages.

  `SSL.Protocol.HandshakeFramer` handles stream fragmentation. This module
  consumes exactly one encoded handshake message and retains its original bytes
  for transcript and signature verification.
  """

  @max_certificate_count 16
  @max_certificate_size 262_144
  @max_chain_size 524_288
  @max_signature_size 16_384
  @max_signature_schemes 128
  @max_authorities 64
  @max_handshake_size 1_048_576

  @type message :: map()

  @spec decode(binary()) :: {:ok, message()} | {:error, term()}
  def decode(<<type, length::24, body::binary>> = encoded)
      when length == byte_size(body) and length <= @max_handshake_size do
    case decode_body(type, body) do
      {:ok, value} -> {:ok, Map.put(value, :encoded, encoded)}
      error -> error
    end
  end

  def decode(_), do: {:error, :invalid_handshake}

  @spec encode_certificate([binary()]) :: {:ok, binary()} | {:error, term()}
  def encode_certificate(chain) when is_list(chain) do
    with :ok <- proper_list(chain),
         :ok <- valid_chain(chain, false) do
      certificates = Enum.map(chain, &[<<byte_size(&1)::24>>, &1])
      length = Enum.reduce(chain, 0, &(byte_size(&1) + 3 + &2))
      encode(11, [<<length::24>>, certificates])
    end
  end

  def encode_certificate(_), do: {:error, :invalid_certificate_chain}

  @spec encode_client_key_exchange(binary()) :: {:ok, binary()} | {:error, term()}
  def encode_client_key_exchange(public_key)
      when is_binary(public_key) and byte_size(public_key) in 1..255,
      do: encode(16, [<<byte_size(public_key)>>, public_key])

  def encode_client_key_exchange(_), do: {:error, :invalid_client_key_exchange}

  @spec encode_certificate_verify(non_neg_integer(), binary()) ::
          {:ok, binary()} | {:error, term()}
  def encode_certificate_verify(scheme, signature)
      when is_integer(scheme) and scheme in 0..0xFFFF and is_binary(signature) and
             byte_size(signature) in 1..@max_signature_size,
      do: encode(15, [<<scheme::16, byte_size(signature)::16>>, signature])

  def encode_certificate_verify(_, _), do: {:error, :invalid_certificate_verify}

  @spec encode_finished(binary()) :: {:ok, binary()} | {:error, term()}
  def encode_finished(verify_data) when is_binary(verify_data) and byte_size(verify_data) == 12,
    do: encode(20, verify_data)

  def encode_finished(_), do: {:error, :invalid_finished}

  defp decode_body(2, <<3, 3, random::binary-size(32), session_length, rest::binary>>)
       when session_length <= 32 do
    case rest do
      <<session_id::binary-size(^session_length), cipher_suite::16, compression,
        extensions::binary>> ->
        with {:ok, decoded_extensions} <- decode_extensions(extensions) do
          {:ok,
           %{
             type: :server_hello,
             random: random,
             session_id: session_id,
             cipher_suite: cipher_suite,
             compression: compression,
             extensions: decoded_extensions
           }}
        end

      _ ->
        {:error, :invalid_server_hello}
    end
  end

  defp decode_body(2, _), do: {:error, :invalid_server_hello}

  defp decode_body(11, <<length::24, certificates::binary>>)
       when length == byte_size(certificates) and
              length <= @max_chain_size + 3 * @max_certificate_count do
    with {:ok, chain} <- decode_certificates(certificates, []),
         :ok <- valid_chain(chain, true) do
      {:ok, %{type: :certificate, chain: chain}}
    end
  end

  defp decode_body(11, _), do: {:error, :invalid_certificate_chain}

  defp decode_body(
         12,
         <<3, group::16, key_length, public_key::binary-size(key_length), scheme::16,
           signature_length::16, signature::binary-size(signature_length)>>
       )
       when key_length > 0 and signature_length in 1..@max_signature_size do
    parameters = <<3, group::16, key_length, public_key::binary>>

    {:ok,
     %{
       type: :server_key_exchange,
       group: group,
       public_key: public_key,
       parameters: parameters,
       scheme: scheme,
       signature: signature
     }}
  end

  defp decode_body(12, _), do: {:error, :invalid_server_key_exchange}

  defp decode_body(
         13,
         <<type_length, certificate_types::binary-size(type_length), scheme_length::16,
           schemes::binary-size(scheme_length), authority_length::16,
           authorities::binary-size(authority_length)>>
       )
       when type_length > 0 and scheme_length > 0 and rem(scheme_length, 2) == 0 and
              scheme_length <= 2 * @max_signature_schemes do
    with {:ok, names} <- decode_authorities(authorities, []) do
      {:ok,
       %{
         type: :certificate_request,
         certificate_types: :binary.bin_to_list(certificate_types),
         signature_schemes: for(<<scheme::16 <- schemes>>, do: scheme),
         authorities: names
       }}
    end
  end

  defp decode_body(13, _), do: {:error, :invalid_certificate_request}
  defp decode_body(14, <<>>), do: {:ok, %{type: :server_hello_done}}
  defp decode_body(14, _), do: {:error, :invalid_server_hello_done}

  defp decode_body(20, <<verify_data::binary-size(12)>>),
    do: {:ok, %{type: :finished, verify_data: verify_data}}

  defp decode_body(20, _), do: {:error, :invalid_finished}
  defp decode_body(_, _), do: {:error, :unsupported_handshake_type}

  defp decode_extensions(<<>>), do: {:ok, []}

  defp decode_extensions(<<length::16, extensions::binary>>) when length == byte_size(extensions),
    do: parse_extensions(extensions, [], %{})

  defp decode_extensions(_), do: {:error, :invalid_server_hello_extensions}

  defp parse_extensions(<<>>, acc, _seen), do: {:ok, Enum.reverse(acc)}

  defp parse_extensions(
         <<id::16, length::16, payload::binary-size(length), rest::binary>>,
         acc,
         seen
       ) do
    if Map.has_key?(seen, id) do
      {:error, :duplicate_server_hello_extension}
    else
      parse_extensions(rest, [{id, payload} | acc], Map.put(seen, id, true))
    end
  end

  defp parse_extensions(_, _, _), do: {:error, :invalid_server_hello_extensions}

  defp decode_certificates(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_certificates(<<length::24, certificate::binary-size(length), rest::binary>>, acc)
       when length in 1..@max_certificate_size and length(acc) < @max_certificate_count,
       do: decode_certificates(rest, [certificate | acc])

  defp decode_certificates(_, _), do: {:error, :invalid_certificate_chain}

  defp valid_chain(chain, require_nonempty) do
    cond do
      require_nonempty and chain == [] ->
        {:error, :invalid_certificate_chain}

      length(chain) > @max_certificate_count ->
        {:error, :invalid_certificate_chain}

      Enum.any?(chain, &(not is_binary(&1) or byte_size(&1) not in 1..@max_certificate_size)) ->
        {:error, :invalid_certificate_chain}

      Enum.reduce(chain, 0, &(byte_size(&1) + &2)) > @max_chain_size ->
        {:error, :invalid_certificate_chain}

      true ->
        :ok
    end
  end

  defp decode_authorities(<<>>, acc), do: {:ok, Enum.reverse(acc)}

  defp decode_authorities(<<length::16, name::binary-size(length), rest::binary>>, acc)
       when length > 0 and length(acc) < @max_authorities do
    if valid_der_name?(name) do
      decode_authorities(rest, [name | acc])
    else
      {:error, :invalid_certificate_request}
    end
  end

  defp decode_authorities(_, _), do: {:error, :invalid_certificate_request}

  defp valid_der_name?(bytes) do
    decoded = :public_key.der_decode(:Name, bytes)
    :public_key.der_encode(:Name, decoded) == bytes
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp encode(type, body) do
    length = IO.iodata_length(body)
    {:ok, IO.iodata_to_binary([<<type, length::24>>, body])}
  end

  defp proper_list(value) do
    _ = length(value)
    :ok
  rescue
    ArgumentError -> {:error, :invalid_certificate_chain}
  end
end
