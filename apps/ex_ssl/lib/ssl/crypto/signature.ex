defmodule SSL.Crypto.Signature do
  @moduledoc """
  TLS 1.3 CertificateVerify and raw TLS 1.2 handshake signatures.

  This module verifies handshake signatures only. Certificate path and service
  identity validation remain separate PKIX responsibilities.
  """

  @server_context "TLS 1.3, server CertificateVerify"
  @client_context "TLS 1.3, client CertificateVerify"
  @space_prefix :binary.copy(<<0x20>>, 64)
  alias SSL.Capabilities
  @rsa_pss_oid {1, 2, 840, 113_549, 1, 1, 10}
  @mgf1_oid {1, 2, 840, 113_549, 1, 1, 8}
  @hash_oids %{
    sha256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
    sha384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
    sha512: {2, 16, 840, 1, 101, 3, 4, 2, 3}
  }

  @type signature_scheme :: 0x0403 | 0x0503 | 0x0804..0x0807 | 0x0809..0x080B
  @type error_reason ::
          :unsupported_hash
          | :invalid_certificate_verify
          | :signature_verification_failed
          | :empty_signature
          | :invalid_public_key
          | {:unsupported_signature_scheme, term()}
          | {:invalid_input, :transcript_hash | :signature}
          | {:invalid_transcript_hash_length, pos_integer()}
          | {:key_type_mismatch, :ecdsa | :rsa | :rsa_pss | :eddsa}
          | {:unsupported_ec_curve, atom() | tuple()}
          | :invalid_ecdsa_signature_encoding
          | :invalid_rsa_pss_parameters

  @spec server_signed_content(atom(), term()) ::
          {:error,
           :unsupported_hash
           | {:invalid_input, :transcript_hash}
           | {:invalid_transcript_hash_length, 32 | 48 | 64}}
          | {:ok, <<_::64, _::_*8>>}
  def server_signed_content(hash, transcript_hash) do
    signed_content(:server, hash, transcript_hash)
  end

  @spec client_signed_content(atom(), term()) ::
          {:error,
           :unsupported_hash
           | {:invalid_input, :transcript_hash}
           | {:invalid_transcript_hash_length, 32 | 48 | 64}}
          | {:ok, <<_::64, _::_*8>>}
  def client_signed_content(hash, transcript_hash) do
    signed_content(:client, hash, transcript_hash)
  end

  @spec signed_content(:server | :client, atom(), term()) ::
          {:ok, binary()} | {:error, error_reason()}
  def signed_content(role, hash, transcript_hash) when role in [:server, :client] do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_transcript_hash(transcript_hash, hash_length) do
      context = if role == :server, do: @server_context, else: @client_context
      {:ok, <<@space_prefix::binary, context::binary, 0, transcript_hash::binary>>}
    end
  end

  @spec verify_server(term(), term(), atom(), term(), term()) :: :ok | {:error, error_reason()}
  def verify_server(
        signature_scheme,
        public_key,
        transcript_hash_algorithm,
        transcript_digest,
        signature
      ) do
    verify_role(
      :server,
      signature_scheme,
      public_key,
      transcript_hash_algorithm,
      transcript_digest,
      signature
    )
  end

  @spec verify_client(term(), term(), atom(), term(), term()) :: :ok | {:error, error_reason()}
  def verify_client(
        signature_scheme,
        public_key,
        transcript_hash_algorithm,
        transcript_digest,
        signature
      ) do
    verify_role(
      :client,
      signature_scheme,
      public_key,
      transcript_hash_algorithm,
      transcript_digest,
      signature
    )
  end

  defp verify_role(
         role,
         signature_scheme,
         public_key,
         transcript_hash_algorithm,
         transcript_digest,
         signature
       ) do
    with {:ok, scheme} <- signature_scheme(signature_scheme),
         {:ok, signed_content} <-
           signed_content(role, transcript_hash_algorithm, transcript_digest),
         :ok <- validate_signature(signature),
         {:ok, verification_key} <- validate_public_key(scheme, public_key),
         :ok <- validate_signature_encoding(scheme, signature) do
      verify(signed_content, scheme.hash, signature, verification_key, scheme.verify_options)
    end
  end

  @spec sign_client(term(), term(), atom(), term()) ::
          {:ok, binary()} | {:error, error_reason()}
  def sign_client(signature_scheme, private_key, transcript_hash_algorithm, transcript_digest) do
    sign_role(
      :client,
      signature_scheme,
      private_key,
      transcript_hash_algorithm,
      transcript_digest
    )
  end

  @spec sign_server(term(), term(), atom(), term()) :: {:ok, binary()} | {:error, error_reason()}
  def sign_server(scheme, key, hash, digest), do: sign_role(:server, scheme, key, hash, digest)

  defp sign_role(
         role,
         signature_scheme,
         private_key,
         transcript_hash_algorithm,
         transcript_digest
       ) do
    with {:ok, scheme} <- signature_scheme(signature_scheme),
         {:ok, content} <- signed_content(role, transcript_hash_algorithm, transcript_digest),
         {:ok, signing_key} <- validate_private_key(scheme, private_key) do
      try do
        {:ok, :public_key.sign(content, scheme.hash, signing_key, scheme.verify_options)}
      catch
        :error, _reason -> {:error, :signature_verification_failed}
      end
    end
  end

  @doc "Verifies exact TLS 1.2 handshake bytes without a TLS 1.3 CertificateVerify context."
  @spec verify_message(term(), term(), term(), term()) ::
          :ok
          | {:error,
             :empty_signature
             | :invalid_certificate_verify
             | :invalid_ecdsa_signature_encoding
             | :invalid_public_key
             | :invalid_rsa_pss_parameters
             | :signature_verification_failed
             | {:invalid_input, :message | :signature}
             | {:key_type_mismatch, :ecdsa | :eddsa | :rsa | :rsa_pss}
             | {:unsupported_ec_curve, term()}
             | {:unsupported_signature_scheme, term()}}
  def verify_message(signature_scheme, public_key, data, signature) do
    with {:ok, scheme} <- signature_scheme(signature_scheme),
         :ok <- validate_message(data),
         :ok <- validate_signature(signature),
         {:ok, verification_key} <- validate_public_key(scheme, public_key),
         :ok <- validate_signature_encoding(scheme, signature) do
      verify(data, scheme.hash, signature, verification_key, scheme.verify_options)
    end
  end

  @doc "Signs exact TLS 1.2 handshake bytes without a TLS 1.3 CertificateVerify context."
  @spec sign_message(term(), term(), term()) ::
          {:error,
           :invalid_rsa_pss_parameters
           | :signature_verification_failed
           | {:invalid_input, :message}
           | {:key_type_mismatch, term()}
           | {:unsupported_signature_scheme, term()}}
          | {:ok, binary()}
  def sign_message(signature_scheme, private_key, data) do
    with {:ok, scheme} <- signature_scheme(signature_scheme),
         :ok <- validate_message(data),
         {:ok, signing_key} <- validate_private_key(scheme, private_key) do
      try do
        {:ok, :public_key.sign(data, scheme.hash, signing_key, scheme.verify_options)}
      catch
        :error, _reason -> {:error, :signature_verification_failed}
      end
    end
  end

  defp validate_message(data) when is_binary(data) and byte_size(data) <= 1_048_576, do: :ok
  defp validate_message(_), do: {:error, {:invalid_input, :message}}

  defp signature_scheme(value) do
    case Capabilities.signature(value) do
      %{id: ^value} = scheme ->
        if value in Capabilities.identifiers(:signature_algorithm),
          do: {:ok, scheme},
          else: {:error, {:unsupported_signature_scheme, value}}

      _ ->
        {:error, {:unsupported_signature_scheme, value}}
    end
  end

  defp validate_public_key(
         %{key: :ecdsa, curve_oid: oid, public_key_size: size},
         {{:ECPoint, <<4, _coordinates::binary>> = point}, {:namedCurve, oid}}
       )
       when byte_size(point) == size,
       do: {:ok, {{:ECPoint, point}, {:namedCurve, oid}}}

  defp validate_public_key(
         %{key: :ecdsa, curve_oid: expected},
         {{:ECPoint, _point}, {:namedCurve, oid}}
       )
       when oid == expected,
       do: {:error, :invalid_public_key}

  defp validate_public_key(
         %{key: :ecdsa},
         {{:ECPoint, _point}, {:namedCurve, {1, 3, 132, 0, 34}}}
       ),
       do: {:error, {:unsupported_ec_curve, :secp384r1}}

  defp validate_public_key(%{key: :ecdsa}, {{:ECPoint, _point}, {:namedCurve, oid}}),
    do: {:error, {:unsupported_ec_curve, oid}}

  defp validate_public_key(%{key: :ecdsa}, {:RSAPublicKey, modulus, exponent})
       when is_integer(modulus) and is_integer(exponent),
       do: {:error, {:key_type_mismatch, :ecdsa}}

  defp validate_public_key(%{key: :rsa}, {:RSAPublicKey, modulus, exponent} = key)
       when is_integer(modulus) and modulus > 0 and is_integer(exponent) and exponent > 0,
       do: {:ok, key}

  defp validate_public_key(
         %{key: :rsa_pss, hash: hash, verify_options: options},
         {@rsa_pss_oid, {:RSAPublicKey, modulus, exponent} = key, parameters}
       )
       when is_integer(modulus) and modulus > 0 and is_integer(exponent) and exponent > 0 do
    if valid_pss_parameters?(parameters, hash, options),
      do: {:ok, key},
      else: {:error, :invalid_rsa_pss_parameters}
  end

  defp validate_public_key(
         %{key: :eddsa, curve_oid: oid, public_key_size: size},
         {oid, {:ECPoint, point}, {:namedCurve, oid}} = key
       )
       when is_binary(point) and byte_size(point) == size,
       do: {:ok, {elem(key, 1), elem(key, 2)}}

  defp validate_public_key(%{key: :eddsa}, {_, {:ECPoint, _}, _}),
    do: {:error, {:key_type_mismatch, :eddsa}}

  defp validate_public_key(%{key: :rsa_pss}, {:RSAPublicKey, _, _}),
    do: {:error, {:key_type_mismatch, :rsa_pss}}

  defp validate_public_key(%{key: :rsa}, {@rsa_pss_oid, _, _}),
    do: {:error, {:key_type_mismatch, :rsa}}

  defp validate_public_key(%{key: key}, {{:ECPoint, _point}, {:namedCurve, _oid}})
       when key in [:rsa, :rsa_pss],
       do: {:error, {:key_type_mismatch, key}}

  defp validate_public_key(_key_type, _public_key), do: {:error, :invalid_public_key}

  defp valid_pss_parameters?(:asn1_NOVALUE, _hash, _options), do: true

  defp valid_pss_parameters?(
         {:"RSASSA-PSS-params", hash_algorithm, mask_gen_algorithm, salt_length, 1},
         hash,
         options
       ) do
    hash_oid = Map.fetch!(@hash_oids, hash)

    valid_hash_algorithm?(hash_algorithm, hash_oid) and
      case mask_gen_algorithm do
        {:MaskGenAlgorithm, @mgf1_oid, mgf_hash} -> valid_hash_algorithm?(mgf_hash, hash_oid)
        _ -> false
      end and salt_length == Keyword.fetch!(options, :rsa_pss_saltlen)
  end

  defp valid_pss_parameters?(_, _, _), do: false

  defp valid_hash_algorithm?({:HashAlgorithm, oid, parameters}, oid)
       when parameters in [:NULL, :asn1_NOVALUE],
       do: true

  defp valid_hash_algorithm?(_, _), do: false

  defp validate_private_key(
         %{key: :ecdsa, curve_oid: oid},
         {:ECPrivateKey, _, _, {:namedCurve, oid}, _, _} = key
       ),
       do: {:ok, key}

  defp validate_private_key(
         %{key: :eddsa, curve_oid: oid},
         {:ECPrivateKey, _, _, {:namedCurve, oid}, _, _} = key
       ),
       do: {:ok, key}

  defp validate_private_key(
         %{key: :rsa},
         {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key
       ),
       do: {:ok, key}

  defp validate_private_key(
         %{key: :rsa_pss, hash: hash, verify_options: options},
         {{:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key, parameters}
       ) do
    if valid_pss_parameters?(parameters, hash, options),
      do: {:ok, key},
      else: {:error, :invalid_rsa_pss_parameters}
  end

  defp validate_private_key(%{key: key}, _private_key), do: {:error, {:key_type_mismatch, key}}

  defp validate_signature_encoding(%{key: :ecdsa}, signature) do
    case :public_key.der_decode(:"ECDSA-Sig-Value", signature) do
      {:"ECDSA-Sig-Value", r, s} when is_integer(r) and r > 0 and is_integer(s) and s > 0 ->
        if :public_key.der_encode(:"ECDSA-Sig-Value", {:"ECDSA-Sig-Value", r, s}) == signature,
          do: :ok,
          else: {:error, :invalid_ecdsa_signature_encoding}

      _ ->
        {:error, :invalid_ecdsa_signature_encoding}
    end
  catch
    :error, _reason -> {:error, :invalid_ecdsa_signature_encoding}
  end

  defp validate_signature_encoding(%{key: :eddsa}, signature) when byte_size(signature) == 64,
    do: :ok

  defp validate_signature_encoding(%{key: :eddsa}, _signature),
    do: {:error, :invalid_certificate_verify}

  defp validate_signature_encoding(_scheme, _signature), do: :ok

  defp validate_signature(signature) when is_binary(signature) and byte_size(signature) > 0,
    do: :ok

  defp validate_signature(<<>>), do: {:error, :empty_signature}
  defp validate_signature(_signature), do: {:error, {:invalid_input, :signature}}

  defp validate_transcript_hash(transcript_hash, expected_length)
       when is_binary(transcript_hash) and byte_size(transcript_hash) == expected_length,
       do: :ok

  defp validate_transcript_hash(transcript_hash, _expected_length)
       when not is_binary(transcript_hash),
       do: {:error, {:invalid_input, :transcript_hash}}

  defp validate_transcript_hash(_transcript_hash, expected_length),
    do: {:error, {:invalid_transcript_hash_length, expected_length}}

  defp hash_length(:sha256), do: {:ok, 32}
  defp hash_length(:sha384), do: {:ok, 48}
  defp hash_length(:sha512), do: {:ok, 64}
  defp hash_length(_hash), do: {:error, :unsupported_hash}

  defp verify(signed_content, hash, signature, public_key, options) do
    if :public_key.verify(signed_content, hash, signature, public_key, options) do
      :ok
    else
      {:error, :invalid_certificate_verify}
    end
  catch
    :error, _reason -> {:error, :signature_verification_failed}
  end
end
