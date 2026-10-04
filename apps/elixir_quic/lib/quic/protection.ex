defmodule Quic.Protection do
  @moduledoc """
  QUIC v1 Initial packet protection primitives.
  """
  import Bitwise

  @salt Base.decode16!("38762c f7f55934 b34d179a e6a4c80c adccbb7f 0a" |> String.replace(" ", ""),
          case: :lower
        )
  @retry_key Base.decode16!("be0c690b 9f66575a 1d766b54 e368c84e" |> String.replace(" ", ""),
               case: :lower
             )
  @retry_nonce Base.decode16!("461599d35d632bf2 239825bb" |> String.replace(" ", ""),
                 case: :lower
               )

  @spec initial_secrets(binary(), :client | :server) :: {:ok, map()} | {:error, atom()}
  def initial_secrets(dcid, role) when is_binary(dcid) and role in [:client, :server] do
    initial = hkdf_extract(@salt, dcid)
    {:ok, client} = hkdf_label(initial, "client in", 32)
    {:ok, server} = hkdf_label(initial, "server in", 32)
    secret = if role == :client, do: client, else: server

    with {:ok, key} <- hkdf_label(secret, "quic key", 16),
         {:ok, iv} <- hkdf_label(secret, "quic iv", 12),
         {:ok, hp} <- hkdf_label(secret, "quic hp", 16) do
      {:ok,
       %{
         client: %{secret: client},
         server: %{secret: server},
         secret: secret,
         key: key,
         iv: iv,
         hp: hp,
         role: role
       }}
    end
  end

  def initial_secrets(_, _), do: {:error, :invalid_initial_context}

  @doc "Derive QUIC Handshake/Application packet protection keys from a TLS secret."
  @spec packet_keys(atom(), non_neg_integer(), atom(), atom(), binary()) ::
          {:ok, map()} | {:error, term()}
  def packet_keys(level, cipher_suite, aead, hkdf, secret)
      when level in [:handshake, :application] and is_integer(cipher_suite) and
             is_binary(secret) do
    with {:ok, spec} <- packet_cipher_spec(cipher_suite, aead, hkdf),
         :ok <- validate_crypto_support(aead, hkdf, spec.hp_algorithm),
         :ok <- validate_secret_length(secret, hkdf),
         {:ok, key} <- hkdf_expand_label(hkdf, secret, "quic key", spec.key_length),
         {:ok, iv} <- hkdf_expand_label(hkdf, secret, "quic iv", 12),
         {:ok, hp} <- hkdf_expand_label(hkdf, secret, "quic hp", spec.hp_length) do
      {:ok,
       %{
         level: level,
         cipher_suite: cipher_suite,
         aead: aead,
         hkdf: hkdf,
         key: key,
         iv: iv,
         hp: hp,
         hp_algorithm: spec.hp_algorithm
       }}
    end
  end

  def packet_keys(_, _, _, _, _), do: {:error, :invalid_packet_key_context}

  @spec aead_encrypt(binary(), binary(), non_neg_integer(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def aead_encrypt(key, iv, packet_number, aad, plaintext, algorithm \\ :aes_128_gcm),
    do: aead(:encrypt, key, iv, packet_number, aad, plaintext, algorithm)

  @spec aead_decrypt(binary(), binary(), non_neg_integer(), binary(), binary()) ::
          {:ok, binary()} | {:error, atom()}
  def aead_decrypt(key, iv, packet_number, aad, ciphertext, algorithm \\ :aes_128_gcm),
    do: aead(:decrypt, key, iv, packet_number, aad, ciphertext, algorithm)

  @spec header_protection_mask(
          binary(),
          binary(),
          :aes_128_gcm | :aes_256_gcm | :chacha20_poly1305
        ) ::
          {:ok, binary()} | {:error, atom()}
  def header_protection_mask(hp, sample, algorithm)
      when is_binary(hp) and byte_size(sample) >= 16 do
    try do
      case algorithm do
        :aes_128_gcm when byte_size(hp) == 16 ->
          {:ok, :crypto.crypto_one_time(:aes_128_ecb, hp, sample, true) |> binary_part(0, 5)}

        :aes_256_gcm when byte_size(hp) == 32 ->
          {:ok, :crypto.crypto_one_time(:aes_256_ecb, hp, sample, true) |> binary_part(0, 5)}

        :chacha20_poly1305 ->
          <<counter::little-32, nonce::binary-size(12)>> = sample

          {:ok,
           :crypto.crypto_one_time(
             :chacha20,
             hp,
             <<counter::little-32, nonce::binary>>,
             <<0, 0, 0, 0, 0>>,
             true
           )
           |> binary_part(0, 5)}

        _ ->
          {:error, :unsupported_header_protection}
      end
    rescue
      _ -> {:error, :crypto_unavailable}
    catch
      _, _ -> {:error, :crypto_unavailable}
    end
  end

  def header_protection_mask(_, _, _), do: {:error, :short_sample}

  @doc "Removes QUIC header protection from a packet prefix and packet number bytes."
  @spec remove_header_protection(
          binary(),
          non_neg_integer(),
          binary(),
          :aes_128_gcm | :chacha20_poly1305
        ) ::
          {:ok, binary(), non_neg_integer()} | {:error, atom()}
  def remove_header_protection(packet, pn_offset, hp, algorithm)
      when is_binary(packet) and is_integer(pn_offset) and pn_offset >= 1 and is_binary(hp) do
    if byte_size(packet) < pn_offset + 4 + 16 do
      {:error, :short_sample}
    else
      sample = binary_part(packet, pn_offset + 4, 16)
      header_rest_size = pn_offset - 1

      with {:ok, mask} <- header_protection_mask(hp, sample, algorithm),
           <<first, header_rest::binary-size(^header_rest_size), rest::binary>> <- packet do
        mask_first = :binary.decode_unsigned(binary_part(mask, 0, 1))
        first_mask = if (first &&& 0x80) == 0, do: 0x1F, else: 0x0F
        first = bxor(first, mask_first &&& first_mask)
        pn_len = (first &&& 3) + 1

        if byte_size(rest) < pn_len do
          {:error, :truncated_packet_number}
        else
          <<pn::binary-size(^pn_len), tail::binary>> = rest

          unmasked =
            for {byte, index} <- Enum.with_index(:binary.bin_to_list(pn)), into: <<>> do
              <<bxor(byte, :binary.at(mask, index + 1))>>
            end

          {:ok, <<first, header_rest::binary, unmasked::binary, tail::binary>>, pn_len}
        end
      else
        _ -> {:error, :malformed_header}
      end
    end
  end

  def remove_header_protection(_, _, _, _), do: {:error, :invalid_header_protection_input}

  @spec retry_tag(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def retry_tag(original_dcid, retry_packet)
      when is_binary(original_dcid) and is_binary(retry_packet) and byte_size(original_dcid) <= 20 do
    pseudo = <<byte_size(original_dcid), original_dcid::binary, retry_packet::binary>>

    try do
      {_, tag} =
        :crypto.crypto_one_time_aead(
          :aes_128_gcm,
          @retry_key,
          @retry_nonce,
          <<>>,
          pseudo,
          16,
          true
        )

      {:ok, tag}
    rescue
      _ -> {:error, :crypto_unavailable}
    catch
      _, _ -> {:error, :crypto_unavailable}
    end
  end

  def retry_tag(_, _), do: {:error, :invalid_retry_input}

  @spec validate_retry(binary(), binary()) :: :ok | {:error, atom()}
  def validate_retry(original_dcid, packet) when is_binary(packet) and byte_size(packet) >= 16 do
    body_size = byte_size(packet) - 16
    <<body::binary-size(^body_size), tag::binary-size(16)>> = packet

    with {:ok, expected} <- retry_tag(original_dcid, body),
         true <- :crypto.hash_equals(expected, tag) do
      :ok
    else
      false -> {:error, :invalid_retry_tag}
      error -> error
    end
  end

  def validate_retry(_, _), do: {:error, :truncated_retry}

  defp aead(mode, key, iv, pn, aad, data, algorithm)
       when is_binary(key) and is_binary(iv) and is_integer(pn) and pn >= 0 and is_binary(aad) and
              is_binary(data) and algorithm in [:aes_128_gcm, :aes_256_gcm, :chacha20_poly1305] do
    if byte_size(iv) != 12 do
      {:error, :invalid_iv}
    else
      try do
        prefix = binary_part(iv, 0, 4)
        suffix = binary_part(iv, 4, 8) |> :binary.decode_unsigned(:big) |> bxor(pn)
        nonce = prefix <> <<suffix::unsigned-big-64>>

        case mode do
          :encrypt ->
            {cipher, tag} =
              :crypto.crypto_one_time_aead(algorithm, key, nonce, data, aad, 16, true)

            {:ok, cipher <> tag}

          :decrypt when byte_size(data) >= 16 ->
            cipher = binary_part(data, 0, byte_size(data) - 16)
            tag = binary_part(data, byte_size(data) - 16, 16)

            case :crypto.crypto_one_time_aead(algorithm, key, nonce, cipher, aad, tag, false) do
              :error -> {:error, :bad_tag}
              plain -> {:ok, plain}
            end

          :decrypt ->
            {:error, :truncated_ciphertext}
        end
      rescue
        _ -> {:error, :crypto_unavailable}
      catch
        _, _ -> {:error, :crypto_unavailable}
      end
    end
  end

  defp aead(_, _, _, _, _, _, _), do: {:error, :invalid_aead_input}

  defp hkdf_extract(salt, input), do: :crypto.mac(:hmac, :sha256, salt, input)
  defp hkdf_expand(prk, info, length), do: hkdf_expand_fallback(prk, info, length)

  defp hkdf_expand_fallback(prk, info, length),
    do: hkdf_expand_fallback(prk, info, length, <<>>, <<>>, 1)

  defp hkdf_expand_fallback(_, _, length, _, out, _) when byte_size(out) >= length,
    do: binary_part(out, 0, length)

  defp hkdf_expand_fallback(prk, info, length, previous, out, counter) do
    block = :crypto.mac(:hmac, :sha256, prk, previous <> info <> <<counter>>)
    hkdf_expand_fallback(prk, info, length, block, out <> block, counter + 1)
  end

  defp hkdf_label(secret, label, length) do
    full_label = "tls13 " <> label
    info = <<length::16, byte_size(full_label)::8, full_label::binary, 0>>
    {:ok, hkdf_expand(secret, info, length)}
  end

  defp hkdf_expand_label(hash, secret, label, length)
       when hash in [:sha256, :sha384] and is_binary(secret) and is_binary(label) and
              is_integer(length) and length >= 0 and length <= 65_535 do
    full_label = "tls13 " <> label
    info = <<length::16, byte_size(full_label)::8, full_label::binary, 0>>
    {:ok, hkdf_expand_hash(hash, secret, info, length)}
  end

  defp hkdf_expand_label(_, _, _, _), do: {:error, :unsupported_hkdf}

  defp hkdf_expand_hash(hash, secret, info, length) do
    hash_length = if hash == :sha256, do: 32, else: 48
    blocks = div(length + hash_length - 1, hash_length)

    {chunks, _previous} =
      Enum.map_reduce(1..blocks, <<>>, fn counter, previous ->
        block = :crypto.mac(:hmac, hash, secret, previous <> info <> <<counter>>)
        {block, block}
      end)

    chunks |> IO.iodata_to_binary() |> binary_part(0, length)
  end

  defp validate_secret_length(secret, :sha256) when byte_size(secret) == 32, do: :ok
  defp validate_secret_length(secret, :sha384) when byte_size(secret) == 48, do: :ok

  defp validate_secret_length(_, _), do: {:error, :invalid_secret_length}

  defp packet_cipher_spec(0x1301, :aes_128_gcm, :sha256),
    do: {:ok, %{key_length: 16, hp_length: 16, hp_algorithm: :aes_128_gcm}}

  defp packet_cipher_spec(0x1302, :aes_256_gcm, :sha384),
    do: {:ok, %{key_length: 32, hp_length: 32, hp_algorithm: :aes_256_gcm}}

  defp packet_cipher_spec(0x1303, :chacha20_poly1305, :sha256),
    do: {:ok, %{key_length: 32, hp_length: 32, hp_algorithm: :chacha20_poly1305}}

  defp packet_cipher_spec(cipher_suite, _aead, _hkdf),
    do: {:error, {:unsupported_cipher_suite, cipher_suite}}

  defp validate_crypto_support(aead, hkdf, hp_algorithm) do
    capabilities = :crypto.supports()
    hashes = Keyword.get(capabilities, :hashs, [])
    ciphers = Keyword.get(capabilities, :ciphers, [])

    cond do
      hkdf not in hashes ->
        {:error, {:unsupported_hkdf, hkdf}}

      aead not in ciphers ->
        {:error, {:unsupported_aead, aead}}

      hp_algorithm == :aes_128_gcm and :aes_128_ecb not in ciphers ->
        {:error, {:unsupported_header_protection, hp_algorithm}}

      hp_algorithm == :aes_256_gcm and :aes_256_ecb not in ciphers ->
        {:error, {:unsupported_header_protection, hp_algorithm}}

      hp_algorithm == :chacha20_poly1305 and :chacha20 not in ciphers ->
        {:error, {:unsupported_header_protection, hp_algorithm}}

      true ->
        :ok
    end
  end
end
