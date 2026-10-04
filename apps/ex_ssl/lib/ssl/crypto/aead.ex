defmodule SSL.Crypto.AEAD do
  @moduledoc """
  Pure TLS 1.3 AEAD encryption and authenticated decryption.

  The record nonce is derived from the supplied traffic state's static IV and
  sequence number. Sequence advancement remains the caller's responsibility.
  """

  alias SSL.Crypto.TrafficState

  @tag_length 16
  @iv_length 12
  @maximum_ciphertext_length 16_640
  @maximum_content_length @maximum_ciphertext_length - @tag_length

  @type error_reason ::
          :authentication_failed
          | :encryption_failed
          | :decryption_failed
          | :invalid_traffic_state
          | {:unsupported_cipher_suite, term()}
          | {:unsupported_capability, TrafficState.cipher_suite()}
          | {:invalid_key, :not_binary | :wrong_length}
          | {:invalid_iv, :not_binary | :wrong_length}
          | {:invalid_sequence, :out_of_range}
          | {:invalid_aad, :not_binary}
          | {:invalid_plaintext, :not_binary | :too_long}
          | {:invalid_ciphertext, :not_binary | :too_long}
          | {:invalid_tag, :not_binary | :wrong_length}

  @spec supported?(term()) :: boolean()
  def supported?(cipher_suite) do
    case cipher_spec(cipher_suite) do
      {:ok, cipher, _key_length} -> cipher in :crypto.supports(:ciphers)
      {:error, _reason} -> false
    end
  end

  @spec encrypt(TrafficState.t(), term(), term()) ::
          {:ok, binary(), binary()} | {:error, error_reason()}
  def encrypt(%TrafficState{} = state, aad, plaintext) do
    with {:ok, cipher} <- validate_state(state),
         :ok <- validate_aad(aad),
         :ok <- validate_content(plaintext, :plaintext),
         {:ok, nonce} <- TrafficState.nonce(state) do
      encrypt_with_cipher(cipher, state.key, nonce, aad, plaintext)
    end
  end

  def encrypt(_state, _aad, _plaintext), do: {:error, :invalid_traffic_state}

  @spec decrypt(TrafficState.t(), term(), term(), term()) ::
          {:ok, binary()} | {:error, error_reason()}
  def decrypt(%TrafficState{} = state, aad, ciphertext, tag) do
    with {:ok, cipher} <- validate_state(state),
         :ok <- validate_aad(aad),
         :ok <- validate_content(ciphertext, :ciphertext),
         :ok <- validate_tag(tag),
         {:ok, nonce} <- TrafficState.nonce(state) do
      decrypt_with_cipher(cipher, state.key, nonce, aad, ciphertext, tag)
    end
  end

  def decrypt(_state, _aad, _ciphertext, _tag), do: {:error, :invalid_traffic_state}

  defp validate_state(%TrafficState{
         cipher_suite: cipher_suite,
         key: key,
         iv: iv,
         sequence: sequence
       }) do
    with {:ok, cipher, key_length} <- cipher_spec(cipher_suite),
         true <- cipher in :crypto.supports(:ciphers),
         :ok <- validate_key(key, key_length),
         :ok <- validate_iv(iv),
         :ok <- validate_sequence(sequence) do
      {:ok, cipher}
    else
      false -> {:error, {:unsupported_capability, cipher_suite}}
      {:error, _reason} = error -> error
    end
  end

  defp cipher_spec(cipher_suite) do
    case SSL.Capabilities.resolve(:cipher_suite, cipher_suite) do
      %{version: 0x0304, cipher: cipher, key_length: length} -> {:ok, cipher, length}
      _ -> {:error, {:unsupported_cipher_suite, cipher_suite}}
    end
  end

  defp validate_key(key, key_length) when is_binary(key) and byte_size(key) == key_length, do: :ok

  defp validate_key(key, _key_length) when is_binary(key),
    do: {:error, {:invalid_key, :wrong_length}}

  defp validate_key(_key, _key_length), do: {:error, {:invalid_key, :not_binary}}

  defp validate_iv(iv) when is_binary(iv) and byte_size(iv) == @iv_length, do: :ok
  defp validate_iv(iv) when is_binary(iv), do: {:error, {:invalid_iv, :wrong_length}}
  defp validate_iv(_iv), do: {:error, {:invalid_iv, :not_binary}}

  defp validate_sequence(sequence)
       when is_integer(sequence) and sequence >= 0 and sequence <= 0xFFFFFFFFFFFFFFFF,
       do: :ok

  defp validate_sequence(_sequence), do: {:error, {:invalid_sequence, :out_of_range}}

  defp validate_aad(aad) when is_binary(aad), do: :ok
  defp validate_aad(_aad), do: {:error, {:invalid_aad, :not_binary}}

  defp validate_content(value, field) when is_binary(value) do
    if byte_size(value) <= @maximum_content_length do
      :ok
    else
      invalid_content(field, :too_long)
    end
  end

  defp validate_content(_value, field), do: invalid_content(field, :not_binary)

  defp invalid_content(:plaintext, reason), do: {:error, {:invalid_plaintext, reason}}
  defp invalid_content(:ciphertext, reason), do: {:error, {:invalid_ciphertext, reason}}

  defp validate_tag(tag) when is_binary(tag) and byte_size(tag) == @tag_length, do: :ok
  defp validate_tag(tag) when is_binary(tag), do: {:error, {:invalid_tag, :wrong_length}}
  defp validate_tag(_tag), do: {:error, {:invalid_tag, :not_binary}}

  defp encrypt_with_cipher(cipher, key, nonce, aad, plaintext) do
    case :crypto.crypto_one_time_aead(cipher, key, nonce, plaintext, aad, @tag_length, true) do
      {ciphertext, tag} -> {:ok, ciphertext, tag}
    end
  catch
    :error, _reason -> {:error, :encryption_failed}
  end

  defp decrypt_with_cipher(cipher, key, nonce, aad, ciphertext, tag) do
    case :crypto.crypto_one_time_aead(cipher, key, nonce, ciphertext, aad, tag, false) do
      :error -> {:error, :authentication_failed}
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
    end
  catch
    :error, _reason -> {:error, :decryption_failed}
  end
end
