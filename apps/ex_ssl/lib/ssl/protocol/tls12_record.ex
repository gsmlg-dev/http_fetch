defmodule SSL.Protocol.TLS12Record do
  @moduledoc "Pure TLS 1.2 AES-GCM record protection for one directional traffic epoch."

  @version 0x0303
  @max_plaintext 16_384
  @tag_length 16
  @explicit_nonce_length 8
  @max_ciphertext @max_plaintext + @tag_length + @explicit_nonce_length
  @maximum_sequence 0xFFFFFFFFFFFFFFFF
  @aes_gcm_encryption_limit 23_726_566

  @derive {Inspect, except: [:key, :iv]}
  @enforce_keys [:cipher, :key, :iv]
  defstruct [:cipher, :key, :iv, sequence: 0]

  @type cipher :: :aes_128_gcm | :aes_256_gcm
  @type content_type :: :alert | :handshake | :application_data
  @type t :: %__MODULE__{
          cipher: cipher(),
          key: binary(),
          iv: <<_::32>>,
          sequence: non_neg_integer()
        }

  @spec new(term(), term(), term()) :: {:ok, t()} | {:error, term()}
  def new(cipher, key, iv) do
    if valid_key?(cipher, key) and is_binary(iv) and byte_size(iv) == 4,
      do: {:ok, %__MODULE__{cipher: cipher, key: key, iv: iv}},
      else: {:error, :invalid_traffic_state}
  end

  @spec encrypt(t(), content_type(), binary()) :: {:ok, binary(), t()} | {:error, term()}
  def encrypt(%__MODULE__{} = state, type, plaintext) do
    with :ok <- validate_state(state),
         {:ok, type_id} <- type_id(type),
         :ok <- validate_plaintext(plaintext),
         :ok <- may_encrypt(state.sequence) do
      explicit = <<state.sequence::unsigned-big-integer-size(64)>>
      nonce = state.iv <> explicit
      aad = <<state.sequence::64, type_id, @version::16, byte_size(plaintext)::16>>

      case :crypto.crypto_one_time_aead(
             state.cipher,
             state.key,
             nonce,
             plaintext,
             aad,
             @tag_length,
             true
           ) do
        {ciphertext, tag} ->
          length = @explicit_nonce_length + byte_size(ciphertext) + @tag_length

          wire =
            <<type_id, @version::16, length::16, explicit::binary, ciphertext::binary,
              tag::binary>>

          {:ok, wire, %{state | sequence: state.sequence + 1}}

        _ ->
          {:error, :encryption_failed}
      end
    end
  end

  def encrypt(_, _, _), do: {:error, :invalid_traffic_state}

  @spec decrypt(t(), binary()) :: {:ok, content_type(), binary(), t()} | {:error, term()}
  def decrypt(%__MODULE__{} = state, wire) do
    with :ok <- validate_state(state),
         :ok <- may_decrypt(state.sequence),
         {:ok, type, explicit, ciphertext, tag} <- parse(wire) do
      nonce = state.iv <> explicit
      aad = <<state.sequence::64, type_id!(type), @version::16, byte_size(ciphertext)::16>>

      case :crypto.crypto_one_time_aead(
             state.cipher,
             state.key,
             nonce,
             ciphertext,
             aad,
             tag,
             false
           ) do
        plaintext when is_binary(plaintext) ->
          {:ok, type, plaintext, %{state | sequence: state.sequence + 1}}

        :error ->
          {:error, :authentication_failed}
      end
    end
  end

  def decrypt(_, _), do: {:error, :invalid_traffic_state}

  defp parse(wire) when not is_binary(wire), do: {:error, :invalid_record}
  defp parse(wire) when byte_size(wire) < 5, do: {:error, :malformed_record}

  defp parse(<<type_id, version::16, length::16, body::binary>>) do
    cond do
      version != @version ->
        {:error, :invalid_record_version}

      length > @max_ciphertext ->
        {:error, :record_length_exceeded}

      length != byte_size(body) ->
        {:error, :record_length_mismatch}

      length < @explicit_nonce_length + @tag_length ->
        {:error, :ciphertext_too_short}

      true ->
        with {:ok, type} <- type_atom(type_id) do
          ciphertext_length = length - @explicit_nonce_length - @tag_length

          <<explicit::binary-size(@explicit_nonce_length),
            ciphertext::binary-size(^ciphertext_length), tag::binary-size(@tag_length)>> = body

          {:ok, type, explicit, ciphertext, tag}
        end
    end
  end

  defp valid_key?(:aes_128_gcm, key), do: is_binary(key) and byte_size(key) == 16
  defp valid_key?(:aes_256_gcm, key), do: is_binary(key) and byte_size(key) == 32
  defp valid_key?(_, _), do: false

  defp validate_state(%__MODULE__{cipher: cipher, key: key, iv: iv, sequence: sequence}) do
    if valid_key?(cipher, key) and is_binary(iv) and byte_size(iv) == 4 and
         is_integer(sequence) and sequence in 0..@maximum_sequence,
       do: :ok,
       else: {:error, :invalid_traffic_state}
  end

  defp validate_plaintext(data) when is_binary(data) and byte_size(data) <= @max_plaintext,
    do: :ok

  defp validate_plaintext(_), do: {:error, :invalid_plaintext}

  defp may_encrypt(sequence) when sequence < @aes_gcm_encryption_limit, do: :ok
  defp may_encrypt(_), do: {:error, :key_usage_exhausted}
  defp may_decrypt(sequence) when sequence < @maximum_sequence, do: :ok
  defp may_decrypt(_), do: {:error, :sequence_exhausted}

  defp type_id(:alert), do: {:ok, 21}
  defp type_id(:handshake), do: {:ok, 22}
  defp type_id(:application_data), do: {:ok, 23}
  defp type_id(_), do: {:error, :unsupported_content_type}

  defp type_id!(:alert), do: 21
  defp type_id!(:handshake), do: 22
  defp type_id!(:application_data), do: 23

  defp type_atom(21), do: {:ok, :alert}
  defp type_atom(22), do: {:ok, :handshake}
  defp type_atom(23), do: {:ok, :application_data}
  defp type_atom(_), do: {:error, :unsupported_content_type}
end
