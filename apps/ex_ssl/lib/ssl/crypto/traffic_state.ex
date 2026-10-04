defmodule SSL.Crypto.TrafficState do
  @moduledoc """
  Immutable key material and record sequence state for one TLS traffic epoch.
  """

  @maximum_sequence 0xFFFFFFFFFFFFFFFF
  # RFC 9846 §5.5: AES-GCM permits at most floor(2^24.5) full-size records.
  @aes_gcm_encryption_limit 23_726_566
  # ChaCha20/Poly1305 reaches the TLS uint64 sequence guard first. `sequence`
  # is the zero-based count of records already protected in this epoch.
  @chacha20_poly1305_encryption_limit @maximum_sequence
  @maximum_write_generation 0xFFFFFFFFFFFF

  @type cipher_suite ::
          :tls_aes_128_gcm_sha256
          | :tls_aes_256_gcm_sha384
          | :tls_chacha20_poly1305_sha256

  @type t :: %__MODULE__{
          secret: binary(),
          key: binary(),
          iv: binary(),
          sequence: non_neg_integer(),
          generation: non_neg_integer(),
          cipher_suite: cipher_suite()
        }

  @derive {Inspect, except: [:secret, :key, :iv]}
  @enforce_keys [:secret, :key, :iv, :cipher_suite]
  defstruct [:secret, :key, :iv, :cipher_suite, sequence: 0, generation: 0]

  @doc false
  @spec encryption_limit(cipher_suite()) :: 23_726_566 | 18_446_744_073_709_551_615
  def encryption_limit(:tls_aes_128_gcm_sha256), do: @aes_gcm_encryption_limit
  def encryption_limit(:tls_aes_256_gcm_sha384), do: @aes_gcm_encryption_limit
  def encryption_limit(:tls_chacha20_poly1305_sha256), do: @chacha20_poly1305_encryption_limit

  @doc false
  @spec maximum_write_generation() :: 281_474_976_710_655
  def maximum_write_generation, do: @maximum_write_generation

  @doc false
  @spec may_encrypt?(t()) :: boolean()
  def may_encrypt?(%__MODULE__{sequence: sequence, cipher_suite: cipher_suite})
      when is_integer(sequence) and sequence >= 0 do
    case encryption_limit_for(cipher_suite) do
      {:ok, limit} -> sequence < limit
      :error -> false
    end
  end

  def may_encrypt?(_state), do: false

  @doc false
  @spec key_update_required?(t()) :: boolean()
  def key_update_required?(%__MODULE__{sequence: sequence, cipher_suite: cipher_suite})
      when is_integer(sequence) and sequence >= 0 do
    case encryption_limit_for(cipher_suite) do
      # Reserve the final permitted protection operation for KeyUpdate itself.
      {:ok, limit} -> sequence >= limit - 1
      :error -> true
    end
  end

  def key_update_required?(_state), do: true

  @doc false
  @spec valid_write_generation?(t()) :: boolean()
  def valid_write_generation?(%__MODULE__{generation: generation})
      when is_integer(generation) and generation >= 0 and generation <= @maximum_write_generation,
      do: true

  def valid_write_generation?(_state), do: false

  @doc false
  @spec may_update_write?(t()) :: boolean()
  def may_update_write?(%__MODULE__{generation: generation})
      when is_integer(generation) and generation >= 0 and generation < @maximum_write_generation,
      do: true

  def may_update_write?(_state), do: false

  @spec nonce(t()) :: {:ok, binary()} | {:error, term()}
  def nonce(%__MODULE__{iv: iv, sequence: sequence})
      when is_binary(iv) and byte_size(iv) == 12 and is_integer(sequence) and sequence >= 0 and
             sequence <= @maximum_sequence do
    padding_bits = (byte_size(iv) - 8) * 8
    padded_sequence = <<0::size(padding_bits), sequence::unsigned-big-integer-size(64)>>

    {:ok, :crypto.exor(iv, padded_sequence)}
  end

  def nonce(%__MODULE__{iv: iv}) when is_binary(iv) and byte_size(iv) < 8,
    do: {:error, {:invalid_iv, :too_short}}

  def nonce(%__MODULE__{iv: iv}) when is_binary(iv) and byte_size(iv) != 12,
    do: {:error, {:invalid_iv, :wrong_length}}

  def nonce(%__MODULE__{iv: iv, sequence: sequence})
      when is_binary(iv) and byte_size(iv) == 12 and is_integer(sequence) and
             (sequence < 0 or sequence > @maximum_sequence),
      do: {:error, {:invalid_sequence, :out_of_range}}

  def nonce(%__MODULE__{iv: iv, sequence: sequence})
      when is_binary(iv) and byte_size(iv) == 12 and not is_integer(sequence),
      do: {:error, {:invalid_sequence, :out_of_range}}

  @spec advance(term()) :: {:ok, t()} | {:error, term()}
  def advance(%__MODULE__{sequence: sequence} = state)
      when is_integer(sequence) and sequence >= 0 and sequence < @maximum_sequence do
    {:ok, %{state | sequence: sequence + 1}}
  end

  def advance(%__MODULE__{sequence: @maximum_sequence}), do: {:error, :sequence_exhausted}

  def advance(%__MODULE__{}), do: {:error, {:invalid_sequence, :out_of_range}}
  def advance(_state), do: {:error, :invalid_traffic_state}

  defp encryption_limit_for(:tls_aes_128_gcm_sha256), do: {:ok, @aes_gcm_encryption_limit}
  defp encryption_limit_for(:tls_aes_256_gcm_sha384), do: {:ok, @aes_gcm_encryption_limit}

  defp encryption_limit_for(:tls_chacha20_poly1305_sha256),
    do: {:ok, @chacha20_poly1305_encryption_limit}

  defp encryption_limit_for(_cipher_suite), do: :error
end
