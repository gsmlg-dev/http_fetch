defmodule SSL.Crypto.HKDF do
  @moduledoc """
  HKDF and TLS 1.3 labeled key derivation.

  Only the SHA-256 and SHA-384 cipher-suite hashes are supported.
  """

  @type hash :: :sha256 | :sha384
  @type error ::
          {:error, :unsupported_hash}
          | {:error, {:length_out_of_range, pos_integer()}}
          | {:error, {:label_length_out_of_range, {1, 249}}}
          | {:error, {:context_length_out_of_range, 255}}
          | {:error, {:invalid_transcript_hash_length, pos_integer()}}

  @spec extract(atom(), binary(), binary()) :: binary() | error()
  def extract(hash, salt, ikm)
      when hash in [:sha256, :sha384] and is_binary(salt) and is_binary(ikm) do
    :crypto.mac(:hmac, hash, salt, ikm)
  end

  def extract(hash, _salt, _ikm) when hash not in [:sha256, :sha384],
    do: {:error, :unsupported_hash}

  @spec expand(atom(), binary(), binary(), integer()) :: binary() | error()
  def expand(hash, prk, info, length)
      when hash in [:sha256, :sha384] and is_binary(prk) and is_binary(info) and
             is_integer(length) do
    hash_length = hash_length(hash)
    maximum_length = 255 * hash_length

    cond do
      length < 0 or length > maximum_length ->
        {:error, {:length_out_of_range, maximum_length}}

      length == 0 ->
        <<>>

      true ->
        do_expand(hash, prk, info, length, hash_length)
    end
  end

  def expand(hash, _prk, _info, _length) when hash not in [:sha256, :sha384],
    do: {:error, :unsupported_hash}

  defp do_expand(hash, prk, info, length, hash_length) do
    block_count = div(length + hash_length - 1, hash_length)

    {blocks, _previous} =
      Enum.reduce(1..block_count, {[], <<>>}, fn counter, {blocks, previous} ->
        block = :crypto.mac(:hmac, hash, prk, [previous, info, <<counter>>])
        {[block | blocks], block}
      end)

    blocks
    |> Enum.reverse()
    |> :erlang.iolist_to_binary()
    |> binary_part(0, length)
  end

  @spec expand_label(atom(), binary(), binary(), binary(), integer()) ::
          binary() | error()
  def expand_label(hash, secret, label, context, length)
      when hash in [:sha256, :sha384] and is_binary(secret) and is_binary(label) and
             is_binary(context) and is_integer(length) do
    label_length = byte_size(label)
    context_length = byte_size(context)
    hash_length = hash_length(hash)
    maximum_length = 255 * hash_length

    cond do
      label_length < 1 or label_length > 249 ->
        {:error, {:label_length_out_of_range, {1, 249}}}

      context_length > 255 ->
        {:error, {:context_length_out_of_range, 255}}

      length < 0 or length > maximum_length ->
        {:error, {:length_out_of_range, maximum_length}}

      true ->
        full_label = <<"tls13 ", label::binary>>

        hkdf_label =
          <<length::16, byte_size(full_label), full_label::binary, context_length,
            context::binary>>

        expand(hash, secret, hkdf_label, length)
    end
  end

  def expand_label(hash, _secret, _label, _context, _length)
      when hash not in [:sha256, :sha384],
      do: {:error, :unsupported_hash}

  @spec derive_secret(atom(), binary(), binary(), binary()) :: binary() | error()
  def derive_secret(hash, secret, label, transcript_hash)
      when hash in [:sha256, :sha384] and is_binary(secret) and is_binary(label) and
             is_binary(transcript_hash) do
    hash_length = hash_length(hash)

    if byte_size(transcript_hash) == hash_length do
      expand_label(hash, secret, label, transcript_hash, hash_length)
    else
      {:error, {:invalid_transcript_hash_length, hash_length}}
    end
  end

  def derive_secret(hash, _secret, _label, _transcript_hash)
      when hash not in [:sha256, :sha384],
      do: {:error, :unsupported_hash}

  defp hash_length(:sha256), do: 32
  defp hash_length(:sha384), do: 48
end
