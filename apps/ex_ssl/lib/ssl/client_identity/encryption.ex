defmodule SSL.ClientIdentity.Encryption do
  @moduledoc false
  # These are public PKCS ASN.1 records returned by public_key.pem_decode/1.
  # Only admission/parameter checks live here; public_key performs all decryption.
  @pbkdf2 {1, 2, 840, 113_549, 1, 5, 12}
  @max_iterations 1_000_000
  @max_work 2_000_000
  @max_salt 65_536
  @max_ciphertext 1_048_576

  @spec validate(term(), binary() | :absent) :: :ok | :error
  def validate({_type, bytes, {cipher, parameters}}, password) when is_binary(password) do
    with {:ok, info} <- cipher(cipher),
         true <- is_binary(bytes) and byte_size(bytes) in 1..@max_ciphertext,
         true <- rem(byte_size(bytes), info.block) == 0,
         true <- info.name in :crypto.supports(:ciphers),
         :ok <- parameters(parameters, cipher, info, byte_size(password)) do
      :ok
    else
      _ -> :error
    end
  catch
    _, _ -> :error
  end

  def validate(_, _), do: :error

  defp cipher(~c"AES-128-CBC"),
    do: {:ok, %{name: :aes_128_cbc, key: 16, block: 16, oid: {2, 16, 840, 1, 101, 3, 4, 1, 2}}}

  defp cipher(~c"AES-192-CBC"),
    do: {:ok, %{name: :aes_192_cbc, key: 24, block: 16, oid: {2, 16, 840, 1, 101, 3, 4, 1, 22}}}

  defp cipher(~c"AES-256-CBC"),
    do: {:ok, %{name: :aes_256_cbc, key: 32, block: 16, oid: {2, 16, 840, 1, 101, 3, 4, 1, 42}}}

  defp cipher(~c"DES-CBC"),
    do: {:ok, %{name: :des_cbc, key: 8, block: 8, oid: {1, 3, 14, 3, 2, 7}}}

  defp cipher(~c"DES-EDE3-CBC"),
    do: {:ok, %{name: :des_ede3_cbc, key: 24, block: 8, oid: {1, 2, 840, 113_549, 3, 7}}}

  defp cipher(~c"RC2-CBC"),
    do: {:ok, %{name: :rc2_cbc, key: 16, block: 8, oid: {1, 2, 840, 113_549, 3, 2}}}

  defp cipher(_), do: :error

  defp parameters(iv, _cipher, info, _password_size) when is_binary(iv),
    do: require_true(byte_size(iv) == info.block)

  defp parameters({{:PBEParameter, salt, count}, hash}, cipher, _info, password_size)
       when cipher in [~c"DES-CBC", ~c"RC2-CBC"] and hash in [:md5, :sha] do
    with true <- is_binary(salt) and byte_size(salt) == 8,
         true <- valid_count?(count),
         true <- count - 1 + ceil_div(password_size + 8, 64) <= @max_work do
      :ok
    else
      _ -> :error
    end
  end

  defp parameters(
         {:"PBES2-params",
          {:"PBES2-params_keyDerivationFunc", @pbkdf2,
           {:"PBKDF2-params", {:specified, salt}, count, length, prf}},
          {:"PBES2-params_encryptionScheme", oid, encoded_iv}},
         _cipher,
         info,
         password_size
       ) do
    with true <- oid == info.oid,
         true <- is_binary(salt) and byte_size(salt) <= @max_salt,
         true <- valid_count?(count),
         {:ok, key_size} <- key_size(length, info),
         {:ok, output_size, hash_block} <- prf(prf),
         :ok <- iv(encoded_iv, info),
         blocks = ceil_div(key_size, output_size),
         cost =
           blocks *
             (count * max(1, ceil_div(password_size, hash_block)) +
                ceil_div(byte_size(salt), hash_block)),
         true <- cost <= @max_work do
      :ok
    else
      _ -> :error
    end
  end

  defp parameters(_, _, _, _), do: :error

  defp valid_count?(count), do: is_integer(count) and count in 1..@max_iterations
  defp key_size(:asn1_NOVALUE, info), do: {:ok, info.key}
  # RC2 is a variable-key cipher; do not force the fixed AES/DES key lengths on it.
  defp key_size(size, %{name: :rc2_cbc}) when is_integer(size) and size in 1..128,
    do: {:ok, size}

  defp key_size(size, %{key: size}), do: {:ok, size}
  defp key_size(_, _), do: :error

  defp prf(:asn1_DEFAULT), do: {:ok, 20, 64}

  defp prf({:"PBKDF2-params_prf", oid, parameters})
       when parameters in [:NULL, :asn1_NOVALUE, {:asn1_OPENTYPE, <<5, 0>>}] do
    case oid do
      {1, 2, 840, 113_549, 2, 7} -> {:ok, 20, 64}
      {1, 2, 840, 113_549, 2, 8} -> {:ok, 28, 64}
      {1, 2, 840, 113_549, 2, 9} -> {:ok, 32, 64}
      {1, 2, 840, 113_549, 2, 10} -> {:ok, 48, 128}
      {1, 2, 840, 113_549, 2, 11} -> {:ok, 64, 128}
      {_, _, _, :"id-hmacWithSHA1"} -> {:ok, 20, 64}
      _ -> :error
    end
  end

  defp prf(_), do: :error

  defp iv({:asn1_OPENTYPE, der}, %{name: :rc2_cbc, block: block}) do
    case :public_key.der_decode(:"RC2-CBC-Parameter", der) do
      {:"RC2-CBC-Parameter", version, iv}
      when (version == :asn1_NOVALUE or (is_integer(version) and version in 0..1024)) and
             is_binary(iv) and byte_size(iv) == block ->
        :ok

      _ ->
        :error
    end
  end

  defp iv({:asn1_OPENTYPE, <<4, size, iv::binary-size(size)>>}, %{block: size})
       when byte_size(iv) == size, do: :ok

  defp iv(_, _), do: :error

  defp ceil_div(number, divisor), do: div(number + divisor - 1, divisor)
  defp require_true(true), do: :ok
  defp require_true(false), do: :error
end
