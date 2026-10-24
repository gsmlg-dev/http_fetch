defmodule SSL.EncryptedIdentityParametersTest do
  use ExUnit.Case, async: true
  alias SSL.ClientIdentity.Encryption

  test "preflight permits empty PBES2 salt default PRF and exact explicit key length" do
    assert :ok = Encryption.validate(entry(), <<>>)
    assert :ok = Encryption.validate(entry(salt: <<>>, length: 32), "password")
    assert :ok = Encryption.validate(entry(prf: :asn1_DEFAULT), "password")
  end

  test "preflight bounds encoded work and rejects malformed algorithms salts and IVs" do
    for options <- [
          [count: 0],
          [count: -1],
          [count: 1_000_001],
          [count: :invalid],
          [length: 0],
          [length: 31],
          [length: 1_000_000_000],
          [salt: :invalid],
          [salt: :binary.copy(<<0>>, 65_537)],
          [prf: :unknown],
          [iv: {:asn1_OPENTYPE, <<4, 0>>}],
          [cipher: ~c"UNKNOWN"]
        ] do
      assert :error = Encryption.validate(entry(options), "password")
    end

    assert :error = Encryption.validate(entry(count: 1_000_000), :binary.copy("x", 129))
    assert :error = Encryption.validate(entry(), :absent)
    assert :error = Encryption.validate(put_elem(entry(), 1, <<0>>), "password")
  end

  defp entry(options \\ []) do
    {:PrivateKeyInfo, :binary.copy(<<0>>, 32),
     {Keyword.get(options, :cipher, ~c"AES-256-CBC"),
      {:"PBES2-params",
       {:"PBES2-params_keyDerivationFunc", {1, 2, 840, 113_549, 1, 5, 12},
        {:"PBKDF2-params", {:specified, Keyword.get(options, :salt, <<1, 2>>)},
         Keyword.get(options, :count, 2048), Keyword.get(options, :length, :asn1_NOVALUE),
         Keyword.get(options, :prf, {:"PBKDF2-params_prf", {1, 2, 840, 113_549, 2, 9}, :NULL})}},
       {:"PBES2-params_encryptionScheme", {2, 16, 840, 1, 101, 3, 4, 1, 42},
        Keyword.get(options, :iv, {:asn1_OPENTYPE, <<4, 16, 0::128>>})}}}}
  end
end
