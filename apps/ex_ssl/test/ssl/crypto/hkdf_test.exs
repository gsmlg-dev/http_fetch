defmodule SSL.Crypto.HKDFTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.HKDF

  test "extract matches RFC 5869 Appendix A.1" do
    ikm = :binary.copy(<<0x0B>>, 22)
    salt = Base.decode16!("000102030405060708090A0B0C")

    assert HKDF.extract(:sha256, salt, ikm) ==
             Base.decode16!("077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5")
  end

  test "expand matches RFC 5869 Appendix A.1" do
    prk = Base.decode16!("077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5")
    info = Base.decode16!("F0F1F2F3F4F5F6F7F8F9")

    assert HKDF.expand(:sha256, prk, info, 42) ==
             Base.decode16!(
               "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865"
             )
  end

  test "SHA-384 extract and expand match an independent OpenSSL 3 vector" do
    ikm =
      Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")

    salt = Base.decode16!("606162636465666768696A6B6C6D6E6F")
    info = Base.decode16!("F0F1F2F3F4F5F6F7F8F9")
    prk = HKDF.extract(:sha384, salt, ikm)

    assert HKDF.expand(:sha384, prk, info, 48) ==
             Base.decode16!(
               "2140D1485FEAE424DA62FBCD47F6C593C4DD158FB1965133F46A0ACDEEB5E86CFC82228C43ADE68BB9BD2DCCD5E65E0D"
             )
  end

  test "expand enforces the RFC 5869 output length bounds" do
    prk = :binary.copy(<<0>>, 32)
    maximum_length = 255 * 32

    assert HKDF.expand(:sha256, prk, <<>>, 0) == <<>>
    assert byte_size(HKDF.expand(:sha256, prk, <<>>, maximum_length)) == maximum_length

    assert {:error, {:length_out_of_range, ^maximum_length}} =
             HKDF.expand(:sha256, prk, <<>>, maximum_length + 1)

    assert {:error, {:length_out_of_range, ^maximum_length}} =
             HKDF.expand(:sha256, prk, <<>>, -1)
  end

  test "expand_label matches the TLS 1.3 derivation in RFC 8448" do
    early_secret =
      Base.decode16!("33AD0A1C607EC03B09E6CD9893680CE210ADF300AA1F2660E1B22E10F170F92A")

    empty_transcript_hash =
      Base.decode16!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")

    assert HKDF.expand_label(
             :sha256,
             early_secret,
             "derived",
             empty_transcript_hash,
             32
           ) ==
             Base.decode16!("6F2615A108C702C5678F54FC9DBAB69716C076189C48250CEBEAC3576C3611BA")
  end

  test "expand_label enforces the TLS HkdfLabel field bounds" do
    secret = :binary.copy(<<0>>, 32)
    maximum_length = 255 * 32

    assert {:error, {:label_length_out_of_range, {1, 249}}} =
             HKDF.expand_label(:sha256, secret, <<>>, <<>>, 32)

    assert {:error, {:label_length_out_of_range, {1, 249}}} =
             HKDF.expand_label(:sha256, secret, :binary.copy("a", 250), <<>>, 32)

    assert {:error, {:context_length_out_of_range, 255}} =
             HKDF.expand_label(:sha256, secret, "key", :binary.copy(<<0>>, 256), 32)

    assert {:error, {:length_out_of_range, ^maximum_length}} =
             HKDF.expand_label(:sha256, secret, "key", <<>>, maximum_length + 1)
  end

  test "derive_secret uses the cipher-suite hash length" do
    early_secret =
      Base.decode16!("33AD0A1C607EC03B09E6CD9893680CE210ADF300AA1F2660E1B22E10F170F92A")

    empty_transcript_hash =
      Base.decode16!("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")

    assert HKDF.derive_secret(:sha256, early_secret, "derived", empty_transcript_hash) ==
             Base.decode16!("6F2615A108C702C5678F54FC9DBAB69716C076189C48250CEBEAC3576C3611BA")
  end

  test "rejects hashes outside the supported TLS 1.3 cipher-suite hashes" do
    assert {:error, :unsupported_hash} = HKDF.extract(:sha512, <<>>, <<>>)
    assert {:error, :unsupported_hash} = HKDF.expand(:sha512, <<>>, <<>>, 32)
    assert {:error, :unsupported_hash} = HKDF.expand_label(:sha512, <<>>, "key", <<>>, 32)
    assert {:error, :unsupported_hash} = HKDF.derive_secret(:sha512, <<>>, "derived", <<>>)
  end

  test "derive_secret rejects a transcript hash of the wrong size" do
    assert {:error, {:invalid_transcript_hash_length, 32}} =
             HKDF.derive_secret(:sha256, :binary.copy(<<0>>, 32), "derived", <<0>>)

    assert {:error, {:invalid_transcript_hash_length, 48}} =
             HKDF.derive_secret(:sha384, :binary.copy(<<0>>, 48), "derived", <<0::256>>)
  end
end
