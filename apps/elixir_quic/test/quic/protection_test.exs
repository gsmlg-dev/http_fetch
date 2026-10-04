defmodule Quic.ProtectionTest do
  use ExUnit.Case, async: true
  import Bitwise

  @dcid Base.decode16!("8394c8f03e515708", case: :lower)

  test "Retry integrity matches RFC 9001 Appendix A.4" do
    original = Base.decode16!("8394c8f03e515708", case: :lower)

    packet =
      Base.decode16!("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba",
        case: :lower
      )

    assert :ok = Quic.Protection.validate_retry(original, packet)
  end

  test "ChaCha header protection matches the RFC 8439 section 2.3.2 block" do
    key = :binary.list_to_bin(Enum.to_list(0..31))
    nonce = Base.decode16!("000000090000004A00000000")
    sample = <<1::little-32, nonce::binary>>

    assert {:ok, <<0x10, 0xF1, 0xE7, 0xE4, 0xD1>>} =
             Quic.Protection.header_protection_mask(key, sample, :chacha20_poly1305)
  end

  test "packet AEAD uses the installed algorithm for every supported TLS suite" do
    for {algorithm, length} <- [aes_128_gcm: 16, aes_256_gcm: 32, chacha20_poly1305: 32] do
      key = :binary.copy(<<1>>, length)
      iv = <<0::96>>

      {cipher, tag} =
        :crypto.crypto_one_time_aead(algorithm, key, <<42::96>>, "QUIC", "header", 16, true)

      expected = cipher <> tag

      assert {:ok, ^expected} =
               Quic.Protection.aead_encrypt(key, iv, 42, "header", "QUIC", algorithm)

      assert {:ok, "QUIC"} =
               Quic.Protection.aead_decrypt(key, iv, 42, "header", expected, algorithm)
    end
  end

  test "short headers unmask all five low bits including bit four" do
    # AES-128 with zero key and block 1 gives 58e2fccefa7e3061367f1d57a4e7455a.
    # The fifth low mask bit is set, exposing a long-header mask used on a short header.
    sample = <<1::128>>
    protected = <<0x58, 1, 2, 3, 4, 0xE2, 0, 0, 0, sample::binary>>
    expected = <<0x40, 1, 2, 3, 4, 0, 0, 0, 0, sample::binary>>

    assert {:ok, ^expected, 1} =
             Quic.Protection.remove_header_protection(protected, 5, <<0::128>>, :aes_128_gcm)
  end

  test "RFC 9001 Initial client vectors" do
    assert {:ok, keys} = Quic.Protection.initial_secrets(@dcid, :client)

    assert Base.encode16(keys.secret, case: :lower) ==
             "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"

    assert Base.encode16(keys.key, case: :lower) == "1f369613dd76d5467730efcbe3b1a22d"
    assert keys.iv == Base.decode16!("fa044b2f42a3fd3b46fb255c", case: :lower)
    assert keys.hp == Base.decode16!("9f50449e04a0e810283a1e9933adedd2", case: :lower)
  end

  test "AES-GCM packet protection round trips and rejects a bad tag" do
    assert {:ok, keys} = Quic.Protection.initial_secrets(@dcid, :client)

    assert {:ok, ciphertext} =
             Quic.Protection.aead_encrypt(keys.key, keys.iv, 0, <<1, 2>>, "payload")

    assert {:ok, "payload"} =
             Quic.Protection.aead_decrypt(keys.key, keys.iv, 0, <<1, 2>>, ciphertext)

    head = binary_part(ciphertext, 0, byte_size(ciphertext) - 1)
    last = :binary.last(ciphertext)

    assert {:error, :bad_tag} =
             Quic.Protection.aead_decrypt(
               keys.key,
               keys.iv,
               0,
               <<1, 2>>,
               head <> <<bxor(last, 1)>>
             )
  end

  test "header protection requires a full sample and Retry tags are deterministic" do
    assert {:error, :short_sample} =
             Quic.Protection.header_protection_mask(<<0::128>>, <<0::64>>, :aes_128_gcm)

    assert {:ok, tag} = Quic.Protection.retry_tag(<<1, 2, 3>>, <<4, 5, 6>>)
    assert byte_size(tag) == 16
    assert :ok == Quic.Protection.validate_retry(<<1, 2, 3>>, <<4, 5, 6, tag::binary>>)

    assert {:error, :invalid_retry_tag} =
             Quic.Protection.validate_retry(<<1, 2, 3>>, <<4, 5, 6, 0::128>>)
  end
end
