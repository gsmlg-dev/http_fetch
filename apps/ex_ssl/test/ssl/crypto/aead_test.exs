defmodule SSL.Crypto.AEADTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.AEAD
  alias SSL.Crypto.TrafficState

  @aes_128_ciphertext Base.decode16!("0388DACE60B6A392F328C2B971B2FE78")
  @aes_128_tag Base.decode16!("AB6E47D42CEC13BDF53A67B21257BDDF")
  @aes_256_ciphertext Base.decode16!("CEA7403D4D606B6E074EC5D3BAF39D18")
  @aes_256_tag Base.decode16!("D0D1C8A799996BF0265B98B5D48AB919")

  test "AES-128-GCM matches the NIST zero-key test vector" do
    state = state(:tls_aes_128_gcm_sha256, <<0::128>>, <<0::96>>)

    assert {:ok, @aes_128_ciphertext, @aes_128_tag} = AEAD.encrypt(state, <<>>, <<0::128>>)
    assert {:ok, <<0::128>>} = AEAD.decrypt(state, <<>>, @aes_128_ciphertext, @aes_128_tag)
  end

  test "AES-256-GCM matches the NIST zero-key test vector" do
    state = state(:tls_aes_256_gcm_sha384, <<0::256>>, <<0::96>>)

    assert {:ok, @aes_256_ciphertext, @aes_256_tag} = AEAD.encrypt(state, <<>>, <<0::128>>)
    assert {:ok, <<0::128>>} = AEAD.decrypt(state, <<>>, @aes_256_ciphertext, @aes_256_tag)
  end

  test "ChaCha20-Poly1305 matches RFC 8439 section 2.8.2" do
    key = hex("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F")
    nonce = hex("070000004041424344454647")
    aad = hex("50515253C0C1C2C3C4C5C6C7")

    plaintext =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for " <>
        "the future, sunscreen would be it."

    ciphertext =
      hex(
        "D31A8D34648E60DB7B86AFBC53EF7EC2A4ADED51296E08FEA9E2B5A736EE62D6" <>
          "3DBEA45E8CA9671282FAFB69DA92728B1A71DE0A9E060B2905D6A5B67ECD3B36" <>
          "92DDBD7F2D778B8C9803AEE328091B58FAB324E4FAD675945585808B4831D7BC" <>
          "3FF4DEF08E4B7A9DE576D26586CEC64B6116"
      )

    tag = hex("1AE10B594F09E26A7E902ECBD0600691")
    state = state(:tls_chacha20_poly1305_sha256, key, nonce)

    assert {:ok, ^ciphertext, ^tag} = AEAD.encrypt(state, aad, plaintext)
    assert {:ok, ^plaintext} = AEAD.decrypt(state, aad, ciphertext, tag)
  end

  test "derives a distinct record nonce from the traffic sequence" do
    key = <<0::128>>
    iv = hex("000102030405060708090A0B")
    plaintext = "same plaintext"
    aad = <<23, 3, 3, 0, byte_size(plaintext) + 16>>

    assert {:ok, first, first_tag} =
             AEAD.encrypt(state(:tls_aes_128_gcm_sha256, key, iv, 0), aad, plaintext)

    assert {:ok, second, second_tag} =
             AEAD.encrypt(state(:tls_aes_128_gcm_sha256, key, iv, 1), aad, plaintext)

    refute {first, first_tag} == {second, second_tag}
  end

  test "rejects tampered ciphertext, tag, and associated data" do
    state = state(:tls_aes_128_gcm_sha256, <<0::128>>, <<0::96>>)
    aad = <<23, 3, 3, 0, 32>>
    assert {:ok, ciphertext, tag} = AEAD.encrypt(state, aad, "authenticated")

    assert {:error, :authentication_failed} =
             AEAD.decrypt(state, aad, flip_first_bit(ciphertext), tag)

    assert {:error, :authentication_failed} =
             AEAD.decrypt(state, aad, ciphertext, flip_first_bit(tag))

    assert {:error, :authentication_failed} =
             AEAD.decrypt(state, flip_first_bit(aad), ciphertext, tag)
  end

  test "validates suite key IV tag and binary inputs without raising" do
    aes128 = state(:tls_aes_128_gcm_sha256, <<0::128>>, <<0::96>>)

    assert {:error, {:unsupported_cipher_suite, :tls_aes_128_ccm_sha256}} =
             AEAD.encrypt(%{aes128 | cipher_suite: :tls_aes_128_ccm_sha256}, <<>>, <<>>)

    assert {:error, {:invalid_key, :wrong_length}} =
             AEAD.encrypt(%{aes128 | key: <<0::120>>}, <<>>, <<>>)

    assert {:error, {:invalid_key, :not_binary}} =
             AEAD.encrypt(%{aes128 | key: nil}, <<>>, <<>>)

    assert {:error, {:invalid_iv, :wrong_length}} =
             AEAD.encrypt(%{aes128 | iv: <<0::104>>}, <<>>, <<>>)

    assert {:error, {:invalid_iv, :not_binary}} =
             AEAD.encrypt(%{aes128 | iv: nil}, <<>>, <<>>)

    assert {:error, {:invalid_sequence, :out_of_range}} =
             AEAD.encrypt(%{aes128 | sequence: -1}, <<>>, <<>>)

    assert {:error, {:invalid_aad, :not_binary}} = AEAD.encrypt(aes128, nil, <<>>)
    assert {:error, {:invalid_plaintext, :not_binary}} = AEAD.encrypt(aes128, <<>>, nil)

    assert {:error, {:invalid_ciphertext, :not_binary}} =
             AEAD.decrypt(aes128, <<>>, nil, <<0::128>>)

    assert {:error, {:invalid_tag, :wrong_length}} = AEAD.decrypt(aes128, <<>>, <<>>, <<0::120>>)
    assert {:error, {:invalid_tag, :not_binary}} = AEAD.decrypt(aes128, <<>>, <<>>, nil)
    assert {:error, :invalid_traffic_state} = AEAD.encrypt(%{}, <<>>, <<>>)
    assert {:error, :invalid_traffic_state} = AEAD.decrypt(nil, <<>>, <<>>, <<0::128>>)
  end

  test "rejects content that cannot fit in a TLSCiphertext record" do
    state = state(:tls_aes_128_gcm_sha256, <<0::128>>, <<0::96>>)
    oversized = :binary.copy(<<0>>, 16_625)

    assert {:error, {:invalid_plaintext, :too_long}} = AEAD.encrypt(state, <<>>, oversized)

    assert {:error, {:invalid_ciphertext, :too_long}} =
             AEAD.decrypt(state, <<>>, oversized, <<0::128>>)
  end

  test "reports runtime cipher capability and rejects unavailable providers" do
    supported_ciphers = :crypto.supports(:ciphers)

    for {suite, cipher} <- [
          tls_aes_128_gcm_sha256: :aes_128_gcm,
          tls_aes_256_gcm_sha384: :aes_256_gcm,
          tls_chacha20_poly1305_sha256: :chacha20_poly1305
        ] do
      assert AEAD.supported?(suite) == cipher in supported_ciphers
    end

    refute AEAD.supported?(:tls_aes_128_ccm_sha256)
    refute AEAD.supported?(nil)
  end

  defp state(cipher_suite, key, iv, sequence \\ 0) do
    %TrafficState{
      secret: <<>>,
      key: key,
      iv: iv,
      sequence: sequence,
      cipher_suite: cipher_suite
    }
  end

  defp flip_first_bit(<<first, rest::binary>>), do: <<Bitwise.bxor(first, 1), rest::binary>>
  defp hex(value), do: Base.decode16!(value)
end
