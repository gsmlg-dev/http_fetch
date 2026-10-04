defmodule SSL.CapabilitiesTest do
  use ExUnit.Case, async: true

  alias SSL.Capabilities

  test "negotiation metadata binds wire identifiers to hashes and public key encodings" do
    assert %{hash: :sha384, key_length: 32} = Capabilities.resolve(:cipher_suite, 0x1302)
    assert %{share_size: 65, share_encoding: :uncompressed} = Capabilities.resolve(:group, 0x0017)
    assert %{share_size: 32, share_encoding: :raw} = Capabilities.resolve(:group, :x25519)
  end

  test "exposes only complete TLS 1.3 handshake primitives in wire order" do
    runtime = %{
      ciphers: [:aes_128_gcm, :aes_256_gcm, :chacha20_poly1305],
      curves: [:x25519, :secp256r1, :secp384r1, :ed25519],
      public_keys: [:ecdh, :ecdsa, :rsa, :eddsa],
      hashs: [:sha256, :sha384, :sha512],
      macs: [:hmac],
      rsa_opts: [:rsa_pkcs1_pss_padding, :rsa_pss_saltlen, :rsa_mgf1_md]
    }

    assert Capabilities.identifiers(:signature_algorithm, runtime) ==
             [
               0x0403,
               :ecdsa_secp256r1_sha256,
               0x0503,
               :ecdsa_secp384r1_sha384,
               0x0804,
               :rsa_pss_rsae_sha256,
               0x0805,
               :rsa_pss_rsae_sha384,
               0x0806,
               :rsa_pss_rsae_sha512,
               0x0807,
               :ed25519,
               0x0809,
               :rsa_pss_pss_sha256,
               0x080A,
               :rsa_pss_pss_sha384,
               0x080B,
               :rsa_pss_pss_sha512
             ]

    assert Capabilities.identifiers(:group, runtime) ==
             [0x001D, :x25519, 0x0017, :secp256r1, 0x0018, :secp384r1]

    assert Capabilities.signature(0x0805).verify_options ==
             [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 48, rsa_mgf1_md: :sha384]
  end

  test "incomplete RSA-PSS and ECDHE prerequisites cannot be advertised" do
    runtime = %{
      ciphers: [:aes_128_gcm],
      curves: [:x25519, :secp256r1],
      public_keys: [:rsa, :ecdsa],
      hashs: [:sha256],
      macs: [:hmac],
      rsa_opts: [:rsa_pkcs1_pss_padding, :rsa_pss_saltlen]
    }

    assert Capabilities.identifiers(:signature_algorithm, runtime) ==
             [0x0403, :ecdsa_secp256r1_sha256]

    assert Capabilities.identifiers(:group, runtime) == []

    assert Capabilities.identifiers(:cipher_suite, runtime) ==
             [0x1301, :tls_aes_128_gcm_sha256]
  end

  test "certificate-chain policy has its own runtime-gated registry" do
    assert Capabilities.certificate_chain_policy() == :enforced
    assert Capabilities.identifiers(:certificate_signature_algorithm, %{}) == []

    assert %{id: 0x0401} =
             Capabilities.resolve(:certificate_signature_algorithm, :rsa_pkcs1_sha256)

    assert %{id: 0x1302} =
             Capabilities.resolve(:cipher_suite, %{
               key_exchange: :any,
               cipher: :aes_256_gcm,
               mac: :aead,
               prf: :sha384
             })

    runtime = %{
      ciphers: [:aes_128_gcm],
      curves: [],
      public_keys: [:rsa],
      hashs: [:sha256],
      macs: [:hmac],
      rsa_opts: [:rsa_pkcs1_padding]
    }

    assert 0x0401 in Capabilities.identifiers(:certificate_signature_algorithm, runtime)
    refute 0x0804 in Capabilities.identifiers(:certificate_signature_algorithm, runtime)

    refute 0x0401 in Capabilities.identifiers(:certificate_signature_algorithm, %{
             runtime
             | rsa_opts: []
           })
  end

  test "each missing PSS option, hash, ECDSA curve, ECDH or HMAC removes its dependent offer" do
    runtime = %{
      ciphers: [:aes_128_gcm],
      curves: [:x25519, :secp256r1],
      public_keys: [:ecdh, :ecdsa, :rsa],
      hashs: [:sha256, :sha384, :sha512],
      macs: [:hmac],
      rsa_opts: [:rsa_pkcs1_pss_padding, :rsa_pss_saltlen, :rsa_mgf1_md]
    }

    for option <- runtime.rsa_opts do
      reduced = %{runtime | rsa_opts: List.delete(runtime.rsa_opts, option)}
      refute 0x0804 in Capabilities.identifiers(:signature_algorithm, reduced)
    end

    for hash <- runtime.hashs do
      reduced = %{runtime | hashs: List.delete(runtime.hashs, hash)}

      refute %{sha256: 0x0804, sha384: 0x0805, sha512: 0x0806}[hash] in Capabilities.identifiers(
               :signature_algorithm,
               reduced
             )
    end

    refute 0x0403 in Capabilities.identifiers(
             :signature_algorithm,
             %{runtime | curves: [:x25519]}
           )

    assert Capabilities.identifiers(:group, %{runtime | public_keys: [:ecdsa, :rsa]}) == []
    assert Capabilities.identifiers(:cipher_suite, %{runtime | macs: []}) == []
  end
end
