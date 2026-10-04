defmodule SSL.Capabilities do
  @moduledoc false

  # Wire order is intentional. Certificate signatures and CertificateVerify
  # signatures have distinct registries even when they share wire IDs.
  @ciphers [
    %{
      id: 0x1301,
      version: 0x0304,
      name: :tls_aes_128_gcm_sha256,
      cipher: :aes_128_gcm,
      hash: :sha256,
      key_length: 16,
      needs: [ciphers: :aes_128_gcm, hashs: :sha256]
    },
    %{
      id: 0x1302,
      version: 0x0304,
      name: :tls_aes_256_gcm_sha384,
      cipher: :aes_256_gcm,
      hash: :sha384,
      key_length: 32,
      needs: [ciphers: :aes_256_gcm, hashs: :sha384]
    },
    %{
      id: 0x1303,
      version: 0x0304,
      name: :tls_chacha20_poly1305_sha256,
      cipher: :chacha20_poly1305,
      hash: :sha256,
      key_length: 32,
      needs: [ciphers: :chacha20_poly1305, hashs: :sha256]
    },
    %{
      id: 0xC02F,
      name: :tls_ecdhe_rsa_with_aes_128_gcm_sha256,
      version: 0x0303,
      key_exchange: :ecdhe_rsa,
      cipher: :aes_128_gcm,
      hash: :sha256,
      key_length: 16,
      needs: [ciphers: :aes_128_gcm, hashs: :sha256, public_keys: :rsa, public_keys: :ecdh]
    },
    %{
      id: 0xC030,
      name: :tls_ecdhe_rsa_with_aes_256_gcm_sha384,
      version: 0x0303,
      key_exchange: :ecdhe_rsa,
      cipher: :aes_256_gcm,
      hash: :sha384,
      key_length: 32,
      needs: [ciphers: :aes_256_gcm, hashs: :sha384, public_keys: :rsa, public_keys: :ecdh]
    },
    %{
      id: 0xC02B,
      name: :tls_ecdhe_ecdsa_with_aes_128_gcm_sha256,
      version: 0x0303,
      key_exchange: :ecdhe_ecdsa,
      cipher: :aes_128_gcm,
      hash: :sha256,
      key_length: 16,
      needs: [ciphers: :aes_128_gcm, hashs: :sha256, public_keys: :ecdsa, public_keys: :ecdh]
    },
    %{
      id: 0xC02C,
      name: :tls_ecdhe_ecdsa_with_aes_256_gcm_sha384,
      version: 0x0303,
      key_exchange: :ecdhe_ecdsa,
      cipher: :aes_256_gcm,
      hash: :sha384,
      key_length: 32,
      needs: [ciphers: :aes_256_gcm, hashs: :sha384, public_keys: :ecdsa, public_keys: :ecdh]
    }
  ]
  @groups [
    %{
      id: 0x001D,
      name: :x25519,
      needs: [public_keys: :ecdh, curves: :x25519],
      share_size: 32,
      share_encoding: :raw
    },
    %{
      id: 0x0017,
      name: :secp256r1,
      needs: [public_keys: :ecdh, curves: :secp256r1],
      share_size: 65,
      share_encoding: :uncompressed
    },
    %{
      id: 0x0018,
      name: :secp384r1,
      needs: [public_keys: :ecdh, curves: :secp384r1],
      share_size: 97,
      share_encoding: :uncompressed
    }
  ]
  @signatures [
    %{
      id: 0x0403,
      name: :ecdsa_secp256r1_sha256,
      key: :ecdsa,
      hash: :sha256,
      curve: :secp256r1,
      curve_oid: {1, 2, 840, 10_045, 3, 1, 7},
      public_key_size: 65,
      needs: [public_keys: :ecdsa, curves: :secp256r1, hashs: :sha256],
      verify_options: []
    },
    %{
      id: 0x0503,
      name: :ecdsa_secp384r1_sha384,
      key: :ecdsa,
      hash: :sha384,
      curve: :secp384r1,
      curve_oid: {1, 3, 132, 0, 34},
      public_key_size: 97,
      needs: [public_keys: :ecdsa, curves: :secp384r1, hashs: :sha384],
      verify_options: []
    },
    %{
      id: 0x0804,
      name: :rsa_pss_rsae_sha256,
      key: :rsa,
      hash: :sha256,
      needs: [
        public_keys: :rsa,
        hashs: :sha256,
        rsa_opts: :rsa_pkcs1_pss_padding,
        rsa_opts: :rsa_pss_saltlen,
        rsa_opts: :rsa_mgf1_md
      ],
      verify_options: [
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 32,
        rsa_mgf1_md: :sha256
      ]
    },
    %{
      id: 0x0805,
      name: :rsa_pss_rsae_sha384,
      key: :rsa,
      hash: :sha384,
      needs: [
        public_keys: :rsa,
        hashs: :sha384,
        rsa_opts: :rsa_pkcs1_pss_padding,
        rsa_opts: :rsa_pss_saltlen,
        rsa_opts: :rsa_mgf1_md
      ],
      verify_options: [
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 48,
        rsa_mgf1_md: :sha384
      ]
    },
    %{
      id: 0x0806,
      name: :rsa_pss_rsae_sha512,
      key: :rsa,
      hash: :sha512,
      needs: [
        public_keys: :rsa,
        hashs: :sha512,
        rsa_opts: :rsa_pkcs1_pss_padding,
        rsa_opts: :rsa_pss_saltlen,
        rsa_opts: :rsa_mgf1_md
      ],
      verify_options: [
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 64,
        rsa_mgf1_md: :sha512
      ]
    },
    %{
      id: 0x0807,
      name: :ed25519,
      key: :eddsa,
      hash: :none,
      curve: :ed25519,
      curve_oid: {1, 3, 101, 112},
      public_key_size: 32,
      needs: [public_keys: :eddsa, curves: :ed25519],
      verify_options: []
    },
    %{
      id: 0x0809,
      name: :rsa_pss_pss_sha256,
      key: :rsa_pss,
      hash: :sha256,
      needs: [
        public_keys: :rsa,
        hashs: :sha256,
        rsa_opts: :rsa_pkcs1_pss_padding,
        rsa_opts: :rsa_pss_saltlen,
        rsa_opts: :rsa_mgf1_md
      ],
      verify_options: [
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 32,
        rsa_mgf1_md: :sha256
      ]
    },
    %{
      id: 0x080A,
      name: :rsa_pss_pss_sha384,
      key: :rsa_pss,
      hash: :sha384,
      needs: [
        public_keys: :rsa,
        hashs: :sha384,
        rsa_opts: :rsa_pkcs1_pss_padding,
        rsa_opts: :rsa_pss_saltlen,
        rsa_opts: :rsa_mgf1_md
      ],
      verify_options: [
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 48,
        rsa_mgf1_md: :sha384
      ]
    },
    %{
      id: 0x080B,
      name: :rsa_pss_pss_sha512,
      key: :rsa_pss,
      hash: :sha512,
      needs: [
        public_keys: :rsa,
        hashs: :sha512,
        rsa_opts: :rsa_pkcs1_pss_padding,
        rsa_opts: :rsa_pss_saltlen,
        rsa_opts: :rsa_mgf1_md
      ],
      verify_options: [
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 64,
        rsa_mgf1_md: :sha512
      ]
    }
  ]
  @tls13_signature_ids [
    0x0403,
    0x0503,
    0x0603,
    0x0804,
    0x0805,
    0x0806,
    0x0807,
    0x0808,
    0x0809,
    0x080A,
    0x080B
  ]
  @certificate_signatures [
    %{
      id: 0x0401,
      name: :rsa_pkcs1_sha256,
      needs: [public_keys: :rsa, hashs: :sha256, rsa_opts: :rsa_pkcs1_padding]
    },
    %{
      id: 0x0501,
      name: :rsa_pkcs1_sha384,
      needs: [public_keys: :rsa, hashs: :sha384, rsa_opts: :rsa_pkcs1_padding]
    },
    %{
      id: 0x0601,
      name: :rsa_pkcs1_sha512,
      needs: [public_keys: :rsa, hashs: :sha512, rsa_opts: :rsa_pkcs1_padding]
    }
    | Enum.map(@signatures, &Map.take(&1, [:id, :name, :needs]))
  ]

  @spec runtime() :: map()
  def runtime do
    for kind <- [:ciphers, :curves, :public_keys, :hashs, :macs, :rsa_opts], into: %{} do
      {kind, :crypto.supports(kind)}
    end
  end

  @doc "Implemented TLS algorithms with separately reported runtime availability."
  @spec describe(atom()) :: [map()]
  def describe(kind) do
    runtime = runtime()

    Enum.map(entries(kind), fn entry ->
      entry
      |> Map.drop([:needs, :verify_options])
      |> Map.put(:implemented, true)
      |> Map.put(:available, available?(entry, runtime))
    end)
  end

  @spec identifiers(atom(), map()) :: [atom() | non_neg_integer()]
  def identifiers(kind, runtime \\ runtime()) do
    kind
    |> entries()
    |> Enum.filter(&available?(&1, runtime))
    |> Enum.flat_map(&[&1.id, &1.name])
  end

  @spec resolve(atom(), term()) :: map() | nil
  def resolve(kind, value), do: Enum.find(entries(kind), &matches?(&1, kind, value))

  @spec signature(term()) :: map() | nil
  def signature(value), do: resolve(:signature_algorithm, value)

  @spec cipher_ids(0x0303 | 0x0304, map()) :: [non_neg_integer()]
  def cipher_ids(version, runtime \\ runtime()) do
    @ciphers
    |> Enum.filter(&(&1.version == version and available?(&1, runtime)))
    |> Enum.map(& &1.id)
  end

  @spec certificate_chain_policy() :: :enforced
  def certificate_chain_policy, do: :enforced

  @spec tls13_signature_scheme?(term()) :: boolean()
  def tls13_signature_scheme?(value), do: value in @tls13_signature_ids

  @spec tls13_signature_ids() :: [
          1027 | 1283 | 1539 | 2052 | 2053 | 2054 | 2055 | 2056 | 2057 | 2058 | 2059,
          ...
        ]
  def tls13_signature_ids, do: @tls13_signature_ids

  @spec key_share_sizes() :: map()
  def key_share_sizes do
    Map.new(@groups, &{&1.id, &1.share_size})
    |> Map.merge(Map.new(@groups, &{&1.name, &1.share_size}))
  end

  defp entries(:cipher_suite), do: @ciphers
  defp entries(:group), do: @groups
  defp entries(:signature_algorithm), do: @signatures
  defp entries(:certificate_signature_algorithm), do: @certificate_signatures
  defp entries(_kind), do: []

  defp matches?(entry, _kind, value) when value == entry.id or value == entry.name,
    do: true

  defp matches?(entry, :cipher_suite, value) when is_binary(value),
    do: value == entry.name |> Atom.to_string() |> String.upcase()

  defp matches?(entry, :cipher_suite, %{
         key_exchange: exchange,
         cipher: cipher,
         mac: :aead,
         prf: hash
       }),
       do:
         Map.get(entry, :key_exchange, :any) == exchange and entry.cipher == cipher and
           entry.hash == hash

  defp matches?(_entry, _kind, _value), do: false

  defp available?(entry, runtime) do
    :hmac in Map.get(runtime, :macs, []) and
      Enum.all?(entry.needs, fn {kind, primitive} -> primitive in Map.get(runtime, kind, []) end)
  end
end
