defmodule SSL.Crypto.KeyExchangeTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.KeyExchange
  alias SSL.Crypto.KeyExchange.KeyPair

  test "X25519 shared secret matches RFC 7748 section 6.1" do
    alice = %KeyPair{
      group: :x25519,
      public_key: hex("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A"),
      private_key: hex("77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A")
    }

    bob_public = hex("DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F")

    assert {:ok, secret} = KeyExchange.shared_secret(alice, bob_public)
    assert secret == hex("4A5D9D5BA4CE2DE1728E3BF480350F25E07E21C947D19E3376F09B3C1E161742")
  end

  test "secp256r1 shared secret matches RFC 5903 section 8.1" do
    initiator = %KeyPair{
      group: :secp256r1,
      public_key:
        hex(
          "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180" <>
            "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"
        ),
      private_key: hex("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
    }

    responder_public =
      hex(
        "04D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63" <>
          "56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB"
      )

    assert {:ok, secret} = KeyExchange.shared_secret(initiator, responder_public)
    assert secret == hex("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")
  end

  for {group, public_size} <- [x25519: 32, secp256r1: 65] do
    @group group
    @public_size public_size

    test "generates fresh #{group} key pairs that agree" do
      if KeyExchange.supported?(@group) do
        assert {:ok, left} = KeyExchange.generate(@group)
        assert {:ok, right} = KeyExchange.generate(@group)

        assert %KeyPair{group: @group, public_key: left_public, private_key: left_private} = left

        assert %KeyPair{group: @group, public_key: right_public, private_key: right_private} =
                 right

        assert byte_size(left_public) == @public_size
        assert byte_size(right_public) == @public_size
        assert byte_size(left_private) == 32
        assert byte_size(right_private) == 32
        refute left_public == right_public
        refute left_private == right_private

        assert {:ok, left_secret} = KeyExchange.shared_secret(left, right_public)
        assert {:ok, right_secret} = KeyExchange.shared_secret(right, left_public)
        assert left_secret == right_secret
        assert byte_size(left_secret) == 32
      else
        assert {:error, {:unsupported_capability, @group}} = KeyExchange.generate(@group)
      end
    end
  end

  test "reports only implemented groups" do
    curves = :crypto.supports(:curves)
    public_keys = :crypto.supports(:public_keys)
    runtime_has_ecdh = :ecdh in public_keys

    assert KeyExchange.supported?(:x25519) == (:x25519 in curves and runtime_has_ecdh)
    assert KeyExchange.supported?(:secp256r1) == (:secp256r1 in curves and runtime_has_ecdh)
    assert KeyExchange.supported?(:secp384r1) == (:secp384r1 in curves and runtime_has_ecdh)
    refute KeyExchange.supported?(:x448)
    refute KeyExchange.supported?(:unknown)
    refute KeyExchange.supported?(nil)

    assert {:error, {:unsupported_group, :x448}} = KeyExchange.generate(:x448)
    assert {:error, {:unsupported_group, nil}} = KeyExchange.generate(nil)
  end

  test "rejects malformed and low-order X25519 peer keys without raising" do
    pair = x25519_pair()

    assert {:error, {:invalid_peer_public_key, :x25519}} =
             KeyExchange.shared_secret(pair, <<1, 2>>)

    assert {:error, {:invalid_peer_public_key, :x25519}} =
             KeyExchange.shared_secret(pair, :not_a_binary)

    assert {:error, {:invalid_peer_public_key, :x25519}} =
             KeyExchange.shared_secret(pair, :binary.copy(<<0>>, 32))

    assert {:error, {:invalid_peer_public_key, :x25519}} =
             KeyExchange.shared_secret(pair, <<1, 0::size(31 * 8)>>)
  end

  test "rejects malformed or off-curve secp256r1 peer keys without raising" do
    pair = secp256r1_pair()

    for peer <- [<<>>, <<4, 1, 2>>, <<3, 0::size(512)>>, <<4, 0::size(512)>>, false] do
      assert {:error, {:invalid_peer_public_key, :secp256r1}} =
               KeyExchange.shared_secret(pair, peer)
    end
  end

  test "rejects malformed local key pairs and unsupported groups" do
    malformed = %KeyPair{group: :x25519, public_key: <<>>, private_key: <<1>>}

    zero_scalar = %KeyPair{
      group: :secp256r1,
      public_key: <<0>>,
      private_key: :binary.copy(<<0>>, 32)
    }

    unsupported = %KeyPair{group: :x448, public_key: <<>>, private_key: <<>>}

    assert {:error, {:invalid_private_key, :x25519}} =
             KeyExchange.shared_secret(malformed, :binary.copy(<<1>>, 32))

    assert {:error, {:invalid_private_key, :secp256r1}} =
             KeyExchange.shared_secret(zero_scalar, secp256r1_pair().public_key)

    assert {:error, {:unsupported_group, :x448}} =
             KeyExchange.shared_secret(unsupported, <<>>)
  end

  test "KeyPair inspection excludes private key material" do
    private_key = :crypto.strong_rand_bytes(32)
    pair = %KeyPair{group: :x25519, public_key: :binary.copy(<<1>>, 32), private_key: private_key}
    inspected = inspect(pair)

    assert inspected =~ "SSL.Crypto.KeyExchange.KeyPair"
    assert inspected =~ "group: :x25519"
    refute inspected =~ "private_key"
    refute inspected =~ inspect(private_key)
  end

  defp x25519_pair do
    %KeyPair{
      group: :x25519,
      public_key: hex("8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A"),
      private_key: hex("77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A")
    }
  end

  defp secp256r1_pair do
    %KeyPair{
      group: :secp256r1,
      public_key:
        hex(
          "04DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180" <>
            "5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3"
        ),
      private_key: hex("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
    }
  end

  defp hex(value), do: Base.decode16!(value)
end
