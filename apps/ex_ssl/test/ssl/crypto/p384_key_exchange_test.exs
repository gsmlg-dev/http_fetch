defmodule SSL.Crypto.P384KeyExchangeTest do
  use ExUnit.Case, async: true
  alias SSL.Crypto.KeyExchange
  alias SSL.Crypto.KeyExchange.KeyPair

  # RFC 5903 section 8.2. TLS uses the same ECDH x-coordinate secret,
  # with the uncompressed 04 prefix added to the public point encoding.
  @private Base.decode16!(
             "099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194"
           )
  @public Base.decode16!(
            "04667842D7D180AC2CDE6F74F37551F55755C7645C20EF73E31634FE72B4C55EE6DE3AC808ACB4BDB4C88732AEE95F41AA9482ED1FC0EEB9CAFC4984625CCFC23F65032149E0E144ADA024181535A0F38EEB9FCFF3C2C947DAE69B4C634573A81C"
          )
  @peer Base.decode16!(
          "04E558DBEF53EECDE3D3FCCFC1AEA08A89A987475D12FD950D83CFA41732BC509D0D1AC43A0336DEF96FDA41D0774A3571DCFBEC7AACF3196472169E838430367F66EEBE3C6E70C416DD5F0C68759DD1FFF83FA40142209DFF5EAAD96DB9E6386C"
        )
  @secret Base.decode16!(
            "11187331C279962D93D604243FD592CB9D0A926F422E47187521287E7156C5C4D603135569B9E9D09CF5D4A270F59746"
          )

  test "P384 matches an independent ECDH vector" do
    assert KeyExchange.supported?(:secp384r1)
    assert :ok = KeyExchange.validate_key_pair(pair())
    assert {:ok, @secret} = KeyExchange.shared_secret(pair(), @peer)
  end

  test "P384 generates fresh validated keys and preserves the 48-byte secret" do
    assert {:ok, left} = KeyExchange.generate(:secp384r1)
    assert {:ok, right} = KeyExchange.generate(:secp384r1)
    assert :ok = KeyExchange.validate_key_pair(left)
    assert byte_size(left.public_key) == 97
    assert byte_size(left.private_key) == 48
    refute left.public_key == right.public_key
    assert {:ok, secret} = KeyExchange.shared_secret(left, right.public_key)
    assert {:ok, ^secret} = KeyExchange.shared_secret(right, left.public_key)
    assert byte_size(secret) == 48
  end

  test "P384 rejects malformed, compressed, off-curve and out-of-range peer points" do
    for peer <- [<<>>, <<4, 1>>, <<2, 0::384>>, <<4, 0::768>>, <<4, -1::384, -1::384>>, false] do
      assert {:error, {:invalid_peer_public_key, :secp384r1}} =
               KeyExchange.shared_secret(pair(), peer)
    end

    for private <- [<<>>, <<0::384>>, <<-1::384>>] do
      assert {:error, {:invalid_private_key, :secp384r1}} =
               KeyExchange.validate_key_pair(%{pair() | private_key: private})
    end

    assert {:error, {:key_pair_mismatch, :secp384r1}} =
             KeyExchange.validate_key_pair(%{pair() | public_key: @peer})
  end

  test "runtime without P384 cannot advertise it even with generic ECDH" do
    runtime = SSL.Capabilities.runtime()
    assert 0x0018 in SSL.Capabilities.identifiers(:group, runtime)

    refute 0x0018 in SSL.Capabilities.identifiers(:group, %{
             runtime
             | curves: List.delete(runtime.curves, :secp384r1)
           })

    refute 0x0018 in SSL.Capabilities.identifiers(:group, %{
             runtime
             | public_keys: List.delete(runtime.public_keys, :ecdh)
           })
  end

  defp pair, do: %KeyPair{group: :secp384r1, public_key: @public, private_key: @private}
end
