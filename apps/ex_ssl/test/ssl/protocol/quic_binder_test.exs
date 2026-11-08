defmodule SSL.Protocol.QUICBinderTest do
  use ExUnit.Case, async: true
  alias SSL.Protocol.Resumption
  @vectors Path.expand("../../fixtures/quic_binder_vectors.json", __DIR__)

  test "independent Python HKDF/HMAC vectors cover SHA256/SHA384, extra identities and HRR prefix" do
    vectors = @vectors |> File.read!() |> JSON.decode!()

    for v <- vectors do
      hello = Base.decode16!(v["hello"], case: :lower)
      psk = Base.decode16!(v["psk"], case: :lower)
      prefix = Base.decode16!(v["prefix"], case: :lower)
      hash = if v["hash"] == "sha256", do: :sha256, else: :sha384
      assert :ok = Resumption.verify_binder(hello, psk, hash, prefix)

      assert {:error, :invalid_psk_binder} =
               Resumption.verify_binder(hello, psk, hash, prefix <> "tamper")

      assert {:error, :invalid_psk_binder} =
               Resumption.verify_binder(hello, :binary.copy(<<1>>, byte_size(psk)), hash, prefix)

      {:ok, early} = SSL.Crypto.KeySchedule.early_secret(hash, psk)

      {:ok, traffic} =
        SSL.Crypto.KeySchedule.client_early_traffic_secret(hash, early, :crypto.hash(hash, hello))

      assert Base.encode16(traffic, case: :lower) == v["early_traffic"]

      for n <- [0, 1, 3, byte_size(hello) - 1] do
        assert {:error, :invalid_psk_binder} =
                 Resumption.verify_binder(binary_part(hello, 0, n), psk, hash, prefix)
      end
    end
  end
end
