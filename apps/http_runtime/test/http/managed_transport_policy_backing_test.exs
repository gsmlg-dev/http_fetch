defmodule HTTP.ManagedTransportPolicyBackingTest do
  use ExUnit.Case, async: true

  alias HTTP.ManagedTransport.Policy

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)

  for key <- [:cacerts, :cert, :key, :ciphers] do
    test "frozen #{key} binary representations own compact backing" do
      option = unquote(key)
      {type, der} = pem(pem_name(option))
      slice = borrowed(der)

      value = value(option, type, slice)

      assert {:ok, policy} = freeze([{option, value}])
      retained = policy.transport[:ssl][option]
      assert retained == value

      for binary <- binaries(retained) do
        assert :binary.referenced_byte_size(binary) == byte_size(binary)
      end
    end
  end

  test "policy digest and equality are independent of borrowed backing" do
    {_, der} = pem("localhost-ca.pem")
    assert {:ok, borrowed_policy} = freeze(cacerts: [borrowed(der)])
    assert {:ok, compact_policy} = freeze(cacerts: [der])
    assert borrowed_policy == compact_policy
  end

  test "frozen origin binaries own compact backing" do
    host = String.duplicate("a", 60) <> "." <> String.duplicate("b", 30) <> ".example.test"
    url = %{URI.parse("https://example.test") | host: borrowed(host)}
    assert {:ok, policy} = freeze([cacerts: []], url)
    assert policy.origin.host == host
    assert :binary.referenced_byte_size(policy.origin.host) == byte_size(policy.origin.host)
  end

  test "logical and serialized policy limits remain enforced before copying" do
    too_large = borrowed(:binary.copy("x", 1_048_577))
    assert {:error, :invalid_transport_scope_tls_policy} = freeze(cert: too_large)
    at_limit = borrowed(:binary.copy("x", 1_048_576))
    assert {:error, :invalid_transport_scope_policy} = freeze(cert: at_limit, cacerts: [])
  end

  defp value(:cacerts, _type, slice), do: [slice]
  defp value(:cert, _type, slice), do: slice
  defp value(:key, type, slice), do: {type, slice}
  defp value(:ciphers, _type, slice), do: [{slice, [slice]}]

  defp pem_name(:key), do: "localhost.key"
  defp pem_name(_), do: "localhost-ca.pem"

  defp freeze(ssl, origin \\ "https://localhost") do
    Policy.freeze(
      origin: origin,
      connect_address: {127, 0, 0, 1},
      http_version: :http1,
      ssl: Keyword.put_new(ssl, :cacerts, [])
    )
  end

  defp pem(name) do
    [{type, der, :not_encrypted}] =
      @fixtures |> Path.join(name) |> File.read!() |> :public_key.pem_decode()

    {type, der}
  end

  defp borrowed(value) do
    backing = value <> :binary.copy(<<0>>, 8 * 1_048_576)
    slice = binary_part(backing, 0, byte_size(value))
    assert :binary.referenced_byte_size(slice) > byte_size(slice)
    slice
  end

  defp binaries(value) when is_binary(value), do: [value]
  defp binaries(value) when is_list(value), do: Enum.flat_map(value, &binaries/1)
  defp binaries(value) when is_tuple(value), do: value |> Tuple.to_list() |> binaries()
  defp binaries(_), do: []
end
