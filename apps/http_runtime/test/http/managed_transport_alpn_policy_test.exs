defmodule HTTP.ManagedTransportALPNPolicyTest do
  use ExUnit.Case, async: true

  alias HTTP.ManagedTransport.Policy

  test "fixed H1 ALPN is frozen with compact backing and distinct identity" do
    backing = "http/1.1" <> :binary.copy(<<0>>, 1_048_576)
    protocol = binary_part(backing, 0, 8)
    assert {:ok, policy} = freeze(:http1, alpn_advertised_protocols: [protocol])
    assert [retained] = policy.transport[:ssl][:alpn_advertised_protocols]
    assert retained == "http/1.1"
    assert :binary.referenced_byte_size(retained) == byte_size(retained)
    assert {:ok, compact} = freeze(:http1, alpn_advertised_protocols: ["http/1.1"])
    assert policy == compact
    assert {:ok, default} = freeze(:http1, [])
    refute Keyword.has_key?(default.transport[:ssl], :alpn_advertised_protocols)
    refute default.identity == policy.identity
  end

  test "only one exact binary H1 protocol is admitted" do
    for protocols <- [
          [],
          ["h2"],
          ["h3"],
          ["http/1.1", "h2"],
          ["http/1.1", "http/1.1"],
          [~c"http/1.1"],
          "http/1.1",
          [:http1],
          [String.duplicate("x", 1_048_577)]
        ] do
      assert {:error, :invalid_transport_scope_tls_policy} =
               freeze(:http1, alpn_advertised_protocols: protocols)
    end

    assert {:error, :invalid_transport_scope_tls_policy} =
             freeze(:http1, alpn_preferred_protocols: ["http/1.1"])

    assert {:error, :invalid_transport_scope_tls_policy} =
             freeze(:http1,
               alpn_advertised_protocols: ["http/1.1"],
               alpn_advertised_protocols: ["http/1.1"]
             )
  end

  test "H2 keeps its existing protocol policy and cleartext rejects TLS settings" do
    assert {:ok, h2} = freeze(:http2, [])
    refute Keyword.has_key?(h2.transport[:ssl], :alpn_advertised_protocols)

    for protocols <- [["http/1.1"], ["h2"]] do
      assert {:error, :invalid_transport_scope_tls_policy} =
               freeze(:http2, alpn_advertised_protocols: protocols)
    end

    assert {:error, :transport_scope_tls_requires_https} =
             Policy.freeze(
               origin: "http://localhost",
               connect_address: {127, 0, 0, 1},
               http_version: :http1,
               ssl: [alpn_advertised_protocols: ["http/1.1"]]
             )
  end

  defp freeze(version, ssl) do
    Policy.freeze(
      origin: "https://localhost",
      connect_address: {127, 0, 0, 1},
      http_version: version,
      ssl: [cacerts: []] ++ ssl
    )
  end
end
