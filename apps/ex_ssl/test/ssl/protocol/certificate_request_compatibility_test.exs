defmodule SSL.Protocol.CertificateRequestCompatibilityTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.{AST, Extension}
  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.Protocol.HandshakeMachine

  @fixture_dir Path.expand("../../fixtures/server_flight", __DIR__)

  test "authenticates an optional CertificateRequest with an unrecognized extension" do
    request_extensions = [
      {13, <<2::16, 0x0403::16>>},
      {0xFAFA, <<1, 2, 3>>}
    ]

    flight =
      SSL.TestServerFlightBuilder.build(
        signature_scheme: 0x0403,
        leaf_pem: Path.join(@fixture_dir, "leaf.pem"),
        leaf_key_pem: Path.join(@fixture_dir, "leaf-key.pem"),
        certificate_request_extensions: request_extensions
      )

    assert {:ok, machine, [client_hello]} =
             HandshakeMachine.init(
               materialized(flight),
               File.read!(Path.join(@fixture_dir, "root.pem")),
               {:dns_id, "example.test"}
             )

    assert client_hello == plaintext_record(flight.client_hello)

    assert {:ok, machine, [], []} =
             HandshakeMachine.feed(machine, plaintext_record(flight.server_hello))

    assert {:ok, machine, [], []} = HandshakeMachine.feed(machine, flight.record_1)
    assert {:ok, machine, [], []} = HandshakeMachine.feed(machine, flight.record_2)

    assert {:ok, %{phase: :connected}, [certificate, finished], [{:connected, nil}]} =
             HandshakeMachine.feed(machine, flight.record_3)

    assert certificate == flight.client_empty_certificate_record
    assert finished == flight.client_finished_record
  end

  defp materialized(flight) do
    {:ok, versions} = Extension.encode({:supported_versions, [0x0304]})
    {:ok, groups} = Extension.encode({:supported_groups, [0x001D]})
    {:ok, shares} = Extension.encode({:key_share, [{0x001D, flight.client_public}]})
    {:ok, signatures} = Extension.encode({:signature_algorithms, [0x0403]})
    {:ok, alpn} = Extension.encode({:alpn, ["h2", "http/1.1"]})

    ast = %AST{
      legacy_version: 0x0303,
      random: <<0::256>>,
      session_id: <<>>,
      cipher_suites: [0x1302],
      compression_methods: [0],
      extensions: [
        versions,
        groups,
        shares,
        signatures,
        alpn,
        {5, <<1, 0::16, 0::16>>},
        {18, <<>>}
      ]
    }

    %Materialized{
      client_hello: ast,
      key_pairs: [
        %KeyPair{
          group: :x25519,
          public_key: flight.client_public,
          private_key: flight.client_private
        }
      ]
    }
  end

  defp plaintext_record(handshake),
    do: <<22, 3, 3, byte_size(handshake)::16, handshake::binary>>
end
