defmodule SSL.Protocol.TLS12DispatchTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.Materializer
  alias SSL.Protocol.{HandshakeFramer, HandshakeMachine, TLS12}

  test "TLS 1.2-only offer has no key share and switches on the first exact ServerHello" do
    for versions <- [[:"tlsv1.2"], [:"tlsv1.3", :"tlsv1.2"]] do
      assert {:ok, %{profile: profile, context: context}} =
               SSL.Options.normalize("mail.example", versions: versions)

      assert {:ok, materialized} =
               Materializer.materialize(profile, SSL.Options.capabilities(), context)

      assert {:ok, machine, [_client_hello]} =
               HandshakeMachine.init(
                 materialized,
                 :public_key.cacerts_get(),
                 {:dns_id, "mail.example"}
               )

      if versions == [:"tlsv1.2"], do: assert(machine.key_pairs == [])

      hello = tls12_server_hello(0xC02F)
      partial_certificate = <<11, 0, 0>>
      payload = hello <> partial_certificate
      record = <<22, 3, 3, byte_size(payload)::16, payload::binary>>

      assert {:ok, %TLS12{} = tls12, [], []} = HandshakeMachine.feed(machine, record)
      assert tls12.phase == :await_certificate
      assert HandshakeFramer.buffered_bytes(tls12.framer) == partial_certificate

      assert tls12.offer.offered_versions ==
               Enum.map(versions, fn
                 :"tlsv1.3" -> 0x0304
                 :"tlsv1.2" -> 0x0303
               end)
    end
  end

  test "TLS 1.3-only offer rejects a TLS 1.2 suite without retry" do
    assert {:ok, %{profile: profile, context: context}} =
             SSL.Options.normalize("mail.example", [])

    assert {:ok, materialized} =
             Materializer.materialize(profile, SSL.Options.capabilities(), context)

    assert {:ok, machine, [_]} =
             HandshakeMachine.init(
               materialized,
               :public_key.cacerts_get(),
               {:dns_id, "mail.example"}
             )

    hello = tls12_server_hello(0xC02F)
    record = <<22, 3, 3, byte_size(hello)::16, hello::binary>>

    assert {:error, {:fatal_alert, :illegal_parameter, :unoffered_tls12_selection}} =
             HandshakeMachine.feed(machine, record)
  end

  test "TLS 1.2-only offer rejects an initial ChangeCipherSpec" do
    assert {:ok, %{profile: profile, context: context}} =
             SSL.Options.normalize("mail.example", versions: [:"tlsv1.2"])

    assert {:ok, materialized} =
             Materializer.materialize(profile, SSL.Options.capabilities(), context)

    assert {:ok, machine, [_]} =
             HandshakeMachine.init(
               materialized,
               :public_key.cacerts_get(),
               {:dns_id, "mail.example"}
             )

    assert {:error, {:fatal_alert, :unexpected_message, :unexpected_tls12_change_cipher_spec}} =
             HandshakeMachine.feed(machine, <<20, 3, 3, 0, 1, 1>>)
  end

  defp tls12_server_hello(suite) do
    random = :binary.copy(<<7>>, 32)
    extensions = <<23::16, 0::16, 0xFF01::16, 1::16, 0>>

    body =
      <<3, 3, random::binary, 0, suite::16, 0, byte_size(extensions)::16, extensions::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end
end
