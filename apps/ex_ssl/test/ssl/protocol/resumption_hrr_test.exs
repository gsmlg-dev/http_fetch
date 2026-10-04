defmodule SSL.Protocol.ResumptionHRRTest do
  use ExUnit.Case, async: true

  alias SSL.{Options, SessionTicket}
  alias SSL.ClientHello.Materializer
  alias SSL.Protocol.{ClientOffer, HandshakeMachine, Resumption, Transcript}

  @hrr_random Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

  test "HRR with a different suite hash drops the ticket and rewrites the exact transcript" do
    assert {:ok, options} =
             Options.normalize({127, 0, 0, 1},
               session_tickets: :auto,
               versions: [:"tlsv1.3"],
               ciphers: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
               supported_groups: [:x25519, :secp384r1],
               server_name_indication: ~c"exssl.test"
             )

    now = System.monotonic_time(:millisecond)

    ticket = %SessionTicket{
      ticket: "ticket-for-sha256",
      psk: :binary.copy(<<7>>, 32),
      hash: :sha256,
      age_add: 11,
      issued_at: now - 1_000,
      expires_at: now + 60_000,
      peer: %{chain: [<<1, 2, 3>>]},
      alpn: nil
    }

    assert :ok = SessionTicket.validate(ticket)
    assert {:ok, payload} = Resumption.psk_extension(ticket, now)

    assert {:ok, materialized} =
             Materializer.materialize(
               options.profile,
               Options.capabilities(),
               Map.put(options.context, :pre_shared_key, payload),
               test_random: <<7::256>>,
               test_session_id: <<8::256>>
             )

    assert {:ok, machine, [_initial_record]} =
             HandshakeMachine.init(materialized, options.trust_source, options.identity,
               ticket: ticket,
               enable_tickets: true
             )

    assert {:ok, initial_offer} = ClientOffer.from_client_hello(machine.client_hello)
    assert initial_offer.psk_count == 1
    assert initial_offer.psk_key_exchange_modes == [1]
    assert [%{group: 0x001D, key_exchange: first_share}] = initial_offer.key_shares

    hrr =
      hello(@hrr_random, materialized.client_hello.session_id, 0x1302, [
        extension(43, <<0x0304::16>>),
        extension(51, <<0x0018::16>>)
      ])

    assert {:ok, retried, [record], []} =
             HandshakeMachine.feed(machine, plaintext_record(hrr))

    <<22, 3, 3, _length::16, client_hello2::binary>> = record
    assert retried.client_hello == client_hello2
    assert retried.ticket == nil
    assert {:ok, retry_offer} = ClientOffer.from_client_hello(client_hello2)
    assert retry_offer.psk_count == 0
    assert retry_offer.psk_key_exchange_modes == [1]
    refute 41 in retry_offer.extension_ids
    assert [%{group: 0x0018, key_exchange: second_share}] = retry_offer.key_shares
    assert byte_size(second_share) == 97
    refute second_share == first_share

    first_hash = :crypto.hash(:sha384, machine.client_hello)
    message_hash = <<254, byte_size(first_hash)::24, first_hash::binary>>
    expected_digest = :crypto.hash(:sha384, [message_hash, hrr, client_hello2])
    assert retried.hrr_transcript.hash == :sha384
    assert Transcript.digest(retried.hrr_transcript) == expected_digest

    assert retried.hrr_transcript.length ==
             byte_size(message_hash) + byte_size(hrr) + byte_size(client_hello2)
  end

  defp hello(random, session_id, cipher, extensions) do
    extension_bytes = IO.iodata_to_binary(extensions)

    body =
      <<0x0303::16, random::binary, byte_size(session_id), session_id::binary, cipher::16, 0,
        byte_size(extension_bytes)::16, extension_bytes::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end

  defp extension(id, payload), do: <<id::16, byte_size(payload)::16, payload::binary>>
  defp plaintext_record(handshake), do: <<22, 3, 3, byte_size(handshake)::16, handshake::binary>>
end
