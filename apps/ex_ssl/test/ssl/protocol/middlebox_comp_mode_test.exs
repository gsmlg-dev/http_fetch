defmodule SSL.Protocol.MiddleboxCompModeTest do
  use ExUnit.Case, async: true

  alias SSL.ClientHello.AST
  alias SSL.ClientHello.Materializer
  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.AEAD
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.Options
  alias SSL.Protocol.{ClientOffer, HandshakeMachine, RecordFramer, Transcript}

  @ccs <<20, 3, 3, 0, 1, 1>>
  @hrr_random Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
  @fixture_dir Path.expand("../../fixtures/server_flight", __DIR__)
  @trust File.read!(Path.join(@fixture_dir, "root.pem"))
  @capture Path.join(@fixture_dir, "capture.txt")
           |> File.read!()
           |> String.split("\n", trim: true)
           |> Map.new(fn line ->
             [name, value] = String.split(line, "=", parts: 2)
             {String.to_atom(name), Base.decode16!(value)}
           end)

  test "fragmented HRR prefixes CH2 exactly once only for an actual nonempty ID" do
    for mode <- [true, false] do
      machine = initial_machine(mode)
      hrr = retry_hello(machine.offer.legacy_session_id, 0x0017)
      <<first::binary-size(3), rest::binary>> = hrr
      assert {:ok, partial, [], []} = HandshakeMachine.feed(machine, plaintext_record(first))
      assert {:ok, retried, records, []} = HandshakeMachine.feed(partial, plaintext_record(rest))

      record = plaintext_record(retried.client_hello)
      assert records == if(mode, do: [@ccs, record], else: [record])
      assert {:ok, offer} = ClientOffer.from_client_hello(retried.client_hello)
      assert offer.legacy_session_id == machine.offer.legacy_session_id
      assert retried.client_ast.random == machine.client_ast.random
      assert retried.client_ast.cipher_suites == machine.client_ast.cipher_suites

      assert Enum.take(retried.client_ast.extensions, 3) ==
               Enum.take(machine.client_ast.extensions, 3)

      assert [%{group: 0x0017, key_exchange: share}] = offer.key_shares
      assert byte_size(share) == 65
      assert [%{key_exchange: initial_share}] = machine.offer.key_shares
      refute share == initial_share

      digest = :crypto.hash(:sha256, machine.client_hello)
      message_hash = <<254, byte_size(digest)::24, digest::binary>>
      expected = :crypto.hash(:sha256, [message_hash, hrr, retried.client_hello])
      assert Transcript.digest(retried.hrr_transcript) == expected

      assert retried.hrr_transcript.length ==
               byte_size(message_hash) + byte_size(hrr) + byte_size(retried.client_hello)

      assert {:error, {:fatal_alert, :unexpected_message, :second_hello_retry_request}} =
               HandshakeMachine.feed(retried, plaintext_record(hrr))
    end
  end

  test "invalid HRR has no tentative CCS or retry flight" do
    for mode <- [true, false] do
      machine = initial_machine(mode)

      assert {:error, {:fatal_alert, :illegal_parameter, _}} =
               HandshakeMachine.feed(
                 machine,
                 plaintext_record(retry_hello(machine.offer.legacy_session_id, 0x0018))
               )

      assert {:error, {:fatal_alert, _, _}} =
               HandshakeMachine.feed(machine, plaintext_record(<<2, 0, 0, 1, 0>>))
    end
  end

  test "incoming literal CCS is independent of outgoing policy in both hello phases" do
    for mode <- [true, false] do
      machine = initial_machine(mode)
      assert {:ok, ^machine, [], []} = HandshakeMachine.feed(machine, @ccs)

      assert {:ok, retried, _, []} =
               HandshakeMachine.feed(
                 machine,
                 plaintext_record(retry_hello(machine.offer.legacy_session_id, 0x0017))
               )

      assert {:ok, ^retried, [], []} = HandshakeMachine.feed(retried, @ccs)

      for current <- [machine, retried],
          invalid <- [<<20, 3, 3, 0, 1, 0>>, <<20, 3, 3, 0, 2, 1, 1>>] do
        assert {:error, {:fatal_alert, :unexpected_message, :invalid_change_cipher_spec}} =
                 HandshakeMachine.feed(current, invalid)
      end
    end
  end

  test "fragmented frozen SID0 authentication ignores CCS without changing Finished or counters" do
    machine = captured_machine()
    assert machine.offer.legacy_session_id == <<>>

    assert {:ok, machine, [], []} =
             HandshakeMachine.feed(machine, plaintext_record(@capture.server_hello))

    assert {:ok, ^machine, [], []} = HandshakeMachine.feed(machine, @ccs)

    stream = @ccs <> @capture.record_1 <> @ccs <> @capture.record_2 <> @ccs <> @capture.record_3

    {connected, framer, outgoing, events} =
      for <<byte <- stream>>, reduce: {machine, RecordFramer.new(), [], []} do
        {current, buffer, out, prior_events} ->
          assert {:ok, records, buffer} = RecordFramer.feed(buffer, <<byte>>)

          Enum.reduce(records, {current, buffer, out, prior_events}, fn record,
                                                                        {state, buffer, out,
                                                                         prior_events} ->
            assert {:ok, next, more, new_events} = HandshakeMachine.feed(state, record)
            {next, buffer, out ++ more, prior_events ++ new_events}
          end)
      end

    assert RecordFramer.buffered_size(framer) == 0
    assert outgoing == [@capture.client_finished_record]
    assert events == [{:connected, nil}]
    assert connected.read_state.sequence == 0
    assert connected.write_state.sequence == 0

    assert {:error, {:fatal_alert, :decode_error, {:unexpected_outer_content_type, 20}}} =
             HandshakeMachine.feed(connected, @ccs)
  end

  test "protected CCS and tampered encrypted input remain structured failures without output" do
    machine = captured_machine()

    assert {:ok, machine, [], []} =
             HandshakeMachine.feed(machine, plaintext_record(@capture.server_hello))

    header = <<23, 3, 3, 18::16>>
    assert {:ok, ciphertext, tag} = AEAD.encrypt(machine.read_state, header, <<1, 20>>)

    assert {:error, {:fatal_alert, :decode_error, {:unsupported_inner_content_type, 20}}} =
             HandshakeMachine.feed(machine, header <> ciphertext <> tag)

    record = @capture.record_1
    <<head::binary-size(byte_size(^record) - 1), last>> = record

    assert {:error, {:fatal_alert, :bad_record_mac, _}} =
             HandshakeMachine.feed(machine, head <> <<Bitwise.bxor(last, 1)>>)
  end

  defp captured_machine do
    materialized = %Materialized{
      client_hello: %AST{
        legacy_version: 0x0303,
        random: <<0::256>>,
        session_id: <<>>,
        cipher_suites: [0x1302],
        compression_methods: [0],
        extensions: []
      },
      key_pairs: [
        %KeyPair{
          group: :x25519,
          public_key: @capture.client_public,
          private_key: @capture.client_private
        }
      ]
    }

    assert {:ok, machine, [initial]} =
             HandshakeMachine.init(materialized, @trust, {:dns_id, "example.test"},
               encoded_client_hello: @capture.client_hello
             )

    assert initial == plaintext_record(@capture.client_hello)
    machine
  end

  defp initial_machine(mode) do
    assert {:ok, options} =
             Options.normalize("example.test",
               verify: :verify_none,
               cacerts: [],
               middlebox_comp_mode: mode,
               ciphers: ["TLS_AES_128_GCM_SHA256"],
               supported_groups: [:x25519, :secp256r1]
             )

    assert {:ok, materialized} =
             Materializer.materialize(options.profile, Options.capabilities(), options.context)

    assert {:ok, machine, [_]} =
             HandshakeMachine.init(materialized, [], options.identity, verify: :verify_none)

    machine
  end

  defp retry_hello(session_id, group) do
    extensions = <<43::16, 2::16, 0x0304::16, 51::16, 2::16, group::16>>

    body =
      <<0x0303::16, @hrr_random::binary, byte_size(session_id), session_id::binary, 0x1301::16, 0,
        byte_size(extensions)::16, extensions::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end

  defp plaintext_record(bytes), do: <<22, 3, 3, byte_size(bytes)::16, bytes::binary>>
end
