defmodule SSL.Protocol.TLS12NegativeTest do
  use ExUnit.Case, async: true
  alias SSL.Protocol.{ClientOffer, HandshakeFramer, TLS12, TLS12Record, Transcript}
  alias SSL.Crypto.TLS12KeySchedule

  test "EMS, secure renegotiation, offered suites and extension response bounds fail closed" do
    for {extensions, suite, alert} <- [
          {[{0xFF01, <<0>>}], 0xC02F, :handshake_failure},
          {[{23, <<>>}], 0xC02F, :handshake_failure},
          {[{23, <<1>>}, {0xFF01, <<0>>}], 0xC02F, :illegal_parameter},
          {[{23, <<>>}, {0xFF01, <<1, 0>>}], 0xC02F, :handshake_failure},
          {[{23, <<>>}, {0xFF01, <<0>>}, {35, <<>>}], 0xC02F, :unsupported_extension},
          {[{23, <<>>}, {0xFF01, <<0>>}], 0xC030, :illegal_parameter}
        ] do
      state = state([0x0303])

      assert {:error, {:fatal_alert, ^alert, _}} =
               TLS12.feed(state, server_hello(extensions, suite))
    end
  end

  test "a nonempty echoed session ID cannot select unsupported TLS12 resumption" do
    initial = state([0x0303])
    initial = %{initial | offer: %{initial.offer | legacy_session_id: <<1, 2>>}}
    extensions = ext([{23, <<>>}, {0xFF01, <<0>>}])
    body = <<3, 3, 0::256, 2, 1, 2, 0xC02F::16, 0, byte_size(extensions)::16, extensions::binary>>

    assert {:error, {:fatal_alert, :illegal_parameter, :tls12_resumption_unsupported}} =
             TLS12.feed(initial, plain(<<2, byte_size(body)::24, body::binary>>))
  end

  test "downgrade markers reject only when TLS1.3 was offered" do
    for suffix <- ["DOWNGRD" <> <<0>>, "DOWNGRD" <> <<1>>] do
      record = server_hello([{23, <<>>}, {0xFF01, <<0>>}], 0xC02F, <<0::192, suffix::binary>>)

      assert {:error, {:fatal_alert, :illegal_parameter, :downgrade_detected}} =
               TLS12.feed(state([0x0304, 0x0303]), record)

      assert {:ok, %{phase: :await_certificate}, [], []} = TLS12.feed(state([0x0303]), record)
    end
  end

  test "ServerHello survives every record fragment boundary with its exact transcript" do
    <<22, 3, 3, _::16, encoded::binary>> = server_hello([{23, <<>>}, {0xFF01, <<0>>}], 0xC02F)

    for split <- 1..(byte_size(encoded) - 1) do
      <<first::binary-size(^split), last::binary>> = encoded
      {:ok, partial, [], []} = TLS12.feed(state([0x0303]), plain(first))
      {:ok, complete, [], []} = TLS12.feed(partial, plain(last))
      assert complete.phase == :await_certificate
      assert hd(complete.transcript.messages) == encoded
    end
  end

  test "early, duplicate, malformed and fragment-crossing CCS reject" do
    ccs = <<20, 3, 3, 1::16, 1>>
    initial = state([0x0303])
    assert {:error, {:fatal_alert, :unexpected_message, _}} = TLS12.feed(initial, ccs)
    assert {:ok, advanced, [], []} = TLS12.feed(%{initial | phase: :await_server_ccs}, ccs)
    assert {:error, {:fatal_alert, :unexpected_message, _}} = TLS12.feed(advanced, ccs)

    assert {:error, {:fatal_alert, :unexpected_message, _}} =
             TLS12.feed(initial, <<20, 3, 3, 1::16, 0>>)

    {:ok, [], partial} = HandshakeFramer.feed(HandshakeFramer.new(), <<20, 0>>)

    assert {:error, {:fatal_alert, :unexpected_message, :fragment_across_ccs}} =
             TLS12.feed(%{initial | phase: :await_server_ccs, framer: partial}, ccs)
  end

  test "encrypted Finished must authenticate before application data or connection events" do
    state = finished_state()

    {:ok, expected} =
      TLS12KeySchedule.finished(0xC02F, state.master_secret, :server, "transcript")

    {:ok, valid_wire, _} =
      TLS12Record.encrypt(state.read_state, :handshake, <<20, 12::24, expected::binary>>)

    assert {:ok, connected, [], [{:connected, nil}]} = TLS12.feed(state, valid_wire)
    assert connected.master_secret == nil
    assert connected.transcript == nil
    <<byte, tail::binary>> = expected

    {:ok, bad, _} =
      TLS12Record.encrypt(
        state.read_state,
        :handshake,
        <<20, 12::24, Bitwise.bxor(byte, 1), tail::binary>>
      )

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} = TLS12.feed(state, bad)
    {:ok, app, _} = TLS12Record.encrypt(state.read_state, :application_data, "early")
    assert {:error, {:fatal_alert, :unexpected_message, _}} = TLS12.feed(state, app)
    <<prefix::binary-size(byte_size(^valid_wire) - 1), tag>> = valid_wire

    assert {:error, {:fatal_alert, :bad_record_mac, _}} =
             TLS12.feed(state, <<prefix::binary, Bitwise.bxor(tag, 1)>>)
  end

  test "record errors retain protocol classification and no mutation" do
    state = finished_state()

    assert {:error, {:fatal_alert, :record_overflow, _}} =
             TLS12.feed(state, <<22, 3, 3, 0xFFFF::16>>)

    assert {:error, {:fatal_alert, :decode_error, _}} = TLS12.feed(state, <<22, 3, 2, 0::16>>)
    assert state.read_state.sequence == 0
    huge = %{state | transcript: %{state.transcript | length: 1_048_576}}

    assert {:error, {:fatal_alert, :unexpected_message, :tls12_transcript_limit_or_complete}} =
             TLS12.feed_handshakes(huge, [<<20, 12::24, 0::96>>], HandshakeFramer.new())
  end

  test "signed ECDHE parameters bind both randoms, offered group and certificate key" do
    private = :public_key.generate_key({:rsa, 2048, 65_537})
    public = {:RSAPublicKey, elem(private, 2), elem(private, 3)}
    {:ok, suite} = TLS12KeySchedule.suite(0xC02F)
    {:ok, pair} = SSL.Crypto.KeyExchange.generate(:secp256r1)
    params = <<3, 0x0017::16, byte_size(pair.public_key), pair.public_key::binary>>

    {:ok, signature} =
      SSL.Crypto.Signature.sign_message(0x0804, private, <<0::512, params::binary>>)

    initial = state([0x0303])

    initial = %{
      initial
      | phase: :await_server_key_exchange,
        suite: suite,
        server_random: <<0::256>>,
        peer: %SSL.PKIX.VerifiedPeer{leaf_der: <<>>, leaf: nil, public_key: public},
        offer: %{initial.offer | supported_groups: [0x0017], signature_schemes: [0x0804]}
    }

    body = <<params::binary, 0x0804::16, byte_size(signature)::16, signature::binary>>
    wire = plain(<<12, byte_size(body)::24, body::binary>>)
    assert {:ok, accepted, [], []} = TLS12.feed(initial, wire)
    assert accepted.phase == :await_request_or_done
    assert accepted.key_pair.public_key != pair.public_key

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_server_key_exchange}} =
             TLS12.feed(%{initial | server_random: <<1::256>>}, wire)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_server_key_exchange}} =
             TLS12.feed(%{initial | offer: %{initial.offer | supported_groups: [0x001D]}}, wire)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_server_key_exchange}} =
             TLS12.feed(%{initial | offer: %{initial.offer | signature_schemes: [0x0403]}}, wire)

    <<first, rest::binary>> = signature

    badbody =
      <<params::binary, 0x0804::16, byte_size(signature)::16, Bitwise.bxor(first, 1),
        rest::binary>>

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_server_key_exchange}} =
             TLS12.feed(initial, plain(<<12, byte_size(badbody)::24, badbody::binary>>))
  end

  defp finished_state do
    {:ok, read} = TLS12Record.new(:aes_128_gcm, <<0::128>>, <<0::32>>)
    {:ok, suite} = TLS12KeySchedule.suite(0xC02F)

    %{
      state([0x0303])
      | phase: :await_server_finished,
        read_state: read,
        suite: suite,
        master_secret: <<0::384>>,
        transcript: Transcript.new(:sha256) |> Transcript.append("transcript")
    }
  end

  defp state(versions) do
    versions = for v <- versions, into: <<>>, do: <<v::16>>

    extensions =
      ext([{43, <<byte_size(versions), versions::binary>>}, {23, <<>>}, {0xFF01, <<0>>}])

    body =
      <<3, 3, 0::256, 0, 2::16, 0xC02F::16, 1, 0, byte_size(extensions)::16, extensions::binary>>

    hello = <<1, byte_size(body)::24, body::binary>>
    {:ok, offer} = ClientOffer.from_client_hello(hello)
    {:ok, state} = TLS12.new(hello, offer, [], {:dns_id, "exssl.test"}, [])
    state
  end

  defp server_hello(extensions, suite, random \\ <<0::256>>) do
    extensions = ext(extensions)

    body =
      <<3, 3, random::binary, 0, suite::16, 0, byte_size(extensions)::16, extensions::binary>>

    plain(<<2, byte_size(body)::24, body::binary>>)
  end

  defp ext(extensions),
    do:
      Enum.map(extensions, fn {id, data} -> <<id::16, byte_size(data)::16, data::binary>> end)
      |> IO.iodata_to_binary()

  defp plain(bytes), do: <<22, 3, 3, byte_size(bytes)::16, bytes::binary>>
end
