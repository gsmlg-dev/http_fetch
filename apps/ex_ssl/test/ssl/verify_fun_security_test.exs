defmodule SSL.VerifyFunSecurityTest do
  use ExUnit.Case, async: true
  @moduletag :integration
  alias SSL.ClientHello.{AST, Materializer}
  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.{KeyExchange, Signature, TLS12KeySchedule}
  alias SSL.Crypto.KeyExchange.KeyPair

  alias SSL.Protocol.{
    HandshakeCore,
    HandshakeFramer,
    HandshakeMachine,
    Record,
    TLS12,
    TLS12Record
  }

  @fixtures Path.expand("../fixtures/server_flight", __DIR__)

  test "accepting callback cannot bypass TLS13 CV Finished or AEAD and leaves no terminal policy" do
    capture = capture()
    initial = tls13(capture)
    assert {:ok, initial, [], []} = HandshakeMachine.feed(initial, plain(capture.server_hello))

    messages =
      messages(initial.read_state, [capture.record_1, capture.record_2, capture.record_3])

    [ee, certificate, cv, finished] = messages
    assert {:ok, core} = HandshakeCore.process_message(initial.verifier.core, ee)
    assert {:ok, core} = HandshakeCore.process_message(core, certificate)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_certificate_verify}} =
             HandshakeCore.process_message(core, flip(cv))

    assert {:ok, core} = HandshakeCore.process_message(core, cv)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} =
             HandshakeCore.process_message(core, flip(finished))

    assert {:connected, result, [_]} = HandshakeCore.process_message(core, finished)
    assert result.resumption_master == nil
    refute contains_function?(result)

    assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
             HandshakeMachine.feed(initial, flip(capture.record_1))

    assert {:ok, wire, _} =
             Record.encrypt(initial.read_state, :handshake, IO.iodata_to_binary(messages))

    assert {:ok, terminal, [_], [{:connected, nil}]} = HandshakeMachine.feed(initial, wire)
    refute terminal.enable_tickets
    assert terminal.resumption_master == nil
    refute contains_function?(terminal)

    ticket = <<4, 15::24, 60::32, 7::32, 1, 9, 1::16, 1, 0::16>>
    assert {:ok, wire, _} = Record.encrypt(terminal.read_state, :handshake, ticket)
    assert {:ok, terminal, [], []} = HandshakeMachine.feed(terminal, wire)
    assert terminal.pending_tickets == []
    assert terminal.ticket_count == 0
  end

  test "accepting callback cannot bypass authenticated TLS12 SKE Finished or AEAD" do
    key = pem_key("leaf-rsa-key.pem")
    [entry] = :public_key.pem_decode(File.read!(Path.join(@fixtures, "leaf-rsa.pem")))
    leaf = elem(entry, 1)
    options = [versions: [:"tlsv1.2"], cacerts: [], verify_fun: callback()]
    assert {:ok, normalized} = SSL.Options.normalize("example.test", options)

    assert {:ok, materialized} =
             Materializer.materialize(
               normalized.profile,
               SSL.Options.capabilities(),
               normalized.context
             )

    assert {:ok, initial, [_]} =
             HandshakeMachine.init(materialized, [], {:dns_id, "example.test"},
               verify_fun: callback()
             )

    extensions = <<23::16, 0::16, 0xFF01::16, 1::16, 0>>
    hello = <<3, 3, 1::256, 0, 0xC02F::16, 0, byte_size(extensions)::16, extensions::binary>>
    assert {:ok, initial, [], []} = HandshakeMachine.feed(initial, plain(handshake(2, hello)))
    chain = <<byte_size(leaf)::24, leaf::binary>>

    assert {:ok, initial, [], []} =
             TLS12.feed(initial, plain(handshake(11, <<byte_size(chain)::24, chain::binary>>)))

    assert initial.peer.leaf_der == leaf
    assert {:ok, pair} = KeyExchange.generate(:secp256r1)
    params = <<3, 0x0017::16, byte_size(pair.public_key), pair.public_key::binary>>

    assert {:ok, signature} =
             Signature.sign_message(
               0x0804,
               key,
               <<initial.client_random::binary, initial.server_random::binary, params::binary>>
             )

    ske =
      handshake(12, <<params::binary, 0x0804::16, byte_size(signature)::16, signature::binary>>)

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_server_key_exchange}} =
             TLS12.feed(initial, plain(flip(ske)))

    assert {:ok, advanced, [], []} = TLS12.feed(initial, plain(ske))
    assert {:ok, advanced, [_ | _], []} = TLS12.feed(advanced, plain(handshake(14, <<>>)))
    assert {:ok, advanced, [], []} = TLS12.feed(advanced, <<20, 3, 3, 1::16, 1>>)
    transcript = advanced.transcript.messages |> Enum.reverse() |> IO.iodata_to_binary()

    assert {:ok, finished} =
             TLS12KeySchedule.finished(
               advanced.suite.id,
               advanced.master_secret,
               :server,
               transcript
             )

    assert {:ok, wire, _} =
             TLS12Record.encrypt(advanced.read_state, :handshake, handshake(20, finished))

    assert {:ok, terminal, [], [{:connected, nil}]} = TLS12.feed(advanced, wire)
    refute contains_function?(terminal)

    assert {:ok, bad, _} =
             TLS12Record.encrypt(advanced.read_state, :handshake, handshake(20, flip(finished)))

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} = TLS12.feed(advanced, bad)

    assert {:error, {:fatal_alert, :bad_record_mac, :authentication_failed}} =
             TLS12.feed(advanced, flip(wire))
  end

  defp tls13(capture) do
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
          public_key: capture.client_public,
          private_key: capture.client_private
        }
      ]
    }

    assert {:ok, initial, [_]} =
             HandshakeMachine.init(materialized, [], {:dns_id, "example.test"},
               encoded_client_hello: capture.client_hello,
               verify_fun: callback(),
               enable_tickets: true
             )

    initial
  end

  defp messages(read, records) do
    {messages, _, _} =
      Enum.reduce(records, {[], HandshakeFramer.new(), read}, fn record, {all, framer, read} ->
        assert {:ok, :handshake, plaintext, read} = Record.decrypt(read, record)
        assert {:ok, decoded, framer} = HandshakeFramer.feed(framer, plaintext)
        {all ++ decoded, framer, read}
      end)

    messages
  end

  defp capture do
    Path.join(@fixtures, "capture.txt")
    |> File.read!()
    |> String.split("\n", trim: true)
    |> Map.new(fn line ->
      [name, value] = String.split(line, "=", parts: 2)
      {String.to_atom(name), Base.decode16!(value)}
    end)
  end

  defp callback, do: {fn _, _, state -> {:valid, state} end, :initial}

  defp pem_key(name) do
    [entry] = Path.join(@fixtures, name) |> File.read!() |> :public_key.pem_decode()
    :public_key.pem_entry_decode(entry)
  end

  defp contains_function?(term) when is_function(term), do: true

  defp contains_function?(term) when is_map(term),
    do: term |> Map.to_list() |> contains_function?()

  defp contains_function?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> contains_function?()

  defp contains_function?(term) when is_list(term), do: Enum.any?(term, &contains_function?/1)
  defp contains_function?(_), do: false

  defp flip(bytes) do
    size = byte_size(bytes) - 1
    <<prefix::binary-size(^size), last>> = bytes
    prefix <> <<Bitwise.bxor(last, 1)>>
  end

  defp handshake(type, bytes), do: <<type, byte_size(bytes)::24, bytes::binary>>
  defp plain(bytes), do: <<22, 3, 3, byte_size(bytes)::16, bytes::binary>>
end
