defmodule SSL.Protocol.TLS12SessionTest do
  use ExUnit.Case, async: true

  alias SSL.Crypto.TLS12KeySchedule, as: Schedule
  alias SSL.Protocol.{ClientOffer, TLS12, TLS12Record}
  alias SSL.TLS12Session

  @id :binary.copy(<<9>>, 32)
  @master :binary.copy(<<83>>, 48)
  @client_random :binary.list_to_bin(Enum.to_list(0..31))
  @server_random :binary.list_to_bin(Enum.to_list(32..63))
  @ccs <<20, 3, 3, 0, 1, 1>>
  # Independently calculated with Python hashlib/hmac (RFC 5246 P_hash).
  # Values cover the exact encoded CH+SH and CH+SH+server Finished transcripts.
  @vectors [
    {0xC02F, "222032eab151d0c94dcd4e19", "bf9eaef4bfd470f0eaad6a51",
     "121b09fdba85e1ae43efbec89611d1d77cb127ca387d7cc7e94d6bd5b0bf9ecbc20af9cda9572c60"},
    {0xC030, "d95710f0a7300328a73b9495", "57119dd63d25af03d35b3eba",
     "4197e119c87da45f21692a7738026dbf59d27e3351b80c960506c5e8d65f2e94566a7c7723a305ccc1587f0bcce0359fec24688879e67a6210249bb5fbe35b04e31a62b7ff9fc8d0"},
    {0xC02B, "0383c3e2a2cba66eff5443dc", "ea99e757a12dcbf0ab52bdbe",
     "121b09fdba85e1ae43efbec89611d1d77cb127ca387d7cc7e94d6bd5b0bf9ecbc20af9cda9572c60"},
    {0xC02C, "f6491859a60b0528c40c5976", "8987440b7baca9b3b796db56",
     "4197e119c87da45f21692a7738026dbf59d27e3351b80c960506c5e8d65f2e94566a7c7723a305ccc1587f0bcce0359fec24688879e67a6210249bb5fbe35b04e31a62b7ff9fc8d0"}
  ]

  for {suite, server_hex, client_hex, block_hex} <- @vectors do
    test "EMS abbreviated suite #{suite} authenticates server-first and uses fresh keys" do
      suite = unquote(suite)
      server_verify = Base.decode16!(unquote(server_hex), case: :lower)
      client_verify = Base.decode16!(unquote(client_hex), case: :lower)
      {:ok, keys} = Schedule.resume(suite, @master, @client_random, @server_random)

      assert Base.encode16(
               keys.write_state.key <>
                 keys.read_state.key <> keys.write_state.iv <> keys.read_state.iv,
               case: :lower
             ) == unquote(block_hex)

      assert {:ok, changed} =
               Schedule.resume(suite, @master, :binary.copy(<<7>>, 32), @server_random)

      refute changed.write_state.key == keys.write_state.key
      refute changed.read_state.key == keys.read_state.key
      assert changed.read_state.sequence == 0

      {:ok, selected, [], []} = TLS12.feed(state(suite), plain(server_hello(suite)))
      assert selected.phase == :await_server_ccs
      assert selected.resumed
      assert selected.peer == session(suite).peer
      assert {:ok, encrypted, [], []} = TLS12.feed(selected, @ccs)

      {:ok, server_wire, _} =
        TLS12Record.encrypt(keys.read_state, :handshake, finished(server_verify))

      assert {:ok, connected, [@ccs, client_wire],
              [{:tls12_session, retained}, {:connected, nil}]} =
               TLS12.feed(encrypted, server_wire)

      assert {:ok, :handshake, client_finished, _} =
               TLS12Record.decrypt(keys.write_state, client_wire)

      assert client_finished == finished(client_verify)
      assert retained.issued_at == 0
      assert retained.expires_at == 600_000
      assert connected.phase == :connected
      assert connected.master_secret == nil
      assert connected.session == nil
      assert connected.transcript == nil
      assert connected.read_state.sequence == 1
      assert connected.write_state.sequence == 1
      assert connected.session_id == @id
    end
  end

  test "resumed ServerHello and encrypted Finished retain every handshake fragment boundary" do
    hello = server_hello(0xC02F)

    for split <- 1..(byte_size(hello) - 1) do
      <<first::binary-size(^split), last::binary>> = hello
      assert {:ok, partial, [], []} = TLS12.feed(state(0xC02F), plain(first))
      assert {:ok, selected, [], []} = TLS12.feed(partial, plain(last))
      assert selected.phase == :await_server_ccs
    end

    encoded = finished(Base.decode16!("222032eab151d0c94dcd4e19", case: :lower))
    {:ok, keys} = Schedule.resume(0xC02F, @master, @client_random, @server_random)

    for split <- 1..(byte_size(encoded) - 1) do
      <<first::binary-size(^split), last::binary>> = encoded
      {:ok, selected, [], []} = TLS12.feed(state(0xC02F), plain(hello))
      {:ok, encrypted, [], []} = TLS12.feed(selected, @ccs)
      {:ok, first_wire, read} = TLS12Record.encrypt(keys.read_state, :handshake, first)
      {:ok, last_wire, _} = TLS12Record.encrypt(read, :handshake, last)
      assert {:ok, partial, [], []} = TLS12.feed(encrypted, first_wire)

      assert {:ok, %{phase: :connected}, [@ccs, _],
              [{:tls12_session, %TLS12Session{}}, {:connected, nil}]} =
               TLS12.feed(partial, last_wire)
    end
  end

  test "resumption negotiates ALPN from the current handshake without renewing the session" do
    for selected <- ["http/1.1", nil] do
      bytes = hello(0xC02F, [{16, <<12::16, 2, "h2", 8, "http/1.1">>}])
      {:ok, offer} = ClientOffer.from_client_hello(bytes)
      saved = %{session(0xC02F) | alpn: "h2"}

      {:ok, initial} =
        TLS12.new(bytes, offer, [], nil, tls12_session: saved, enable_session: true)

      extra = if selected, do: [{16, <<9::16, 8, selected::binary>>}], else: []
      hello = server_hello(0xC02F, @id, [{23, <<>>}, {0xFF01, <<0>>}] ++ extra)
      assert {:ok, resumed, [], []} = TLS12.feed(initial, plain(hello))
      assert resumed.resumed
      assert resumed.negotiated_protocol == selected
      assert {:ok, encrypted, [], []} = TLS12.feed(resumed, @ccs)
      {:ok, keys} = Schedule.resume(0xC02F, @master, @client_random, @server_random)
      {:ok, verify} = Schedule.finished(0xC02F, @master, :server, bytes <> hello)
      {:ok, wire, _} = TLS12Record.encrypt(keys.read_state, :handshake, finished(verify))

      assert {:ok, _, [@ccs, _], [{:tls12_session, retained}, {:connected, ^selected}]} =
               TLS12.feed(encrypted, wire)

      assert retained == %{saved | alpn: selected}
    end
  end

  test "resumed ALPN still rejects an unoffered selection and malformed encoding" do
    bytes = hello(0xC02F, [{16, <<3::16, 2, "h2">>}])
    {:ok, offer} = ClientOffer.from_client_hello(bytes)
    {:ok, initial} = TLS12.new(bytes, offer, [], nil, tls12_session: session(0xC02F))

    for alpn <- [<<9::16, 8, "http/1.1">>, <<4::16, 2, "h2">>] do
      hello = server_hello(0xC02F, @id, [{23, <<>>}, {0xFF01, <<0>>}, {16, alpn}])

      assert {:error, {:fatal_alert, :illegal_parameter, :invalid_tls12_extensions}} =
               TLS12.feed(initial, plain(hello))
    end
  end

  test "changed suite, missing EMS and invalid saved material fail before CCS" do
    initial = state(0xC02F)

    for changed <- [
          %{initial | session: %{initial.session | suite: 0xC030}},
          %{initial | session: %{initial.session | master_secret: <<>>}},
          %{initial | session: %{initial.session | id: <<1>>}}
        ] do
      assert {:error, {:fatal_alert, :illegal_parameter, _}} =
               TLS12.feed(changed, plain(server_hello(0xC02F)))
    end

    assert {:error, {:fatal_alert, :handshake_failure, :extended_master_secret_required}} =
             TLS12.feed(initial, plain(server_hello(0xC02F, @id, [{0xFF01, <<0>>}])))
  end

  test "a declined saved session continues one full authenticated handshake" do
    assert {:ok, full, [], []} = TLS12.feed(state(0xC02F), plain(server_hello(0xC02F, <<1>>)))
    assert full.phase == :await_certificate
    assert full.session == nil
    refute full.resumed
    assert full.master_secret == nil
  end

  test "bad Finished, AEAD, early data, CCS and epoch fragments cannot release client Finished" do
    {:ok, selected, [], []} = TLS12.feed(state(0xC02F), plain(server_hello(0xC02F)))
    {:ok, encrypted, [], []} = TLS12.feed(selected, @ccs)
    {:ok, keys} = Schedule.resume(0xC02F, @master, @client_random, @server_random)
    {:ok, wrong, _} = TLS12Record.encrypt(keys.read_state, :handshake, finished(<<0::96>>))

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} =
             TLS12.feed(encrypted, wrong)

    {:ok, valid, _} =
      TLS12Record.encrypt(
        keys.read_state,
        :handshake,
        finished(Base.decode16!("222032eab151d0c94dcd4e19", case: :lower))
      )

    <<prefix::binary-size(byte_size(^valid) - 1), tag>> = valid

    assert {:error, {:fatal_alert, :bad_record_mac, _}} =
             TLS12.feed(encrypted, <<prefix::binary, Bitwise.bxor(tag, 1)>>)

    {:ok, early, _} = TLS12Record.encrypt(keys.read_state, :application_data, "early")
    assert {:error, {:fatal_alert, :unexpected_message, _}} = TLS12.feed(encrypted, early)
    assert {:error, {:fatal_alert, :unexpected_message, _}} = TLS12.feed(encrypted, @ccs)

    assert {:error, {:fatal_alert, :unexpected_message, :fragment_across_epoch}} =
             TLS12.feed(state(0xC02F), plain(server_hello(0xC02F) <> <<20, 0>>))

    assert {:error, :invalid_master_secret} =
             Schedule.resume(0xC02F, <<>>, @client_random, @server_random)

    assert {:error, {:invalid_random, :server_random}} =
             Schedule.resume(0xC02F, @master, @client_random, <<>>)
  end

  defp state(suite) do
    bytes = hello(suite)
    {:ok, offer} = ClientOffer.from_client_hello(bytes)

    {:ok, state} =
      TLS12.new(bytes, offer, [], nil, tls12_session: session(suite), enable_session: true)

    state
  end

  defp session(suite),
    do: %TLS12Session{
      id: @id,
      master_secret: @master,
      suite: suite,
      peer: %{chain: [<<1>>]},
      alpn: nil,
      issued_at: 0,
      expires_at: 600_000
    }

  defp hello(suite, extra \\ []) do
    extensions =
      extensions(
        [
          {43, <<2, 3, 3>>},
          {10, <<2::16, 0x0017::16>>},
          {13, <<4::16, 0x0804::16, 0x0403::16>>},
          {23, <<>>},
          {0xFF01, <<0>>}
        ] ++ extra
      )

    body =
      <<3, 3, @client_random::binary, 32, @id::binary, 2::16, suite::16, 1, 0,
        byte_size(extensions)::16, extensions::binary>>

    <<1, byte_size(body)::24, body::binary>>
  end

  defp server_hello(suite, id \\ @id, ext \\ [{23, <<>>}, {0xFF01, <<0>>}]) do
    extensions = extensions(ext)

    body =
      <<3, 3, @server_random::binary, byte_size(id), id::binary, suite::16, 0,
        byte_size(extensions)::16, extensions::binary>>

    <<2, byte_size(body)::24, body::binary>>
  end

  defp extensions(values),
    do:
      IO.iodata_to_binary(
        Enum.map(values, fn {id, bytes} -> <<id::16, byte_size(bytes)::16, bytes::binary>> end)
      )

  defp plain(bytes), do: <<22, 3, 3, byte_size(bytes)::16, bytes::binary>>
  defp finished(bytes), do: <<20, 12::24, bytes::binary>>
end
