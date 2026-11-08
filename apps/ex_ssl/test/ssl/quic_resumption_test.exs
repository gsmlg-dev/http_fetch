defmodule SSL.QUICResumptionTest do
  use ExUnit.Case, async: true
  alias SSL.QUIC.{Request, Session, Secret}
  @fixtures Path.expand("../fixtures/server_flight", __DIR__)

  defp der(name) do
    [{:Certificate, der, :not_encrypted}] =
      File.read!(Path.join(@fixtures, name <> ".pem")) |> :public_key.pem_decode()

    der
  end

  defp policy(extra \\ []),
    do: Keyword.merge([enabled: true, context: "test-policy-v1", now: 1000], extra)

  defp options(role, extra \\ []) do
    common = [
      alpn: ["test"],
      transport_parameters: if(role == :client, do: <<1, 0>>, else: <<2, 0>>),
      ciphers: [0x1301],
      resumption: policy()
    ]

    auth =
      if role == :client do
        [
          cacerts: [der("root")],
          reference_identity: {:dns_id, "example.test"},
          server_name: "example.test"
        ]
      else
        [{type, key, :not_encrypted}] =
          File.read!(Path.join(@fixtures, "leaf-key.pem")) |> :public_key.pem_decode()

        [cert: [der("leaf")], key: {type, key}]
      end

    Keyword.merge(common ++ auth, extra)
  end

  defp exchange(client_opts \\ [], server_opts \\ [], cached \\ nil, commit \\ :resumed) do
    {:ok, c, co} = SSL.QUIC.new(:client, options(:client, client_opts))
    {:ok, s, so} = SSL.QUIC.new(:server, options(:server, server_opts))
    drive(c, s, co, so, co, so, cached, commit, 0)
  end

  defp drive(c, s, [], [], ca, sa, _, _, _), do: {c, s, ca, sa}

  defp drive(c, s, co, so, ca, sa, cached, commit, n) when n < 30 do
    {s, out_s} = deliver(s, co, cached, commit)
    {c, out_c} = deliver(c, so, cached, commit)
    drive(c, s, out_c, out_s, ca ++ out_c, sa ++ out_s, cached, commit, n + 1)
  end

  defp deliver(state, actions, cached, commit) do
    Enum.reduce(actions, {state, []}, fn
      {:emit, level, bytes}, {state, out} ->
        assert {:ok, next, actions} = SSL.QUIC.feed(state, level, bytes)
        {next, extra} = authorities(next, actions, cached, commit)
        {next, out ++ actions ++ extra}

      _, acc ->
        acc
    end)
  end

  defp authorities(state, actions, cached, commit) do
    Enum.reduce(actions, {state, []}, fn
      {kind, %Request{} = req}, {state, out}
      when kind in [:session_lookup, :session_commit, :session_store] ->
        reply =
          case kind do
            :session_lookup -> if cached, do: {:ok, cached, :lease, 1010}, else: :miss
            :session_commit -> {:ok, commit}
            :session_store -> :ok
          end

        assert {:ok, next, actions} = SSL.QUIC.continue(state, req.id, reply)
        {next, extra} = authorities(next, actions, cached, commit)
        {next, out ++ actions ++ extra}

      _, acc ->
        acc
    end)
  end

  defp tickets do
    {_, _, ca, sa} = exchange()
    [{:session_ticket, client}] = Enum.filter(ca, &match?({:session_ticket, _}, &1))

    [{:session_store, %Request{session: server}}] =
      Enum.filter(sa, &match?({:session_store, _}, &1))

    assert client.psk == server.psk
    assert client.identity == server.identity

    {:ok, cfg} =
      SSL.QUIC.Config.build(:client, options(:client, resumption: policy(session: client)))

    assert SSL.QUIC.Resumption.eligible?(client, cfg, 1000)
    assert SSL.QUIC.Resumption.client_session(cfg) != nil
    {client, server}
  end

  test "full authenticated handshake stores before NST and receipts pair the derived PSK" do
    {client, server} = tickets()
    assert :ok = Session.validate(client)
    assert :ok = Session.validate(server)
    assert client.server_name == server.server_name
    assert client.transport_parameters == <<2, 0>>
    assert server.transport_parameters == <<2, 0>>
    refute inspect(client) =~ inspect(client.psk)
    refute inspect(client) =~ inspect(client.identity)
  end

  test "resumed PSK-DHE authenticates Finished without certificate flight and rotates tickets" do
    {client, server} = tickets()
    {c, s, ca, sa} = exchange([resumption: policy(session: client)], [], server)
    assert %{resumed: true, handshake_complete: true, peer_authenticated: true} = SSL.QUIC.info(c)
    assert %{resumed: true, handshake_complete: true} = SSL.QUIC.info(s)
    refute Enum.any?(sa, &match?({:emit, :handshake, <<11, _::binary>>}, &1))
    refute Enum.any?(ca ++ sa, &match?(%Secret{level: :early_data}, &1))
    assert Enum.count(sa, &match?({:session_commit, _}, &1)) == 1
    assert [{:session_ticket, new}] = Enum.filter(ca, &match?({:session_ticket, _}, &1))
    refute new.identity == client.identity

    for level <- [:handshake, :application], direction <- [:read, :write] do
      [left] = Enum.filter(ca, &match?(%Secret{level: ^level, direction: ^direction}, &1))
      opposite = if direction == :read, do: :write, else: :read
      [right] = Enum.filter(sa, &match?(%Secret{level: ^level, direction: ^opposite}, &1))
      assert left.secret == right.secret
    end

    {_, _, ca2, _} = exchange([resumption: policy(session: client)], [], server)
    [a] = Enum.filter(ca, &match?(%Secret{level: :handshake, direction: :write}, &1))
    [b] = Enum.filter(ca2, &match?(%Secret{level: :handshake, direction: :write}, &1))
    refute a.secret == b.secret
  end

  test "resumed HRR verifies rewritten binder and consumes only CH1" do
    {client, server} = tickets()

    {c, s, ca, sa} =
      exchange([groups: [29, 23], resumption: policy(session: client)], [groups: [23]], server)

    assert SSL.QUIC.info(c).resumed
    assert SSL.QUIC.info(s).handshake_complete
    assert Enum.count(sa, &match?({:session_lookup, _}, &1)) == 1
    assert Enum.count(sa, &match?({:session_commit, _}, &1)) == 1
    assert Enum.count(ca, &match?({:emit, :initial, _}, &1)) == 2
  end

  test "one continuation rejects mismatched IDs, new input, duplicate replies and abort clears secrets" do
    {client, server} = tickets()

    {:ok, _, [{:emit, :initial, ch}]} =
      SSL.QUIC.new(:client, options(:client, resumption: policy(session: client)))

    {:ok, s, []} = SSL.QUIC.new(:server, options(:server))
    assert {:ok, waiting, [{:session_lookup, req}]} = SSL.QUIC.feed(s, :initial, ch)

    assert {:error, %{reason: :invalid_continuation}, ^waiting, []} =
             SSL.QUIC.continue(waiting, :wrong, :miss)

    assert {:error, %{reason: :continuation_pending}, ^waiting, []} =
             SSL.QUIC.feed(waiting, :initial, ch)

    assert {:ok, committing, [{:session_commit, commit}]} =
             SSL.QUIC.continue(waiting, req.id, {:ok, server, :lease, 1010})

    assert {:error, %{reason: :invalid_continuation}, ^committing, []} =
             SSL.QUIC.continue(committing, req.id, :miss)

    assert {:ok, next, out} = SSL.QUIC.continue(committing, commit.id, {:ok, :resumed})
    assert Enum.any?(out, &match?({:emit, :initial, _}, &1))

    assert {:error, %{reason: :invalid_continuation}, ^next, []} =
             SSL.QUIC.continue(next, commit.id, {:ok, :resumed})

    assert SSL.QUIC.abort(committing, :owner_down).pending == nil

    assert {:error, %{kind: :closed}, _, []} =
             SSL.QUIC.continue(SSL.QUIC.abort(waiting, :stop), req.id, :miss)

    assert {:error, %{reason: :invalid_continuation_result}, failed, [_]} =
             SSL.QUIC.continue(waiting, req.id, {:ok, :bad})

    assert failed.pending == nil
    refute inspect(commit) =~ inspect(server.psk)
  end

  test "unknown or no-longer-live ticket falls back before selected flight" do
    {client, _} = tickets()

    for commit <- [:resumed] do
      {c, _, _, sa} = exchange([resumption: policy(session: client)], [], nil, commit)
      refute SSL.QUIC.info(c).resumed
      assert Enum.any?(sa, &match?({:emit, :handshake, <<11, _::binary>>}, &1))
    end
  end

  test "selected binder mismatch is fatal before atomic consumption" do
    {client, server} = tickets()

    {:ok, _, [{:emit, :initial, ch}]} =
      SSL.QUIC.new(:client, options(:client, resumption: policy(session: client)))

    n = byte_size(ch) - 1
    <<prefix::binary-size(n), last>> = ch
    ch = <<prefix::binary, Bitwise.bxor(last, 1)>>
    {:ok, s, []} = SSL.QUIC.new(:server, options(:server))
    {:ok, s, [{:session_lookup, req}]} = SSL.QUIC.feed(s, :initial, ch)

    assert {:error, %{alert: :decrypt_error, reason: :invalid_psk_binder}, failed, [_]} =
             SSL.QUIC.continue(s, req.id, {:ok, server, :lease, 1010})

    assert failed.pending == nil
    assert failed.core == nil
  end

  test "expired, changed context and changed reference identity never offer cached PSK" do
    {client, _} = tickets()

    for extra <- [
          [resumption: policy(session: client, now: client.expires_at)],
          [resumption: policy(session: client, context: "new-policy")],
          [resumption: policy(session: client), reference_identity: {:dns_id, "wrong.test"}],
          [resumption: policy(session: client), cacerts: [der("leaf-rsa")]]
        ] do
      assert {:ok, _, [{:emit, :initial, ch}]} = SSL.QUIC.new(:client, options(:client, extra))
      {:ok, offer} = SSL.Protocol.ClientOffer.from_client_hello(ch)
      assert offer.psk_count == 0
    end
  end

  test "store failures skip optional NST after completed handshake" do
    {:ok, c, co} = SSL.QUIC.new(:client, options(:client))
    {:ok, s, []} = SSL.QUIC.new(:server, options(:server))
    {s, so} = deliver(s, co, nil, :resumed)
    {_, cf} = deliver(c, so, nil, :resumed)
    [{:emit, :handshake, finished}] = Enum.filter(cf, &match?({:emit, :handshake, _}, &1))
    assert {:ok, s, actions} = SSL.QUIC.feed(s, :handshake, finished)
    assert :handshake_complete in actions
    [{:session_store, req}] = Enum.filter(actions, &match?({:session_store, _}, &1))
    refute Enum.any?(actions, &match?({:emit, :application, _}, &1))
    assert {:ok, s, []} = SSL.QUIC.continue(s, req.id, {:error, :capacity})
    assert SSL.QUIC.info(s).handshake_complete
  end

  test "R2 emits paired early secrets only with commit approval and readiness still needs Finished" do
    {_, _, ca, sa} =
      exchange([resumption: policy(early_data: true)], resumption: policy(early_data: true))

    [{:session_ticket, client}] = Enum.filter(ca, &match?({:session_ticket, _}, &1))
    [{:session_store, %{session: server}}] = Enum.filter(sa, &match?({:session_store, _}, &1))

    for decision <- [:resumed, :early_data] do
      {c, s, ca, sa} =
        exchange(
          [resumption: policy(session: client, early_data: true)],
          [resumption: policy(early_data: true)],
          server,
          decision
        )

      assert SSL.QUIC.info(c).handshake_complete
      assert SSL.QUIC.info(s).handshake_complete
      assert [%Secret{} = early] = Enum.filter(ca, &match?(%Secret{level: :early_data}, &1))

      if decision == :early_data do
        assert [%Secret{} = remote] = Enum.filter(sa, &match?(%Secret{level: :early_data}, &1))
        assert early.secret == remote.secret
        assert {:early_data, :accepted} in ca
        assert {:early_data, :accepted} in sa
      else
        refute Enum.any?(sa, &match?(%Secret{level: :early_data}, &1))
        assert {:early_data, :rejected} in ca
        assert {:early_data, :rejected} in sa
      end

      refute Enum.any?(ca ++ sa, &match?({:emit, _, <<5, _::binary>>}, &1))
    end
  end

  test "commit loss falls back, while invalid Finished never completes or issues a ticket" do
    {client, server} = tickets()
    {:ok, c, co} = SSL.QUIC.new(:client, options(:client, resumption: policy(session: client)))
    [{:emit, :initial, ch}] = co
    {:ok, s, []} = SSL.QUIC.new(:server, options(:server))
    {:ok, s, [{:session_lookup, lookup}]} = SSL.QUIC.feed(s, :initial, ch)

    {:ok, s, [{:session_commit, commit}]} =
      SSL.QUIC.continue(s, lookup.id, {:ok, server, :lease, 1010})

    assert {:ok, _, fallback} = SSL.QUIC.continue(s, commit.id, {:error, :expired_lease})
    assert Enum.any?(fallback, &match?({:emit, :handshake, <<11, _::binary>>}, &1))
    assert {:ok, s, flight} = SSL.QUIC.continue(s, commit.id, {:ok, :resumed})
    refute SSL.QUIC.info(s).handshake_complete
    [{:emit, :initial, sh}] = Enum.filter(flight, &match?({:emit, :initial, _}, &1))
    {:ok, c, _} = SSL.QUIC.feed(c, :initial, sh)
    [ee, finished] = for {:emit, :handshake, bytes} <- flight, do: bytes
    {:ok, c, _} = SSL.QUIC.feed(c, :handshake, ee)

    assert {:error, %{alert: :decrypt_error}, failed, [{:error, _}]} =
             SSL.QUIC.feed(c, :handshake, flip(finished))

    refute SSL.QUIC.info(failed).handshake_complete
    {:ok, _, out} = SSL.QUIC.feed(c, :handshake, finished)
    [{:emit, :handshake, cf}] = Enum.filter(out, &match?({:emit, :handshake, _}, &1))

    assert {:error, %{alert: :decrypt_error}, failed, [{:error, _}]} =
             SSL.QUIC.feed(s, :handshake, flip(cf))

    refute SSL.QUIC.info(failed).handshake_complete
    assert failed.config == nil
  end

  test "consumed resumed HRR rejects a changed CH2 binder without a second authority call" do
    {client, server} = tickets()

    {:ok, c, co} =
      SSL.QUIC.new(
        :client,
        options(:client, groups: [29, 23], resumption: policy(session: client))
      )

    {:ok, s, []} = SSL.QUIC.new(:server, options(:server, groups: [23]))
    {s, hrr} = deliver(s, co, server, :resumed)
    {_, ch2} = deliver(c, hrr, server, :resumed)
    [{:emit, :initial, ch2}] = Enum.filter(ch2, &match?({:emit, :initial, _}, &1))
    assert s.core.session != nil
    assert s.pending == nil

    assert {:error, %{alert: :decrypt_error}, failed, [{:error, _}]} =
             SSL.QUIC.feed(s, :initial, flip(ch2))

    assert failed.core == nil
  end

  test "R2 HRR rejects early once and never exports server early keys" do
    {_, _, ca, sa} =
      exchange([resumption: policy(early_data: true)], resumption: policy(early_data: true))

    [{:session_ticket, client}] = Enum.filter(ca, &match?({:session_ticket, _}, &1))
    [{:session_store, %{session: server}}] = Enum.filter(sa, &match?({:session_store, _}, &1))

    {c, s, ca, sa} =
      exchange(
        [groups: [29, 23], resumption: policy(session: client, early_data: true)],
        [groups: [23], resumption: policy(early_data: true)],
        server,
        :resumed
      )

    assert SSL.QUIC.info(c).resumed
    assert SSL.QUIC.info(s).handshake_complete
    assert Enum.count(ca, &(&1 == {:early_data, :rejected})) == 1
    assert Enum.count(sa, &(&1 == {:early_data, :rejected})) == 1
    refute Enum.any?(sa, &match?(%Secret{level: :early_data}, &1))
  end

  test "R2 acceptance cannot be manufactured before commit and Finished" do
    {_, _, ca, sa} =
      exchange([resumption: policy(early_data: true)], resumption: policy(early_data: true))

    [{:session_ticket, client}] = Enum.filter(ca, &match?({:session_ticket, _}, &1))
    [{:session_store, %{session: server}}] = Enum.filter(sa, &match?({:session_store, _}, &1))

    {:ok, _, out} =
      SSL.QUIC.new(
        :client,
        options(:client, resumption: policy(session: client, early_data: true))
      )

    [{:emit, :initial, ch}] = Enum.filter(out, &match?({:emit, :initial, _}, &1))
    {:ok, s, []} = SSL.QUIC.new(:server, options(:server, resumption: policy(early_data: true)))
    {:ok, s, [{:session_lookup, req}]} = SSL.QUIC.feed(s, :initial, ch)
    {:ok, s, [{:session_commit, req}]} = SSL.QUIC.continue(s, req.id, {:ok, server, :lease, 1010})
    assert req.early_data
    refute SSL.QUIC.info(s).handshake_complete
    {:ok, s, out} = SSL.QUIC.continue(s, req.id, {:ok, :early_data})
    assert {:early_data, :accepted} in out
    refute :handshake_complete in out
    refute SSL.QUIC.info(s).handshake_complete

    assert {:error, _, failed, [{:error, _}]} =
             SSL.QUIC.feed(s, :handshake, <<20, 32::24, 0::256>>)

    refute SSL.QUIC.info(failed).handshake_complete
    assert failed.pending == nil
  end

  test "QUIC NST early-data maximum is validated even with caching disabled" do
    for resumption <- [nil, policy()] do
      {c, _, _, _} = exchange(resumption: resumption)

      for maximum <- [0, 1, 65_536] do
        body = <<600::32, 0::32, 0, 1::16, "x", 8::16, 42::16, 4::16, maximum::32>>

        assert {:error, %{kind: :quic, reason: :invalid_quic_early_data_maximum}, _, [_]} =
                 SSL.QUIC.feed(c, :application, <<4, byte_size(body)::24, body::binary>>)
      end
    end
  end

  test "R2 stale ticket age cannot acquire an early acceptance receipt" do
    {_, _, ca, sa} =
      exchange([resumption: policy(early_data: true)], resumption: policy(early_data: true))

    [{:session_ticket, client}] = Enum.filter(ca, &match?({:session_ticket, _}, &1))
    [{:session_store, %{session: server}}] = Enum.filter(sa, &match?({:session_store, _}, &1))

    {:ok, _, out} =
      SSL.QUIC.new(
        :client,
        options(:client, resumption: policy(session: client, early_data: true))
      )

    [{:emit, :initial, ch}] = Enum.filter(out, &match?({:emit, :initial, _}, &1))
    {:ok, s, []} = SSL.QUIC.new(:server, options(:server, resumption: policy(early_data: true)))
    {:ok, s, [{:session_lookup, req}]} = SSL.QUIC.feed(s, :initial, ch)

    {:ok, s, [{:session_commit, req}]} =
      SSL.QUIC.continue(s, req.id, {:ok, server, :lease, 21_001})

    refute req.early_data

    assert {:error, %{reason: :invalid_continuation_result}, _, [_]} =
             SSL.QUIC.continue(s, req.id, {:ok, :early_data})

    assert {:ok, _, out} = SSL.QUIC.continue(s, req.id, {:ok, :resumed})
    assert {:early_data, :rejected} in out
  end

  test "cached sessions cannot bypass malformed custom-profile validation" do
    {client, _} = tickets()
    {:ok, config} = SSL.QUIC.Config.build(:client, options(:client))
    profile = SSL.QUIC.Config.default_profile(config)
    invalid = %{profile | extensions: [{:signature_algorithms_cert, :invalid}]}

    assert {:error, %{kind: :configuration}} =
             SSL.QUIC.new(
               :client,
               options(:client, profile: invalid, resumption: policy(session: client))
             )
  end

  defp flip(bytes) do
    n = byte_size(bytes) - 1
    <<prefix::binary-size(n), last>> = bytes
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end
end
