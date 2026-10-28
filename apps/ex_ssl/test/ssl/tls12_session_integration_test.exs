defmodule SSL.TLS12SessionIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.{ClientAuthFixtures, OpenSSLPeer}
  alias SSL.{Options, SessionCache, TLS12ResumptionContext}
  @host {127, 0, 0, 1}
  @response "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong"
  @suites [
    {:server, 0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"},
    {:server, 0xC030, "ECDHE-RSA-AES256-GCM-SHA384"},
    {:ec_server, 0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256"},
    {:ec_server, 0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384"}
  ]

  setup_all do
    dir = Path.join(System.tmp_dir!(), "tls12-sessions-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(dir) end)
    %{fixtures: ClientAuthFixtures.create(dir)}
  end

  for {identity, suite, cipher} <- @suites do
    test "OpenSSL #{cipher} observes EMS full/resumed HTTP exactly once with fresh record keys",
         %{fixtures: f} do
      with_peer(
        f,
        [
          certfile: f[unquote(identity)].certificate,
          keyfile: f[unquote(identity)].key,
          cipher: unquote(cipher)
        ],
        fn peer ->
          opts = Keyword.put(options(f), :ciphers, [cipher_option(unquote(suite))])
          first = exchange(peer, opts, false, f[unquote(identity)].der)
          second = exchange(peer, opts, true, f[unquote(identity)].der)
          assert first.id == second.id
          refute same_keys?(first.machine, second.machine)
          assert second.machine.master_secret == nil
          assert second.machine.session == nil
        end
      )
    end
  end

  test "false and omission always use a full handshake and never save", %{fixtures: f} do
    for mode <- [false, :omitted] do
      with_peer(f, [], fn peer ->
        opts =
          if mode == :omitted,
            do: Keyword.delete(options(f), :reuse_sessions),
            else: Keyword.put(options(f), :reuse_sessions, mode)

        first = exchange(peer, opts, false, f.server.der)
        second = exchange(peer, opts, false, f.server.der)
        refute first.id == second.id
        {:ok, normalized} = Options.normalize(@host, opts)
        key = TLS12ResumptionContext.partition(normalized, {@host, peer.port})
        assert :miss = SessionCache.lookup(key, first.id)
        assert :miss = SessionCache.lookup(key, second.id)
      end)
    end
  end

  test "OpenSSL resumes the same EMS session with a newly selected offered ALPN", %{fixtures: f} do
    with_peer(f, [mode: :echo, alpn: ["h2"], alpn_after_first: ["http/1.1"]], fn peer ->
      opts = Keyword.put(options(f), :alpn_advertised_protocols, ["h2", "http/1.1"])

      sessions =
        for {resumed, alpn} <- [{false, "h2"}, {true, "http/1.1"}] do
          assert {:ok, socket} = SSL.connect(@host, peer.port, opts, 5000)
          on_exit(fn -> SSL.close(socket) end)

          assert {:ok, %{"resumed" => ^resumed, "alpn" => ^alpn}} =
                   OpenSSLPeer.event(peer, "handshake", 5000)

          assert {:ok, ^alpn} = SSL.negotiated_protocol(socket)
          {:connected, state} = :sys.get_state(socket.pid)
          assert state.session_material.alpn == alpn
          {:ok, normalized} = Options.normalize(@host, opts)
          key = TLS12ResumptionContext.partition(normalized, {@host, peer.port})
          assert {:ok, cached} = SessionCache.lookup(key, state.session_material.id)
          assert cached.alpn == alpn
          assert :ok = SSL.send(socket, <<4::32, "ping">>)
          assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 5000)
          assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5000)
          monitor = Process.monitor(socket.pid)
          assert :ok = SSL.close(socket)
          assert_receive {:DOWN, ^monitor, :process, _, _}, 5000
          {cached, state.machine}
        end

      [{first, first_keys}, {second, second_keys}] = sessions
      assert first.id == second.id
      assert first.issued_at == second.issued_at
      assert first.expires_at == second.expires_at
      refute same_keys?(first_keys, second_keys)
    end)
  end

  test "save creates fresh sessions and public IDs select a saved session without automatic reuse",
       %{fixtures: f} do
    with_peer(f, [max_connections: 4], fn peer ->
      opts = Keyword.put(options(f), :reuse_sessions, :save)
      first = exchange(peer, opts, false, f.server.der)
      second = exchange(peer, opts, false, f.server.der)
      refute first.id == second.id

      selected =
        opts |> Keyword.put(:reuse_session, first.id) |> Keyword.put(:reuse_sessions, false)

      third = exchange(peer, selected, true, f.server.der)
      fourth = exchange(peer, selected, true, f.server.der)
      assert third.id == first.id
      assert fourth.id == first.id
      refute same_keys?(third.machine, fourth.machine)
    end)
  end

  test "mTLS resumed identity is server observed and changed credentials require full authentication",
       %{fixtures: f} do
    with_peer(f, [max_connections: 4, cafile: f.ca.certificate, verify: :required], fn peer ->
      opts = options(f) ++ [certfile: f.rsa.certificate, keyfile: f.rsa.key]
      exchange(peer, opts, false, f.server.der, f.rsa.der)
      exchange(peer, opts, true, f.server.der, f.rsa.der)
      changed = Keyword.merge(opts, certfile: f.ec.certificate, keyfile: f.ec.key)
      exchange(peer, changed, false, f.server.der, f.ec.der)
      exchange(peer, changed, true, f.server.der, f.ec.der)
    end)
  end

  test "policy callbacks always receive full certificate handshakes", %{fixtures: f} do
    with_peer(f, [], fn peer ->
      owner = self()

      callback =
        {fn _cert, event, count ->
           if event == :valid_peer, do: send(owner, :verified_full_chain)

           case event do
             {:extension, _} -> {:unknown, count}
             {:bad_cert, reason} -> {:fail, reason}
             _ -> {:valid, count + 1}
           end
         end, 0}

      opts = Keyword.put(options(f), :verify_fun, callback)
      exchange(peer, opts, false, f.server.der)
      assert_receive :verified_full_chain
      exchange(peer, opts, false, f.server.der)
      assert_receive :verified_full_chain
    end)
  end

  test "changed profile or ALPN performs one full handshake and preserves the original partition",
       %{fixtures: f} do
    for changes <- [
          [supported_groups: [:secp384r1]],
          [alpn_advertised_protocols: ["http/1.1", "h2"]]
        ] do
      with_peer(f, [max_connections: 3], fn peer ->
        exchange(peer, options(f), false, f.server.der)
        exchange(peer, Keyword.merge(options(f), changes), false, f.server.der)
        exchange(peer, options(f), true, f.server.der)
      end)
    end
  end

  test "changed trust or reference identity authenticates afresh and rejects", %{fixtures: f} do
    for changes <- [[cacerts: [f.wrong.der]], [server_name_indication: ~c"wrong.exssl.test"]] do
      with_peer(f, [], fn peer ->
        exchange(peer, options(f), false, f.server.der)

        assert {:error, _} =
                 SSL.connect(@host, peer.port, Keyword.merge(options(f), changes), 5000)

        assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5000)
      end)
    end
  end

  test "server cache loss declines a session and continues full authentication on the same connection",
       %{fixtures: f} do
    with_peer(f, [restart_context: true], fn peer ->
      first = exchange(peer, options(f), false, f.server.der)
      second = exchange(peer, options(f), false, f.server.der)
      refute first.id == second.id
    end)
  end

  test "an invalid cached master fails without application data or automatic reconnect", %{
    fixtures: f
  } do
    with_peer(f, [], fn peer ->
      first = exchange(peer, options(f), false, f.server.der)
      {:ok, normalized} = Options.normalize(@host, options(f))
      key = TLS12ResumptionContext.partition(normalized, {@host, peer.port})
      {:ok, saved} = SessionCache.lookup(key, first.id)
      :ok = SessionCache.put(key, %{saved | master_secret: :binary.copy(<<0>>, 48)})
      assert {:error, _} = SSL.connect(@host, peer.port, options(f), 5000)
      assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5000)
      assert {:error, {:peer_exit, 0}} = OpenSSLPeer.event(peer, "exchange", 5000)
    end)
  end

  test "mixed offers retain TLS12 session reuse and do not alter capable TLS13 negotiation", %{
    fixtures: f
  } do
    opts = Keyword.put(options(f), :versions, [:"tlsv1.3", :"tlsv1.2"])

    with_peer(f, [], fn peer ->
      exchange(peer, opts, false, f.server.der)
      exchange(peer, opts, true, f.server.der)
    end)

    with_peer(f, [max_version: :tls13], fn peer ->
      exchange(peer, opts, false, f.server.der, nil, :"tlsv1.3")
      exchange(peer, opts, false, f.server.der, nil, :"tlsv1.3")
    end)
  end

  test "public opaque tuple shape resumes false-export and save sessions with stable credentials",
       %{fixtures: f} do
    for mode <- [false, :save] do
      with_peer(f, [], fn peer ->
        opts = Keyword.put(options(f), :reuse_sessions, mode)
        first = exchange(peer, opts, false, f.server.der, nil, :"tlsv1.2", true)
        assert is_binary(first.data) and byte_size(first.data) == 40

        selected =
          opts
          |> Keyword.put(:reuse_session, {first.id, first.data})
          |> Keyword.put(:reuse_sessions, false)

        second = exchange(peer, selected, true, f.server.der, nil, :"tlsv1.2", true)
        assert second.id == first.id
        assert second.data == first.data
        assert second.session.issued_at == first.session.issued_at
        assert second.session.expires_at == first.session.expires_at
      end)
    end
  end

  test "explicit true promotes a successfully resumed credential to automatic eligibility without renewal",
       %{fixtures: f} do
    with_peer(f, [max_connections: 3], fn peer ->
      opts = Keyword.put(options(f), :reuse_sessions, false)
      first = exchange(peer, opts, false, f.server.der, nil, :"tlsv1.2", true)
      selected = options(f) |> Keyword.put(:reuse_session, {first.id, first.data})
      second = exchange(peer, selected, true, f.server.der)
      third = exchange(peer, options(f), true, f.server.der)
      assert second.session.expires_at == first.session.expires_at
      assert third.session.expires_at == first.session.expires_at
      assert third.id == first.id
      assert third.session.auto
    end)
  end

  test "forged or evicted capabilities take one full handshake and cannot revive stale material",
       %{fixtures: f} do
    with_peer(f, [max_connections: 4], fn peer ->
      opts = Keyword.put(options(f), :reuse_sessions, false)
      first = exchange(peer, opts, false, f.server.der, nil, :"tlsv1.2", true)
      <<prefix::binary-size(39), last>> = first.data
      invalid = <<prefix::binary, Bitwise.bxor(last, 1)>>
      exchange(peer, Keyword.put(opts, :reuse_session, {first.id, invalid}), false, f.server.der)

      exchange(
        peer,
        Keyword.put(opts, :reuse_session, {first.id, first.data}),
        true,
        f.server.der
      )

      for n <- 1..129 do
        key = :crypto.hash(:sha256, <<n::32, "eviction-fixture">>)
        assert :ok = SessionCache.put(key, %{first.session | id: <<n::16>>, data: nil})
      end

      exchange(
        peer,
        Keyword.put(opts, :reuse_session, {first.id, first.data}),
        false,
        f.server.der
      )
    end)
  end

  test "logical peer closure erases live master and timer while authenticated response bytes remain drainable",
       %{fixtures: f} do
    with_peer(f, [max_connections: 1], fn peer ->
      assert {:ok, socket} = SSL.connect(@host, peer.port, options(f), 5000)
      on_exit(fn -> SSL.close(socket) end)
      assert {:ok, _} = OpenSSLPeer.event(peer, "handshake", 5000)
      {:connected, initial} = :sys.get_state(socket.pid)
      assert initial.session_material != nil
      assert is_integer(Process.read_timer(initial.session_timer))
      request = "GET /buffered HTTP/1.1\r\nHost: exssl.test\r\nConnection: close\r\n\r\n"
      assert :ok = SSL.send(socket, request)
      assert {:ok, %{"request_sha256" => digest}} = OpenSSLPeer.event(peer, "exchange", 5000)
      assert digest == Base.encode16(:crypto.hash(:sha256, request), case: :lower)
      closed = await_closed(socket, System.monotonic_time(:millisecond) + 2000)
      assert closed.size == byte_size(@response)
      assert closed.session_material == nil
      assert closed.session_timer == nil
      assert closed.session_token == nil
      assert Process.read_timer(initial.session_timer) == false
      assert {:error, :closed} = SSL.connection_information(socket, [:session_data])
      assert {:ok, @response} = SSL.recv(socket, byte_size(@response), 5000)
      assert :ok = SSL.close(socket)
    end)
  end

  test "the absolute live-session timer discards resumable master without closing application traffic",
       %{fixtures: f} do
    with_peer(f, [max_connections: 1], fn peer ->
      opts = Keyword.put(options(f), :reuse_sessions, false)
      assert {:ok, socket} = SSL.connect(@host, peer.port, opts, 5000)
      on_exit(fn -> SSL.close(socket) end)
      assert {:ok, _} = OpenSSLPeer.event(peer, "handshake", 5000)
      {:connected, initial} = :sys.get_state(socket.pid)

      :sys.replace_state(socket.pid, fn {phase, state} ->
        Process.cancel_timer(state.session_timer)

        retained = %{
          state.session_material
          | expires_at: System.monotonic_time(:millisecond) + 30
        }

        timer = Process.send_after(self(), {:session_expired, state.session_token}, 30)
        {phase, %{state | session_material: retained, session_timer: timer}}
      end)

      Process.send_after(self(), :session_timer_elapsed, 60)
      assert_receive :session_timer_elapsed, 2000
      assert {:error, :no_session} = SSL.connection_information(socket, [:session_data])
      {:connected, expired} = :sys.get_state(socket.pid)
      assert expired.session_material == nil
      assert expired.session_timer == nil
      assert Process.read_timer(initial.session_timer) == false
      request = "GET /after-expiry HTTP/1.1\r\nHost: exssl.test\r\nConnection: close\r\n\r\n"
      assert :ok = SSL.send(socket, request)
      assert {:ok, @response} = SSL.recv(socket, byte_size(@response), 5000)
      assert {:ok, %{"bytes" => 0}} = OpenSSLPeer.event(peer, "exchange", 5000)
      assert :ok = SSL.close(socket)
    end)
  end

  defp await_closed(socket, deadline) do
    case :sys.get_state(socket.pid) do
      {_phase, %{closed: true} = state} ->
        state

      _ ->
        if System.monotonic_time(:millisecond) >= deadline,
          do: flunk("peer close_notify was not processed")

        receive do
        after
          10 -> :ok
        end

        await_closed(socket, deadline)
    end
  end

  defp exchange(
         peer,
         opts,
         resumed,
         expected_der,
         client_der \\ nil,
         protocol \\ :"tlsv1.2",
         capture_data \\ false
       ) do
    assert {:ok, socket} = SSL.connect(@host, peer.port, opts, 5000)
    on_exit(fn -> SSL.close(socket) end)
    assert {:ok, %{"resumed" => ^resumed} = event} = OpenSSLPeer.event(peer, "handshake", 5000)
    assert event["client_der_b64"] == if(client_der, do: Base.encode64(client_der), else: :null)

    assert {:ok, info} =
             SSL.connection_information(socket, [:session_id, :session_resumption, :protocol])

    assert info[:session_resumption] == resumed
    assert info[:protocol] == protocol
    assert {:ok, ^expected_der} = SSL.peercert(socket)
    {:connected, state} = :sys.get_state(socket.pid)

    data =
      if capture_data do
        assert {:ok, [session_data: data]} = SSL.connection_information(socket, [:session_data])

        assert {:ok, [session_data: repeated]} =
                 SSL.connection_information(socket, [:session_data])

        assert repeated == data
        refute inspect(:sys.get_status(socket.pid), limit: :infinity) =~ "EXSSL12"
        refute inspect(state.session_material) =~ "EXSSL12"
        data
      end

    if protocol == :"tlsv1.3" do
      refute Keyword.has_key?(state.machine.options, :tls12_session)
      refute Keyword.has_key?(state.machine.options, :enable_session)
    end

    request =
      "POST /exactly-once HTTP/1.1\r\nHost: exssl.test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping"

    assert :ok = SSL.setopts(socket, active: :once)
    assert :ok = SSL.send(socket, request)

    received =
      receive do
        {:ssl, ^socket, bytes} -> bytes
      after
        5000 -> flunk("resumed application output was not delivered")
      end

    assert received == @response

    assert {:ok, %{"bytes" => 4, "request_sha256" => digest}} =
             OpenSSLPeer.event(peer, "exchange", 5000)

    assert digest == Base.encode16(:crypto.hash(:sha256, request), case: :lower)
    monitor = Process.monitor(socket.pid)
    assert :ok = SSL.close(socket)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 5000
    if state.session_timer, do: assert(Process.read_timer(state.session_timer) == false)
    %{id: info[:session_id], machine: state.machine, session: state.session_material, data: data}
  end

  defp cipher_option(id) do
    suite = SSL.Capabilities.resolve(:cipher_suite, id)
    %{key_exchange: suite.key_exchange, cipher: suite.cipher, mac: :aead, prf: suite.hash}
  end

  defp same_keys?(a, b),
    do: a.read_state.key == b.read_state.key or a.write_state.key == b.write_state.key

  defp options(f),
    do: [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      cacerts: [f.ca.der],
      server_name_indication: ~c"exssl.test",
      versions: [:"tlsv1.2"],
      reuse_sessions: true,
      alpn_advertised_protocols: ["http/1.1"]
    ]

  defp with_peer(f, extra, fun) do
    assert {:ok, peer} =
             OpenSSLPeer.start(
               Keyword.merge(
                 [
                   certfile: f.server.certificate,
                   keyfile: f.server.key,
                   min_version: :tls12,
                   max_version: :tls12,
                   max_connections: 2,
                   mode: :http1,
                   alpn: ["http/1.1"]
                 ],
                 extra
               )
             )

    try do
      fun.(peer)
    after
      OpenSSLPeer.stop(peer)
    end
  end
end
