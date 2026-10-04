defmodule SSL.ResumptionInteropTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer, OpenSSLPeer}
  alias SSL.{Options, ResumptionContext, TicketCache}
  @moduletag :integration
  @host {127, 0, 0, 1}

  setup_all do
    directory = Path.join(System.tmp_dir!(), "resumption-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(directory) end)
    %{fixtures: ClientAuthFixtures.create(directory)}
  end

  test "actual resumption preserves authenticated DER and bounded diagnostics", %{fixtures: f} do
    with_peer(f, [], fn peer ->
      exchange(peer, options(f), false, f.server.der)
      exchange(peer, options(f), true, f.server.der)
    end)
  end

  test "HelloRetryRequest rebinds CH2 with fresh P384 key share on both handshakes", %{
    fixtures: f
  } do
    with_peer(f, [group: "secp384r1"], fn peer ->
      opts = options(f) ++ [supported_groups: [:x25519, :secp384r1]]
      exchange(peer, opts, false, f.server.der)
      exchange(peer, opts, true, f.server.der)
    end)
  end

  test "server ticket-key restart declines PSK and authenticates full flight on same connection",
       %{fixtures: f} do
    with_peer(f, [restart_context: true], fn peer ->
      exchange(peer, options(f), false, f.server.der)
      exchange(peer, options(f), false, f.server.der)
    end)
  end

  test "disabled tickets never resume", %{fixtures: f} do
    with_peer(f, [], fn peer ->
      opts = Keyword.delete(options(f), :session_tickets)
      exchange(peer, opts, false, f.server.der)
      exchange(peer, opts, false, f.server.der)
    end)
  end

  test "full and resumed connections preserve active-once ownership and close behavior", %{
    fixtures: f
  } do
    with_peer(f, [], fn peer ->
      active_exchange(peer, options(f), false)
      active_exchange(peer, options(f), true)
    end)
  end

  test "an authenticated ticket fragmented by TCP reaches the bounded cache", %{fixtures: f} do
    with_peer(f, [max_connections: 1], fn peer ->
      {:ok, proxy} = LocalTLSPeer.start_fragmenting_proxy(peer.port, self())

      try do
        opts = options(f)
        assert {:ok, socket} = SSL.connect(@host, proxy.port, opts, 5_000)
        assert {:ok, %{"resumed" => false}} = OpenSSLPeer.event(peer, "handshake", 5_000)
        assert :ok = SSL.send(socket, <<4::32, "ping">>)
        assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 5_000)

        assert {:ok, %{"kind" => "exchange", "bytes" => 4}} =
                 OpenSSLPeer.event(peer, "exchange", 5_000)

        assert :ok = SSL.close(socket)
        assert {:ok, _ticket} = TicketCache.checkout(cache_key(opts, proxy))
      after
        if Process.alive?(proxy.task.pid), do: LocalTLSPeer.stop_fragmenting_proxy(proxy)
      end
    end)
  end

  test "an invalid PSK binder fails without application replay or reconnect", %{fixtures: f} do
    with_peer(f, [], fn peer ->
      opts = options(f)
      exchange(peer, opts, false, f.server.der)
      key = cache_key(opts, peer)
      assert {:ok, ticket} = TicketCache.checkout(key)

      assert :ok =
               TicketCache.put(key, %{ticket | psk: :binary.copy(<<0>>, byte_size(ticket.psk))})

      assert {:error, _} = SSL.connect(@host, peer.port, opts, 5_000)
      assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
      assert :miss = TicketCache.checkout(key)
    end)
  end

  test "trust and identity changes cannot reuse an authenticated ticket", %{fixtures: f} do
    for changed <- [[cacerts: [f.wrong.der]], [server_name_indication: ~c"wrong.exssl.test"]] do
      with_peer(f, [], fn peer ->
        opts = options(f)
        exchange(peer, opts, false, f.server.der)
        assert {:error, _} = SSL.connect(@host, peer.port, Keyword.merge(opts, changed), 5_000)
        assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
      end)
    end
  end

  test "ALPN policy changes use full authentication", %{fixtures: f} do
    with_peer(f, [alpn: ["http/1.1", "h2"]], fn peer ->
      exchange(peer, options(f), false, f.server.der)

      exchange(
        peer,
        Keyword.put(options(f), :alpn_advertised_protocols, ["h2"]),
        false,
        f.server.der
      )
    end)
  end

  test "port and key-exchange policy isolation retain tickets for their original context", %{
    fixtures: f
  } do
    with_peer(f, [], fn peer ->
      exchange(peer, options(f), false, f.server.der)
      {:ok, proxy} = LocalTLSPeer.start_backpressure_proxy(peer.port, self())

      try do
        # Same OpenSSL context and ticket keys, different client-visible port.
        # Thus a cache-isolation regression would actually resume at this peer.
        exchange(%{peer | port: proxy.port}, options(f), false, f.server.der)
      after
        if Process.alive?(proxy.task.pid), do: LocalTLSPeer.stop_backpressure_proxy(proxy)
      end
    end)

    with_peer(f, [group: "secp384r1", max_connections: 3], fn peer ->
      exchange(peer, options(f), false, f.server.der)

      exchange(
        peer,
        Keyword.put(options(f), :supported_groups, [:secp384r1]),
        false,
        f.server.der
      )

      exchange(peer, options(f), true, f.server.der)
    end)
  end

  test "wire profile and signature policy changes keep the original ticket isolated", %{
    fixtures: f
  } do
    {:ok, normalized} = Options.normalize(@host, options(f))

    reordered = %{
      normalized.profile
      | cipher_suites: Enum.reverse(normalized.profile.cipher_suites)
    }

    for changed <- [
          [ex_ssl: [profile: reordered]],
          [signature_algs: [:rsa_pss_rsae_sha256]]
        ] do
      with_peer(f, [max_connections: 3], fn peer ->
        exchange(peer, options(f), false, f.server.der)
        exchange(peer, Keyword.merge(options(f), changed), false, f.server.der)
        exchange(peer, options(f), true, f.server.der)
      end)
    end
  end

  defp options(f) do
    [
      cacerts: [f.ca.der],
      server_name_indication: ~c"exssl.test",
      versions: [:"tlsv1.3"],
      alpn_advertised_protocols: ["http/1.1"],
      session_tickets: :auto
    ]
  end

  defp cache_key(opts, peer) do
    {:ok, normalized} = Options.normalize(@host, opts)
    ResumptionContext.partition(normalized, {@host, peer.port})
  end

  defp exchange(peer, opts, resumed, der) do
    assert {:ok, socket} = SSL.connect(@host, peer.port, opts, 5_000)
    assert {:ok, evidence} = OpenSSLPeer.event(peer, "handshake", 5_000)
    assert evidence["resumed"] == resumed

    assert {:ok, [session_resumption: ^resumed, protocol: :"tlsv1.3"]} =
             SSL.connection_information(socket, [:session_resumption, :protocol])

    assert {:ok, ^der} = SSL.peercert(socket)
    assert {:ok, {@host, port}} = SSL.peername(socket)
    assert port == peer.port
    assert {:ok, {@host, local}} = SSL.sockname(socket)
    assert local != port
    assert :ok = SSL.send(socket, <<4::32, "ping">>)
    assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 5_000)
    assert {:ok, _} = OpenSSLPeer.event(peer, "exchange", 5_000)
    assert :ok = SSL.close(socket)
  end

  defp active_exchange(peer, opts, resumed) do
    assert {:ok, socket} = SSL.connect(@host, peer.port, opts, 5_000)
    assert {:ok, %{"resumed" => ^resumed}} = OpenSSLPeer.event(peer, "handshake", 5_000)

    assert {:ok, [session_resumption: ^resumed]} =
             SSL.connection_information(socket, [:session_resumption])

    parent = self()

    owner =
      spawn(fn ->
        receive do
          {:activate, ^socket} ->
            send(parent, {:active_once_armed, self(), SSL.setopts(socket, active: :once)})

            receive do
              {:ssl, ^socket, <<4::32, "ping">>} ->
                send(parent, {:active_once_data, self()})
            end

            receive do
              :finish -> :ok
            end
        end
      end)

    assert :ok = SSL.controlling_process(socket, owner)
    send(owner, {:activate, socket})
    assert_receive {:active_once_armed, ^owner, :ok}, 1_000
    assert :ok = SSL.send(socket, <<4::32, "ping">>)

    assert {:ok, %{"kind" => "exchange", "bytes" => 4}} =
             OpenSSLPeer.event(peer, "exchange", 5_000)

    assert_receive {:active_once_data, ^owner}, 1_000
    assert :ok = SSL.close(socket)
    send(owner, :finish)
  end

  defp with_peer(f, extra, fun) do
    {:ok, peer} =
      OpenSSLPeer.start(
        Keyword.merge(
          [
            certfile: f.server.certificate,
            keyfile: f.server.key,
            min_version: :tls13,
            max_version: :tls13,
            max_connections: 2,
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
