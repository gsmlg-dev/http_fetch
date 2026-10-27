defmodule SSL.ManualTicketIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.{ClientAuthFixtures, OpenSSLPeer}
  alias SSL.{Options, ResumptionContext, SessionTicket, TicketCache}
  @host {127, 0, 0, 1}

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "manual-tickets-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    %{fixtures: ClientAuthFixtures.create(directory)}
  end

  for backend <- [:ssl, SSL] do
    @backend backend
    test "#{backend} delivers public manual tickets without consuming active-once credit", %{
      fixtures: f
    } do
      with_peer(f, [], fn peer ->
        ticket = exchange(@backend, peer, options(f), false, f.server.der)

        exchange(
          @backend,
          peer,
          Keyword.put(options(f), :use_ticket, [ticket]),
          true,
          f.server.der
        )

        if @backend == SSL do
          assert :ok = SessionTicket.validate(ticket)
          assert {:ok, normalized} = Options.normalize(@host, options(f))
          key = ResumptionContext.partition(normalized, {@host, peer.port})
          assert ticket.context == key
          assert :miss = TicketCache.checkout(key)
        end
      end)
    end
  end

  test "an expired manual ticket takes one full authenticated handshake", %{fixtures: f} do
    with_peer(f, [], fn peer ->
      ticket = exchange(SSL, peer, options(f), false, f.server.der)
      now = System.monotonic_time(:millisecond)
      expired = %{ticket | issued_at: now - 2, expires_at: now - 1}
      exchange(SSL, peer, Keyword.put(options(f), :use_ticket, [expired]), false, f.server.der)
    end)
  end

  test "a changed ALPN or key-exchange policy cannot select the original manual PSK", %{
    fixtures: f
  } do
    for changed <- [
          [alpn_advertised_protocols: ["http/1.1", "h2"]],
          [supported_groups: [:secp384r1]]
        ] do
      with_peer(f, [max_connections: 3], fn peer ->
        ticket = exchange(SSL, peer, options(f), false, f.server.der)
        selected = Keyword.put(options(f), :use_ticket, [ticket])
        exchange(SSL, peer, Keyword.merge(selected, changed), false, f.server.der)
        exchange(SSL, peer, selected, true, f.server.der)
      end)
    end
  end

  test "changed trust or reference identity requires full authentication and fails closed", %{
    fixtures: f
  } do
    for changed <- [[cacerts: [f.wrong.der]], [server_name_indication: ~c"wrong.exssl.test"]] do
      with_peer(f, [], fn peer ->
        ticket = exchange(SSL, peer, options(f), false, f.server.der)
        opts = options(f) |> Keyword.put(:use_ticket, [ticket]) |> Keyword.merge(changed)
        assert {:error, _} = SSL.connect(@host, peer.port, opts, 5_000)
        assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
      end)
    end
  end

  test "an invalid manual binder fails without reconnecting or sending application bytes", %{
    fixtures: f
  } do
    with_peer(f, [], fn peer ->
      ticket = exchange(SSL, peer, options(f), false, f.server.der)
      invalid = %{ticket | psk: :binary.copy(<<0>>, byte_size(ticket.psk))}
      opts = Keyword.put(options(f), :use_ticket, [invalid])
      assert {:error, _} = SSL.connect(@host, peer.port, opts, 5_000)
      assert {:error, %{"kind" => "failure"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
    end)
  end

  test "manual tickets retain client identity and verification mode partitions", %{fixtures: f} do
    with_peer(f, [max_connections: 3, cafile: f.ca.certificate, verify: :required], fn peer ->
      opts = options(f) ++ [certfile: f.rsa.certificate, keyfile: f.rsa.key]
      ticket = exchange(SSL, peer, opts, false, f.server.der, f.rsa.der)
      selected = Keyword.put(opts, :use_ticket, [ticket])
      exchange(SSL, peer, selected, true, f.server.der, f.rsa.der)
      changed = Keyword.merge(selected, certfile: f.ec.certificate, keyfile: f.ec.key)
      exchange(SSL, peer, changed, false, f.server.der, f.ec.der)
    end)

    with_peer(f, [max_connections: 3], fn peer ->
      opts = Keyword.put(options(f), :verify, :verify_none)
      ticket = exchange(SSL, peer, opts, false, f.server.der)
      selected = Keyword.put(opts, :use_ticket, [ticket])
      exchange(SSL, peer, selected, true, f.server.der)
      exchange(SSL, peer, Keyword.put(selected, :verify, :verify_peer), false, f.server.der)
    end)
  end

  test "OTP manual mTLS resumes the authenticated client identity", %{fixtures: f} do
    with_peer(f, [cafile: f.ca.certificate, verify: :required], fn peer ->
      opts = options(f) ++ [certfile: f.rsa.certificate, keyfile: f.rsa.key]
      ticket = exchange(:ssl, peer, opts, false, f.server.der, f.rsa.der)
      selected = Keyword.put(opts, :use_ticket, [ticket])
      exchange(:ssl, peer, selected, true, f.server.der, f.rsa.der)
    end)
  end

  test "manual mixed-version configuration authenticates a TLS12-only peer", %{fixtures: f} do
    with_peer(f, [min_version: :tls12, max_version: :tls12, max_connections: 1], fn peer ->
      opts = Keyword.put(options(f), :versions, [:"tlsv1.3", :"tlsv1.2"])
      assert {:ok, socket} = SSL.connect(@host, peer.port, opts, 5_000)
      on_exit(fn -> SSL.close(socket) end)

      assert {:ok, %{"version" => "TLSv1.2", "resumed" => false}} =
               OpenSSLPeer.event(peer, "handshake", 5_000)

      assert {:ok, [protocol: :"tlsv1.2"]} = SSL.connection_information(socket, [:protocol])
      assert :ok = SSL.send(socket, <<4::32, "ping">>)
      assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 5_000)
      assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
      assert :ok = SSL.close(socket)
    end)
  end

  defp exchange(backend, peer, opts, resumed, expected_der, client_der \\ nil) do
    assert {:ok, socket} = backend.connect(@host, peer.port, opts, 5_000)
    on_exit(fn -> backend.close(socket) end)

    assert {:ok, %{"resumed" => ^resumed} = event} =
             OpenSSLPeer.event(peer, "handshake", 5_000)

    assert event["client_der_b64"] == if(client_der, do: Base.encode64(client_der), else: :null)
    assert {:ok, info} = backend.connection_information(socket, [:session_resumption, :protocol])
    assert Keyword.fetch!(info, :session_resumption) == resumed
    assert Keyword.fetch!(info, :protocol) == :"tlsv1.3"
    # OTP 29 does not retain peer DER in a manually resumed session. ExSSL
    # deliberately retains and revalidates the saved certificate chain.
    if backend == :ssl and resumed do
      assert {:error, :no_peercert} = backend.peercert(socket)
    else
      assert {:ok, ^expected_der} = backend.peercert(socket)
    end

    assert :ok = backend.setopts(socket, active: :once)
    assert :ok = backend.send(socket, <<4::32, "ping">>)

    # The public OTP ticket map contains secrets. Receive it without an assertion
    # that could dump the map or an unrelated ticket from the process mailbox.
    ticket =
      receive do
        {:ssl, :session_ticket, ticket} when is_map(ticket) -> ticket
      after
        1_000 -> flunk("manual session ticket was not delivered")
      end

    assert Map.fetch!(ticket, :sni) == ~c"exssl.test"

    bytes =
      receive do
        {:ssl, ^socket, bytes} -> bytes
      after
        1_000 -> flunk("manual ticket consumed application active-once credit")
      end

    assert bytes == <<4::32, "ping">>
    assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
    assert :ok = backend.close(socket)
    # A server can send multiple tickets. close/1 completes delivery from this
    # connection before the next exchange, so no previous peer's ticket can leak
    # into a later exchange in the same test process.
    drain_tickets()
    ticket
  end

  defp drain_tickets do
    receive do
      {:ssl, :session_ticket, ticket} when is_map(ticket) ->
        assert Map.fetch!(ticket, :sni) == ~c"exssl.test"
        drain_tickets()
    after
      0 -> :ok
    end
  end

  defp options(f) do
    [
      mode: :binary,
      active: false,
      cacerts: [f.ca.der],
      server_name_indication: ~c"exssl.test",
      versions: [:"tlsv1.3"],
      alpn_advertised_protocols: ["http/1.1"],
      session_tickets: :manual
    ]
  end

  defp with_peer(f, extra, fun) do
    assert {:ok, peer} =
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
