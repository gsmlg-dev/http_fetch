defmodule SSL.MiddleboxCompModeInteropTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer, OpenSSLPeer}
  alias SSL.Protocol.{ClientHandshake, ClientOffer, HandshakeFramer, TLS12Codec}

  @moduletag :integration
  @ccs <<20, 3, 3, 0, 1, 1>>
  @request "GET /middlebox HTTP/1.1\r\nHost: exssl.test\r\nConnection: close\r\n\r\n"
  @response "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong"
  @versions [[:"tlsv1.3"], [:"tlsv1.3", :"tlsv1.2"], [:"tlsv1.2", :"tlsv1.3"]]

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "r51-middlebox-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    %{fixtures: ClientAuthFixtures.create(directory)}
  end

  for versions <- @versions, mode <- [:omitted, true, false], hrr? <- [false, true] do
    test "TLS13 #{inspect(versions)} #{mode} HRR=#{hrr?} controls", %{fixtures: fixtures} do
      for backend <- [SSL, :ssl] do
        exchange(fixtures, backend, unquote(versions), unquote(mode), unquote(hrr?), nil)
      end
    end
  end

  for mode <- [:omitted, true, false], hrr? <- [false, true] do
    test "required mTLS #{mode} HRR=#{hrr?} controls", %{fixtures: fixtures} do
      for backend <- [SSL, :ssl] do
        exchange(fixtures, backend, [:"tlsv1.3"], unquote(mode), unquote(hrr?), fixtures.rsa)
      end
    end
  end

  test "large mTLS certificate keeps one prefix before the entire fragmented flight", %{
    fixtures: fixtures
  } do
    assert byte_size(fixtures.large.der) > 16_384

    for backend <- [SSL, :ssl],
        do: exchange(fixtures, backend, [:"tlsv1.3"], true, false, fixtures.large)
  end

  test "TLS12 genuine CCS controls preserve EMS and authenticated bytes", %{fixtures: fixtures} do
    for backend <- [SSL, :ssl] do
      tls12_exchange(fixtures, backend, [:"tlsv1.2"], :omitted)

      for versions <- tl(@versions), mode <- [:omitted, true, false] do
        tls12_exchange(fixtures, backend, versions, mode)
      end
    end
  end

  defp tls12_exchange(fixtures, backend, versions, mode) do
    assert {:ok, peer} =
             OpenSSLPeer.start(
               certfile: fixtures.server.certificate,
               keyfile: fixtures.server.key,
               min_version: :tls12,
               max_version: :tls12
             )

    {:ok, proxy} = LocalTLSPeer.start_fragmenting_proxy(peer.port, self())
    1 = :erlang.trace(proxy.task.pid, true, [:procs, :set_on_spawn])

    try do
      options =
        client_options(fixtures, versions, mode, nil)
        |> tls12_reference_options(backend, versions)

      assert {:ok, socket} = backend.connect(~c"127.0.0.1", proxy.port, options, 5_000)

      try do
        assert {:ok, %{"version" => "TLSv1.2", "resumed" => false}} =
                 OpenSSLPeer.event(peer, "handshake", 5_000)

        wire = collect_wire(proxy.ref)
        children = proxy_children(proxy.task.pid)
        flight = assert_tls12_flight(wire, backend, versions)
        monitor = if backend == SSL, do: Process.monitor(socket.pid)
        assert :ok = backend.send(socket, <<4::32, "ping">>)
        assert {:ok, <<4::32, "ping">>} = backend.recv(socket, 8, 5_000)
        assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        assert :ok = backend.close(socket)
        if monitor, do: assert_receive({:DOWN, ^monitor, :process, _, _}, 1_000)
        stop_proxy(proxy, children)
        assert :ok = OpenSSLPeer.stop(peer)
        assert Port.info(peer.handle) == nil

        {message, status} =
          System.cmd("kill", ["-0", Integer.to_string(peer.os_pid)], stderr_to_stdout: true)

        assert status != 0
        assert message =~ "No such process"

        assert {:error, :econnrefused} =
                 :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 1_000)

        final_wire = collect_wire(proxy.ref, wire)
        assert Enum.count(records(final_wire.client_to_server), &(&1 == @ccs)) == 1

        IO.puts(
          "R51 #{inspect(backend)} TLS12 mode=#{mode} offer=#{inspect(versions)} ccs=genuine " <>
            "ems=#{flight.ems} client_extensions=#{inspect(flight.client_extensions, charlists: :as_lists)} " <>
            "server_extensions=#{inspect(flight.server_extensions, charlists: :as_lists)} authenticated=true cleanup=true"
        )
      after
        _ = backend.close(socket)
      end
    after
      if Process.alive?(proxy.task.pid), do: LocalTLSPeer.stop_fragmenting_proxy(proxy)
      OpenSSLPeer.stop(peer)
    end
  end

  defp tls12_reference_options(options, :ssl, [:"tlsv1.2"]) do
    groups = Keyword.fetch!(options, :supported_groups)

    options
    |> Keyword.delete(:supported_groups)
    |> Keyword.put(:eccs, groups)
  end

  defp tls12_reference_options(options, _backend, _versions), do: options

  defp assert_tls12_flight(wire, backend, versions) do
    assert [hello, exchange, @ccs, finished] = records(wire.client_to_server)
    assert <<1, _::binary>> = handshake_payload(hello)
    assert {:ok, offer} = ClientOffer.from_client_hello(handshake_payload(hello))

    if backend == :ssl and versions == [:"tlsv1.2"] do
      assert {:ok, %{supported_groups: [0x001D, 0x0017]}} =
               ClientOffer.from_client_hello(handshake_payload(hello))
    end

    assert <<16, length::24, _::binary-size(length)>> = handshake_payload(exchange)
    assert <<22, 3, 3, _::binary>> = finished
    [server_first | _] = records(wire.server_to_client)
    <<2, length::24, body::binary-size(length), _::binary>> = handshake_payload(server_first)

    assert {:ok, %{type: :server_hello, extensions: extensions}} =
             TLS12Codec.decode(<<2, length::24, body::binary>>)

    if backend == SSL do
      assert {23, <<>>} in offer.extensions
      assert {23, <<>>} in extensions
    else
      # OTP 29 omits EMS; this reference behavior is not ExSSL's security policy.
      refute 23 in offer.extension_ids
      refute List.keymember?(extensions, 23, 0)
    end

    %{
      ems: {23, <<>>} in offer.extensions and {23, <<>>} in extensions,
      client_extensions: offer.extension_ids,
      server_extensions: Enum.map(extensions, &elem(&1, 0))
    }
  end

  defp exchange(fixtures, backend, versions, mode, hrr?, identity) do
    group = if hrr?, do: "prime256v1", else: "X25519"
    expected_der = if identity, do: Base.encode64(identity.der), else: :null

    assert {:ok, peer} =
             OpenSSLPeer.start(
               certfile: fixtures.server.certificate,
               keyfile: fixtures.server.key,
               cafile: fixtures.ca.certificate,
               min_version: :tls13,
               max_version: :tls13,
               verify: if(identity, do: :required, else: :none),
               group: group,
               mode: :http1
             )

    {:ok, proxy} = LocalTLSPeer.start_fragmenting_proxy(peer.port, self())
    1 = :erlang.trace(proxy.task.pid, true, [:procs, :set_on_spawn])

    try do
      options = client_options(fixtures, versions, mode, identity)
      assert {:ok, socket} = backend.connect(~c"127.0.0.1", proxy.port, options, 5_000)

      try do
        assert backend.peercert(socket) == {:ok, fixtures.server.der}
        assert {:ok, [protocol: :"tlsv1.3"]} = backend.connection_information(socket, [:protocol])

        assert {:ok,
                %{"version" => "TLSv1.3", "resumed" => false, "client_der_b64" => ^expected_der}} =
                 OpenSSLPeer.event(peer, "handshake", 5_000)

        wire = collect_wire(proxy.ref)
        children = proxy_children(proxy.task.pid)

        assert_tls13_flight(
          wire,
          mode,
          hrr?,
          identity != nil and byte_size(identity.der) > 16_384
        )

        monitor = if backend == SSL, do: Process.monitor(socket.pid)
        assert :ok = backend.send(socket, @request)
        assert {:ok, @response} = backend.recv(socket, byte_size(@response), 5_000)
        request_sha256 = :crypto.hash(:sha256, @request) |> Base.encode16(case: :lower)

        assert {:ok, %{"bytes" => 0, "request_sha256" => ^request_sha256}} =
                 OpenSSLPeer.event(peer, "exchange", 5_000)

        assert :ok = backend.close(socket)
        if monitor, do: assert_receive({:DOWN, ^monitor, :process, _, _}, 1_000)
        stop_proxy(proxy, children)
        assert :ok = OpenSSLPeer.stop(peer)
        assert Port.info(peer.handle) == nil

        {message, status} =
          System.cmd("kill", ["-0", Integer.to_string(peer.os_pid)], stderr_to_stdout: true)

        assert status != 0
        assert message =~ "No such process"

        assert {:error, :econnrefused} =
                 :gen_tcp.connect(~c"127.0.0.1", peer.port, [:binary, active: false], 1_000)

        final_wire = collect_wire(proxy.ref, wire)

        assert Enum.count(records(final_wire.client_to_server), &(&1 == @ccs)) ==
                 if(mode == false, do: 0, else: 1)

        IO.puts(
          "R51 #{inspect(backend)} TLS13 mode=#{mode} hrr=#{hrr?} mtls=#{identity != nil} authenticated=true cleanup=true"
        )
      after
        _ = backend.close(socket)
      end
    after
      if Process.alive?(proxy.task.pid), do: LocalTLSPeer.stop_fragmenting_proxy(proxy)
      OpenSSLPeer.stop(peer)
    end
  end

  defp client_options(fixtures, versions, mode, identity) do
    [
      active: false,
      mode: :binary,
      verify: :verify_peer,
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      supported_groups: [:x25519, :secp256r1],
      versions: versions
    ] ++
      control(mode) ++
      if(identity, do: [certfile: identity.certificate, keyfile: identity.key], else: [])
  end

  defp assert_tls13_flight(wire, mode, hrr?, large?) do
    [initial | rest] = records(wire.client_to_server)
    assert {:ok, offer} = ClientOffer.from_client_hello(handshake_payload(initial))
    initial_offer = offer
    assert byte_size(offer.legacy_session_id) == if(mode == false, do: 0, else: 32)

    rest =
      if mode == false do
        rest
      else
        assert [@ccs | remaining] = rest
        remaining
      end

    {offer, encrypted} =
      if hrr? do
        assert [retry | encrypted] = rest
        assert {:ok, second} = ClientOffer.from_client_hello(handshake_payload(retry))
        assert second.legacy_session_id == offer.legacy_session_id
        assert second.cipher_suites == offer.cipher_suites
        <<1, _::24, _::16, random::binary-size(32), _::binary>> = offer.encoded
        assert <<1, _::24, _::16, ^random::binary-size(32), _::binary>> = second.encoded
        assert [%{group: 0x0017, key_exchange: share}] = second.key_shares
        assert byte_size(share) == 65
        {second, encrypted}
      else
        {offer, rest}
      end

    assert [_ | _] = encrypted
    assert Enum.all?(encrypted, &match?(<<23, 3, 3, _::binary>>, &1))
    if large?, do: assert(length(encrypted) >= 4)
    plaintext = for <<22, _::16, _::16, body::binary>> <- records(wire.server_to_client), do: body

    assert {:ok, hellos, framer} =
             HandshakeFramer.feed(HandshakeFramer.new(), IO.iodata_to_binary(plaintext))

    assert HandshakeFramer.buffered_size(framer) == 0
    assert_server_hellos(hellos, initial_offer, offer, hrr?)
  end

  defp assert_server_hellos([retry, final], initial_offer, offer, true) do
    # Parsing the actual HRR is independent of counting plaintext records.
    assert {:ok, %{kind: :hello_retry_request} = hrr} =
             ClientHandshake.decode_server_hello(retry, initial_offer, nil)

    assert {:ok, %{kind: :server_hello}} = ClientHandshake.decode_server_hello(final, offer, hrr)
  end

  defp assert_server_hellos([hello], _initial_offer, offer, false) do
    assert {:ok, %{kind: :server_hello}} = ClientHandshake.decode_server_hello(hello, offer, nil)
  end

  defp collect_wire(ref, wire \\ %{client_to_server: <<>>, server_to_client: <<>>}) do
    receive do
      {:tls_proxy, ^ref, direction, bytes} ->
        updated = Map.update!(wire, direction, &(&1 <> bytes))

        assert byte_size(updated.client_to_server) + byte_size(updated.server_to_client) <=
                 2_097_152

        collect_wire(ref, updated)
    after
      0 -> wire
    end
  end

  defp records(bytes), do: records(bytes, [])
  defp records(<<>>, acc), do: Enum.reverse(acc)

  defp records(<<type, version::16, length::16, rest::binary>>, acc) do
    assert length <= 16_640
    assert byte_size(rest) >= length
    <<body::binary-size(^length), tail::binary>> = rest
    records(tail, [<<type, version::16, length::16, body::binary>> | acc])
  end

  defp handshake_payload(<<22, _::16, length::16, body::binary-size(length)>>), do: body

  defp proxy_children(proxy_pid) do
    for _ <- 1..2 do
      receive do
        {:trace, ^proxy_pid, :spawn, child, _} -> child
      after
        1_000 -> flunk("proxy forwarding task spawn was not observed")
      end
    end
  end

  defp stop_proxy(proxy, children) do
    monitors = for pid <- [proxy.task.pid | children], do: Process.monitor(pid)
    _ = LocalTLSPeer.stop_fragmenting_proxy(proxy)
    for monitor <- monitors, do: assert_receive({:DOWN, ^monitor, :process, _, _}, 1_000)
    assert_stopped(proxy.task.pid, proxy.port)
    assert Enum.all?(children, &(not Process.alive?(&1)))
  end

  defp assert_stopped(pid, port) do
    refute Process.alive?(pid)

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1_000)
  end

  defp control(:omitted), do: []
  defp control(mode), do: [middlebox_comp_mode: mode]
end
