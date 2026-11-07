defmodule SSL.VersionPolicyInteropTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures

  @moduletag :integration
  @mixed_versions [[:"tlsv1.2", :"tlsv1.3"], [:"tlsv1.3", :"tlsv1.2"]]
  @request "version policy request"
  @response "version policy response"

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-version-policy-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    fixtures = ClientAuthFixtures.create(directory)

    [{:Certificate, wrong_ca, _}] =
      directory |> Path.join("wrong-ca.pem") |> File.read!() |> :public_key.pem_decode()

    [entry] = fixtures.rsa.key |> File.read!() |> :public_key.pem_decode()
    key = :public_key.pem_entry_decode(entry)
    key_der = {elem(key, 0), :public_key.der_encode(elem(key, 0), key)}
    {:ok, fixtures: fixtures, key_der: key_der, wrong_ca: wrong_ca}
  end

  for backend <- [:ssl, SSL],
      mutual? <- [false, true],
      versions <- @mixed_versions ++ [[:"tlsv1.3"]] do
    test "#{backend} negotiates TLS 1.3 with #{inspect(versions)} and mTLS=#{mutual?}", context do
      exchange(
        context,
        unquote(backend),
        unquote(mutual?),
        unquote(versions),
        :"tlsv1.3"
      )
    end
  end

  for backend <- [:ssl, SSL], mutual? <- [false, true] do
    test "#{backend} negotiates TLS 1.2 with a dual-version OTP peer and mTLS=#{mutual?}",
         context do
      exchange(context, unquote(backend), unquote(mutual?), [:"tlsv1.2"], :"tlsv1.2")
    end
  end

  for backend <- [:ssl, SSL],
      mutual? <- [false, true],
      versions <- @mixed_versions ++ [[:"tlsv1.2"]] do
    test "#{backend} completes TLS 1.2 with #{inspect(versions)} and mTLS=#{mutual?}", context do
      exchange(context, unquote(backend), unquote(mutual?), unquote(versions), :"tlsv1.2",
        versions: [:"tlsv1.2"]
      )
    end
  end

  for backend <- [:ssl, SSL],
      version <- [:"tlsv1.2", :"tlsv1.3"],
      failure <- [:untrusted_ca, :wrong_hostname] do
    test "#{backend} rejects #{failure} under a mixed policy with a #{version} peer", context do
      peer = start_peer(context.fixtures, false, versions: [unquote(version)])

      options = client_options(context, false, [:"tlsv1.3", :"tlsv1.2"])

      options =
        case unquote(failure) do
          :untrusted_ca -> Keyword.put(options, :cacerts, [context.wrong_ca])
          :wrong_hostname -> Keyword.put(options, :server_name_indication, ~c"wrong.exssl.test")
        end

      try do
        assert {:error, _} = unquote(backend).connect(~c"127.0.0.1", peer.port, options, 5_000)
        assert {:error, _} = Task.await(peer.task, 5_000)
      after
        stop_peer(peer)
      end
    end
  end

  for mode <- [false, true, :save] do
    test "non-EMS handshakes never retain or reuse sessions with reuse_sessions=#{mode}",
         context do
      peer = start_peer(context.fixtures, true, [versions: [:"tlsv1.2"]], 2)

      options =
        context
        |> client_options(true, [:"tlsv1.2"])
        |> Keyword.put(:reuse_sessions, unquote(mode))

      assert {:ok, normalized} = SSL.Options.normalize(~c"127.0.0.1", options)

      partition =
        SSL.TLS12ResumptionContext.partition(normalized, {{127, 0, 0, 1}, peer.port})

      try do
        for _ <- 1..2 do
          assert {:ok, socket} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)

          try do
            assert {:ok, context.fixtures.server.der} == SSL.peercert(socket)

            assert {:ok, [protocol: :"tlsv1.2", session_resumption: false]} =
                     SSL.connection_information(socket, [:protocol, :session_resumption])

            assert {:error, :no_session} = SSL.connection_information(socket, [:session_data])
            {:connected, state} = :sys.get_state(socket.pid)
            refute state.machine.extended_master_secret
            assert state.machine.master_secret == nil
            assert state.session_material == nil
            assert state.session_timer == nil
            assert :miss = SSL.SessionCache.lookup(partition, :auto)
            assert :miss = SSL.SessionCache.lookup(partition, state.machine.session_id)
            assert :ok = SSL.send(socket, @request)
            assert {:ok, @response} = SSL.recv(socket, byte_size(@response), 5_000)
          after
            SSL.close(socket)
          end
        end

        expected = {:ok, :"tlsv1.2", {:ok, context.fixtures.rsa.der}}
        assert [^expected, ^expected] = Task.await(peer.task, 5_000)
        assert :miss = SSL.SessionCache.lookup(partition, :auto)
      after
        stop_peer(peer)
      end
    end
  end

  for identity <- [:missing, :wrong, :expired] do
    test "TLS 1.2 mTLS rejects a #{identity} client identity", context do
      peer = start_peer(context.fixtures, true, versions: [:"tlsv1.2"])
      options = client_options(context, false, [:"tlsv1.2"])

      options =
        case unquote(identity) do
          :missing ->
            options

          name ->
            identity = context.fixtures[name]
            [entry] = identity.key |> File.read!() |> :public_key.pem_decode()
            key = :public_key.pem_entry_decode(entry)
            key_der = {elem(key, 0), :public_key.der_encode(elem(key, 0), key)}
            Keyword.put(options, :certs_keys, [%{cert: identity.der, key: key_der}])
        end

      try do
        assert {:error, _} = SSL.connect(~c"127.0.0.1", peer.port, options, 5_000)
        assert {:error, _} = Task.await(peer.task, 5_000)
      after
        stop_peer(peer)
      end
    end
  end

  defp exchange(context, backend, mutual?, versions, protocol, peer_options \\ []) do
    peer = start_peer(context.fixtures, mutual?, peer_options)

    try do
      assert {:ok, socket} =
               backend.connect(
                 ~c"127.0.0.1",
                 peer.port,
                 client_options(context, mutual?, versions),
                 5_000
               )

      try do
        assert backend.peercert(socket) == {:ok, context.fixtures.server.der}
        assert {:ok, [protocol: ^protocol]} = backend.connection_information(socket, [:protocol])
        assert :ok = backend.send(socket, @request)
        assert {:ok, @response} = backend.recv(socket, byte_size(@response), 5_000)

        expected_client =
          if mutual?, do: {:ok, context.fixtures.rsa.der}, else: {:error, :no_peercert}

        assert {:ok, ^protocol, ^expected_client} = Task.await(peer.task, 5_000)
      after
        backend.close(socket)
      end
    after
      stop_peer(peer)
    end
  end

  defp client_options(context, mutual?, versions) do
    [
      active: false,
      mode: :binary,
      verify: :verify_peer,
      cacerts: [context.fixtures.ca.der],
      versions: versions,
      server_name_indication: ~c"exssl.test",
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)]
    ] ++
      if mutual?,
        do: [certs_keys: [%{cert: context.fixtures.rsa.der, key: context.key_der}]],
        else: []
  end

  defp start_peer(fixtures, mutual?, extra, connections \\ 1) do
    options =
      [
        active: false,
        mode: :binary,
        ip: {127, 0, 0, 1},
        reuseaddr: true,
        certfile: String.to_charlist(fixtures.server.certificate),
        keyfile: String.to_charlist(fixtures.server.key),
        cacerts: [fixtures.ca.der],
        verify: if(mutual?, do: :verify_peer, else: :verify_none),
        fail_if_no_peer_cert: mutual?
      ] ++ extra

    {:ok, listener} = :ssl.listen(0, options)
    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        results = for _ <- 1..connections, do: serve_connection(listener)

        case results do
          [result] -> result
          _ -> results
        end
      end)

    %{listener: listener, port: port, task: task}
  end

  defp serve_connection(listener) do
    case :ssl.transport_accept(listener, 5_000) do
      {:ok, transport} ->
        try do
          case :ssl.handshake(transport, 5_000) do
            {:ok, socket} ->
              {:ok, [protocol: protocol]} = :ssl.connection_information(socket, [:protocol])
              client = :ssl.peercert(socket)
              {:ok, @request} = :ssl.recv(socket, byte_size(@request), 5_000)
              :ok = :ssl.send(socket, @response)
              {:ok, protocol, client}

            {:error, _} = error ->
              error
          end
        after
          :ssl.close(transport)
        end

      {:error, _} = error ->
        error
    end
  end

  defp stop_peer(peer) do
    :ssl.close(peer.listener)
    Task.shutdown(peer.task, :brutal_kill)
    :ok
  end
end
