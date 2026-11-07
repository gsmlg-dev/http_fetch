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

  for mutual? <- [false, true], versions <- @mixed_versions ++ [[:"tlsv1.2"]] do
    test "TLS 1.2-only OTP peer retains the EMS rejection for #{inspect(versions)} and mTLS=#{mutual?}",
         context do
      versions = unquote(versions)
      mutual? = unquote(mutual?)
      peer_options = [versions: [:"tlsv1.2"]]

      # This configured OTP reference peer omits EMS. Its successful OTP-client
      # control does not change ExSSL's mandatory EMS policy.
      exchange(context, :ssl, mutual?, versions, :"tlsv1.2", peer_options)
      peer = start_peer(context.fixtures, mutual?, peer_options)

      try do
        assert {:error, {:tls_alert, {:handshake_failure, _}}} =
                 SSL.connect(
                   ~c"127.0.0.1",
                   peer.port,
                   client_options(context, mutual?, versions),
                   5_000
                 )

        assert {:error, {:tls_alert, {:handshake_failure, _}}} = Task.await(peer.task, 5_000)
      after
        stop_peer(peer)
      end
    end
  end

  for backend <- [:ssl, SSL], failure <- [:untrusted_ca, :wrong_hostname] do
    test "#{backend} rejects #{failure} under a mixed version policy", context do
      peer = start_peer(context.fixtures, false, [])

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

  defp start_peer(fixtures, mutual?, extra) do
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
      end)

    %{listener: listener, port: port, task: task}
  end

  defp stop_peer(peer) do
    :ssl.close(peer.listener)
    Task.shutdown(peer.task, :brutal_kill)
    :ok
  end
end
