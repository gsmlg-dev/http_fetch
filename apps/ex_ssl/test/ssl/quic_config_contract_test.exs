defmodule SSL.QUICConfigContractTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "ex_ssl_quic_config_#{System.unique_integer([:positive])}")

    fixtures = ClientAuthFixtures.create(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: fixtures}
  end

  test "rejects malformed IP reference identities at construction" do
    for identity <- [
          {:ip, {127, 0, 0, 256}},
          {:ip, {127, 0, 0, -1}},
          {:ip, {0, 0, 0, 0, 0, 0, 0, 65_536}},
          {:ip, {127, 0, 0, "1"}},
          {:ip, <<255>>},
          {:ip, "not-an-ip"}
        ] do
      assert {:error, %SSL.QUIC.Error{kind: :configuration, reason: :invalid_configuration}} =
               SSL.QUIC.new(:client, client_options(reference_identity: identity))
    end
  end

  test "authenticates matching textual and tuple IP SANs independently from SNI", %{
    fixtures: fixtures
  } do
    for identity <- [
          {:ip, "127.0.0.1"},
          {:ip, {127, 0, 0, 1}},
          {:ip, "::1"},
          {:ip, {0, 0, 0, 0, 0, 0, 0, 1}}
        ] do
      client_options =
        client_options(
          cacerts: [fixtures.ca.der],
          reference_identity: identity,
          server_name: "unrelated-sni.test"
        )

      assert {:ok, client, client_actions} = SSL.QUIC.new(:client, client_options)
      assert {:ok, server, []} = SSL.QUIC.new(:server, server_options(fixtures))
      {client, server} = drive(client, server, client_actions, [])

      assert %{handshake_complete: true, peer_authenticated: true, alpn: "test"} =
               SSL.QUIC.info(client)

      assert %{handshake_complete: true, peer_authenticated: false, alpn: "test"} =
               SSL.QUIC.info(server)
    end
  end

  test "returns an opaque negotiated ALPN", %{fixtures: fixtures} do
    alpn = <<0xFF>>
    client_options = client_options(cacerts: [fixtures.ca.der], alpn: [alpn])
    server_options = Keyword.put(server_options(fixtures), :alpn, [alpn])
    assert {:ok, client, client_actions} = SSL.QUIC.new(:client, client_options)
    assert {:ok, server, []} = SSL.QUIC.new(:server, server_options)
    {client, server} = drive(client, server, client_actions, [])

    assert %{handshake_complete: true, alpn: ^alpn} = SSL.QUIC.info(client)
    assert %{handshake_complete: true, alpn: ^alpn} = SSL.QUIC.info(server)
  end

  test "rejects an untrusted CA and a wrong IP after a real server flight", %{fixtures: fixtures} do
    for {client_options, alert, reason} <- [
          {client_options(cacerts: [fixtures.wrong.der]), :unknown_ca, :path_validation_failed},
          {client_options(
             cacerts: [fixtures.ca.der],
             reference_identity: {:ip, "127.0.0.2"},
             server_name: "exssl.test"
           ), :certificate_unknown, :hostname_mismatch}
        ] do
      assert {:error, %SSL.QUIC.Error{kind: :tls, alert: ^alert, reason: ^reason}, failed, [_]} =
               receive_server_flight(client_options, server_options(fixtures))

      refute SSL.QUIC.info(failed).handshake_complete
      refute SSL.QUIC.info(failed).peer_authenticated
    end
  end

  test "rejects duplicate top-level and nested options while accepting opaque ALPN tokens" do
    assert {:error, %SSL.QUIC.Error{kind: :configuration}} =
             SSL.QUIC.new(:client, client_options([]) ++ [alpn: ["test"]])

    assert {:error, %SSL.QUIC.Error{kind: :configuration}} =
             SSL.QUIC.new(
               :client,
               client_options(limits: [max_extension_bytes: 16, max_extension_bytes: 8])
             )

    assert {:ok, _, [{:emit, :initial, _}]} =
             SSL.QUIC.new(:client, client_options(alpn: [:binary.copy(<<0>>, 255)]))

    assert {:error, %SSL.QUIC.Error{kind: :configuration}} =
             SSL.QUIC.new(:client, client_options(alpn: [:binary.copy(<<0>>, 256)]))
  end

  test "accepts in-memory PEM trust and rejects unsafe option combinations", %{fixtures: fixtures} do
    assert {:ok, _, [{:emit, :initial, _}]} =
             SSL.QUIC.new(:client, client_options(cacerts: File.read!(fixtures.ca.certificate)))

    for options <- [
          server_options(fixtures) ++ [cacerts: [fixtures.ca.der]],
          Keyword.delete(server_options(fixtures), :key),
          Keyword.put(server_options(fixtures), :key, private_key(fixtures.ec.key)),
          client_options(alpn: ["test", "test"]),
          client_options(limits: [max_handshake_length: 1_048_577]),
          client_options(unknown: true)
        ] do
      role = if Keyword.has_key?(options, :cert), do: :server, else: :client
      assert {:error, %SSL.QUIC.Error{kind: :configuration}} = SSL.QUIC.new(role, options)
    end
  end

  test "an explicit record-free QUIC profile materializes fresh shares with a stable fingerprint" do
    profile = %SSL.ClientHello.WireProfile{
      session_id: :empty,
      record: %SSL.ClientHello.RecordPolicy{mode: :none},
      cipher_suites: [0x1301],
      extensions: [
        {:supported_versions, [0x0304]},
        {:supported_groups, [0x001D]},
        {:signature_algorithms, [0x0403, 0x0804]},
        {:signature_algorithms_cert, [0x0403, 0x0804]},
        {:alpn, ["test"]},
        {:key_share, [0x001D]},
        {:raw, 57, <<1, 0>>}
      ]
    }

    assert {:ok, _, [{:emit, :initial, first}]} =
             SSL.QUIC.new(
               :client,
               client_options(profile: profile, ciphers: [0x1301], groups: [0x001D])
             )

    assert {:ok, _, [{:emit, :initial, second}]} =
             SSL.QUIC.new(
               :client,
               client_options(profile: profile, ciphers: [0x1301], groups: [0x001D])
             )

    refute first == second
    assert {:ok, first_offer} = SSL.Protocol.ClientOffer.from_client_hello(first)
    assert {:ok, second_offer} = SSL.Protocol.ClientOffer.from_client_hello(second)
    <<1, _::24, _::16, first_random::binary-size(32), _::binary>> = first
    <<1, _::24, _::16, second_random::binary-size(32), _::binary>> = second
    refute first_random == second_random
    assert [%{key_exchange: first_share}] = first_offer.key_shares
    assert [%{key_exchange: second_share}] = second_offer.key_shares
    refute first_share == second_share
    assert {:ok, first_fingerprint} = SSL.Fingerprint.client_hello(first, :quic)
    assert {:ok, second_fingerprint} = SSL.Fingerprint.client_hello(second, :quic)
    assert first_fingerprint.ja3 == second_fingerprint.ja3
    assert first_fingerprint.ja4 == second_fingerprint.ja4
  end

  defp client_options(extra) do
    Keyword.merge(
      [
        cacerts: [server_flight_der("root.pem")],
        reference_identity: {:dns_id, "exssl.test"},
        alpn: ["test"],
        transport_parameters: <<1, 0>>
      ],
      extra
    )
  end

  defp server_options(fixtures) do
    [
      cert: [fixtures.ec_server.der],
      key: private_key(fixtures.ec_server.key),
      alpn: ["test"],
      transport_parameters: <<2, 0>>
    ]
  end

  defp private_key(path) do
    [entry] = path |> File.read!() |> :public_key.pem_decode()
    {type, der, :not_encrypted} = entry
    {type, der}
  end

  defp server_flight_der(name) do
    path = Path.expand("../fixtures/server_flight/#{name}", __DIR__)
    [{:Certificate, der, :not_encrypted}] = path |> File.read!() |> :public_key.pem_decode()
    der
  end

  defp receive_server_flight(client_options, server_options) do
    {:ok, client, client_actions} = SSL.QUIC.new(:client, client_options)
    {:ok, server, []} = SSL.QUIC.new(:server, server_options)
    {_, server_actions} = deliver(server, client_actions)

    [{:emit, :initial, server_hello}] =
      Enum.filter(server_actions, &match?({:emit, :initial, _}, &1))

    {:ok, client, _} = SSL.QUIC.feed(client, :initial, server_hello)

    server_flight =
      for {:emit, :handshake, bytes} <- server_actions, into: <<>>, do: bytes

    SSL.QUIC.feed(client, :handshake, server_flight)
  end

  defp drive(client, server, [], []), do: {client, server}

  defp drive(client, server, client_actions, server_actions) do
    {server, next_server_actions} = deliver(server, client_actions)
    {client, next_client_actions} = deliver(client, server_actions)
    drive(client, server, next_client_actions, next_server_actions)
  end

  defp deliver(state, actions) do
    Enum.reduce(actions, {state, []}, fn
      {:emit, level, bytes}, {state, emitted} ->
        assert {:ok, next, next_actions} = SSL.QUIC.feed(state, level, bytes)
        {next, emitted ++ next_actions}

      _, result ->
        result
    end)
  end
end
