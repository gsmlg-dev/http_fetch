defmodule HTTP.ExSSLVersionPolicyTest do
  use ExUnit.Case, async: true
  @moduletag :integration

  alias ExSSL.TestSupport.OpenSSLPeer
  alias HTTP.Transport.ExSSL
  alias SSL.ClientHello.WireProfile

  @fixtures Path.expand("../../../http_fetch/test/support/fixtures", __DIR__)
  @ca Path.join(@fixtures, "localhost-ca.pem")

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "omitted versions authenticate and exchange bytes with an independent #{version}-only peer" do
      assert_exchange(unquote(version), [])
    end

    test "TCP upgrade with omitted versions supports an independent #{version}-only peer" do
      assert_exchange(unquote(version), [], :upgrade)
    end

    test "explicit #{version} authenticates with the matching independent peer" do
      assert_exchange(unquote(version), versions: [unquote(version)])
    end

    test "a concrete #{version} profile determines omitted versions" do
      profile = profile([unquote(version)])
      assert_exchange(unquote(version), ex_ssl: [profile: profile])
    end
  end

  test "explicit TLS 1.3 rejects the same EMS-capable TLS 1.2 peer supported by the default" do
    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        min_version: :tls12,
        max_version: :tls12
      )

    try do
      assert {:error, {:tls_alert, _}} = connect(peer.port, [versions: [:"tlsv1.3"]], :direct)
    after
      OpenSSLPeer.stop(peer)
    end
  end

  test "TLS 1.3-only ciphers with omitted versions retain existing ExSSL behavior" do
    assert_exchange(:"tlsv1.3", ciphers: ["TLS_AES_128_GCM_SHA256"])
  end

  test "explicit TLS 1.3 remains compatible with the existing cipher policy" do
    assert_exchange(:"tlsv1.3", versions: [:"tlsv1.3"], ciphers: ["TLS_AES_128_GCM_SHA256"])
  end

  test "OTP accepts the same TLS 1.3-only cipher policy with omitted versions" do
    assert_exchange(:"tlsv1.3", [ciphers: ["TLS_AES_128_GCM_SHA256"]], :otp)
  end

  test "a concrete mixed profile retains TLS 1.2-first version order" do
    profile = profile([:"tlsv1.2", :"tlsv1.3"])
    assert_exchange(:"tlsv1.2", ex_ssl: [profile: profile])
    assert_exchange(:"tlsv1.3", [ex_ssl: [profile: profile]], :openssl)
  end

  test "symbolic versions and GREASE in a concrete profile retain their policy" do
    profile = %{
      profile([:"tlsv1.3"])
      | extensions: [
          {:supported_versions, [{:grease, :version}, :tlsv1_3]},
          {:supported_groups, [0x001D]},
          {:signature_algorithms, [0x0804]},
          {:key_share, [0x001D]}
        ],
        grease: %SSL.ClientHello.GreasePolicy{mode: {:deterministic, 7}}
    }

    assert_exchange(:"tlsv1.3", ex_ssl: [profile: profile])
  end

  test "the generated default profile follows the ordinary mixed default" do
    assert_exchange(:"tlsv1.2", ex_ssl: [profile: :default])
  end

  test "auto tickets with omitted versions keep the TLS 1.3 context" do
    assert_exchange(:"tlsv1.3", session_tickets: :auto)
    assert_exchange(:"tlsv1.3", session_tickets: :auto, ex_ssl: [profile: :default])
  end

  test "a ticket-ready concrete TLS 1.3 profile works without explicit versions" do
    profile = profile([:"tlsv1.3"])

    profile = %{
      profile
      | extensions:
          profile.extensions ++ [{:psk_key_exchange_modes, [1]}, {:pre_shared_key, :deferred}]
    }

    assert_exchange(:"tlsv1.3", session_tickets: :auto, ex_ssl: [profile: profile])
  end

  test "explicit version/profile conflicts fail before TCP I/O" do
    for {versions, profile_versions} <- [
          {[:"tlsv1.2"], [:"tlsv1.3"]},
          {[:"tlsv1.3", :"tlsv1.2"], [:"tlsv1.3"]},
          {[:"tlsv1.3"], [:"tlsv1.2"]}
        ] do
      assert_before_io(
        [versions: versions, ex_ssl: [profile: profile(profile_versions)]],
        {:versions, :profile_conflict}
      )
    end
  end

  test "explicit invalid versions are not replaced by a contextual default" do
    for versions <- [nil, [], [:"tlsv1.1"]] do
      assert_before_io([versions: versions], {:versions, :unsupported_or_invalid})
    end
  end

  test "explicit mixed versions with auto tickets fail before TCP I/O" do
    assert_before_io(
      [versions: [:"tlsv1.3", :"tlsv1.2"], session_tickets: :auto],
      {:session_tickets, :tls13_only}
    )
  end

  test "auto tickets do not rewrite an incompatible concrete profile" do
    assert_before_io(
      [session_tickets: :auto, ex_ssl: [profile: profile([:"tlsv1.3"])]],
      {:session_tickets, :profile_conflict}
    )

    assert_before_io(
      [session_tickets: :auto, ex_ssl: [profile: profile([:"tlsv1.2"])]],
      {:session_tickets, :tls13_only}
    )
  end

  test "the OTP TLS 1.2 peer without EMS fails before application traffic" do
    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        active: false,
        ip: {127, 0, 0, 1},
        versions: [:"tlsv1.2"],
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key")
      )

    {:ok, {_, port}} = :ssl.sockname(listener)
    parent = self()

    {peer, monitor} =
      spawn_monitor(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
        send(parent, {:otp_tls12_handshake, :ssl.handshake(tcp, 5_000)})
      end)

    on_exit(fn ->
      :ssl.close(listener)
      if Process.alive?(peer), do: Process.exit(peer, :kill)
    end)

    assert {:error, {:tls_alert, {:handshake_failure, _}}} =
             ExSSL.connect("localhost", port, [ssl: [cacertfile: @ca]], 5_000)

    assert_receive {:otp_tls12_handshake, {:error, {:tls_alert, {:handshake_failure, _}}}}, 5_000
    assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}, 5_000
  end

  defp assert_exchange(version, options, route \\ :direct)

  defp assert_exchange(version, options, :openssl),
    do: assert_openssl_exchange(version, options, :direct)

  defp assert_exchange(:"tlsv1.2", options, route),
    do: assert_openssl_exchange(:"tlsv1.2", options, route)

  defp assert_exchange(version, options, route),
    do: assert_otp_exchange(version, options, route)

  defp assert_openssl_exchange(version, options, route) do
    peer_version = if version == :"tlsv1.2", do: :tls12, else: :tls13
    negotiated_version = if version == :"tlsv1.2", do: "TLSv1.2", else: "TLSv1.3"

    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key"),
        min_version: peer_version,
        max_version: peer_version
      )

    try do
      assert {:ok, socket} =
               connect(peer.port, options, route)

      try do
        assert {:ok, %{"version" => ^negotiated_version}} =
                 OpenSSLPeer.event(peer, "handshake", 5_000)

        assert :ok = ExSSL.send(socket, <<4::32, "ping">>)
        assert {:ok, <<4::32, "ping">>} = ExSSL.recv(socket, 8, 5_000)
        assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
      after
        ExSSL.close(socket)
      end
    after
      OpenSSLPeer.stop(peer)
    end
  end

  defp assert_otp_exchange(version, options, route) do
    transport = if route == :otp, do: HTTP.Transport.SSL, else: ExSSL

    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        active: false,
        ip: {127, 0, 0, 1},
        versions: [version],
        certfile: Path.join(@fixtures, "localhost.pem"),
        keyfile: Path.join(@fixtures, "localhost.key")
      )

    {:ok, {_, port}} = :ssl.sockname(listener)
    parent = self()
    token = make_ref()

    {peer, monitor} =
      spawn_monitor(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
        {:ok, socket} = :ssl.handshake(tcp, 5_000)
        {:ok, info} = :ssl.connection_information(socket, [:protocol])
        send(parent, {token, info[:protocol]})
        {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
        :ok = :ssl.send(socket, "pong")
        :ssl.close(socket)
      end)

    on_exit(fn ->
      :ssl.close(listener)
      if Process.alive?(peer), do: Process.exit(peer, :kill)
    end)

    assert {:ok, socket} = connect(port, options, route)

    try do
      assert_receive {^token, ^version}, 5_000
      assert :ok = transport.send(socket, "ping")
      assert {:ok, "pong"} = transport.recv(socket, 4, 5_000)
      assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}, 5_000
    after
      transport.close(socket)
    end
  end

  defp connect(port, options, :direct),
    do: ExSSL.connect("localhost", port, [ssl: [cacertfile: @ca] ++ options], 5_000)

  defp connect(port, options, :otp),
    do: HTTP.Transport.SSL.connect("localhost", port, [ssl: [cacertfile: @ca] ++ options], 5_000)

  defp connect(port, options, :upgrade) do
    {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)
    ExSSL.upgrade(tcp, "localhost", [ssl: [cacertfile: @ca] ++ options], 5_000)
  end

  defp assert_before_io(options, reason) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)

    assert {:error, {:options, ^reason}} =
             ExSSL.connect("localhost", port, [ssl: [cacertfile: @ca] ++ options], 1_000)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 30)
  end

  defp profile(versions) do
    tls12? = :"tlsv1.2" in versions
    tls13? = :"tlsv1.3" in versions

    %WireProfile{
      cipher_suites: if(tls13?, do: [0x1301], else: []) ++ if(tls12?, do: [0xC02F], else: []),
      extensions:
        [
          {:supported_versions, Enum.map(versions, &version_id/1)},
          {:supported_groups, [0x001D]},
          {:signature_algorithms, [0x0804]}
        ] ++
          if(tls13?, do: [{:key_share, [0x001D]}], else: []) ++
          if(tls12?,
            do: [
              {:ec_point_formats, [0]},
              {:extended_master_secret, <<>>},
              {:renegotiation_info, <<0>>}
            ],
            else: []
          )
    }
  end

  defp version_id(:"tlsv1.3"), do: 0x0304
  defp version_id(:"tlsv1.2"), do: 0x0303
end
