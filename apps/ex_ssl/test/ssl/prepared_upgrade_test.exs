defmodule SSL.PreparedUpgradeTest do
  use ExUnit.Case, async: false

  alias SSL.ClientHello.{Profile, WireProfile}

  test "upgrade context rejects bind/family options and absent required SNI" do
    for option <- [{:ip, {127, 0, 0, 1}}, {:port, 0}, :inet, :inet6] do
      assert {:error, {:options, _}} =
               SSL.prepare_upgrade([option, verify: :verify_none])
    end

    assert {:error, {:options, _}} = SSL.prepare_upgrade([])
    assert {:ok, prepared} = SSL.prepare_upgrade(verify: :verify_none)
    assert inspect(prepared) == "#SSL.PreparedUpgrade<...>"

    assert {:error, {:options, {:ex_ssl, :unsupported_profile}}} =
             SSL.prepare_upgrade(verify: :verify_none, ex_ssl: [profile: profile()])
  end

  test "actual SNI bytes are included in the existing profile extension limit" do
    base = profile()
    # The static vector is exactly 65535 bytes; dynamic SNI must not fit.
    padded = %{base | extensions: base.extensions ++ [{:padding, 65_462}]}
    assert {:ok, _} = Profile.validate(padded, SSL.Options.capabilities())

    assert {:error, {:options, {:ex_ssl, :unsupported_profile}}} =
             SSL.prepare_upgrade(
               verify: :verify_none,
               server_name_indication: ~c"exssl.test",
               ex_ssl: [profile: padded]
             )
  end

  for change <- [:replace, :delete] do
    @tag :tmp_dir
    @tag :integration
    test "loaded trust and client credentials survive source file #{change}", %{
      tmp_dir: directory
    } do
      fixtures = ExSSL.TestSupport.ClientAuthFixtures.create(Path.join(directory, "fixtures"))
      ca = Path.join(directory, "snapshot-ca.pem")
      cert = Path.join(directory, "snapshot-client.pem")
      key = Path.join(directory, "snapshot-client.key")
      File.cp!(fixtures.ca.certificate, ca)
      File.cp!(fixtures.rsa.certificate, cert)
      File.cp!(fixtures.rsa.key, key)

      options = [
        cacertfile: ca,
        certfile: cert,
        keyfile: key,
        server_name_indication: ~c"exssl.test",
        alpn_advertised_protocols: ["h2"]
      ]

      assert {:ok, prepared} = SSL.prepare_upgrade(options)
      assert inspect(prepared) == "#SSL.PreparedUpgrade<...>"

      case unquote(change) do
        :replace ->
          File.cp!(Path.join([directory, "fixtures", "wrong-ca.pem"]), ca)
          File.cp!(fixtures.wrong.certificate, cert)
          File.cp!(fixtures.wrong.key, key)
          assert {:ok, _} = SSL.prepare_upgrade(options)

        :delete ->
          for path <- [ca, cert, key] do
            assert Path.dirname(Path.expand(path)) == Path.expand(directory)
            File.rm!(path)
          end

          assert {:error, {:options, _}} = SSL.prepare_upgrade(options)
      end

      {:ok, listener} =
        :ssl.listen(0,
          certfile: fixtures.server.certificate,
          keyfile: fixtures.server.key,
          cacerts: [fixtures.ca.der],
          verify: :verify_peer,
          fail_if_no_peer_cert: true,
          versions: [:"tlsv1.3"],
          alpn_preferred_protocols: ["h2"],
          active: false,
          mode: :binary,
          ip: {127, 0, 0, 1},
          reuseaddr: true
        )

      on_exit(fn -> :ssl.close(listener) end)
      {:ok, {_, port}} = :ssl.sockname(listener)

      peer =
        Task.async(fn ->
          {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
          {:ok, socket} = :ssl.handshake(tcp, 5_000)
          assert {:ok, fixtures.rsa.der} == :ssl.peercert(socket)
          assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
          :ok = :ssl.send(socket, "pong")
          :ssl.close(socket)
        end)

      {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)
      assert {:ok, socket} = SSL.connect_prepared(tcp, prepared, 5_000)
      assert {:ok, "h2"} = SSL.negotiated_protocol(socket)
      assert :ok = SSL.send(socket, "ping")
      assert {:ok, "pong"} = SSL.recv(socket, 4, 5_000)
      SSL.close(socket)
      Task.await(peer, 5_000)
    end
  end

  @tag :integration
  test "a reused snapshot generates fresh wire random, session ID and key share" do
    {listener, port} = listener()
    assert {:ok, prepared} = SSL.prepare_upgrade(verify: :verify_none)
    parent = self()

    peer =
      Task.async(fn ->
        for _ <- 1..2 do
          {:ok, tcp} = :gen_tcp.accept(listener, 5_000)
          hello = recv_hello(tcp)
          {:ok, offer} = SSL.Protocol.ClientOffer.from_client_hello(hello)

          <<1, _::24, _::16, random::binary-size(32), size, session::binary-size(size),
            _::binary>> = hello

          send(parent, {:hello, random, session, offer.key_shares})
          :gen_tcp.close(tcp)
        end
      end)

    for _ <- 1..2 do
      {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)
      assert {:error, _} = SSL.connect_prepared(tcp, prepared, 5_000)
    end

    assert_receive {:hello, random1, session1, shares1}, 5_000
    assert_receive {:hello, random2, session2, shares2}, 5_000
    assert byte_size(random1) == 32 and random1 != random2
    assert byte_size(session1) == 32 and session1 != session2
    assert shares1 != [] and shares1 != shares2
    Task.await(peer, 5_000)
  end

  @tag :tmp_dir
  @tag :integration
  test "reused policy selects live tickets and authenticates fresh resumed flights", %{
    tmp_dir: directory
  } do
    fixtures = ExSSL.TestSupport.ClientAuthFixtures.create(Path.join(directory, "resumption"))

    {:ok, prepared} =
      SSL.prepare_upgrade(
        cacerts: [fixtures.ca.der],
        server_name_indication: ~c"exssl.test",
        session_tickets: :auto
      )

    {:ok, listener} =
      :ssl.listen(0,
        certfile: fixtures.server.certificate,
        keyfile: fixtures.server.key,
        versions: [:"tlsv1.3"],
        session_tickets: :stateful,
        active: false,
        mode: :binary,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      )

    on_exit(fn -> :ssl.close(listener) end)
    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      Task.async(fn ->
        for resumed <- [false, true, true] do
          {:ok, tcp} = :ssl.transport_accept(listener, 5_000)
          {:ok, socket} = :ssl.handshake(tcp, 5_000)

          assert {:ok, [session_resumption: resumed]} ==
                   :ssl.connection_information(socket, [:session_resumption])

          assert {:ok, "ping"} = :ssl.recv(socket, 4, 5_000)
          :ok = :ssl.send(socket, "pong")
          assert {:error, :closed} = :ssl.recv(socket, 0, 5_000)
          :ssl.close(socket)
        end
      end)

    for resumed <- [false, true, true] do
      {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)
      assert {:ok, socket} = SSL.connect_prepared(tcp, prepared, 5_000)

      assert {:ok, [session_resumption: resumed]} ==
               SSL.connection_information(socket, [:session_resumption])

      assert :ok = SSL.send(socket, "ping")
      assert {:ok, "pong"} = SSL.recv(socket, 4, 5_000)
      assert :ok = SSL.close(socket)
    end

    Task.await(peer, 5_000)
  end

  @tag :integration
  test "prepared consumption preserves ownership and pending-plaintext boundaries" do
    {listener, port} = listener()
    {:ok, prepared} = SSL.prepare_upgrade(verify: :verify_none)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)
    {:ok, peer} = :gen_tcp.accept(listener, 5_000)
    on_exit(fn -> :gen_tcp.close(peer) end)

    task = Task.async(fn -> SSL.connect_prepared(client, prepared, 1_000) end)
    assert {:error, :not_owner} = Task.await(task)
    assert :ok = :gen_tcp.send(peer, "plaintext")
    assert {:ok, "plaintext"} = :gen_tcp.recv(client, 9, 5_000)
    assert :ok = :gen_tcp.unrecv(client, "plaintext")
    assert {:error, :pending_plaintext} = SSL.connect_prepared(client, prepared, 1_000)
    assert {:error, :closed} = :gen_tcp.recv(peer, 0, 5_000)
  end

  defp recv_hello(tcp, acc \\ <<>>) do
    case acc do
      <<1, length::24, body::binary>> when byte_size(body) >= length ->
        binary_part(acc, 0, 4 + length)

      _ ->
        {:ok, <<22, 3, _, size::16>>} = :gen_tcp.recv(tcp, 5, 5_000)
        assert size <= 16_384 and byte_size(acc) + size <= 1_048_576
        {:ok, bytes} = :gen_tcp.recv(tcp, size, 5_000)
        recv_hello(tcp, acc <> bytes)
    end
  end

  defp profile do
    %WireProfile{
      extensions: [
        {:server_name, :from_connection},
        {:supported_versions, [0x0304]},
        {:supported_groups, [:x25519]},
        {:signature_algorithms, [:rsa_pss_rsae_sha256]},
        {:key_share, [:x25519]}
      ]
    }
  end

  defp listener do
    {:ok, socket} =
      :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true])

    {:ok, port} = :inet.port(socket)
    on_exit(fn -> :gen_tcp.close(socket) end)
    {socket, port}
  end
end
