defmodule SSL.EncryptedClientIdentityMTLSTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.{EncryptedIdentityFixtures, LocalTLSPeer}
  @request "GET / HTTP/1.1\r\nHost: exssl.test\r\nConnection: close\r\n\r\n"
  @response "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong"

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-encrypted-mtls-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    Map.put(EncryptedIdentityFixtures.create(directory), :directory, directory)
  end

  for role <- [:rsa, :ec], mode <- [:host, :port] do
    test "TLS13 #{role} encrypted identity authenticates public #{mode} and HTTP", context do
      fixture = Map.fetch!(context.encrypted, unquote(role))
      exchange(context, fixture, options(context, fixture), unquote(mode))
    end
  end

  for version <- [:"tlsv1.2", :"tlsv1.3"],
      role <- [:rsa, :ec],
      mode <- [:host, :port, :prepared] do
    test "OpenSSL #{version} required-mTLS #{role} public #{mode} serves authenticated HTTP",
         context do
      openssl_exchange(
        context,
        Map.fetch!(context.encrypted, unquote(role)),
        unquote(version),
        unquote(mode)
      )
    end
  end

  for mutation <- [:delete, :replace] do
    @tag :tmp_dir
    test "prepared encrypted snapshot survives #{mutation} and closure mutation for two attaches",
         context do
      original = context.encrypted.rsa
      cert = Path.join(context.tmp_dir, "client.pem")
      key = Path.join(context.tmp_dir, "client.key")
      File.cp!(original.certificate, cert)
      File.cp!(original.encrypted_key, key)
      fixture = %{original | certificate: cert, encrypted_key: key}
      counter = :atomics.new(1, [])

      password = fn ->
        if :atomics.add_get(counter, 1, 1) == 1,
          do: original.password,
          else: raise("PRIVATE_CALLBACK_REINVOKED")
      end

      assert {:ok, prepared} =
               SSL.prepare_upgrade(Keyword.put(options(context, fixture), :password, password))

      assert :atomics.get(counter, 1) == 1
      assert inspect(prepared) == "#SSL.PreparedUpgrade<...>"
      assert :binary.match(:erlang.term_to_binary(prepared), original.password) == :nomatch

      case unquote(mutation) do
        :delete ->
          File.rm!(cert)
          File.rm!(key)

        :replace ->
          File.cp!(context.fixtures.wrong.certificate, cert)
          File.cp!(context.fixtures.wrong.key, key)
      end

      for _ <- 1..2, do: exchange(context, original, prepared, :prepared)
      assert :atomics.get(counter, 1) == 1
    end
  end

  test "encrypted wrong-CA expired and server-purpose identities cannot return HTTP", context do
    for role <- [:wrong, :expired, :server] do
      fixture =
        EncryptedIdentityFixtures.encrypt(
          Map.fetch!(context.fixtures, role),
          context.directory,
          "negative-#{role}",
          context.encrypted.rsa.password
        )

      {:ok, peer} =
        LocalTLSPeer.start(fn _socket -> :unexpected_authenticated_http end,
          ssl_options: [
            certfile: context.fixtures.server.certificate,
            keyfile: context.fixtures.server.key,
            cacerts: [context.fixtures.ca.der],
            verify: :verify_peer,
            fail_if_no_peer_cert: true,
            versions: [:"tlsv1.3"]
          ]
        )

      try do
        case SSL.connect({127, 0, 0, 1}, peer.port, options(context, fixture), 5_000) do
          {:error, _} ->
            :ok

          {:ok, socket} ->
            try do
              _ = SSL.send(socket, @request)
              assert {:error, _} = SSL.recv(socket, 0, 5_000)
            after
              SSL.close(socket)
            end
        end
      after
        assert {:handshake_error, _} = LocalTLSPeer.stop(peer)
      end
    end
  end

  defp options(context, fixture) do
    [
      cacerts: [context.fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      versions: [:"tlsv1.3"],
      active: false,
      mode: :binary,
      certfile: fixture.certificate,
      keyfile: fixture.encrypted_key,
      password: fixture.password
    ]
  end

  defp exchange(context, fixture, options, mode) do
    {:ok, listener} =
      :ssl.listen(0,
        certfile: context.fixtures.server.certificate,
        keyfile: context.fixtures.server.key,
        cacerts: [context.fixtures.ca.der],
        verify: :verify_peer,
        fail_if_no_peer_cert: true,
        versions: [:"tlsv1.3"],
        mode: :binary,
        active: false,
        ip: {127, 0, 0, 1}
      )

    {:ok, {_, port}} = :ssl.sockname(listener)

    peer =
      Task.async(fn ->
        {:ok, tcp} = :ssl.transport_accept(listener, 5_000)

        try do
          {:ok, socket} = :ssl.handshake(tcp, 5_000)
          assert {:ok, fixture.der} == :ssl.peercert(socket)
          assert {:ok, @request} = :ssl.recv(socket, byte_size(@request), 5_000)
          :ok = :ssl.send(socket, @response)
        after
          :ssl.close(tcp)
        end
      end)

    try do
      result =
        case mode do
          :host ->
            SSL.connect({127, 0, 0, 1}, port, options, 5_000)

          mode when mode in [:port, :prepared] ->
            {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)

            if mode == :port,
              do: SSL.connect(tcp, options, 5_000),
              else: SSL.connect_prepared(tcp, options, 5_000)
        end

      assert {:ok, socket} = result

      try do
        assert {:ok, diagnostics} = SSL.connection_information(socket)
        status = inspect(:sys.get_status(socket.pid))

        for visible <- [status, inspect(diagnostics), inspect(socket)] do
          refute visible =~ fixture.password
          refute visible =~ fixture.encrypted_key
          refute visible =~ "PRIVATE KEY"
          refute visible =~ "private_key"
          refute visible =~ "PRIVATE_CALLBACK_REINVOKED"
        end

        assert :ok = SSL.send(socket, @request)
        assert {:ok, @response} = SSL.recv(socket, byte_size(@response), 5_000)
      after
        SSL.close(socket)
      end

      Task.await(peer, 5_000)
    after
      :ssl.close(listener)
      Task.shutdown(peer, :brutal_kill)
    end
  end

  defp openssl_exchange(context, fixture, version, mode) do
    {:ok, reservation} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(reservation)
    :gen_tcp.close(reservation)
    executable = System.find_executable("openssl") || raise "openssl is required"
    version_flag = if version == :"tlsv1.2", do: "-tls1_2", else: "-tls1_3"

    handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 524_288},
        args: [
          "s_server",
          "-accept",
          "127.0.0.1:#{port}",
          "-cert",
          context.fixtures.server.certificate,
          "-key",
          context.fixtures.server.key,
          "-CAfile",
          context.fixtures.ca.certificate,
          "-Verify",
          "2",
          "-verify_return_error",
          version_flag,
          "-cipher",
          "ECDHE-RSA-AES128-GCM-SHA256",
          "-ciphersuites",
          "TLS_AES_128_GCM_SHA256",
          "-no_ticket",
          "-www",
          "-naccept",
          "1"
        ]
      ])

    try do
      await_openssl(handle, System.monotonic_time(:millisecond) + 5_000, :ready)
      options = Keyword.put(options(context, fixture), :versions, [version])

      result =
        case mode do
          :host ->
            SSL.connect({127, 0, 0, 1}, port, options, 5_000)

          mode when mode in [:port, :prepared] ->
            prepared =
              if mode == :prepared do
                {:ok, prepared} = SSL.prepare_upgrade(options)
                prepared
              end

            {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 5_000)

            if mode == :prepared,
              do: SSL.connect_prepared(tcp, prepared, 5_000),
              else: SSL.connect(tcp, options, 5_000)
        end

      assert {:ok, socket} = result

      try do
        assert :ok = SSL.send(socket, "GET / HTTP/1.0\r\n\r\n")
        response = response(socket, <<>>)
        assert response =~ "HTTP/1.0 200 ok"

        [pem] =
          Regex.run(
            ~r/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s,
            response,
            capture: :first
          )

        assert [{:Certificate, fixture.der, :not_encrypted}] == :public_key.pem_decode(pem)
      after
        SSL.close(socket)
      end

      assert :ok = await_openssl(handle, System.monotonic_time(:millisecond) + 5_000, :exit)
    after
      LocalTLSPeer.stop_openssl(%{port_handle: handle})
    end
  end

  defp await_openssl(handle, deadline, phase) do
    receive do
      {^handle, {:data, {:eol, line}}} ->
        if phase == :ready and String.starts_with?(line, "ACCEPT"),
          do: :ok,
          else: await_openssl(handle, deadline, phase)

      {^handle, {:data, _}} ->
        await_openssl(handle, deadline, phase)

      {^handle, {:exit_status, 0}} when phase == :exit ->
        :ok

      {^handle, {:exit_status, status}} ->
        flunk("OpenSSL #{phase} exit #{status}")
    after
      max(0, deadline - System.monotonic_time(:millisecond)) -> flunk("OpenSSL #{phase} timeout")
    end
  end

  defp response(socket, bytes) when byte_size(bytes) < 65_536 do
    case SSL.recv(socket, 0, 5_000) do
      {:ok, chunk} -> response(socket, bytes <> chunk)
      {:error, :closed} -> bytes
      error -> flunk("HTTP response failed: #{inspect(error)}")
    end
  end
end
