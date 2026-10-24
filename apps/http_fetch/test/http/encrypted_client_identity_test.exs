defmodule HTTP.EncryptedClientIdentityTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.EncryptedIdentityFixtures
  @timeout 10_000
  @python Path.expand("../../../../scripts/ex_ssl_tls12_peer.py", __DIR__)

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "http-encrypted-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    EncryptedIdentityFixtures.create(directory)
  end

  for protocol <- [:http1, :http2],
      version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :connect] do
    test "multiple encrypted identities #{version} #{protocol} fetch selects exact EC through #{route}",
         context do
      counts = :atomics.new(2, [])

      entries =
        for {role, index} <- [{:rsa, 1}, {:ec, 2}] do
          fixture = context.encrypted[role]

          %{
            certfile: fixture.certificate,
            keyfile: fixture.encrypted_key,
            password: fn ->
              assert :atomics.add_get(counts, index, 1) == 1
              fixture.password
            end
          }
        end

      peer = start_peer(context.fixtures, unquote(protocol), unquote(version))

      tunnel =
        if unquote(route) == :connect,
          do:
            start_proxy(peer.port, fn ->
              assert [:atomics.get(counts, 1), :atomics.get(counts, 2)] == [1, 1]
            end)

      try do
        options = [
          tls_backend: :ex_ssl,
          http_version: unquote(protocol),
          timeout: @timeout,
          connect_timeout: @timeout,
          ssl: [
            versions: [unquote(version)],
            alpn_advertised_protocols: [
              unquote(if protocol == :http2, do: "h2", else: "http/1.1")
            ],
            cacerts: [context.fixtures.ca.der],
            server_name_indication: ~c"exssl.test",
            certs_keys: entries,
            password: fn -> flunk("ignored legacy password invoked") end
          ]
        ]

        options =
          if tunnel,
            do: Keyword.put(options, :proxy, {:http, "127.0.0.1", tunnel.port, []}),
            else: options

        promise = HTTP.fetch("https://127.0.0.1:#{peer.port}/tls12", options)
        assert {:ok, handshake} = event(peer, "handshake")
        assert handshake["client_der_b64"] == Base.encode64(context.encrypted.ec.der)

        assert handshake["version"] ==
                 unquote(if version == :"tlsv1.2", do: "TLSv1.2", else: "TLSv1.3")

        assert handshake["alpn"] == unquote(if protocol == :http2, do: "h2", else: "http/1.1")
        assert {:ok, %{"bytes" => 6}} = event(peer, "exchange")
        assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, @timeout)
        assert HTTP.Response.read_all(response) == "BBBBBB"
        assert [:atomics.get(counts, 1), :atomics.get(counts, 2)] == [1, 1]

        if unquote(protocol) == :http2 do
          assert Port.command(peer.handle, "go\n")
          assert {:ok, _} = event(peer, "released")
        end
      after
        stop_peer(peer)

        if tunnel do
          :gen_tcp.close(tunnel.listener)
          Task.shutdown(tunnel.task, :brutal_kill)
        end
      end

      assert {:error, :econnrefused} =
               :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 1_000)
    end
  end

  for role <- [:rsa, :ec],
      protocol <- [:http1, :http2],
      version <- [:"tlsv1.2", :"tlsv1.3"],
      route <- [:direct, :connect] do
    @tag :tmp_dir
    test "encrypted #{role} #{version} #{protocol} fetch authenticates through #{route}",
         context do
      fixture = Map.fetch!(context.encrypted, unquote(role))
      certificate = Path.join(context.tmp_dir, "client.pem")
      key = Path.join(context.tmp_dir, "encrypted.key")
      File.cp!(fixture.certificate, certificate)
      File.cp!(fixture.encrypted_key, key)
      counter = :atomics.new(1, [])

      password = fn ->
        assert :atomics.add_get(counter, 1, 1) == 1
        fixture.password
      end

      peer = start_peer(context.fixtures, unquote(protocol), unquote(version))

      tunnel =
        if unquote(route) == :connect do
          start_proxy(peer.port, fn ->
            # The CONNECT route must already have frozen and decrypted the identity.
            assert :atomics.get(counter, 1) == 1
          end)
        end

      try do
        ssl = [
          versions: [unquote(version)],
          alpn_advertised_protocols: [unquote(if protocol == :http2, do: "h2", else: "http/1.1")],
          cacerts: [context.fixtures.ca.der],
          server_name_indication: ~c"exssl.test",
          certfile: certificate,
          keyfile: key,
          password: password
        ]

        options = [
          tls_backend: :ex_ssl,
          http_version: unquote(protocol),
          ssl: ssl,
          timeout: @timeout,
          connect_timeout: @timeout
        ]

        options =
          if tunnel,
            do: Keyword.put(options, :proxy, {:http, "127.0.0.1", tunnel.port, []}),
            else: options

        promise = HTTP.fetch("https://127.0.0.1:#{peer.port}/tls12", options)
        assert {:ok, handshake} = event(peer, "handshake")
        assert handshake["client_der_b64"] == Base.encode64(fixture.der)

        assert handshake["version"] ==
                 unquote(if version == :"tlsv1.2", do: "TLSv1.2", else: "TLSv1.3")

        assert handshake["alpn"] == unquote(if protocol == :http2, do: "h2", else: "http/1.1")
        assert {:ok, %{"bytes" => 6}} = event(peer, "exchange")
        assert %HTTP.Response{status: 200} = response = HTTP.Promise.await(promise, @timeout)
        assert HTTP.Response.read_all(response) == "BBBBBB"
        assert :atomics.get(counter, 1) == 1

        if unquote(protocol) == :http2 do
          assert Port.command(peer.handle, "go\n")
          assert {:ok, _} = event(peer, "released")
        end
      after
        stop_peer(peer)

        if tunnel do
          :gen_tcp.close(tunnel.listener)
          Task.shutdown(tunnel.task, :brutal_kill)
        end
      end

      assert {:error, :econnrefused} =
               :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 1_000)
    end
  end

  test "managed transport still rejects password callbacks and encrypted file snapshots",
       context do
    fixture = context.encrypted.rsa
    counter = :atomics.new(1, [])

    callback = fn ->
      :atomics.add_get(counter, 1, 1)
      fixture.password
    end

    for ssl <- [[password: fixture.password], [password: callback], [certs_keys: []]] do
      assert {:error, :invalid_transport_scope_tls_policy} =
               HTTP.ManagedTransport.Policy.freeze(
                 origin: "https://127.0.0.1",
                 connect_address: {127, 0, 0, 1},
                 http_version: :http1,
                 ssl: [cacerts: []] ++ ssl
               )
    end

    assert {:error, {:invalid_transport_scope_tls_file, :keyfile}} =
             HTTP.ManagedTransport.Policy.freeze(
               origin: "https://127.0.0.1",
               connect_address: {127, 0, 0, 1},
               http_version: :http1,
               ssl: [cacerts: [], certfile: fixture.certificate, keyfile: fixture.encrypted_key]
             )

    assert :atomics.get(counter, 1) == 0
  end

  defp start_peer(fixtures, protocol, version) do
    executable = System.find_executable("python3") || raise "python3 is required"

    args = [
      "-B",
      "-u",
      @python,
      "--certfile",
      fixtures.server.certificate,
      "--keyfile",
      fixtures.server.key,
      "--cafile",
      fixtures.ca.certificate,
      "--mode",
      if(protocol == :http2, do: "h2", else: "http1"),
      "--max-version",
      if(version == :"tlsv1.2", do: "tls12", else: "tls13")
    ]

    handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: args
      ])

    {:os_pid, os_pid} = Port.info(handle, :os_pid)
    peer = %{handle: handle, os_pid: os_pid, port: nil}

    case event(peer, "ready") do
      {:ok, %{"port" => port}} ->
        %{peer | port: port}

      error ->
        stop_peer(peer)
        flunk("independent peer startup failed: #{inspect(error)}")
    end
  end

  defp event(%{handle: handle}, expected) do
    receive do
      {^handle, {:data, {:eol, line}}} ->
        case JSON.decode(line) do
          {:ok, %{"kind" => ^expected} = value} -> {:ok, value}
          {:ok, value} -> {:error, {:unexpected_peer_event, value}}
          _ -> {:error, :invalid_peer_event}
        end

      {^handle, {:data, {:noeol, _}}} ->
        {:error, :peer_line_too_long}

      {^handle, {:exit_status, status}} ->
        {:error, {:peer_exit, status}}
    after
      @timeout -> {:error, :peer_timeout}
    end
  end

  defp stop_peer(%{handle: handle, os_pid: os_pid}) do
    case Port.info(handle, :os_pid) do
      {:os_pid, ^os_pid} ->
        _ = System.cmd("kill", ["-TERM", Integer.to_string(os_pid)], stderr_to_stdout: true)

        receive do
          {^handle, {:exit_status, _}} -> :ok
        after
          2_000 -> flunk("independent peer did not stop")
        end

      nil ->
        :ok
    end
  end

  defp start_proxy(origin_port, prepared) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listener)

    task =
      Task.async(fn ->
        {:ok, client} = :gen_tcp.accept(listener, @timeout)

        try do
          assert recv_head(client) =~ "CONNECT 127.0.0.1:#{origin_port} HTTP/1.1\r\n"
          prepared.()

          {:ok, upstream} =
            :gen_tcp.connect({127, 0, 0, 1}, origin_port, [:binary, active: false], @timeout)

          try do
            :ok = :gen_tcp.send(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
            :ok = :inet.setopts(client, active: :once)
            :ok = :inet.setopts(upstream, active: :once)
            forward(client, upstream)
          after
            :gen_tcp.close(upstream)
          end
        after
          :gen_tcp.close(client)
        end
      end)

    %{port: port, listener: listener, task: task}
  end

  defp recv_head(socket, bytes \\ <<>>) do
    assert byte_size(bytes) <= 16_384

    if :binary.match(bytes, "\r\n\r\n") != :nomatch do
      bytes
    else
      {:ok, chunk} = :gen_tcp.recv(socket, 0, @timeout)
      recv_head(socket, bytes <> chunk)
    end
  end

  defp forward(client, upstream) do
    receive do
      {:tcp, ^client, bytes} ->
        case :gen_tcp.send(upstream, bytes) do
          :ok ->
            :ok = :inet.setopts(client, active: :once)
            forward(client, upstream)

          {:error, :closed} ->
            :ok
        end

      {:tcp, ^upstream, bytes} ->
        case :gen_tcp.send(client, bytes) do
          :ok ->
            :ok = :inet.setopts(upstream, active: :once)
            forward(client, upstream)

          {:error, :closed} ->
            :ok
        end

      {:tcp_closed, socket} when socket in [client, upstream] ->
        :ok

      {:tcp_error, socket, _} when socket in [client, upstream] ->
        :ok
    after
      @timeout -> flunk("CONNECT relay did not finish")
    end
  end
end
