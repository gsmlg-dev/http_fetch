# Run only through scripts/ex_ssl_source_smoke.sh with an explicit source checkout.
source = System.fetch_env!("EX_SSL_SOURCE_DIR")
Code.require_file(Path.join(source, "test/support/signature_fixtures.ex"))
Code.require_file(Path.join(source, "test/support/client_auth_fixtures.ex"))

defmodule CandidateOptionsTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias HTTP.Transport.ExSSL
  alias SSL.ClientHello.WireProfile

  @body "ordered-options"

  setup_all do
    directory = Path.join(System.tmp_dir!(), "http-options-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  test "HTTP.fetch honors ordered cipher, group, CertificateVerify, and issuer policies",
       context do
    response =
      with_peer(
        context.fixtures,
        fn port ->
          fetch(port, context.fixtures,
            ciphers: ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"],
            supported_groups: [:secp256r1, :x25519],
            signature_algs: [:rsa_pss_rsae_sha256, :ecdsa_secp256r1_sha256],
            signature_algs_cert: [:rsa_pkcs1_sha256]
          )
        end,
        @body,
        ciphers: [
          %{key_exchange: :any, cipher: :aes_256_gcm, mac: :aead, prf: :sha384}
        ],
        supported_groups: [:secp256r1]
      )

    assert response.status == 200
    assert HTTP.Response.read_all(response) == @body
  end

  test "an incompatible CertificateVerify or issuer policy fails authentication", context do
    for policy <- [
          [signature_algs: [:ecdsa_secp256r1_sha256]],
          [signature_algs: [:rsa_pss_rsae_sha256], signature_algs_cert: [:ecdsa_secp256r1_sha256]]
        ] do
      with_peer(
        context.fixtures,
        fn port ->
          assert {:error, _} = fetch(port, context.fixtures, policy)
        end,
        :reject
      )
    end
  end

  test "a conflicting explicit profile fails before TCP I/O" do
    profile = %WireProfile{
      name: :candidate_option_conflict,
      cipher_suites: [0x1301],
      extensions: [
        {:supported_versions, [0x0304]},
        {:supported_groups, [0x001D]},
        {:signature_algorithms, [0x0804]},
        {:key_share, [0x001D]},
        {:alpn, ["http/1.1"]}
      ]
    }

    assert_before_io(fn port ->
      assert {:error, {:options, _}} =
               fetch(port, nil,
                 ex_ssl: [profile: profile],
                 ciphers: ["TLS_AES_256_GCM_SHA384"]
               )
    end)
  end

  test "adapter applies safe TCP options and socket_opts override matching ssl entries",
       context do
    with_peer(
      context.fixtures,
      fn port ->
        ssl = tls_options(context.fixtures) ++ [nodelay: false, keepalive: false]

        socket_opts = [
          nodelay: true,
          keepalive: true,
          sndbuf: 16_384,
          recbuf: 16_384,
          ip: {127, 0, 0, 1},
          port: 0
        ]

        {:ok, socket} =
          ExSSL.connect("127.0.0.1", port, [ssl: ssl, socket_opts: socket_opts], 5_000)

        try do
          {:connected, state} = :sys.get_state(socket.pid)
          tcp = state.tcp
          assert {:ok, values} = :inet.getopts(tcp, [:nodelay, :keepalive, :sndbuf, :recbuf])
          assert Keyword.fetch!(values, :nodelay)
          assert Keyword.fetch!(values, :keepalive)
          assert Keyword.fetch!(values, :sndbuf) >= 16_384
          assert Keyword.fetch!(values, :recbuf) >= 16_384
          assert {:ok, {{127, 0, 0, 1}, local_port}} = :inet.sockname(tcp)
          assert local_port > 0
        after
          ExSSL.close(socket)
        end
      end,
      :no_http
    )
  end

  test "HTTP.fetch forwards the safe TCP allowlist", context do
    response =
      with_peer(context.fixtures, fn port ->
        fetch(port, context.fixtures, [],
          socket_opts: [
            nodelay: true,
            keepalive: true,
            sndbuf: 16_384,
            recbuf: 16_384,
            ip: {127, 0, 0, 1},
            port: 0
          ]
        )
      end)

    assert response.status == 200
    assert HTTP.Response.read_all(response) == @body
  end

  test "mutable TCP options apply, but an invalid combined setopts changes nothing", context do
    with_peer(
      context.fixtures,
      fn port ->
        {:ok, socket} =
          ExSSL.connect("127.0.0.1", port, [ssl: tls_options(context.fixtures)], 5_000)

        try do
          {:connected, state} = :sys.get_state(socket.pid)
          tcp = state.tcp

          assert :ok =
                   ExSSL.setopts(socket,
                     nodelay: true,
                     keepalive: true,
                     sndbuf: 16_384,
                     recbuf: 16_384
                   )

          assert {:ok, values} = :inet.getopts(tcp, [:nodelay, :keepalive, :sndbuf, :recbuf])
          assert Keyword.fetch!(values, :nodelay)
          assert Keyword.fetch!(values, :keepalive)
          assert Keyword.fetch!(values, :sndbuf) >= 16_384
          assert Keyword.fetch!(values, :recbuf) >= 16_384

          assert {:error, {:options, _}} =
                   ExSSL.setopts(socket, nodelay: false, ip: {127, 0, 0, 1})

          assert {:ok, [nodelay: true]} = :inet.getopts(tcp, [:nodelay])
        after
          ExSSL.close(socket)
        end
      end,
      :no_http
    )
  end

  test "IPv6 local bind selects the DNS address family with certificate verification", context do
    response =
      with_peer(
        context.fixtures,
        fn port ->
          HTTP.fetch("https://localhost:#{port}/options",
            tls_backend: :ex_ssl,
            ssl: tls_options(context.fixtures),
            socket_opts: [ip: {0, 0, 0, 0, 0, 0, 0, 1}],
            timeout: 5_000,
            connect_timeout: 5_000
          )
          |> HTTP.Promise.await(10_000)
        end,
        @body,
        ip: {0, 0, 0, 0, 0, 0, 0, 1}
      )

    assert response.status == 200
    assert HTTP.Response.read_all(response) == @body
  end

  test "malformed and unsafe socket options fail before network I/O" do
    for socket_opts <- [
          [linger: {true, 0}],
          [active: true],
          [packet: 4],
          [nodelay: :invalid],
          [nodelay: true, nodelay: false],
          [ip: {999, 0, 0, 1}],
          [port: -1],
          [send_timeout_close: false, linger: {true, 0}],
          [{:nodelay, true} | :improper]
        ] do
      assert_before_io(fn port ->
        assert {:error, {:options, _}} =
                 HTTP.fetch("https://127.0.0.1:#{port}/options",
                   tls_backend: :ex_ssl,
                   socket_opts: socket_opts,
                   timeout: 2_000,
                   connect_timeout: 2_000
                 )
                 |> HTTP.Promise.await(3_000)
      end)
    end
  end

  test "malformed ssl options fail before HTTP/2 ALPN construction and network I/O" do
    assert_before_io(fn port ->
      assert {:error, {:options, _}} =
               HTTP.fetch("https://127.0.0.1:#{port}/options",
                 http_version: :http2,
                 tls_backend: :ex_ssl,
                 ssl: [{:verify, :verify_peer} | :improper],
                 timeout: 2_000,
                 connect_timeout: 2_000
               )
               |> HTTP.Promise.await(3_000)
    end)
  end

  defp fetch(port, fixtures, ssl_extra, opts \\ []) do
    ssl = if(fixtures, do: tls_options(fixtures), else: []) ++ ssl_extra

    HTTP.fetch(
      "https://127.0.0.1:#{port}/options",
      [
        tls_backend: :ex_ssl,
        ssl: ssl,
        timeout: 5_000,
        connect_timeout: 5_000
      ] ++ opts
    )
    |> HTTP.Promise.await(10_000)
  end

  defp tls_options(fixtures) do
    [
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      verify: :verify_peer,
      alpn_advertised_protocols: ["http/1.1"]
    ]
  end

  defp with_peer(fixtures, client, response \\ @body, extra \\ []) do
    options =
      [
        certfile: String.to_charlist(fixtures.server.certificate),
        keyfile: String.to_charlist(fixtures.server.key),
        versions: [:"tlsv1.3"],
        active: false,
        mode: :binary,
        reuseaddr: true,
        alpn_preferred_protocols: ["http/1.1"]
      ]
      |> Keyword.merge(extra)

    {:ok, listener} = :ssl.listen(0, options)
    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, transport} = :ssl.transport_accept(listener, 5_000)

        case :ssl.handshake(transport, 5_000) do
          {:ok, socket} ->
            try do
              case response do
                :reject ->
                  assert {:error, _} = :ssl.recv(socket, 0, 5_000)

                :no_http ->
                  assert {:error, _} = :ssl.recv(socket, 0, 5_000)
                  :ok

                body ->
                  assert {:ok, "http/1.1"} = :ssl.negotiated_protocol(socket)
                  assert String.starts_with?(headers(socket, ""), "GET /options HTTP/1.1\r\n")

                  :ok =
                    :ssl.send(socket, [
                      "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: #{byte_size(body)}\r\n\r\n",
                      body
                    ])
              end
            after
              :ssl.close(socket)
            end

          {:error, _} when response == :reject ->
            :ok
        end
      end)

    try do
      result = client.(port)
      assert :ok = Task.await(task, 10_000)
      result
    after
      :ssl.close(listener)
      Task.shutdown(task, :brutal_kill)
    end
  end

  defp headers(socket, buffer) when byte_size(buffer) < 16_384 do
    if String.contains?(buffer, "\r\n\r\n") do
      buffer
    else
      {:ok, bytes} = :ssl.recv(socket, 0, 5_000)
      headers(socket, buffer <> bytes)
    end
  end

  defp assert_before_io(client) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)

    try do
      client.(port)
      assert {:error, :timeout} = :gen_tcp.accept(listener, 200)
    after
      :gen_tcp.close(listener)
    end
  end
end
