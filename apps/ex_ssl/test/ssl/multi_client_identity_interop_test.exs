defmodule SSL.MultiClientIdentityInteropTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-multi-wire-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  for {version, names, expected, scheme, schemes} <- [
        {"tls13", ["p256-a", "rsa2048-a"], "rsa2048-a", 0x0804, "rsa_pss_rsae_sha256"},
        {"tls13", ["pss256-a", "p256-a"], "p256-a", 0x0403,
         "ecdsa_secp256r1_sha256:rsa_pss_pss_sha256"},
        {"tls13", ["rsa2048-a", "pss256-a"], "pss256-a", 0x0809,
         "rsa_pss_pss_sha256:rsa_pss_rsae_sha256"},
        {"tls13", ["p256-a", "ed25519-a"], "ed25519-a", 0x0807, "ed25519:ecdsa_secp256r1_sha256"},
        {"tls12", ["p256-a", "rsa2048-a"], "rsa2048-a", 0x0804, "rsa_pss_rsae_sha256"},
        {"tls12", ["p256-a", "rsa2048-a"], "rsa2048-a", 0x0401, "rsa_pkcs1_sha256"},
        {"tls12", ["pss256-a", "p256-a"], "p256-a", 0x0403,
         "ecdsa_secp256r1_sha256:rsa_pss_pss_sha256"},
        {"tls12", ["rsa2048-a", "pss256-a"], "pss256-a", 0x0809,
         "rsa_pss_pss_sha256:rsa_pss_rsae_sha256"}
      ] do
    test "#{version} independent pair selects #{expected} CV #{scheme}", %{fixtures: m} do
      {result, events} =
        F.exchange(m, F.options(m, unquote(names), unquote(version)),
          version: unquote(version),
          schemes: unquote(schemes) <> ":rsa_pkcs1_sha256"
        )

      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, unquote(expected), unquote(scheme), unquote(version))
    end
  end

  for version <- ["tls12", "tls13"] do
    test "#{version} later actual CA match and supplied/reconstructed exact chains", %{
      fixtures: m
    } do
      version = unquote(version)
      opts = F.options(m, ["p256-b", "rsa2048-a"], version)
      {result, events} = F.exchange(m, opts, version: version, hint: "client-a")
      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, "rsa2048-a", 0x0804, version)

      for form <- [:full, :files] do
        opts =
          F.options(m, [], version)
          |> Keyword.put(:certs_keys, [
            F.identity(m, "chain-b", :full),
            F.identity(m, "chain-a", form)
          ])
          |> Keyword.put(:cacerts, [
            F.root(m, "server-root"),
            F.root(m, "client-a"),
            Base.decode64!(m["intermediates"]["a"]["der_b64"])
          ])

        {result, events} = F.exchange(m, opts, version: version, hint: "client-a")
        assert result == {:ok, F.response()}

        F.assert_authenticated(m, events, "chain-a", 0x0804, version, [
          m["identities"]["chain-a"]["sha256"],
          m["intermediates"]["a"]["sha256"],
          m["roots"]["client-a"]["sha256"]
        ])
      end
    end

    test "#{version} no eligible identity is empty for optional and rejected for required", %{
      fixtures: m
    } do
      version = unquote(version)
      opts = F.options(m, ["rsa2048-a", "pss256-a"], version)
      settings = [version: version, schemes: "ecdsa_secp256r1_sha256"]
      {result, events} = F.exchange(m, opts, Keyword.put(settings, :auth, "optional"))
      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, nil, nil, version)
      {result, events} = F.exchange(m, opts, settings)
      assert {:error, _} = result
      assert Enum.any?(events, &(&1["event"] == "handshake_error"))
      refute Enum.any?(events, &(&1["event"] in ["authenticated", "client_cv", "http"]))
      assert [%{"sha256" => []}] = Enum.filter(events, &(&1["event"] == "wire_client_chain"))
    end

    test "#{version} intermediate-only local snapshot emits the exact verified partial chain", %{
      fixtures: m
    } do
      version = unquote(version)

      options =
        F.options(m, ["chain-a"], version)
        |> Keyword.put(
          :cacerts,
          [F.root(m, "server-root"), Base.decode64!(m["intermediates"]["a"]["der_b64"])]
        )

      {result, events} = F.exchange(m, options, version: version, hint: "client-a")
      assert result == {:ok, F.response()}

      F.assert_authenticated(m, events, "chain-a", 0x0804, version, [
        m["identities"]["chain-a"]["sha256"],
        m["intermediates"]["a"]["sha256"]
      ])
    end

    test "#{version} unrequested identities send no Certificate or CV", %{fixtures: m} do
      version = unquote(version)

      {result, events} =
        F.exchange(m, F.options(m, ["p256-a", "rsa2048-a"], version),
          version: version,
          auth: "none"
        )

      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, nil, nil, version)

      refute Enum.any?(
               events,
               &(&1["event"] in ["certificate_request", "wire_client_chain", "client_cv"])
             )
    end

    test "#{version} actual local signature offer excludes otherwise usable peer EC", %{
      fixtures: m
    } do
      version = unquote(version)

      options =
        F.options(m, ["p256-a", "p384-a"], version)
        |> Keyword.put(:signature_algs, [:rsa_pss_rsae_sha256])

      {result, events} =
        F.exchange(m, options,
          version: version,
          auth: "optional",
          schemes: "ecdsa_secp256r1_sha256:rsa_pkcs1_sha256"
        )

      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, nil, nil, version)
    end

    test "#{version} same modulus PSS restrictions select their own certificate", %{fixtures: m} do
      version = unquote(version)

      for {scheme, name, wire} <- [
            {0x0809, "pss256-a", "rsa_pss_pss_sha256"},
            {0x080A, "pss384-a", "rsa_pss_pss_sha384"}
          ] do
        {result, events} =
          F.exchange(m, F.options(m, ["pss256-a", "pss384-a"], version),
            version: version,
            schemes: wire <> ":rsa_pkcs1_sha256"
          )

        assert result == {:ok, F.response()}
        F.assert_authenticated(m, events, name, scheme, version)
      end
    end

    @tag :tmp_dir
    test "#{version} prepare freezes every file and callback across two differing requests", %{
      fixtures: m,
      tmp_dir: dir
    } do
      version = unquote(version)
      counts = :atomics.new(2, [])

      entries =
        for {name, index} <- [{"rsa2048-a", 1}, {"p256-a", 2}] do
          item = m["identities"][name]
          cert = Path.join(dir, name <> ".pem")
          key = Path.join(dir, name <> ".key")
          File.cp!(item["cert"], cert)
          File.cp!(item["encrypted_key"], key)
          secret = File.read!(item["password_file"])

          %{
            certfile: cert,
            keyfile: key,
            password: fn ->
              assert :atomics.add_get(counts, index, 1) == 1
              secret
            end
          }
        end

      ca = Path.join(dir, "trust.pem")
      File.cp!(m["roots"]["server-root"]["cert"], ca)

      opts =
        F.options(m, [], version)
        |> Keyword.delete(:cacerts)
        |> Keyword.put(:cacertfile, ca)
        |> Keyword.put(:certs_keys, entries)

      assert {:ok, prepared} = SSL.prepare_upgrade(opts)
      retained = :erlang.term_to_binary(prepared)
      refute retained =~ dir

      for entry <- entries do
        File.rm!(entry.certfile)
        File.write!(entry.keyfile, "replaced invalid private source")
      end

      File.write!(ca, File.read!(m["roots"]["client-c"]["cert"]))

      randoms =
        for {name, scheme, wire} <- [
              {"rsa2048-a", 0x0804, "rsa_pss_rsae_sha256"},
              {"p256-a", 0x0403, "ecdsa_secp256r1_sha256"}
            ] do
          {result, events} =
            F.exchange(
              m,
              prepared,
              [version: version, schemes: wire <> ":rsa_pkcs1_sha256"],
              :prepared
            )

          assert result == {:ok, F.response()}
          F.assert_authenticated(m, events, name, scheme, version)
          [random] = Enum.filter(events, &(&1["event"] == "client_hello_random"))
          random["sha256"]
        end

      assert [first, second] = randoms
      refute first == second
      assert [:atomics.get(counts, 1), :atomics.get(counts, 2)] == [1, 1]
    end

    test "#{version} usable candidates never bypass server trust or hostname", %{fixtures: m} do
      version = unquote(version)

      for {key, value} <- [
            {:cacerts, [F.root(m, "client-a")]},
            {:server_name_indication, ~c"wrong.r47.server"}
          ] do
        opts = F.options(m, ["rsa2048-a", "p256-a"], version) |> Keyword.put(key, value)
        {result, events} = F.exchange(m, opts, version: version)
        assert {:error, _} = result
        refute Enum.any?(events, &(&1["event"] in ["authenticated", "http", "client_cv"]))
      end
    end
  end

  test "TLS12 certificate types filter ranked EC inside candidate iteration", %{fixtures: m} do
    {result, events} =
      F.exchange(m, F.options(m, ["p256-a", "rsa2048-a"], "tls12"),
        version: "tls12",
        types: "rsa"
      )

    assert result == {:ok, F.response()}
    F.assert_authenticated(m, events, "rsa2048-a", 0x0804, "tls12")
  end

  test "TLS12 P384 uses SHA256 CV with EMS and exact authenticated HTTP", %{fixtures: m} do
    {result, events} =
      F.exchange(m, F.options(m, ["p256-a", "p384-a"], "tls12"),
        version: "tls12",
        schemes: "ecdsa_secp256r1_sha256:rsa_pkcs1_sha256"
      )

    assert result == {:ok, F.response()}
    F.assert_authenticated(m, events, "p384-a", 0x0403, "tls12")
  end

  for version <- ["tls12", "tls13"] do
    test "#{version} selected large identity crosses fragmented server flight with exact wire bytes",
         %{
           fixtures: m
         } do
      alias ExSSL.TestSupport.LocalTLSPeer
      assert byte_size(F.der(m, "large-a")) > 16_384

      {result, events} =
        F.with_peer(m, [hint: "client-a", version: unquote(version)], fn port ->
          {:ok, proxy} = LocalTLSPeer.start_fragmenting_proxy(port, self())

          try do
            assert {:ok, socket} =
                     SSL.connect(
                       {127, 0, 0, 1},
                       proxy.port,
                       F.options(m, ["p256-b", "large-a"], unquote(version)),
                       3_000
                     )

            try do
              assert :ok =
                       SSL.send(
                         socket,
                         "GET /r47 HTTP/1.1\r\nHost: r47.server\r\nConnection: close\r\n\r\n"
                       )

              SSL.recv(socket, byte_size(F.response()), 3_000)
            after
              SSL.close(socket)
            end
          after
            LocalTLSPeer.stop_fragmenting_proxy(proxy)
          end
        end)

      assert result == {:ok, F.response()}
      F.assert_authenticated(m, events, "large-a", 0x0804, unquote(version))
    end
  end

  test "multiple identities retain HRR transcript and exact selected chain", %{fixtures: m} do
    {result, events} =
      F.exchange(m, F.options(m, ["p256-b", "rsa2048-a"]), groups: "P-384", hint: "client-a")

    assert result == {:ok, F.response()}
    F.assert_authenticated(m, events, "rsa2048-a", 0x0804, "tls13")
    assert [_, _] = Enum.filter(events, &(&1["event"] == "client_hello_random"))
  end
end
