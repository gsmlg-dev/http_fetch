defmodule SSL.ServerCertsKeysTest do
  use ExUnit.Case, async: true

  alias SSL.ServerOptions

  @ecdsa_only [signature_algs: [:ecdsa_secp256r1_sha256]]
  @rsa_pss_only [signature_algs: [:rsa_pss_rsae_sha256]]

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssl)
    %{rsa: identity(~c"multi.test", {:rsa, 2048, 65_537}), ec: identity(~c"multi.test", :ec)}
  end

  test "an ECDSA-only client gets the ECDSA identity of an RSA+ECDSA server", ctx do
    listen = listen(certs_keys: [entry(ctx.rsa), entry(ctx.ec)])
    assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, ctx, ~c"multi.test", @ecdsa_only)
    assert peer == ctx.ec.cert
  end

  test "an RSA-PSS-only client gets the RSA identity of an ECDSA+RSA server", ctx do
    listen = listen(certs_keys: [entry(ctx.ec), entry(ctx.rsa)])
    assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, ctx, ~c"multi.test", @rsa_pss_only)
    assert peer == ctx.rsa.cert
  end

  test "a client accepting every identity gets the first certs_keys entry", ctx do
    for {entries, expected} <- [{[ctx.rsa, ctx.ec], ctx.rsa}, {[ctx.ec, ctx.rsa], ctx.ec}] do
      listen = listen(certs_keys: Enum.map(entries, &entry/1))
      assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, ctx, ~c"multi.test")
      assert peer == expected.cert
    end
  end

  test "sni_hosts and sni_fun entries select among their certs_keys", ctx do
    keys = [certs_keys: [entry(ctx.rsa), entry(ctx.ec)]]

    for options <- [
          [sni_hosts: [{~c"multi.test", keys}]],
          [sni_fun: fn _ -> keys end]
        ] do
      listen = listen(options)
      assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, ctx, ~c"multi.test", @ecdsa_only)
      assert peer == ctx.ec.cert
    end
  end

  test "every certs_keys entry is validated when options are built", ctx do
    assert {:ok, %{identity: rsa, identities: [rsa, ec]}} =
             ServerOptions.build(certs_keys: [entry(ctx.rsa), entry(ctx.ec)])

    assert rsa.chain == [ctx.rsa.cert]
    assert ec.chain == [ctx.ec.cert]

    for entries <- [
          [entry(ctx.rsa), :garbage],
          [entry(ctx.rsa), %{cert: ctx.ec.cert}],
          [entry(ctx.rsa), %{cert: ctx.ec.cert, key: ctx.rsa.key}],
          [entry(ctx.rsa), %{certfile: "/nonexistent.pem", keyfile: "/nonexistent.pem"}],
          []
        ] do
      assert {:error, _} = ServerOptions.build(certs_keys: entries)
      assert {:error, _} = SSL.listen(0, certs_keys: entries)
    end

    hosts = [{~c"multi.test", [certs_keys: [entry(ctx.rsa), :garbage]]}]
    assert ServerOptions.build(sni_hosts: hosts) == {:error, {:invalid_option, :sni_hosts}}
  end

  defp entry(identity), do: %{cert: identity.cert, key: identity.key}

  defp handshake(listen, ctx, sni, extra \\ []) do
    {:ok, {_, port}} = SSL.sockname(listen)

    client =
      Task.async(fn ->
        options =
          [
            mode: :binary,
            active: false,
            versions: [:"tlsv1.3"],
            verify: :verify_peer,
            cacerts: ctx.rsa.cacerts ++ ctx.ec.cacerts,
            server_name_indication: sni,
            signature_algs_cert: [:rsa_pkcs1_sha256, :ecdsa_secp256r1_sha256],
            log_level: :none
          ] ++ extra

        with {:ok, c} <- :ssl.connect({127, 0, 0, 1}, port, options, 5000) do
          peer = :ssl.peercert(c)
          :ssl.close(c)
          {:ok, peer}
        end
      end)

    {:ok, accepted} = SSL.transport_accept(listen, 5000)
    server = SSL.handshake(accepted, 5000)
    with {:ok, s} <- server, do: SSL.close(s)
    {Task.await(client), server}
  end

  defp listen(options) do
    {:ok, listen} = SSL.listen(0, [ip: {127, 0, 0, 1}] ++ options)
    on_exit(fn -> SSL.close(listen) end)
    listen
  end

  defp identity(name, :ec), do: identity(name, {:namedCurve, :secp256r1})

  defp identity(name, key) do
    root =
      :public_key.pkix_test_root_cert(~c"ca-" ++ name,
        key: :public_key.generate_key(key),
        digest: :sha256
      )

    data =
      :public_key.pkix_test_data(%{
        root: root,
        peer: [
          key: key,
          digest: :sha256,
          extensions: [{:Extension, {2, 5, 29, 17}, false, [{:dNSName, name}]}]
        ]
      })

    %{cert: data[:cert], key: data[:key], cacerts: data[:cacerts]}
  end
end
