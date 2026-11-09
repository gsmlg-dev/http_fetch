defmodule SSL.ServerSNITest do
  use ExUnit.Case, async: true

  alias SSL.ServerOptions

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssl)
    %{a: identity(~c"a.test"), b: identity(~c"b.test")}
  end

  test "sni_hosts selects the identity for the requested name", %{a: a, b: b} do
    listen =
      listen(cert: b.cert, key: b.key, sni_hosts: [{~c"a.test", [cert: a.cert, key: a.key]}])

    assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, a, ~c"a.test")
    assert peer == a.cert
  end

  test "an unknown name falls back to the default identity", %{a: a, b: b} do
    listen =
      listen(cert: b.cert, key: b.key, sni_hosts: [{~c"a.test", [cert: a.cert, key: a.key]}])

    assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, b, ~c"b.test")
    assert peer == b.cert
  end

  test "the identity selected for the first ClientHello survives a HelloRetryRequest",
       %{a: a, b: b} do
    test = self()

    fun = fn name ->
      send(test, {:sni_fun, name})
      if name == ~c"a.test", do: [cert: a.cert, key: a.key], else: :undefined
    end

    listen = listen(cert: b.cert, key: b.key, sni_fun: fun)
    retry = [supported_groups: [:secp256r1, :x25519]]
    assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, a, ~c"a.test", retry)
    assert peer == a.cert
    assert_received {:sni_fun, ~c"a.test"}
    refute_received {:sni_fun, _}
  end

  test "sni_fun selects an identity per handshake", %{a: a} do
    fun = fn
      ~c"a.test" -> [cert: a.cert, key: a.key]
      _ -> :undefined
    end

    listen = listen(sni_fun: fun)
    assert {{:ok, {:ok, peer}}, {:ok, _}} = handshake(listen, a, ~c"a.test")
    assert peer == a.cert
  end

  test "sni_fun returning :undefined without a default identity is unrecognized_name",
       %{a: a} do
    listen = listen(sni_fun: fn _ -> :undefined end)

    assert {{:error, {:tls_alert, {:unrecognized_name, _}}},
            {:error, {:tls_alert, {:unrecognized_name, _}}}} = handshake(listen, a, ~c"c.test")
  end

  test "a client without SNI and no default identity is unrecognized_name", %{a: a} do
    listen = listen(sni_hosts: [{~c"a.test", [cert: a.cert, key: a.key]}])

    assert {{:error, {:tls_alert, {:unrecognized_name, _}}},
            {:error, {:tls_alert, {:unrecognized_name, _}}}} = handshake(listen, a, :disable)
  end

  for {label, fun} <- [
        raise: quote(do: fn _ -> raise "boom" end),
        throw: quote(do: fn _ -> throw(:boom) end),
        exit: quote(do: fn _ -> exit(:boom) end),
        bad_return: quote(do: fn _ -> :not_options end),
        bad_options: quote(do: fn _ -> [verify: :verify_peer] end),
        empty_options: quote(do: fn _ -> [] end)
      ] do
    test "sni_fun #{label} fails the handshake with internal_error", %{a: a} do
      listen = listen(sni_fun: unquote(fun))

      assert {{:error, {:tls_alert, {:internal_error, _}}},
              {:error, {:tls_alert, {:internal_error, _}}}} = handshake(listen, a, ~c"a.test")
    end
  end

  test "sni_hosts identities are loaded and validated when options are built", %{a: a} do
    assert {:ok, %{sni: {:hosts, %{~c"a.test" => %SSL.ClientIdentity{chain: [cert | _]}}}}} =
             ServerOptions.build(sni_hosts: [{~c"a.test", [cert: a.cert, key: a.key]}])

    assert cert == a.cert

    for hosts <- [
          [{~c"a.test", [cert: a.cert, key: a.key]}, {~c"a.test", [cert: a.cert, key: a.key]}],
          [{~c"a.test", []}],
          [{~c"a.test", [cert: a.cert]}],
          [{~c"a.test", [certfile: "/nonexistent.pem", keyfile: "/nonexistent.pem"]}],
          [{~c"a.test", [cert: a.cert, key: a.key, verify: :verify_peer]}]
        ] do
      assert ServerOptions.build(sni_hosts: hosts) == {:error, {:invalid_option, :sni_hosts}}
    end

    assert SSL.listen(0, sni_hosts: [{~c"a.test", [cert: a.cert]}]) ==
             {:error, {:invalid_option, :sni_hosts}}
  end

  # Runs one server handshake against an OTP client; returns {client, server} results.
  defp handshake(listen, identity, sni, extra \\ []) do
    {:ok, {_, port}} = SSL.sockname(listen)

    client =
      Task.async(fn ->
        result =
          :ssl.connect(
            {127, 0, 0, 1},
            port,
            [
              mode: :binary,
              active: false,
              versions: [:"tlsv1.3"],
              verify: :verify_peer,
              cacerts: identity.cacerts,
              server_name_indication: sni,
              log_level: :none
            ] ++ extra,
            5000
          )

        case result do
          {:ok, c} ->
            peer = :ssl.peercert(c)
            :ssl.close(c)
            {:ok, peer}

          error ->
            error
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

  defp identity(name) do
    root =
      :public_key.pkix_test_root_cert(~c"ca-" ++ name,
        key: :public_key.generate_key({:namedCurve, :secp256r1}),
        digest: :sha256
      )

    data =
      :public_key.pkix_test_data(%{
        root: root,
        peer: [
          key: {:namedCurve, :secp256r1},
          digest: :sha256,
          extensions: [{:Extension, {2, 5, 29, 17}, false, [{:dNSName, name}]}]
        ]
      })

    %{cert: data[:cert], key: data[:key], cacerts: data[:cacerts]}
  end
end
