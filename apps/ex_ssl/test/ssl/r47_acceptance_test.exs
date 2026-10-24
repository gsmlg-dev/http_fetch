defmodule SSL.R47AcceptanceTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F
  alias SSL.ClientIdentity
  alias SSL.ClientIdentity.{Candidates, Chain}
  alias SSL.Protocol.{ClientAuthentication, ServerFlight, Transcript}
  alias SSL.Protocol.ServerFlight.CertificateRequest

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-r47-acceptance-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  test "M04 equal-bitlength distinct RSA moduli are numerically ordered in both versions", %{
    fixtures: m
  } do
    entries = Enum.map(["rsa2048-a", "rsa2048-equal"], &F.identity(m, &1, :der))
    {:ok, set} = ClientIdentity.load(certs_keys: entries)
    [a, b] = set.identities
    {:RSAPublicKey, an, _} = a.public_key
    {:RSAPublicKey, bn, _} = b.public_key
    assert an != bn
    assert bit_size(:binary.encode_unsigned(an)) == 2048
    assert bit_size(:binary.encode_unsigned(bn)) == 2048
    expected = if an < bn, do: a.chain, else: b.chain

    for version <- [:tls12, :tls13], ordered <- [entries, Enum.reverse(entries)] do
      {:ok, candidates} = ClientIdentity.load(certs_keys: ordered)

      assert {:ok, {selected, 0x0804}} =
               ClientAuthentication.select(request(), candidates, version)

      assert selected.chain == expected
    end
  end

  test "M05 usage and certificate-signature exclusions preserve later eligible candidates", %{
    fixtures: m
  } do
    leaf = F.der(m, "p256-a")
    signing_key = key(m["roots"]["client-a"]["key"])
    denied = replace_extension(leaf, {2, 5, 29, 15}, [:keyEncipherment], signing_key)
    first = %{F.identity(m, "p256-a", :der) | cert: denied}
    later = F.identity(m, "rsa2048-b", :der)
    {:ok, set} = ClientIdentity.load(certs_keys: [first, later])
    ca = [F.name(F.root(m, "client-a"))]

    for version <- [:tls12, :tls13] do
      assert {:ok, {chosen, 0x0804}} = ClientAuthentication.select(request(ca), set, version)
      assert chosen.chain == [later.cert]
      {:ok, only_denied} = ClientIdentity.load(certs_keys: [first])
      assert {:ok, nil} = ClientAuthentication.select(request(ca), only_denied, version)

      {:ok, signatures} =
        ClientIdentity.load(
          certs_keys: Enum.map(["p256-a", "p256-ecissuer"], &F.identity(m, &1, :der))
        )

      policy = %{
        request()
        | extensions: [signature_algorithms: [0x0403], signature_algorithms_cert: [0x0403]]
      }

      assert {:ok, {selected, 0x0403}} = ClientAuthentication.select(policy, signatures, version)
      assert selected.chain == [F.der(m, "p256-ecissuer")]
      {:ok, first_only} = ClientIdentity.load(certs_keys: [F.identity(m, "p256-a", :der)])
      assert {:ok, nil} = ClientAuthentication.select(policy, first_only, version)

      {:ok, mixed} =
        ClientIdentity.load(
          certs_keys: Enum.map(["p256-a", "rsa2048-a"], &F.identity(m, &1, :der))
        )

      assert {:ok, {local, 0x0804}} =
               ClientAuthentication.select(request(), mixed, version, signature_schemes: [0x0804])

      assert local.chain == [F.der(m, "rsa2048-a")]
    end
  end

  test "M07 a real unsupported later Ed448 identity rejects before TCP dial", %{fixtures: m} do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_tcp.close(listener) end)
    {:ok, {_, port}} = :inet.sockname(listener)
    entry = F.identity(m, "ed448-a", :der)
    decoded = :public_key.pkix_decode_cert(entry.cert, :otp)

    assert {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, {1, 3, 101, 113}, _}, _} =
             elem(elem(decoded, 1), 7)

    assert {:error, {:options, _}} =
             SSL.connect({127, 0, 0, 1}, port, F.options(m, ["rsa2048-a", "ed448-a"]), 1_000)

    assert {:error, :timeout} = :gen_tcp.accept(listener, 10)
  end

  test "M19 QUIC rejects a nonempty valid multiple-identity set", %{fixtures: m} do
    entries = Enum.map(["rsa2048-a", "p256-a"], &F.identity(m, &1, :der))
    assert {:ok, %Candidates{count: 2}} = ClientIdentity.load(certs_keys: entries)

    options = [
      cacerts: [F.root(m, "server-root")],
      reference_identity: {:dns_id, "r47.server"},
      alpn: ["test"],
      transport_parameters: <<1, 0>>
    ]

    assert {:ok, _, [{:emit, :initial, <<1, _::binary>>}]} = SSL.QUIC.new(:client, options)

    assert {:error, %SSL.QUIC.Error{kind: :configuration, reason: :invalid_configuration}} =
             SSL.QUIC.new(:client, Keyword.put(options, :certs_keys, entries))
  end

  test "M03 65536 visits succeed and the next visit fails on a valid branching issuer graph", %{
    fixtures: m
  } do
    {leaf, pool, extra} = visit_graph(m)
    assert length(pool) == 4096
    snapshot = Chain.snapshot(pool)
    assert {:ok, [^leaf, issuer], 0} = Chain.complete([leaf], snapshot, 65_536)
    assert issuer == hd(pool)

    assert {:error, :client_identity_chain_search_limit} =
             Chain.complete([leaf], Chain.snapshot([extra | Enum.take(pool, 4095)]), 65_536)

    assert {:error, :client_identity_chain_search_limit} =
             Chain.complete([leaf], snapshot, 65_535)
  end

  test "M03 sixteen real candidates execute the aggregate 1048576-visit maximum", %{fixtures: m} do
    {leaf, pool, _} = visit_graph(m)
    # Preserve all 15 branches and 4096 entries. The repeated first issuer is already
    # visited in every scan, so these visits exercise budget charging without repeated
    # certificate decoding. The separate per-identity test retains unrelated issuers.
    pool = Enum.take(pool, 15) ++ List.duplicate(hd(pool), 4081)
    assert length(pool) == 4096
    entry = %{F.identity(m, "chain-a", :der) | cert: leaf}
    {:ok, set} = ClientIdentity.load(certs_keys: List.duplicate(entry, 16))
    unmatched = request([F.name(F.root(m, "client-c"))])
    # Count actual private search invocations, including each exhausted-list terminal.
    # 16 candidates * 16 scanned nodes * (4096 visits + 1 terminal) = 1048832 calls.
    assert {:module, Chain} = Code.ensure_loaded(Chain)
    assert 1 = :erlang.trace_pattern({Chain, :issuers, 6}, true, [:local, :call_count])

    try do
      assert {:call_count, 0} = :erlang.trace_info({Chain, :issuers, 6}, :call_count)
      assert {:ok, nil} = ClientAuthentication.select(unmatched, set, :tls13, trust_source: pool)
      assert {:call_count, 1_048_832} = :erlang.trace_info({Chain, :issuers, 6}, :call_count)
    after
      :erlang.trace_pattern({Chain, :issuers, 6}, false, [:local, :call_count])
    end

    assert {:error, {:options, :identity_count_limit}} =
             ClientIdentity.load(certs_keys: List.duplicate(entry, 17))
  end

  test "M03 emitted certificate bytes, total bytes and count have exact valid boundaries", %{
    fixtures: m
  } do
    [leaf, issuer] = linear_chain(m, 2)
    signing_key = key(m["roots"]["client-a"]["key"])
    per_cert = pad_certificate(leaf, signing_key, 262_144)
    assert_emitted(m, [per_cert, issuer])
    assert_rejected(m, [pad_certificate(leaf, signing_key, 262_145), issuer])
    total = [per_cert, pad_certificate(issuer, signing_key, 262_144)]
    assert Enum.sum(Enum.map(total, &byte_size/1)) == 524_288
    assert_emitted(m, total)
    [a, b, c] = linear_chain(m, 3)
    a = pad_certificate(a, signing_key, 200_000)
    b = pad_certificate(b, signing_key, 200_000)
    assert_rejected(m, [a, b, pad_certificate(c, signing_key, 124_289)])
    assert_emitted(m, linear_chain(m, 16))
    assert_rejected(m, linear_chain(m, 17))
  end

  defp assert_emitted(m, chain) do
    entry = %{F.identity(m, "rsa2048-a", :der) | cert: chain}
    assert {:ok, set} = ClientIdentity.load(certs_keys: [entry])

    assert {:ok, _, [certificate, <<15, _::binary>>]} =
             ClientAuthentication.messages(request(), set, Transcript.new(:sha256))

    assert {:ok, %ServerFlight.Certificate{entries: entries}, <<>>} =
             ServerFlight.decode(certificate)

    assert Enum.map(entries, & &1.der) == chain
  end

  defp assert_rejected(m, chain) do
    entry = %{F.identity(m, "rsa2048-a", :der) | cert: chain}

    assert {:error, {:options, :invalid_certificate_chain}} =
             ClientIdentity.load(certs_keys: [entry])
  end

  defp visit_graph(m) do
    template = Base.decode64!(m["intermediates"]["a"]["der_b64"])
    signing_key = key(m["roots"]["client-a"]["key"])

    variants =
      for serial <- 10_001..10_016, do: resign(template, signing_key, &put_elem(&1, 2, serial))

    {first, [extra]} = Enum.split(variants, 15)
    # Duplicated unrelated trust DERs are valid normalized trust entries. Global visited
    # tracking must not turn repeated non-issuers into a hidden budget exemption.
    pool = first ++ List.duplicate(F.root(m, "client-b"), 4081)
    {F.der(m, "chain-a"), pool, extra}
  end

  defp linear_chain(m, count) do
    signing_key = key(m["roots"]["client-a"]["key"])

    for i <- 0..(count - 1) do
      template = if i == 0, do: F.der(m, "rsa2048-a"), else: F.root(m, "client-a")

      resign(template, signing_key, fn tbs ->
        extensions = Enum.reject(elem(tbs, 10), &match?({:Extension, {2, 5, 29, 35}, _, _}, &1))

        tbs
        |> put_elem(2, 20_000 + i)
        |> put_elem(4, name(min(i + 1, count - 1)))
        |> put_elem(6, name(i))
        |> put_elem(10, extensions)
      end)
    end
  end

  defp name(i),
    do:
      {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, "R47 bound #{i}"}}]]}

  defp pad_certificate(der, signing_key, target) do
    padded =
      replace_extension(
        der,
        {1, 3, 6, 1, 4, 1, 55_555, 47},
        :binary.copy(<<0>>, target - byte_size(der)),
        signing_key
      )

    padding = target - byte_size(der) + target - byte_size(padded)

    exact =
      replace_extension(
        der,
        {1, 3, 6, 1, 4, 1, 55_555, 47},
        :binary.copy(<<0>>, padding),
        signing_key
      )

    assert byte_size(exact) == target
    exact
  end

  defp replace_extension(der, oid, value, signing_key) do
    resign(der, signing_key, fn tbs ->
      entries = Enum.reject(elem(tbs, 10), fn {:Extension, id, _, _} -> id == oid end)
      put_elem(tbs, 10, entries ++ [{:Extension, oid, false, value}])
    end)
  end

  defp resign(der, signing_key, update),
    do:
      der
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> update.()
      |> :public_key.pkix_sign(signing_key)

  defp key(path),
    do: path |> File.read!() |> :public_key.pem_decode() |> hd() |> :public_key.pem_entry_decode()

  defp request(authorities \\ []),
    do: %CertificateRequest{
      encoded: <<>>,
      request_context: <<>>,
      extensions: [
        signature_algorithms: [0x0804, 0x0403],
        signature_algorithms_cert: [0x0401, 0x0403],
        certificate_authorities: authorities
      ]
    }
end
