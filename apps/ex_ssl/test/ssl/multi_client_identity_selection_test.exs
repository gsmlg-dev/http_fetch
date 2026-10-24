defmodule SSL.MultiClientIdentitySelectionTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F
  alias SSL.ClientIdentity.{Candidates, Chain}
  alias SSL.Protocol.ClientAuthentication, as: Auth
  alias SSL.Protocol.ServerFlight.CertificateRequest

  @schemes [0x0804, 0x0805, 0x0809, 0x080A, 0x0403, 0x0503, 0x0807, 0x0401, 0x0501]

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "exssl-multi-select-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  test "observed family, curve and numeric-modulus priorities ignore input/peer family order", %{
    fixtures: m
  } do
    for version <- [:tls13, :tls12], reversed <- [false, true] do
      for {names, expected} <- [
            {["rsa2048-a", "pss256-a", "p256-a"], "p256-a"},
            {["rsa2048-a", "pss256-a"], "pss256-a"},
            {["p256-a", "p384-a"], "p384-a"},
            {["rsa3072-a", "rsa2048-a"], "rsa2048-a"},
            {["pss256-strong", "pss256-a"], "pss256-a"}
          ] do
        names = if reversed, do: Enum.reverse(names), else: names
        assert {:ok, {identity, _}} = Auth.select(request(), load(m, names), version)
        assert hd(identity.chain) == F.der(m, expected)
      end
    end

    assert {:ok, {identity, 0x0807}} = Auth.select(request(), load(m, ["p256-a", "ed25519-a"]))
    assert identity.chain == [F.der(m, "ed25519-a")]
  end

  test "exact-key ties retain caller order and PSS restrictions remain bound to their own cert",
       %{fixtures: m} do
    for version <- [:tls13, :tls12],
        names <- [
          ["rsa2048-a", "rsa2048-same-key"],
          ["rsa2048-same-key", "rsa2048-a"],
          ["pss256-a", "pss256-equal"],
          ["pss256-equal", "pss256-a"]
        ] do
      assert {:ok, {identity, _}} = Auth.select(request(), load(m, names), version)
      assert hd(identity.chain) == F.der(m, hd(names))
    end

    for version <- [:tls13, :tls12],
        reverse <- [false, true],
        {scheme, expected} <- [{0x0809, "pss256-a"}, {0x080A, "pss384-a"}] do
      names = if reverse, do: ["pss384-a", "pss256-a"], else: ["pss256-a", "pss384-a"]

      assert {:ok, {identity, ^scheme}} =
               Auth.select(request([scheme, 0x0401]), load(m, names), version)

      assert identity.chain == [F.der(m, expected)]
    end
  end

  test "local empty offer, TLS12 types and TLS13 curve binding filter inside the loop", %{
    fixtures: m
  } do
    set = load(m, ["p256-a", "rsa2048-a"])
    assert {:ok, nil} = Auth.select(request(), set, :tls13, signature_schemes: [])
    assert {:ok, {rsa, 0x0804}} = Auth.select(request(), set, :tls12, certificate_types: [1])
    assert rsa.chain == [F.der(m, "rsa2048-a")]
    assert {:ok, nil} = Auth.select(request(), set, :tls12, certificate_types: [])
    assert {:ok, {ec, 0x0403}} = Auth.select(request(), set, :tls12, certificate_types: [64])
    assert ec.chain == [F.der(m, "p256-a")]
    curves = load(m, ["p384-a", "p256-a"])

    for {version, name} <- [{:tls13, "p256-a"}, {:tls12, "p384-a"}] do
      assert {:ok, {chosen, 0x0403}} = Auth.select(request([0x0403, 0x0401]), curves, version)
      assert chosen.chain == [F.der(m, name)]
    end
  end

  test "later actual CA match wins over ranked leaf/full fallback; no-match policies differ", %{
    fixtures: m
  } do
    hint_a = F.name(F.root(m, "client-a"))
    hint_c = F.name(F.root(m, "client-c"))
    leafs = load(m, ["p256-b", "rsa2048-a"])
    full = load_entries([F.identity(m, "chain-a", :full), F.identity(m, "chain-b", :full)])

    for version <- [:tls13, :tls12] do
      assert {:ok, {chosen, _}} = Auth.select(request(@schemes, [hint_a]), leafs, version)
      assert chosen.chain == [F.der(m, "rsa2048-a")]
      assert {:ok, {chosen, _}} = Auth.select(request(@schemes, [hint_a]), full, version)
      assert hd(chosen.chain) == F.der(m, "chain-a")
    end

    assert {:ok, nil} = Auth.select(request(@schemes, [hint_c]), full, :tls13)
    assert {:ok, {fallback, _}} = Auth.select(request(@schemes, [hint_c]), full, :tls12)
    assert fallback == hd(Candidates.ordered(full, :tls12))
  end

  test "only leaf chains reconstruct from bounded original PEM/DER trust, never other identities",
       %{fixtures: m} do
    leaf = load(m, ["chain-a"])
    interm = Base.decode64!(m["intermediates"]["a"]["der_b64"])
    root = F.root(m, "client-a")
    hint = F.name(F.root(m, "client-c"))
    matching = F.name(root)
    pool = [interm, root]

    pem =
      File.read!(m["intermediates"]["a"]["cert"]) <> File.read!(m["roots"]["client-a"]["cert"])

    for source <- [pool, pem], version <- [:tls13, :tls12] do
      assert {:ok, {identity, _}} =
               Auth.select(request(@schemes, [matching]), leaf, version, trust_source: source)

      assert identity.chain == [F.der(m, "chain-a"), interm, root]
    end

    assert {:ok, nil} = Auth.select(request(@schemes, [hint]), leaf, :tls13, trust_source: pool)
    assert {:ok, {identity, _}} = Auth.select(request(@schemes, [hint]), leaf, :tls13)
    assert identity.chain == [F.der(m, "chain-a")]

    assert {:error, :client_identity_chain_search_limit} =
             Chain.complete(identity.chain, Chain.snapshot(pool), 0)

    # A second configured chain cannot supply its root/intermediate as trust.
    set = load_entries([F.identity(m, "chain-a"), F.identity(m, "chain-b", :full)])
    assert {:ok, {identity, _}} = Auth.select(request(@schemes, [matching]), set)
    assert identity.chain == [F.der(m, "chain-a")]
  end

  defp load(m, names), do: load_entries(Enum.map(names, &F.identity(m, &1)))

  defp load_entries(entries) do
    {:ok, set} = SSL.ClientIdentity.load(certs_keys: entries)
    set
  end

  defp request(schemes \\ @schemes, authorities \\ []),
    do: %CertificateRequest{
      encoded: <<>>,
      request_context: <<>>,
      extensions: [
        signature_algorithms: schemes,
        signature_algorithms_cert: @schemes,
        certificate_authorities: authorities
      ]
    }
end
