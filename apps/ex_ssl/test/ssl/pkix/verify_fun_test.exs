defmodule SSL.PKIX.VerifyFunTest do
  use ExUnit.Case, async: true

  alias SSL.PKIX
  alias SSL.PKIX.VerifiedPeer

  @identity {:dns_id, "r44.example.test"}
  @san {:extension, {2, 5, 29, 17}, false}
  @unknown_oid {1, 3, 6, 1, 4, 1, 55_555, 44}

  setup_all do
    [root_key, other_key, issuer_key, leaf_key] =
      for _ <- 1..4, do: :public_key.generate_key({:rsa, 2048, 65_537})

    root = :public_key.pkix_test_root_cert(~c"R44 root", key: root_key, digest: :sha256)
    other = :public_key.pkix_test_root_cert(~c"R44 other", key: other_key, digest: :sha256)
    base = chain(root, issuer_key, leaf_key, [])
    alternative = chain(other, issuer_key, leaf_key, [])
    [issuer_a] = intermediate(base, root.cert)
    [issuer_b] = intermediate(alternative, other.cert)
    leaf = Keyword.fetch!(base, :cert)

    selfsigned =
      :public_key.pkix_test_root_cert(~c"R44 selfsigned",
        key: leaf_key,
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}}
          | extensions()
        ]
      )

    {:ok,
     root: root.cert,
     other: other.cert,
     leaf: leaf,
     root_key: root_key,
     issuer_key: issuer_key,
     issuer_a: issuer_a,
     issuer_b: issuer_b,
     selfsigned: selfsigned.cert,
     variants:
       for {name, extra} <- [
             critical: [{:Extension, @unknown_oid, true, <<5, 0>>}],
             noncritical: [{:Extension, @unknown_oid, false, <<5, 0>>}],
             server_eku: [eku({1, 3, 6, 1, 5, 5, 7, 3, 1})],
             client_eku: [eku({1, 3, 6, 1, 5, 5, 7, 3, 2})]
           ],
           into: %{} do
         config = chain(root, issuer_key, leaf_key, extra)
         {name, [Keyword.fetch!(config, :cert) | intermediate(config, root.cert)]}
       end}
  end

  test "tuple3 and native-DER tuple4 see actual ordered path events", f do
    for form <- [:tuple3, :tuple4] do
      {callback, events} = recording(:accept, form)

      assert {:ok, %VerifiedPeer{leaf_der: leaf}} =
               PKIX.verify([f.leaf, f.issuer_a], [f.root], @identity, verify_fun: callback)

      assert leaf == f.leaf
      assert [{issuer, :valid, 0}, {^leaf, @san, 1}, {^leaf, :valid_peer, 2}] = events.()
      assert issuer == f.issuer_a
    end
  end

  test "cross-sign sibling paths reset initial state in both supplied orders", f do
    for [first, second] <- [[f.issuer_a, f.issuer_b], [f.issuer_b, f.issuer_a]] do
      ref = make_ref()

      {callback, events} =
        recording(fn event, state ->
          if event == :valid_peer and not Process.get(ref, false) do
            Process.put(ref, true)
            {:fail, :first_path_private_reason}
          else
            answer(:accept, event, state)
          end
        end)

      assert {:ok, %VerifiedPeer{}} =
               PKIX.verify([f.leaf, first, second], [f.root, f.other], @identity,
                 verify_fun: callback
               )

      leaf = f.leaf

      assert [
               {^second, :valid, 0},
               {^leaf, @san, 1},
               {^leaf, :valid_peer, 2},
               {^first, :valid, 0},
               {^leaf, @san, 1},
               {^leaf, :valid_peer, 2}
             ] = events.()
    end
  end

  test "unknown CA acceptance uses the supplied top and does not invent leaf success", f do
    {callback, events} = recording(:accept)

    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([f.leaf, f.issuer_a, f.root], [], @identity, verify_fun: callback)

    root = f.root
    issuer = f.issuer_a
    leaf = f.leaf

    assert [
             {^root, {:bad_cert, :unknown_ca}, 0},
             {^issuer, :valid, 1},
             {^leaf, @san, 2},
             {^leaf, :valid_peer, 3}
           ] = events.()

    {callback, events} = recording(:accept)
    assert {:ok, %VerifiedPeer{}} = PKIX.verify([leaf], [], @identity, verify_fun: callback)
    assert [{^leaf, {:bad_cert, :unknown_ca}, 0}] = events.()
  end

  test "selfsigned peer remains an error event even if explicitly trusted", f do
    for trust <- [[], [f.selfsigned]], policy <- [:accept, :reject_errors] do
      {callback, events} = recording(policy)
      result = PKIX.verify([f.selfsigned], trust, @identity, verify_fun: callback)

      if policy == :accept,
        do: assert(match?({:ok, %VerifiedPeer{}}, result)),
        else: assert(result == {:error, {:path_validation_failed, {:verify_fun, :rejected}}})

      leaf = f.selfsigned
      assert [{^leaf, {:bad_cert, :selfsigned_peer}, 0}] = events.()
    end
  end

  test "hostname failure replaces valid_peer and accepting it does not add another event", f do
    {callback, events} = recording(:accept)

    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([f.leaf, f.issuer_a], [f.root], {:dns_id, "wrong.example.test"},
               verify_fun: callback
             )

    issuer = f.issuer_a
    leaf = f.leaf

    assert [
             {^issuer, :valid, 0},
             {^leaf, @san, 1},
             {^leaf, {:bad_cert, :hostname_check_failed}, 2}
           ] = events.()
  end

  test "critical and noncritical unknown extensions keep native PKIX return semantics", f do
    for {name, critical} <- [critical: true, noncritical: false] do
      [leaf, issuer] = f.variants[name]
      {callback, events} = recording(:reject_errors)
      result = PKIX.verify([leaf, issuer], [f.root], @identity, verify_fun: callback)

      if critical,
        do:
          assert(
            result ==
              {:error, {:path_validation_failed, {:bad_cert, :unknown_critical_extension}}}
          ),
        else: assert(match?({:ok, %VerifiedPeer{}}, result))

      expected = [
        {issuer, :valid, 0},
        {leaf, @san, 1},
        {leaf, {:extension, @unknown_oid, critical}, 2}
      ]

      assert events.() == if(critical, do: expected, else: expected ++ [{leaf, :valid_peer, 3}])

      {callback, _} = recording(:accept)

      assert {:ok, %VerifiedPeer{}} =
               PKIX.verify([leaf, issuer], [f.root], @identity, verify_fun: callback)
    end
  end

  test "recognized server EKU is consumed and incompatible EKU reaches the policy", f do
    [leaf, issuer] = f.variants.server_eku
    {callback, events} = recording(:reject_errors)

    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([leaf, issuer], [f.root], @identity, verify_fun: callback)

    assert [{^issuer, :valid, 0}, {^leaf, @san, 1}, {^leaf, :valid_peer, 2}] = events.()

    [leaf, issuer] = f.variants.client_eku
    {callback, events} = recording(:accept)

    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([leaf, issuer], [f.root], @identity, verify_fun: callback)

    assert [
             {^issuer, :valid, 0},
             {^leaf, @san, 1},
             {^leaf, {:bad_cert, :ca_invalid_ext_keyusage}, 2},
             {^leaf, :valid_peer, 3}
           ] = events.()
  end

  test "verify_none custom policy validates trusted and empty CA paths before rejecting peer",
       f do
    for {trust, chain, expected_state} <- [
          {[f.root], [f.leaf, f.issuer_a], 2},
          {[], [f.leaf, f.issuer_a, f.root], 3}
        ] do
      {callback, events} =
        recording(fn
          :valid_peer, _ -> {:fail, :private_rejection}
          event, state -> answer(:accept, event, state)
        end)

      assert {:error, {:path_validation_failed, {:bad_cert, {:verify_fun, :rejected}}}} =
               PKIX.peer(chain, trust, @identity, :verify_none, verify_fun: callback)

      assert {f.leaf, :valid_peer, expected_state} == List.last(events.())
    end
  end

  test "callback failure payloads, malformed terms and exceptions never leave fixed classes", f do
    marker = "R44_PRIVATE_CALLBACK_MARKER"

    for {policy, expected} <- [
          {fn _, _ -> {:fail, %{secret: marker}} end, :rejected},
          {fn _, _ -> {:secret, marker} end, :invalid_return},
          {fn _, _ -> raise marker end, :exception},
          {fn _, _ -> throw(marker) end, :exception},
          {fn _, _ -> exit(marker) end, :exception},
          {fn _, state -> {:unknown, {state, marker}} end, :invalid_return}
        ] do
      {callback, _} = recording(policy)
      result = PKIX.verify([f.leaf, f.issuer_a], [f.root], @identity, verify_fun: callback)
      assert result == {:error, {:path_validation_failed, {:bad_cert, {:verify_fun, expected}}}}
      refute inspect(result) =~ marker
    end
  end

  test "legacy callback receives only errors and undefined preserves default validation", f do
    ref = make_ref()

    callback = fn errors ->
      Process.put(ref, errors)
      true
    end

    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([f.leaf, f.issuer_a], [f.root], @identity, verify_fun: callback)

    assert Process.get(ref) == nil
    assert {:ok, %VerifiedPeer{}} = PKIX.verify([f.leaf], [], @identity, verify_fun: callback)
    assert Process.get(ref) == [{:bad_cert, :unknown_ca}]

    assert PKIX.verify([f.leaf, f.issuer_a], [f.root], @identity, verify_fun: :undefined) ==
             PKIX.verify([f.leaf, f.issuer_a], [f.root], @identity)
  end

  test "malformed DER and admitted-count bounds reject before callbacks", f do
    {callback, events} = recording(:accept)

    assert {:error, {:invalid_certificate, 0}} =
             PKIX.verify([<<1, 2, 3>>], [], @identity, verify_fun: callback)

    assert {:error, {:certificate_count_limit_exceeded, 2, 1}} =
             PKIX.verify([f.leaf, f.issuer_a], [], @identity,
               verify_fun: callback,
               max_certificates: 1
             )

    assert events.() == []
  end

  test "TLS12 verify_none returns invalid-options errors for malformed option containers", f do
    inputs = [nil, :invalid, %{}, [1], [{:depth, 1}, :invalid]]

    results =
      Enum.map(inputs, fn options ->
        try do
          PKIX.peer([f.leaf], [f.root], @identity, :verify_none, options, :tls12)
        catch
          kind, reason -> {:unexpected_exception, kind, reason}
        end
      end)

    assert results == Enum.map(inputs, fn _ -> {:error, {:invalid_input, :options}} end)
  end

  test "leaf-only unknownCA callback cannot exempt the leaf from signature policy", f do
    {callback, events} = recording(:accept)

    assert {:error, {:certificate_signature_scheme_not_allowed, [0x0403]}} =
             PKIX.verify([f.leaf], [], @identity,
               verify_fun: callback,
               certificate_signature_schemes: [0x0403]
             )

    leaf = f.leaf
    assert [{^leaf, {:bad_cert, :unknown_ca}, 0}] = events.()
  end

  test "accepting callback cannot bypass TLS13 version checks on any presented certificate", f do
    legacy_leaf =
      resign(f.leaf, f.issuer_key, &(&1 |> put_elem(1, :v1) |> put_elem(10, :asn1_NOVALUE)))

    legacy_issuer =
      resign(f.issuer_a, f.root_key, &(&1 |> put_elem(1, :v1) |> put_elem(10, :asn1_NOVALUE)))

    for mode <- [:verify_peer, :verify_none] do
      {callback, _} = recording(:accept)

      assert {:ok, %VerifiedPeer{}} =
               PKIX.peer([f.leaf, f.issuer_a], [f.root], @identity, mode, verify_fun: callback)

      for {chain, index} <- [{[legacy_leaf, f.issuer_a], 0}, {[f.leaf, legacy_issuer], 1}] do
        {callback, events} = recording(:accept)

        assert {:error, {:invalid_peer_certificate_version, ^index}} =
                 PKIX.peer(chain, [f.root], @identity, mode, [verify_fun: callback], :tls13)

        assert events.() == []

        assert {:ok, %VerifiedPeer{}} =
                 PKIX.peer(chain, [f.root], @identity, mode, [verify_fun: callback], :tls12)
      end
    end
  end

  test "accepting callback cannot bypass leaf digitalSignature key usage", f do
    for usage <- [:absent, [:digitalSignature], [:keyEncipherment]] do
      leaf =
        resign(f.leaf, f.issuer_key, fn tbs ->
          extensions = Enum.reject(elem(tbs, 10), &(elem(&1, 1) == {2, 5, 29, 15}))

          extensions =
            if usage == :absent,
              do: extensions,
              else: [{:Extension, {2, 5, 29, 15}, true, usage} | extensions]

          put_elem(tbs, 10, extensions)
        end)

      for mode <- [:verify_peer, :verify_none], protocol <- [:tls12, :tls13] do
        {callback, events} = recording(:accept)

        result =
          PKIX.peer(
            [leaf, f.issuer_a],
            [f.root],
            @identity,
            mode,
            [verify_fun: callback],
            protocol
          )

        if usage == [:keyEncipherment],
          do: assert(result == {:error, :invalid_peer_key_usage}),
          else: assert(match?({:ok, %VerifiedPeer{}}, result))

        assert Enum.any?(events.(), fn {_, event, _} -> event == :valid_peer end)
      end
    end
  end

  defp resign(der, key, change) do
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :otp)
    :public_key.pkix_sign(change.(tbs), key)
  end

  defp recording(policy, form \\ :tuple3) do
    ref = make_ref()

    record = fn certificate, der, event, state ->
      encoded = :public_key.pkix_encode(:OTPCertificate, certificate, :otp)
      if der, do: assert(der == encoded)
      Process.put(ref, [{encoded, event_label(event), state} | Process.get(ref, [])])
      if is_function(policy, 2), do: policy.(event, state), else: answer(policy, event, state)
    end

    callback =
      case form do
        :tuple3 -> fn cert, event, state -> record.(cert, nil, event, state) end
        :tuple4 -> record
      end

    {{callback, 0}, fn -> Process.get(ref, []) |> Enum.reverse() end}
  end

  defp answer(:accept, _, state), do: {:valid, state + 1}
  defp answer(:reject_errors, {:bad_cert, _}, _), do: {:fail, :private_reason}
  defp answer(:reject_errors, {:extension, _}, state), do: {:unknown, state + 1}
  defp answer(:reject_errors, _, state), do: {:valid, state + 1}
  defp event_label({:extension, {:Extension, oid, critical, _}}), do: {:extension, oid, critical}
  defp event_label({:bad_cert, {reason, _}}), do: {:bad_cert, reason}
  defp event_label(event), do: event

  defp chain(root, issuer_key, leaf_key, extra) do
    :public_key.pkix_test_data(%{
      root: root,
      intermediates: [[key: issuer_key, digest: :sha256]],
      peer: [key: leaf_key, digest: :sha256, extensions: extensions() ++ extra]
    })
  end

  defp intermediate(config, root),
    do: Keyword.fetch!(config, :cacerts) |> Enum.reject(&(&1 == root)) |> Enum.uniq()

  defp extensions do
    [
      {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]},
      {:Extension, {2, 5, 29, 17}, false, [{:dNSName, ~c"r44.example.test"}]}
    ]
  end

  defp eku(purpose), do: {:Extension, {2, 5, 29, 37}, false, [purpose]}
end
