defmodule SSL.PKIXTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.PKIX
  alias SSL.PKIX.Certificate
  alias SSL.PKIX.VerifiedPeer

  @fixture_dir Path.expand("../../fixtures/pkix", __DIR__)
  @leaf_pem File.read!(Path.join(@fixture_dir, "leaf.pem"))
  @root_pem File.read!(Path.join(@fixture_dir, "root.pem"))
  @wrong_root_pem File.read!(Path.join(@fixture_dir, "wrong_root.pem"))
  @leaf_der @leaf_pem |> :public_key.pem_decode() |> hd() |> elem(1)
  @root_der @root_pem |> :public_key.pem_decode() |> hd() |> elem(1)
  @wrong_root_der @wrong_root_pem |> :public_key.pem_decode() |> hd() |> elem(1)
  @identity_fixture_dir Path.expand("../../fixtures/pkix_identity", __DIR__)
  @identity_root_pem File.read!(Path.join(@identity_fixture_dir, "root.pem"))
  @invalid_sans_root_pem File.read!(Path.join(@identity_fixture_dir, "invalid_sans_root.pem"))

  test "decodes an ordered leaf-first DER chain without discarding exact bytes" do
    assert {:ok, [%Certificate{der: @leaf_der}, %Certificate{der: @root_der}]} =
             PKIX.decode_chain([@leaf_der, @root_der])
  end

  test "normalizes DER lists and PEM bundles into trust anchors" do
    assert {:ok, [%Certificate{der: @root_der}]} = PKIX.normalize_trust([@root_der])
    assert {:ok, [%Certificate{der: @root_der}]} = PKIX.normalize_trust(@root_pem)
  end

  test "normalizes the tagged entries returned by public_key.cacerts_get/0" do
    cacerts = :public_key.cacerts_get()
    assert cacerts != []
    assert {:ok, certificates} = PKIX.normalize_trust(cacerts)
    assert length(certificates) == length(cacerts)
    assert Enum.all?(certificates, &match?(%Certificate{}, &1))
  end

  test "trust-anchor limits are independent from peer-chain limits" do
    anchors = List.duplicate({:cert, @root_der, :ignored_decoded_term}, 129)

    assert {:ok, certificates} = PKIX.normalize_trust(anchors)
    assert length(certificates) == 129

    assert {:error, {:certificate_count_limit_exceeded, 129, 128}} =
             PKIX.decode_chain(List.duplicate(@root_der, 129))
  end

  test "validates a path and DNS service identity and exposes the verified leaf" do
    assert {:ok,
            %VerifiedPeer{
              leaf_der: @leaf_der,
              leaf: leaf,
              public_key: {{:ECPoint, <<4, _::binary-size(64)>>}, {:namedCurve, _}}
            }} = PKIX.verify([@leaf_der], @root_pem, {:dns_id, "example.test"})

    assert leaf == :public_key.pkix_decode_cert(@leaf_der, :otp)
  end

  test "certificate-chain policy constrains issuer signature independently of leaf key" do
    # The leaf has an EC key for CertificateVerify but its RSA issuer used
    # sha256WithRSAEncryption to sign the certificate.
    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([@leaf_der, @root_der], [@root_der], {:dns_id, "example.test"},
               certificate_signature_schemes: [0x0401]
             )

    assert {:error, {:certificate_signature_scheme_not_allowed, [0x0804]}} =
             PKIX.verify([@leaf_der], [@root_der], {:dns_id, "example.test"},
               certificate_signature_schemes: [0x0804]
             )

    assert {:error, {:certificate_signature_scheme_not_allowed, [0x0804]}} =
             PKIX.verify([@leaf_der], [@root_der, @wrong_root_der], {:dns_id, "example.test"},
               certificate_signature_schemes: [0x0804]
             )

    assert {:error, {:path_validation_failed, _}} =
             PKIX.verify([@leaf_der], [@wrong_root_der], {:dns_id, "example.test"},
               certificate_signature_schemes: [0x0401]
             )

    assert {:error, {:invalid_input, :options}} =
             PKIX.verify([@leaf_der], [@root_der], {:dns_id, "example.test"},
               certificate_signature_schemes: [0x0401 | :bad]
             )
  end

  test "applies depth to PKIX path validation rather than certificate-message framing" do
    assert {:ok, %VerifiedPeer{leaf_der: @leaf_der}} =
             PKIX.verify([@leaf_der], @root_pem, {:dns_id, "example.test"}, depth: 0)

    assert {:error, {:invalid_input, :options}} =
             PKIX.verify([@leaf_der], @root_pem, {:dns_id, "example.test"}, depth: -1)
  end

  test "honors a bounded custom hostname match function" do
    allow_alias = fn
      {:dns_id, "alias.example.test"}, {:dNSName, presented} ->
        to_string(presented) == "example.test"

      _reference, _presented ->
        :default
    end

    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([@leaf_der], @root_pem, {:dns_id, "alias.example.test"},
               customize_hostname_check: [match_fun: allow_alias]
             )

    reject_all = fn _reference, _presented -> false end

    assert {:error, :hostname_mismatch} =
             PKIX.verify([@leaf_der], @root_pem, {:dns_id, "example.test"},
               customize_hostname_check: [match_fun: reject_all]
             )

    https_match = :public_key.pkix_verify_hostname_match_fun(:https)

    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify([@leaf_der], @root_pem, {:dns_id, "example.test"},
               customize_hostname_check: [match_fun: https_match]
             )
  end

  test "validates an IP subject alternative name" do
    assert {:ok, %VerifiedPeer{leaf_der: @leaf_der}} =
             PKIX.verify([@leaf_der], [@root_der], {:ip, {127, 0, 0, 1}})
  end

  test "rejects a matching common name when the certificate has no DNS SAN" do
    assert {:error, :hostname_mismatch} =
             PKIX.verify(
               [identity_der("cn_only.pem")],
               @identity_root_pem,
               {:dns_id, "example.test"}
             )
  end

  test "CN never rescues a mismatching SAN and an unrelated CN does not block a SAN match" do
    assert {:error, :hostname_mismatch} =
             verify_identity("mismatch.pem", {:dns_id, "example.test"})

    assert {:ok, %VerifiedPeer{}} =
             verify_identity("san_match.pem", {:dns_id, "example.test"})
  end

  test "matches IPv4 and IPv6 only against exact IP SAN values" do
    for identity <- [
          {:ip, "127.0.0.1"},
          {:ip, {127, 0, 0, 1}},
          {:ip, "::1"},
          {:ip, {0, 0, 0, 0, 0, 0, 0, 1}}
        ] do
      assert {:ok, %VerifiedPeer{}} = verify_identity("ip.pem", identity)
    end

    assert {:error, :hostname_mismatch} = verify_identity("ip.pem", {:ip, "127.0.0.2"})
  end

  test "does not treat an IP-looking DNS SAN as an IP identity" do
    assert {:error, :hostname_mismatch} =
             verify_identity("dns_ip.pem", {:ip, "192.0.2.1"})
  end

  test "supports only a complete leftmost DNS wildcard matching one label" do
    for reference <- [
          "www.example.test",
          "WWW.EXAMPLE.TEST",
          "valid-host.example.test",
          "xn--bcher-kva.example.test"
        ] do
      assert {:ok, %VerifiedPeer{}} =
               verify_identity("wildcard.pem", {:dns_id, reference})
    end

    assert {:error, :hostname_mismatch} =
             verify_identity("wildcard.pem", {:dns_id, "example.test"})

    assert {:error, :hostname_mismatch} =
             verify_identity("wildcard.pem", {:dns_id, "a.b.example.test"})

    assert {:error, :hostname_mismatch} =
             verify_identity("partial_wildcard.pem", {:dns_id, "foo.example.test"})
  end

  test "rejects invalid ASCII DNS references before identity matching" do
    oversized_label = String.duplicate("a", 64) <> ".example.test"
    oversized_name = Enum.join(List.duplicate(String.duplicate("a", 63), 4), ".")

    invalid_references = [
      ".example.test",
      "www..example.test",
      "*.example.test",
      "w*w.example.test",
      "www.example.test.",
      " .example.test",
      "\t.example.test",
      "\n.example.test",
      "\0.example.test",
      " www.example.test",
      "www .example.test",
      "www\texample.test",
      "www\nexample.test",
      "www_example.test",
      "bücher.example.test",
      "-www.example.test",
      "www-.example.test",
      oversized_label,
      oversized_name
    ]

    for reference <- invalid_references do
      identity = {:dns_id, reference}

      assert {:error, {:invalid_identity, ^identity}} =
               verify_identity("wildcard.pem", identity)
    end
  end

  test "ignores invalid presented wildcard patterns while allowing another valid SAN" do
    assert {:error, :hostname_mismatch} =
             verify_identity(
               "invalid_sans.pem",
               {:dns_id, "foo.bar.example.test"},
               @invalid_sans_root_pem
             )

    assert {:error, :hostname_mismatch} =
             verify_identity(
               "invalid_sans.pem",
               {:dns_id, "foo.example.test"},
               @invalid_sans_root_pem
             )

    assert {:ok, %VerifiedPeer{}} =
             verify_identity(
               "invalid_sans.pem",
               {:dns_id, "valid.example.test"},
               @invalid_sans_root_pem
             )
  end

  property "bounded malformed DNS references return the precise identity error" do
    invalid_label =
      one_of([
        member_of(["", " ", "\t", "\n", "\0", "bad_name", "-bad", "bad-", "*"]),
        binary(min_length: 64, max_length: 70)
      ])

    check all(label <- invalid_label, max_runs: 100) do
      identity = {:dns_id, label <> ".example.test"}
      result = verify_identity("wildcard.pem", identity)

      assert {:error, {:invalid_identity, ^identity}} = result
    end
  end

  test "accepts a peer chain that includes the supplied trust anchor" do
    assert {:ok, %VerifiedPeer{leaf_der: @leaf_der}} =
             PKIX.verify(
               [@leaf_der, @root_der],
               [@root_der],
               {:dns_id, "example.test"}
             )
  end

  test "rejects hostname mismatches and paths outside the supplied trust" do
    assert {:error, :hostname_mismatch} =
             PKIX.verify([@leaf_der], [@root_der], {:dns_id, "wrong.example.test"})

    assert {:error, {:path_validation_failed, _reason}} =
             PKIX.verify([@leaf_der], [@wrong_root_der], {:dns_id, "example.test"})
  end

  test "rejects malformed and tampered certificates" do
    tampered_leaf = flip_last_bit(@leaf_der)

    assert {:error, {:invalid_certificate, 0}} = PKIX.decode_chain([<<1, 2, 3>>])

    assert {:error, {:path_validation_failed, _reason}} =
             PKIX.verify([tampered_leaf], [@root_der], {:dns_id, "example.test"})

    assert {:error, :malformed_pem} = PKIX.normalize_trust("not a PEM bundle")
    assert {:error, {:invalid_certificate, 0}} = PKIX.normalize_trust([<<0>>])
  end

  test "rejects empty inputs and malformed arbitrary terms" do
    assert {:error, :empty_certificate_chain} = PKIX.decode_chain([])
    assert {:error, :empty_trust_anchors} = PKIX.normalize_trust([])
    assert {:error, :empty_trust_anchors} = PKIX.normalize_trust(<<>>)
    assert {:error, {:invalid_input, :certificate_chain}} = PKIX.decode_chain(nil)
    assert {:error, {:invalid_input, :trust_source}} = PKIX.normalize_trust(nil)

    assert {:error, {:invalid_identity, nil}} = PKIX.verify([@leaf_der], [@root_der], nil)

    assert {:error, {:invalid_identity, {:dns_id, <<255>>}}} =
             PKIX.verify([@leaf_der], [@root_der], {:dns_id, <<255>>})

    assert {:error, {:invalid_identity, {:ip, <<255>>}}} =
             PKIX.verify([@leaf_der], [@root_der], {:ip, <<255>>})

    assert {:error, {:invalid_input, :options}} = PKIX.decode_chain([@leaf_der], nil)
    assert {:error, {:invalid_input, :certificate_chain}} = PKIX.decode_chain([@leaf_der | :bad])

    assert {:error, {:invalid_input, :options}} =
             PKIX.decode_chain([@leaf_der], [{:max_der_bytes, 1} | :bad])
  end

  test "enforces certificate count, individual DER, total DER, and PEM bounds" do
    assert {:error, {:certificate_count_limit_exceeded, 2, 1}} =
             PKIX.decode_chain([@leaf_der, @root_der], max_certificates: 1)

    assert {:error, {:certificate_der_limit_exceeded, 0, actual, 10}} =
             PKIX.decode_chain([@leaf_der], max_der_bytes: 10)

    assert actual == byte_size(@leaf_der)

    assert {:error, {:certificate_total_der_limit_exceeded, total, 1_000}} =
             PKIX.decode_chain([@leaf_der, @root_der], max_total_der_bytes: 1_000)

    assert total == byte_size(@leaf_der) + byte_size(@root_der)

    assert {:error, {:pem_limit_exceeded, pem_size, 10}} =
             PKIX.normalize_trust(@root_pem, max_pem_bytes: 10)

    assert pem_size == byte_size(@root_pem)
  end

  property "bounded malformed PKIX inputs always return tagged results" do
    malformed_entry = one_of([constant(nil), constant(false), integer(), binary(max_length: 32)])

    malformed_input =
      one_of([
        malformed_entry,
        list_of(malformed_entry, max_length: 8)
      ])

    check all(input <- malformed_input, max_runs: 100) do
      for result <- [
            PKIX.decode_chain(input),
            PKIX.normalize_trust(input),
            PKIX.verify(input, [@root_der], {:dns_id, "example.test"})
          ] do
        assert match?({:ok, _value}, result) or match?({:error, _reason}, result)
      end
    end
  end

  defp flip_last_bit(der) do
    prefix_size = byte_size(der) - 1
    <<prefix::binary-size(^prefix_size), last>> = der
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end

  defp identity_der(name) do
    [entry] =
      name
      |> then(&Path.join(@identity_fixture_dir, &1))
      |> File.read!()
      |> :public_key.pem_decode()

    elem(entry, 1)
  end

  defp verify_identity(name, identity, root_pem \\ @identity_root_pem),
    do: PKIX.verify([identity_der(name)], root_pem, identity)
end
