defmodule SSL.PKIX.CrossSignedChainTest do
  use ExUnit.Case, async: true

  alias SSL.PKIX
  alias SSL.PKIX.VerifiedPeer

  @fixtures Path.expand("../../fixtures/pkix_cross_signed", __DIR__)
  @chain (for name <- ["leaf.pem", "intermediate_a.pem", "intermediate_b.pem"] do
            File.read!(Path.join(@fixtures, name)) |> :public_key.pem_decode() |> hd() |> elem(1)
          end)
  @root File.read!(Path.join(@fixtures, "root_a.pem"))
        |> :public_key.pem_decode()
        |> hd()
        |> elem(1)
  @expired File.read!(Path.join(@fixtures, "expired.pem"))
           |> :public_key.pem_decode()
           |> hd()
           |> elem(1)
  @wrong_root File.read!(Path.expand("../../fixtures/pkix/wrong_root.pem", __DIR__))
              |> :public_key.pem_decode()
              |> hd()
              |> elem(1)
  @identity {:dns_id, "example.test"}

  test "selects the independently validated prefix of the long-lived cross-signed three-certificate chain" do
    [leaf, intermediate, _alternate] = @chain

    assert {:ok, {{_algorithm, expected_key, expected_parameters}, _policy}} =
             :public_key.pkix_path_validation(@root, [intermediate, leaf], max_path_length: 1)

    assert {:error, {:bad_cert, :invalid_issuer}} =
             :public_key.pkix_path_validation(@root, Enum.reverse(@chain), max_path_length: 1)

    for chain <- [[leaf, intermediate], @chain] do
      assert {:ok,
              %VerifiedPeer{
                leaf_der: ^leaf,
                public_key: {^expected_key, ^expected_parameters},
                chain: ^chain
              }} = PKIX.verify(chain, [@root], @identity, depth: 1)
    end
  end

  test "path selection is independent of unrelated supplied anchor ordering" do
    for trust <- [[@wrong_root, @root], [@root, @wrong_root]] do
      assert {:ok, %VerifiedPeer{}} = PKIX.verify(@chain, trust, @identity)
    end
  end

  test "a supplied earlier trust anchor preserves independent PKIX policy rejection" do
    [leaf, intermediate | _] = @chain

    assert {:error, {:bad_cert, {:policy_requirement_not_met, _}} = reason} =
             :public_key.pkix_path_validation(intermediate, [leaf], max_path_length: 0)

    assert {:error, {:path_validation_failed, ^reason}} =
             PKIX.verify(@chain, [intermediate], @identity, depth: 0)
  end

  test "missing or unrelated trust never selects an untrusted path" do
    assert {:error, :empty_trust_anchors} = PKIX.verify(@chain, [], @identity)

    assert {:error, {:path_validation_failed, _}} =
             PKIX.verify(@chain, [@wrong_root], @identity)
  end

  test "selected paths still enforce hostname and intermediate depth" do
    assert {:error, :hostname_mismatch} =
             PKIX.verify(@chain, [@root], {:dns_id, "unrelated.example.test"})

    assert {:error, {:path_validation_failed, {:bad_cert, :max_path_length_reached}}} =
             PKIX.verify(@chain, [@root], @identity, depth: 0)
  end

  test "selected paths still verify leaf and intermediate signatures" do
    [leaf, intermediate, alternate] = @chain

    for chain <- [
          [tamper_signature(leaf), intermediate, alternate],
          [leaf, tamper_signature(intermediate), alternate]
        ] do
      assert {:error, {:path_validation_failed, {:bad_cert, :invalid_signature}}} =
               PKIX.verify(chain, [@root], @identity)
    end
  end

  test "selected paths still reject an independently signed expired leaf" do
    [_leaf, intermediate, alternate] = @chain

    assert {:error, {:bad_cert, :cert_expired}} =
             :public_key.pkix_path_validation(@root, [intermediate, @expired], max_path_length: 1)

    assert {:error, {:path_validation_failed, {:bad_cert, :cert_expired}}} =
             PKIX.verify([@expired, intermediate, alternate], [@root], @identity)
  end

  test "certificate signature policy applies to the selected path" do
    # Leaf uses P-256/SHA256; its chosen intermediate uses P-384/SHA384.
    assert {:ok, %VerifiedPeer{}} =
             PKIX.verify(@chain, [@root], @identity,
               certificate_signature_schemes: [0x0403, 0x0503]
             )

    for schemes <- [[0x0403], [0x0503], [0x0804]] do
      assert {:error, {:certificate_signature_scheme_not_allowed, ^schemes}} =
               PKIX.verify(@chain, [@root], @identity, certificate_signature_schemes: schemes)
    end
  end

  test "path selection does not bypass decoding or bounds on unused peer certificates" do
    assert {:error, {:invalid_certificate, 3}} =
             PKIX.verify(@chain ++ [<<0>>], [@root], @identity)

    assert {:error, {:certificate_count_limit_exceeded, 3, 2}} =
             PKIX.verify(@chain, [@root], @identity, max_certificates: 2)
  end

  test "malformed issuer text in decodable DER returns a path error without raising" do
    [leaf | rest] = @chain
    decoded = :public_key.pkix_decode_cert(leaf, :otp)

    malformed_issuer =
      {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, <<255>>}}]]}

    malformed_tbs = put_elem(elem(decoded, 1), 4, malformed_issuer)

    malformed_der =
      :public_key.pkix_encode(:OTPCertificate, put_elem(decoded, 1, malformed_tbs), :otp)

    assert {:error, {:path_validation_failed, _}} =
             PKIX.verify([malformed_der | rest], [@root], @identity)
  end

  defp tamper_signature(der) do
    size = byte_size(der) - 1
    <<prefix::binary-size(^size), last>> = der
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end
end

defmodule SSL.PKIX.PublicChainTest do
  use ExUnit.Case, async: true

  @fixtures Path.expand("../../fixtures/pkix_icloud", __DIR__)
  @chain File.read!(Path.join(@fixtures, "chain.pem"))
         |> :public_key.pem_decode()
         |> Enum.map(&elem(&1, 1))
  @root File.read!(Path.join(@fixtures, "digicert_global_root_g3.pem"))
        |> :public_key.pem_decode()
        |> hd()
        |> elem(1)

  test "exact iCloud public chain agrees with independently validated prefix, including expiry" do
    [leaf, intermediate, _alternate] = @chain

    assert Base.encode16(:crypto.hash(:sha256, leaf)) ==
             "882969869F9E85BBE6A6E009698DE55CC041DAFBB19A3303971E9AEF4C9A15CD"

    assert Base.encode16(:crypto.hash(:sha256, @root)) ==
             "31AD6648F8104138C738F39EA4320133393E3A18CC02296EF97C2AC9EF6731D0"

    assert {:error, {:bad_cert, :invalid_issuer}} =
             :public_key.pkix_path_validation(@root, Enum.reverse(@chain), max_path_length: 1)

    # This captured leaf expires on 2027-02-18. Its expiry must remain enforced;
    # the synthetic topology above separately tests acceptance through 2036.
    expected = :public_key.pkix_path_validation(@root, [intermediate, leaf], max_path_length: 1)

    for chain <- [[leaf, intermediate], @chain] do
      case expected do
        {:ok, {{_algorithm, key, parameters}, _policy}} ->
          assert {:ok, %SSL.PKIX.VerifiedPeer{leaf_der: ^leaf, public_key: {^key, ^parameters}}} =
                   SSL.PKIX.verify(chain, [@root], {:dns_id, "caldav.icloud.com"}, depth: 1)

        {:error, {:bad_cert, :cert_expired} = reason} ->
          assert {:error, {:path_validation_failed, ^reason}} =
                   SSL.PKIX.verify(chain, [@root], {:dns_id, "caldav.icloud.com"}, depth: 1)
      end
    end
  end
end
