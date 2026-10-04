defmodule SSL.PKIX.CertificateSignaturePolicy do
  @moduledoc false

  @rsa_pss_oid {1, 2, 840, 113_549, 1, 1, 10}
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @ec_oid {1, 2, 840, 10_045, 2, 1}
  @ecdsa_sha256_oid {1, 2, 840, 10_045, 4, 3, 2}
  @ecdsa_sha384_oid {1, 2, 840, 10_045, 4, 3, 3}
  @ed25519_oid {1, 3, 101, 112}
  @mgf1_oid {1, 2, 840, 113_549, 1, 1, 8}
  @sha256_oid {2, 16, 840, 1, 101, 3, 4, 2, 1}
  @sha384_oid {2, 16, 840, 1, 101, 3, 4, 2, 2}
  @sha512_oid {2, 16, 840, 1, 101, 3, 4, 2, 3}
  @pss_hashes %{
    @sha256_oid => {0x0804, 0x0809, 32},
    @sha384_oid => {0x0805, 0x080A, 48},
    @sha512_oid => {0x0806, 0x080B, 64}
  }

  @spec compatible?([binary()], binary() | nil, [non_neg_integer()]) :: boolean()
  def compatible?(chain, anchor, accepted) when is_list(chain) and is_list(accepted) do
    Enum.all?(Enum.with_index(chain), fn {der, index} ->
      cond do
        anchor == der ->
          true

        :public_key.pkix_is_self_signed(der) ->
          true

        true ->
          issuer = Enum.at(chain, index + 1) || anchor
          Enum.any?(schemes(der, issuer), &(&1 in accepted))
      end
    end)
  catch
    _, _ -> false
  end

  def compatible?(_chain, _anchor, _accepted), do: false

  @spec schemes(binary(), binary() | nil) :: [non_neg_integer()]
  def schemes(der, issuer_der) do
    cert = :public_key.pkix_decode_cert(der, :otp)
    {:SignatureAlgorithm, oid, params} = elem(cert, 2)
    issuer_key = if issuer_der, do: public_key_algorithm(issuer_der)

    case oid do
      {1, 2, 840, 113_549, 1, 1, 11} -> rsa_pkcs1(0x0401, issuer_key)
      {1, 2, 840, 113_549, 1, 1, 12} -> rsa_pkcs1(0x0501, issuer_key)
      {1, 2, 840, 113_549, 1, 1, 13} -> rsa_pkcs1(0x0601, issuer_key)
      @ecdsa_sha256_oid -> ecdsa(0x0403, issuer_key)
      @ecdsa_sha384_oid -> ecdsa(0x0503, issuer_key)
      @ed25519_oid -> ed25519(issuer_key)
      @rsa_pss_oid -> pss(params, issuer_key)
      _ -> []
    end
  catch
    _, _ -> []
  end

  defp rsa_pkcs1(scheme, nil), do: [scheme]
  defp rsa_pkcs1(scheme, {@rsa_encryption_oid, _}), do: [scheme]
  defp rsa_pkcs1(_, _), do: []

  defp ecdsa(scheme, nil), do: [scheme]

  defp ecdsa(
         0x0403,
         {@ec_oid, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}}
       ),
       do: [0x0403]

  defp ecdsa(0x0503, {@ec_oid, {:namedCurve, {1, 3, 132, 0, 34}}}), do: [0x0503]
  defp ecdsa(_, _), do: []

  defp ed25519(nil), do: [0x0807]
  defp ed25519({@ed25519_oid, :asn1_NOVALUE}), do: [0x0807]
  defp ed25519(_), do: []

  defp pss(
         {:"RSASSA-PSS-params", {:HashAlgorithm, hash_oid, hash_params},
          {:MaskGenAlgorithm, @mgf1_oid, {:HashAlgorithm, hash_oid, mgf_params}}, salt_length, 1},
         issuer_key
       ) do
    case Map.get(@pss_hashes, hash_oid) do
      {rsae, pss, ^salt_length}
      when hash_params in [:NULL, :asn1_NOVALUE] and
             mgf_params in [:NULL, :asn1_NOVALUE] ->
        case issuer_key do
          nil ->
            [rsae, pss]

          {@rsa_encryption_oid, _} ->
            [rsae]

          {@rsa_pss_oid, issuer_params} ->
            if pss_issuer_parameters_compatible?(issuer_params, hash_oid, salt_length),
              do: [pss],
              else: []

          _ ->
            []
        end

      _ ->
        []
    end
  end

  defp pss(_, _), do: []

  defp pss_issuer_parameters_compatible?(:asn1_NOVALUE, _hash_oid, _salt_length), do: true

  defp pss_issuer_parameters_compatible?(
         {:"RSASSA-PSS-params", {:HashAlgorithm, hash_oid, hash_params},
          {:MaskGenAlgorithm, @mgf1_oid, {:HashAlgorithm, hash_oid, mgf_params}}, salt_length, 1},
         hash_oid,
         salt_length
       ),
       do: hash_params in [:NULL, :asn1_NOVALUE] and mgf_params in [:NULL, :asn1_NOVALUE]

  defp pss_issuer_parameters_compatible?(_, _, _), do: false

  defp public_key_algorithm(der) do
    der
    |> :public_key.pkix_decode_cert(:otp)
    |> elem(1)
    |> elem(7)
    |> elem(1)
    |> then(fn {:PublicKeyAlgorithm, oid, params} -> {oid, params} end)
  end
end
