defmodule SSL.ClientIdentity.Chain do
  @moduledoc false

  # The caller's immutable in-memory trust source is the only reconstruction
  # source. Identity leaves/chains never become server trust or another pool.
  def snapshot(nil), do: []

  def snapshot(source) do
    case SSL.PKIX.normalize_trust(source) do
      {:ok, certificates} -> certificates
      _ -> []
    end
  end

  def authorities(names) do
    {:ok,
     MapSet.new(names, fn der ->
       der |> then(&:public_key.der_decode(:Name, &1)) |> :public_key.pkix_normalize_name()
     end)}
  catch
    _, _ -> {:error, :invalid_client_authentication}
  end

  def matches?(chain, names) do
    Enum.any?(chain, fn der ->
      issuer = der |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(4)
      MapSet.member?(names, :public_key.pkix_normalize_name(issuer))
    end)
  end

  def complete([leaf], pool, remaining) do
    budget = min(65_536, remaining)

    case search([leaf], pool, MapSet.new([leaf]), budget) do
      {:found, path, left, _seen} -> {:ok, Enum.reverse(path), remaining - budget + left}
      {:missing, path, left, _seen} -> {:ok, Enum.reverse(path), remaining - budget + left}
      {:error, _} = error -> error
    end
  end

  def complete(chain, _pool, remaining), do: {:ok, chain, remaining}

  defp search([last | _] = path, pool, seen, budget) do
    if :public_key.pkix_is_self_signed(last),
      do: {:found, path, budget, seen},
      else: issuers(pool, path, pool, seen, budget, path)
  end

  defp issuers([], _path, _pool, seen, budget, best), do: {:missing, best, budget, seen}

  defp issuers([_ | _], _path, _pool, _seen, 0, _best),
    do: {:error, :client_identity_chain_search_limit}

  defp issuers([issuer | rest], [child | _] = path, pool, seen, budget, best) do
    budget = budget - 1

    if MapSet.member?(seen, issuer.der) or not signed_by?(child, issuer) do
      issuers(rest, path, pool, seen, budget, best)
    else
      next = [issuer.der | path]

      if bounded?(next) do
        case search(next, pool, MapSet.put(seen, issuer.der), budget) do
          {:missing, partial, left, visited} ->
            issuers(rest, path, pool, visited, left, longer_path(partial, best))

          result ->
            result
        end
      else
        {:error, :client_identity_chain_limit}
      end
    end
  end

  defp longer_path(partial, best) when length(partial) > length(best), do: partial
  defp longer_path(_partial, best), do: best

  defp bounded?(chain) do
    length(chain) <= 16 and Enum.all?(chain, &(byte_size(&1) <= 262_144)) and
      Enum.sum(Enum.map(chain, &byte_size/1)) <= 524_288
  end

  defp signed_by?(child_der, issuer) do
    child = :public_key.pkix_decode_cert(child_der, :otp)
    extensions = elem(elem(issuer.decoded, 1), 10)

    ca? =
      is_list(extensions) and
        Enum.any?(extensions, fn
          {:Extension, {2, 5, 29, 19}, _, {:BasicConstraints, true, _}} -> true
          _ -> false
        end)

    signing? =
      is_list(extensions) and
        Enum.all?(extensions, fn
          {:Extension, {2, 5, 29, 15}, _, usages} -> is_list(usages) and :keyCertSign in usages
          _ -> true
        end)

    ca? and signing? and :public_key.pkix_is_issuer(child, issuer.decoded) and
      :public_key.pkix_verify(child_der, issuer_key(issuer.decoded))
  catch
    _, _ -> false
  end

  defp issuer_key(certificate) do
    case elem(elem(certificate, 1), 7) do
      {:OTPSubjectPublicKeyInfo, _, {:RSAPublicKey, _, _} = key} ->
        key

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, {1, 3, 101, 112}, _}, key} ->
        {key, {:namedCurve, {1, 3, 101, 112}}}

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, _, parameters}, key} ->
        {key, parameters}
    end
  end
end
