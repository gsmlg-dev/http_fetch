defmodule SSL.PKIX.Revocation do
  @moduledoc false
  alias SSL.PKIX.PartialChain

  alias SSL.PolicyIO
  alias SSL.PolicyIO.Bounded
  require Record

  Record.defrecordp(
    :cert,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :tbs,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :crl,
    :CertificateList,
    Record.extract(:CertificateList, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :crl_tbs,
    :TBSCertList,
    Record.extract(:TBSCertList, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :dp,
    :DistributionPoint,
    Record.extract(:DistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :idp,
    :IssuingDistributionPoint,
    Record.extract(:IssuingDistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  def check(_context, %{crl_check: false}, _certificate, _der, event, _selected, _pool, _options),
    do: event

  def check(
        _context,
        %{crl_check: :peer},
        _certificate,
        _der,
        :valid,
        _selected,
        _pool,
        _options
      ),
      do: :valid

  def check(context, policy, certificate, _der, event, selected, pool, path_options) do
    issuer = certificate |> cert(:tbsCertificate) |> tbs(:issuer)
    points = bounded_list(:public_key.pkix_dist_points(certificate), 128)

    validate = fn crls, pairs ->
      options = [
        issuer_fun:
          {fn _dp, crl, _issuer, _state ->
             signer(crl, selected, pool, context, path_options, crls)
           end, nil},
        update_crl: fn point, current -> refresh(context, policy.crl_cache, point, current) end,
        undetermined_details: true
      ]

      validate_crls(certificate, pairs, options)
    end

    {status, rejected_signer} =
      if points == [] do
        same_issuer(context, policy, certificate, issuer, points, validate)
      else
        {crls, pairs} = lookup_points(context, policy.crl_cache, points, issuer, points)

        case validate.(crls, pairs) do
          {{:bad_cert, {:revocation_status_undetermined, _}}, rejected} ->
            case same_issuer(context, policy, certificate, issuer, points, validate) do
              {:valid, _} -> {:valid, false}
              {other, fallback_rejected} -> {other, rejected or fallback_rejected}
            end

          other ->
            other
        end
      end

    case status do
      :valid ->
        event

      {:bad_cert, {:revoked, reason}} when is_atom(reason) ->
        {:bad_cert, {:revoked, reason}}

      {:bad_cert, {:revocation_status_undetermined, _}} when rejected_signer ->
        {:bad_cert, :revoked_crl_signer}

      {:bad_cert, {:revocation_status_undetermined, _}} when policy.crl_check == :best_effort ->
        event

      {:bad_cert, _} ->
        {:bad_cert, :revocation_status_undetermined}
    end
  end

  # public_key converts issuer_fun errors into undetermined status. Preserve only
  # the exhausted known-revoked outcome, scoped to this one primitive invocation.
  defp validate_crls(certificate, pairs, options) do
    Process.put({__MODULE__, :revoked_signer}, false)

    try do
      status = :public_key.pkix_crls_validate(certificate, pairs, options)
      {status, status != :valid and Process.get({__MODULE__, :revoked_signer}, false)}
    after
      Process.delete({__MODULE__, :revoked_signer})
    end
  end

  defp same_issuer(context, policy, certificate, issuer, points, validate) do
    crls = select(context, policy.crl_cache, issuer) |> eligible_crls()
    points = actual_or_issuer_points(certificate, points)
    validate.(crls, applicable_pairs(points, crls))
  end

  defp lookup_points(_context, _cache, [], _issuer, _points), do: {[], []}

  defp lookup_points(context, cache, [point | rest], issuer, points) do
    check_deadline(context)

    case lookup(context, cache, point, issuer) do
      :not_available ->
        lookup_points(context, cache, rest, issuer, points)

      values ->
        crls = eligible_crls(values)

        pairs = applicable_pairs(points, crls)

        if pairs != [],
          do: {crls, pairs},
          else: lookup_points(context, cache, rest, issuer, points)
    end
  end

  defp actual_or_issuer_points(certificate, []),
    do: [:public_key.pkix_dist_point(certificate)]

  defp actual_or_issuer_points(_certificate, points), do: points

  defp applicable_pairs(points, crls) do
    scoped = Enum.map(crls, &{&1, distribution_scope(&1)})

    for point <- points,
        {crl, scope} <- scoped,
        applicable?(point, crl, scope),
        do: {point, crl}
  end

  defp distribution_scope({_der, decoded}) do
    extensions = decoded |> crl(:tbsCertList) |> crl_tbs(:crlExtensions)
    extensions = if extensions == :asn1_NOVALUE, do: [], else: extensions

    case Enum.find(extensions, &match?({:Extension, {2, 5, 29, 28}, _, _}, &1)) do
      nil ->
        :asn1_NOVALUE

      {:Extension, _, _, encoded} ->
        encoded
        |> then(&:public_key.der_decode(:IssuingDistributionPoint, &1))
        |> idp(:distributionPoint)
    end
  end

  # OTP28's URI name matcher compares only hosts. Scope requires an exact URI
  # GeneralName intersection; public_key still validates every cryptographic,
  # issuer, reason, delta and critical-extension condition on admitted pairs.
  defp applicable?(point, {_der, decoded}, {:fullName, scope_names}) do
    case dp(point, :distributionPoint) do
      {:fullName, names} ->
        scope_names = bounded_list(scope_names, 128)

        names
        |> bounded_list(128)
        |> Enum.any?(fn
          {:uniformResourceIdentifier, uri} ->
            {:uniformResourceIdentifier, uri} in scope_names

          name ->
            :public_key.pkix_match_dist_point(
              decoded,
              dp(point, distributionPoint: {:fullName, [name]})
            )
        end)

      _ ->
        true
    end
  end

  # Relative names require certificate/issuer context. The primitive expands
  # them using the real DP; do not synthesize a relative name.
  defp applicable?(_point, _crl, _scope), do: true

  defp lookup(context, {:ssl_crl_hash_dir, _} = cache, point, issuer) do
    case dp(point, :cRLIssuer) do
      :asn1_NOVALUE ->
        select(context, cache, issuer)

      names ->
        for der <- select(context, cache, names),
            :public_key.pkix_match_dist_point(der, point),
            do: der
    end
  end

  defp lookup(context, {:ssl_crl_cache, _} = cache, point, _issuer),
    do: SSL.CRLCache.lookup_owned(context, point, cache)

  defp lookup(_context, {module, reference}, point, issuer) do
    _ = Code.ensure_loaded(module)

    result =
      if function_exported?(module, :lookup, 3),
        do: module.lookup(point, issuer, reference),
        else: module.lookup(point, reference)

    result |> unwrap() |> cache_values()
  end

  defp select(context, {:ssl_crl_hash_dir, {_reference, [{:dir, directory}]}}, issuer) do
    names =
      if match?({:rdnSequence, _}, issuer),
        do: [directoryName: issuer],
        else: bounded_list(issuer, 128)

    case Enum.find(names, &match?({:directoryName, _}, &1)) do
      {:directoryName, name} ->
        hash =
          name
          |> :public_key.pkix_normalize_name()
          |> :public_key.short_name_hash()
          |> List.to_string()

        hash_files(context, directory, hash, 0, [])

      nil ->
        []
    end
  end

  defp select(context, {:ssl_crl_cache, _} = cache, issuer),
    do: SSL.CRLCache.select_owned(context, issuer, cache)

  defp select(_context, {module, reference}, issuer),
    do: module.select(issuer, reference) |> unwrap() |> cache_values()

  defp hash_files(context, directory, hash, index, acc) when index < 256 do
    path = Path.join(to_string(directory), hash <> ".r" <> Integer.to_string(index))

    case PolicyIO.read_file(context, path) do
      {:ok, bytes} ->
        values = pem_or_der(bytes)

        case Bounded.list(values ++ acc, 256) do
          {:ok, values} -> hash_files(context, directory, hash, index + 1, values)
          _ -> PolicyIO.fail!(:policy_capacity)
        end

      {:error, :enoent} ->
        acc

      {:error, :policy_capacity} ->
        PolicyIO.fail!(:policy_capacity)

      _ ->
        PolicyIO.fail!(:policy_io_failed)
    end
  end

  defp hash_files(_, _, _, _, _), do: PolicyIO.fail!(:policy_capacity)

  def pem_or_der(<<"-----BEGIN", _::binary>> = pem) when byte_size(pem) <= 16_777_216 do
    # Bound byte/count admission before retaining decoded DER; each DER is
    # independently preflighted before CertificateList decoding.
    case Bounded.pem_count(pem, 256) do
      :ok -> :ok
      _ -> PolicyIO.fail!(:policy_capacity)
    end

    entries = :public_key.pem_decode(pem) |> bounded_list(256)

    Enum.flat_map(entries, fn
      {:CertificateList, der, :not_encrypted} -> [der]
      _ -> []
    end)
    |> cache_values()
  end

  def pem_or_der(der) when is_binary(der), do: cache_values([der])

  defp cache_values(:not_available), do: :not_available

  defp cache_values(values) do
    values = bounded_list(values, 256)

    Enum.each(values, fn der ->
      case PolicyIO.material(der) do
        :ok -> :ok
        {:error, :policy_capacity} -> PolicyIO.fail!(:policy_capacity)
        _ -> PolicyIO.fail!(:invalid_policy_material)
      end
    end)

    values
  end

  defp bounded_list(value, limit) do
    case Bounded.list(value, limit) do
      {:ok, values} -> values
      {:error, :policy_capacity} -> PolicyIO.fail!(:policy_capacity)
      _ -> PolicyIO.fail!(:invalid_policy_material)
    end
  end

  defp decode(der) do
    case PolicyIO.material(der) do
      :ok -> {der, :public_key.der_decode(:CertificateList, der)}
      {:error, :policy_capacity} -> PolicyIO.fail!(:policy_capacity)
      _ -> PolicyIO.fail!(:invalid_policy_material)
    end
  end

  defp eligible_crls(values) do
    for der <- values, pair = decode(der), eligible?(pair), do: pair
  end

  # OTP28 checks nextUpdate but admits future thisUpdate. Such a CRL cannot
  # establish current status; public_key still owns all cryptographic/path checks.
  defp eligible?({_der, decoded}) do
    seconds = decoded |> crl(:tbsCertList) |> crl_tbs(:thisUpdate) |> time_seconds()
    seconds <= System.system_time(:second)
  end

  defp time_seconds({:utcTime, [y1, y2, m1, m2, d1, d2, h1, h2, n1, n2, s1, s2, ?Z]}) do
    century = if y1 < ?5, do: ~c"20", else: ~c"19"
    calendar_seconds(century ++ [y1, y2], [m1, m2, d1, d2, h1, h2, n1, n2, s1, s2])
  end

  defp time_seconds({:generalTime, [y1, y2, y3, y4, m1, m2, d1, d2, h1, h2, n1, n2, s1, s2, ?Z]}) do
    calendar_seconds([y1, y2, y3, y4], [m1, m2, d1, d2, h1, h2, n1, n2, s1, s2])
  end

  defp time_seconds(_), do: PolicyIO.fail!(:invalid_policy_material)

  defp calendar_seconds(year, [m1, m2, d1, d2, h1, h2, n1, n2, s1, s2] = fields) do
    if Enum.all?(year ++ fields, &(&1 in ?0..?9)) do
      :calendar.rfc3339_to_system_time(
        year ++ [?-, m1, m2, ?-, d1, d2, ?T, h1, h2, ?:, n1, n2, ?:, s1, s2, ?Z],
        unit: :second
      )
    else
      PolicyIO.fail!(:invalid_policy_material)
    end
  rescue
    _ -> PolicyIO.fail!(:invalid_policy_material)
  end

  defp refresh(_context, {module, _}, _point, current)
       when module in [:ssl_crl_cache, :ssl_crl_hash_dir],
       do: current

  defp refresh(_context, {module, _}, point, current) do
    case module.fresh_crl(point, current) |> unwrap() do
      ^current -> current
      der when is_binary(der) -> refreshed(point, der, current)
      {der, _decoded} when is_binary(der) -> refreshed(point, der, current)
      _ -> PolicyIO.fail!(:invalid_policy_material)
    end
  end

  defp refreshed(point, der, current) do
    pair = decode(der)

    if eligible?(pair) and applicable?(point, pair, distribution_scope(pair)),
      do: pair,
      else: current
  end

  defp unwrap({:logger, _private_log, values}), do: values
  defp unwrap({{:logger, _private_log}, values}), do: values
  defp unwrap(values), do: values

  defp signer(_crl, {anchor, _}, _pool, _context, _options, _crls) when is_atom(anchor),
    do: {:error, :unknown_ca}

  defp signer(crl, {anchor, _} = selected, pool, context, options, crls) do
    issuer = crl |> :public_key.pkix_crl_issuer() |> :public_key.pkix_normalize_name()

    case selected_signer(crl, issuer, selected) do
      {:ok, _, _} = result -> result
      _ -> offpath_signer(crl, issuer, anchor, pool, context, options, crls)
    end
  end

  defp selected_signer(crl, issuer, {anchor, _} = selected) do
    full = PartialChain.full_path(selected)

    case Enum.find_index(full, &signs_crl?(&1, issuer, crl)) do
      nil ->
        {:error, :unknown_ca}

      index ->
        # Preserve the selected path's existing issuer_fun contract. The CRL
        # primitive remains responsible for this path's signature and key usage.
        path = full |> Enum.drop(index) |> Enum.drop(-1) |> Enum.map(& &1.der) |> Enum.reverse()
        {:ok, anchor.decoded, path}
    end
  end

  defp signs_crl?(candidate, issuer, crl) do
    subject =
      candidate.decoded
      |> cert(:tbsCertificate)
      |> tbs(:subject)
      |> :public_key.pkix_normalize_name()

    subject == issuer and :public_key.pkix_crl_verify(crl, candidate.decoded)
  end

  defp offpath_signer(crl, issuer, anchor, pool, context, options, crls) do
    result =
      Enum.reduce_while(pool, {:error, false}, fn candidate, {:error, rejected} ->
        check_deadline(context)

        if signs_crl?(candidate, issuer, crl) do
          case signer_path(candidate, pool, anchor, context, options, crls) do
            {:ok, _, _} = result -> {:halt, result}
            {:error, candidate_rejected} -> {:cont, {:error, rejected or candidate_rejected}}
          end
        else
          {:cont, {:error, rejected}}
        end
      end)

    case result do
      {:ok, _, _} ->
        result

      {:error, rejected} ->
        if rejected, do: Process.put({__MODULE__, :revoked_signer}, true)
        {:error, :unknown_ca}
    end
  end

  defp signer_path(candidate, pool, anchor, context, options, crls) do
    case PartialChain.signer_paths(
           candidate,
           pool,
           anchor,
           PolicyIO.path_budget(),
           context.deadline
         ) do
      {:ok, paths, _remaining, visits} ->
        :ok = PolicyIO.charge(:paths, visits, 4_096)

        Enum.reduce_while(Enum.reverse(paths), {:error, false}, fn {selected, path},
                                                                   {:error, rejected} ->
          validate_signer_path(selected, path, context, options, crls, rejected)
        end)

      {:error, :policy_capacity} ->
        PolicyIO.fail!(:policy_capacity)

      {:error, :deadline_exceeded} ->
        throw(:deadline_exceeded)
    end
  end

  defp validate_signer_path(selected, path, context, options, crls, rejected) do
    charge_validation(context)
    ders = path |> Enum.map(& &1.der) |> Enum.reverse()

    case :public_key.pkix_path_validation(selected.der, ders,
           max_path_length: Keyword.get(options, :depth, 10)
         ) do
      {:ok, _} ->
        # Every non-anchor member of this already validated signer path
        # must be free of positively proven revocation in admitted CRLs.
        if Enum.any?(path, &revoked_signer?(&1, {selected, path}, context, crls)),
          do: {:cont, {:error, true}},
          else: {:halt, {:ok, selected.decoded, ders}}

      _ ->
        {:cont, {:error, rejected}}
    end
  end

  defp revoked_signer?(candidate, selected, context, crls) do
    charge_validation(context)
    points = candidate.decoded |> :public_key.pkix_dist_points() |> bounded_list(128)
    points = actual_or_issuer_points(candidate.decoded, points)
    pairs = applicable_pairs(points, crls)

    result =
      :public_key.pkix_crls_validate(candidate.decoded, pairs,
        issuer_fun:
          {fn _, crl, _, _ ->
             issuer = crl |> :public_key.pkix_crl_issuer() |> :public_key.pkix_normalize_name()
             selected_signer(crl, issuer, selected)
           end, nil},
        update_crl: fn _, current -> current end,
        undetermined_details: true
      )

    check_deadline(context)
    match?({:bad_cert, {:revoked, _}}, result)
  end

  defp charge_validation(context) do
    check_deadline(context)

    case PolicyIO.charge(:paths, 1, 4_096) do
      :ok -> :ok
      _ -> PolicyIO.fail!(:policy_capacity)
    end
  end

  defp check_deadline(context) do
    if PolicyIO.remaining(context.deadline) == 0, do: throw(:deadline_exceeded)
  end
end
