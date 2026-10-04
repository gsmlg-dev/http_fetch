defmodule SSL.QUIC.Config do
  @moduledoc false
  alias SSL.{Capabilities, ClientIdentity, PKIX}
  alias SSL.ClientHello.{Materializer, RecordPolicy, WireProfile}

  @limits [
    max_handshake_length: 1_048_576,
    max_total_handshake_bytes: 2_097_152,
    max_certificate_count: 16,
    max_total_certificate_bytes: 524_288,
    max_certificate_bytes: 262_144,
    max_extension_bytes: 65_535,
    max_signature_bytes: 16_384
  ]
  @keys [
    :cert,
    :key,
    :cacerts,
    :reference_identity,
    :server_name,
    :alpn,
    :transport_parameters,
    :ciphers,
    :groups,
    :signature_algorithms,
    :profile,
    :limits,
    :depth,
    :customize_hostname_check
  ]

  def build(role, options) when role in [:client, :server] and is_list(options) do
    with true <- Keyword.keyword?(options),
         true <- Enum.all?(Keyword.keys(options), &(&1 in @keys)),
         true <- Keyword.keys(options) == Enum.uniq(Keyword.keys(options)),
         {:ok, limits} <- limits(Keyword.get(options, :limits, [])),
         {:ok, ciphers} <-
           algorithms(options, :ciphers, :cipher_suite, Capabilities.cipher_ids(0x0304)),
         {:ok, groups} <- algorithms(options, :groups, :group, ids(:group)),
         {:ok, signatures} <-
           algorithms(
             options,
             :signature_algorithms,
             :signature_algorithm,
             ids(:signature_algorithm)
           ),
         alpn = Keyword.get(options, :alpn),
         true <-
           is_list(alpn) and alpn != [] and
             Enum.all?(alpn, &(is_binary(&1) and byte_size(&1) in 1..255)),
         true <-
           alpn == Enum.uniq(alpn) and Enum.sum(Enum.map(alpn, &(byte_size(&1) + 1))) <= 65_533,
         tp = Keyword.get(options, :transport_parameters),
         true <- is_binary(tp) and byte_size(tp) <= min(limits[:max_extension_bytes], 65_000),
         {:ok, identity} <- ClientIdentity.load(Keyword.take(options, [:cert, :key])),
         :ok <- identity_required(role, identity),
         :ok <- identity_limits(identity, limits),
         true <- role != :server or Enum.any?(signatures, &(&1 in identity.signature_schemes)),
         :ok <- client_trust(role, options),
         name = Keyword.get(options, :server_name),
         true <- is_nil(name) or (is_binary(name) and byte_size(name) in 1..253),
         depth = Keyword.get(options, :depth, 10),
         true <- is_integer(depth) and depth >= 0,
         matcher = Keyword.get(options, :customize_hostname_check, []),
         true <-
           valid_matcher?(matcher),
         true <- role != :server or not Keyword.has_key?(options, :profile) do
      {:ok,
       %{
         role: role,
         ciphers: ciphers,
         groups: groups,
         alpn: alpn,
         signature_algorithms:
           if(role == :server,
             do: Enum.filter(signatures, &(&1 in identity.signature_schemes)),
             else: signatures
           ),
         identity: identity,
         trust: Keyword.get(options, :cacerts),
         reference_identity: Keyword.get(options, :reference_identity),
         server_name: name,
         transport_parameters: tp,
         limits: limits,
         verifier_options:
           Keyword.delete(limits, :max_total_handshake_bytes) ++
             [depth: depth, customize_hostname_check: matcher],
         profile: Keyword.get(options, :profile)
       }}
    else
      _ -> {:error, :invalid_configuration}
    end
  end

  def build(_, _), do: {:error, :invalid_configuration}

  def materialize(config) do
    capabilities = %{
      versions: [0x0304],
      ciphers: config.ciphers,
      groups: config.groups,
      signature_algorithms: config.signature_algorithms,
      certificate_signature_algorithms:
        Capabilities.identifiers(:certificate_signature_algorithm),
      raw_extensions: [57],
      key_share_sizes: Capabilities.key_share_sizes(),
      record_modes: [:none]
    }

    profile = config.profile || default_profile(config)

    with %WireProfile{session_id: :empty, record: %RecordPolicy{mode: :none}} <- profile,
         true <- quic_extensions?(profile.extensions),
         {:ok, materialized} <-
           Materializer.materialize(profile, capabilities, %{server_name: config.server_name}),
         extensions = materialized.client_hello.extensions,
         {57, tp} when tp == config.transport_parameters <- List.keyfind(extensions, 57, 0),
         {16, alpn_payload} <- List.keyfind(extensions, 16, 0),
         {:ok, {16, ^alpn_payload}} <- SSL.ClientHello.Extension.encode({:alpn, config.alpn}) do
      {:ok, materialized}
    else
      _ -> {:error, :invalid_quic_profile}
    end
  end

  defp quic_extensions?([]), do: true

  defp quic_extensions?([{tag, _} | _])
       when tag in [
              :pre_shared_key,
              :psk_key_exchange_modes,
              :extended_master_secret,
              :renegotiation_info
            ],
       do: false

  defp quic_extensions?([_ | rest]), do: quic_extensions?(rest)
  defp quic_extensions?(_), do: false

  def default_profile(config) do
    %WireProfile{
      session_id: :empty,
      record: %RecordPolicy{mode: :none},
      cipher_suites: config.ciphers,
      extensions:
        if(config.server_name, do: [{:server_name, :from_connection}], else: []) ++
          [
            {:supported_versions, [0x0304]},
            {:supported_groups, config.groups},
            {:signature_algorithms, config.signature_algorithms},
            {:signature_algorithms_cert, ids(:certificate_signature_algorithm)},
            {:alpn, config.alpn},
            {:key_share, [hd(config.groups)]},
            {:raw, 57, config.transport_parameters}
          ]
    }
  end

  defp algorithms(opts, key, kind, defaults) do
    values = Keyword.get(opts, key, defaults)

    if is_list(values) and values != [] and values == Enum.uniq(values) and
         Enum.all?(values, &(&1 in defaults)) do
      # IDs are canonical and order remains the caller's order.
      {:ok, Enum.map(values, &Capabilities.resolve(kind, &1).id)}
    else
      {:error, key}
    end
  end

  defp ids(kind), do: Capabilities.identifiers(kind) |> Enum.filter(&is_integer/1)
  defp identity_limits(nil, _), do: :ok

  defp identity_limits(identity, limits) do
    case PKIX.decode_chain(identity.chain,
           max_certificates: limits[:max_certificate_count],
           max_der_bytes: limits[:max_certificate_bytes],
           max_total_der_bytes: limits[:max_total_certificate_bytes]
         ) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp identity_required(:server, nil), do: {:error, :server_identity_required}
  defp identity_required(_, _), do: :ok

  defp client_trust(:server, opts) do
    if Enum.any?(
         [:cacerts, :reference_identity, :server_name, :depth, :customize_hostname_check],
         &Keyword.has_key?(opts, &1)
       ) do
      {:error, :unsupported_server_authentication}
    else
      :ok
    end
  end

  defp client_trust(:client, opts) do
    with {:ok, _} <- PKIX.normalize_trust(Keyword.get(opts, :cacerts)),
         true <- valid_reference?(Keyword.get(opts, :reference_identity)) do
      :ok
    else
      _ -> {:error, :client_trust_required}
    end
  end

  defp valid_reference?({:dns_id, name}), do: is_binary(name) and byte_size(name) in 1..253
  defp valid_reference?({:ip, ip}), do: valid_ip_reference?(ip)
  defp valid_reference?(_), do: false

  defp valid_ip_reference?({a, b, c, d})
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255,
       do: true

  defp valid_ip_reference?({a, b, c, d, e, f, g, h})
       when a in 0..65_535 and b in 0..65_535 and c in 0..65_535 and d in 0..65_535 and
              e in 0..65_535 and f in 0..65_535 and g in 0..65_535 and h in 0..65_535,
       do: true

  defp valid_ip_reference?(ip) when is_binary(ip) and byte_size(ip) > 0 do
    String.valid?(ip) and match?({:ok, _}, :inet.parse_address(String.to_charlist(ip)))
  end

  defp valid_ip_reference?(_), do: false

  defp limits(opts) when is_list(opts) do
    if Keyword.keyword?(opts) and Keyword.keys(opts) == Enum.uniq(Keyword.keys(opts)) and
         Enum.all?(opts, fn {key, value} ->
           key in Keyword.keys(@limits) and is_integer(value) and value > 0 and
             value <= @limits[key]
         end) do
      {:ok, Keyword.merge(@limits, opts)}
    else
      {:error, :invalid_limits}
    end
  end

  defp limits(_), do: {:error, :invalid_limits}

  defp valid_matcher?(matcher) do
    matcher == [] or
      (is_list(matcher) and Keyword.keyword?(matcher) and
         Keyword.keys(matcher) == [:match_fun] and is_function(matcher[:match_fun], 2))
  end
end
