defmodule SSL.Options do
  @moduledoc false
  alias SSL.ClientHello.{Profile, WireProfile}
  alias SSL.Capabilities

  @derive {Inspect, only: [:identity]}
  defstruct [
    :profile,
    :endpoint,
    :identity,
    :trust_source,
    :client_identity,
    :alpn_advertised_protocols,
    session_tickets: :disabled,
    tcp_options: [],
    active: false,
    depth: 10,
    send_timeout: 5_000,
    send_timeout_close: true,
    context: %{},
    hostname_check: []
  ]

  @type t :: %__MODULE__{}

  @keys [
    :mode,
    :active,
    :packet,
    :depth,
    :send_timeout,
    :send_timeout_close,
    :verify,
    :cacerts,
    :cacertfile,
    :cert,
    :certfile,
    :key,
    :keyfile,
    :server_name_indication,
    :customize_hostname_check,
    :versions,
    :session_tickets,
    :ciphers,
    :signature_algs,
    :signature_algs_cert,
    :supported_groups,
    :alpn_advertised_protocols,
    :ex_ssl
  ]

  @spec capabilities() :: %{
          certificate_signature_algorithms: [atom() | non_neg_integer()],
          ciphers: [atom() | non_neg_integer()],
          groups: [atom() | non_neg_integer()],
          key_share_sizes: map(),
          psk_key_exchange_modes: [:psk_dhe_ke | 1, ...],
          raw_extensions: [],
          signature_algorithms: [atom() | non_neg_integer()],
          versions: [:tlsv1_2 | :tlsv1_3 | 771 | 772, ...]
        }
  def capabilities do
    %{
      versions: [0x0304, :tlsv1_3, 0x0303, :tlsv1_2],
      ciphers: Capabilities.identifiers(:cipher_suite),
      groups: Capabilities.identifiers(:group),
      signature_algorithms: Capabilities.identifiers(:signature_algorithm),
      certificate_signature_algorithms:
        Capabilities.identifiers(:certificate_signature_algorithm),
      psk_key_exchange_modes: [1, :psk_dhe_ke],
      raw_extensions: [],
      key_share_sizes: Capabilities.key_share_sizes()
    }
  end

  @spec normalize(term(), term()) :: {:ok, t()} | {:error, term()}
  def normalize(host, options) do
    with {:ok, options, tcp_options} <- SSL.TCPOptions.extract(host, options),
         {:ok, options} <- option_list(options),
         :ok <- validate_options(options),
         {:ok, identity, context} <-
           identity(
             host,
             Keyword.get(options, :server_name_indication),
             get_in(options, [:ex_ssl, :reference_identity])
           ),
         {:ok, trust} <- trust_source(options),
         {:ok, profile} <- profile(options, context),
         {:ok, client_identity} <-
           SSL.ClientIdentity.load(Keyword.take(options, [:cert, :certfile, :key, :keyfile])),
         :ok <- ticket_identity(options, client_identity) do
      {:ok,
       %__MODULE__{
         profile: profile,
         endpoint: host,
         session_tickets: Keyword.get(options, :session_tickets, :disabled),
         identity: identity,
         context: context,
         trust_source: trust,
         client_identity: client_identity,
         tcp_options: tcp_options,
         alpn_advertised_protocols: profile_alpn(profile),
         active: Keyword.get(options, :active, false),
         depth: Keyword.get(options, :depth, 10),
         send_timeout: Keyword.get(options, :send_timeout, 5_000),
         send_timeout_close: Keyword.get(options, :send_timeout_close, true),
         hostname_check: Keyword.get(options, :customize_hostname_check, [])
       }}
    end
  end

  @spec normalize_setopts(term()) :: {:ok, keyword()} | {:error, term()}
  def normalize_setopts(options) do
    with {:ok, options, tcp_options} <- SSL.TCPOptions.extract_setopts(options),
         {:ok, options} <- option_list(options),
         :ok <- validate_setopts(options) do
      {:ok, options ++ tcp_options}
    end
  end

  @spec deadline(timeout()) :: {:ok, integer() | :infinity} | {:error, :badarg}
  def deadline(:infinity), do: {:ok, :infinity}

  def deadline(timeout) when is_integer(timeout) and timeout >= 0 do
    now = System.monotonic_time(:millisecond)
    deadline = now + timeout

    if deadline <= timer_end_time(), do: {:ok, deadline}, else: {:error, :badarg}
  end

  def deadline(_), do: {:error, :badarg}

  @spec remaining(integer() | :infinity) :: timeout()
  def remaining(:infinity), do: :infinity
  def remaining(deadline), do: max(0, deadline - System.monotonic_time(:millisecond))

  defp timer_end_time do
    :erlang.system_info(:end_time)
    |> :erlang.convert_time_unit(:native, :millisecond)
  end

  defp option_list(options) when is_list(options) do
    normalized =
      Enum.map(options, fn
        :binary -> {:mode, :binary}
        other -> other
      end)

    if Keyword.keyword?(normalized) and
         length(Keyword.keys(normalized)) == length(Enum.uniq(Keyword.keys(normalized))),
       do: {:ok, normalized},
       else: option_error(:invalid_options)
  end

  defp validate_options(options) do
    Enum.reduce_while(options, :ok, fn {key, value}, :ok ->
      if key in @keys and valid_option?(key, value),
        do: {:cont, :ok},
        else: {:halt, option_error({key, :unsupported_or_invalid})}
    end)
  end

  defp validate_setopts(options) do
    Enum.reduce_while(options, :ok, fn {key, value}, :ok ->
      if key in [:active, :send_timeout, :send_timeout_close] and valid_option?(key, value),
        do: {:cont, :ok},
        else: {:halt, option_error({key, :unsupported_or_invalid})}
    end)
  end

  defp valid_option?(:session_tickets, value), do: value in [:disabled, :auto]
  defp valid_option?(:mode, value), do: value == :binary
  defp valid_option?(:active, value), do: value in [false, :once]
  defp valid_option?(:packet, value), do: value in [:raw, 0]
  defp valid_option?(:depth, value), do: is_integer(value) and value >= 0

  defp valid_option?(:send_timeout, :infinity), do: true

  defp valid_option?(:send_timeout, value) when is_integer(value) and value >= 0,
    do: match?({:ok, _deadline}, deadline(value))

  defp valid_option?(:send_timeout, _value), do: false

  defp valid_option?(:send_timeout_close, value), do: value == true
  defp valid_option?(:verify, value), do: value == :verify_peer

  defp valid_option?(:versions, value),
    do: value in [[:"tlsv1.3"], [:"tlsv1.2"], [:"tlsv1.3", :"tlsv1.2"], [:"tlsv1.2", :"tlsv1.3"]]

  defp valid_option?(key, value)
       when key in [:ciphers, :signature_algs, :signature_algs_cert, :supported_groups],
       do: is_list(value) and value != [] and proper_list?(value)

  defp valid_option?(:alpn_advertised_protocols, value), do: valid_alpn_protocols?(value)
  defp valid_option?(:cacerts, value), do: is_list(value) and value != []

  # The identity loader owns shape, size, source-conflict and key matching checks.
  defp valid_option?(key, _value) when key in [:cert, :certfile, :key, :keyfile], do: true

  defp valid_option?(:cacertfile, value),
    do: (is_binary(value) or is_list(value)) and value not in ["", []]

  defp valid_option?(:server_name_indication, value),
    do: value == :disable or match?({:ok, _}, dns_name(value))

  defp valid_option?(:customize_hostname_check, value) do
    value == [] or
      (Keyword.keyword?(value) and length(value) == 1 and is_function(value[:match_fun], 2))
  end

  defp valid_option?(:ex_ssl, value) do
    Keyword.keyword?(value) and value != [] and
      length(Keyword.keys(value)) == length(Enum.uniq(Keyword.keys(value))) and
      Enum.all?(value, fn
        {:profile, profile} -> profile == :default or match?(%WireProfile{}, profile)
        {:reference_identity, reference} -> match?({:ok, _}, reference_identity(reference))
        _ -> false
      end)
  end

  defp identity(host, sni, nil), do: identity(host, sni)

  defp identity(host, sni, reference) do
    with {:ok, reference} <- reference_identity(reference),
         {:ok, context} <- reference_context(host, sni),
         do: {:ok, reference, context}
  end

  defp reference_context(:upgrade, sni) when sni in [nil, :disable], do: {:ok, %{}}

  defp reference_context(:upgrade, sni) do
    with {:ok, name} <- dns_name(sni), do: {:ok, %{server_name: name}}
  end

  defp reference_context(host, sni) do
    with {:ok, _} <- host_identity(host),
         {:ok, _, context} <- identity(host, sni) do
      {:ok, context}
    else
      _ -> option_error({:host, :invalid})
    end
  end

  defp reference_identity({:dns_id, name}) when is_binary(name) and byte_size(name) in 1..253 do
    if String.valid?(name) and
         Enum.all?(String.split(name, "."), fn label ->
           byte_size(label) in 1..63 and
             Regex.match?(~r/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/, label)
         end),
       do: {:ok, {:dns_id, name}},
       else: :error
  end

  defp reference_identity({:ip, address})
       when is_binary(address) and byte_size(address) in 1..45 do
    if String.valid?(address) do
      case :inet.parse_address(String.to_charlist(address)) do
        {:ok, ip} -> reference_identity({:ip, ip})
        {:error, _} -> :error
      end
    else
      :error
    end
  end

  defp reference_identity({:ip, address}) when tuple_size(address) in [4, 8] do
    maximum = if tuple_size(address) == 4, do: 255, else: 65_535

    if Enum.all?(Tuple.to_list(address), &(is_integer(&1) and &1 >= 0 and &1 <= maximum)),
      do: {:ok, {:ip, address}},
      else: :error
  end

  defp reference_identity(_), do: :error

  defp identity(_host, sni) when sni not in [nil, :disable] do
    with {:ok, name} <- dns_name(sni), do: {:ok, {:dns_id, name}, %{server_name: name}}
  end

  defp identity(:upgrade, _), do: option_error({:server_name_indication, :required_for_upgrade})

  defp identity(host, sni) do
    case host_identity(host) do
      {:ok, {:dns_id, name} = identity} ->
        {:ok, identity, if(sni == :disable, do: %{}, else: %{server_name: name})}

      {:ok, {:ip, _} = identity} ->
        {:ok, identity, %{}}

      :error ->
        option_error({:host, :invalid})
    end
  end

  defp host_identity(host) when is_tuple(host) do
    case :inet.ntoa(host) do
      {:error, _} -> :error
      _ -> {:ok, {:ip, host}}
    end
  catch
    _, _ -> :error
  end

  defp host_identity(host) when is_binary(host) or is_list(host) do
    case host_text(host) do
      {:ok, text} ->
        case :inet.parse_address(String.to_charlist(text)) do
          {:ok, ip} ->
            {:ok, {:ip, ip}}

          {:error, _} ->
            with {:ok, name} <- dns_name(text), do: {:ok, {:dns_id, name}}
        end

      _ ->
        :error
    end
  end

  defp host_identity(_host), do: :error

  defp host_text(host) when is_binary(host),
    do: if(String.valid?(host), do: {:ok, host}, else: :error)

  defp host_text(host) when is_list(host) do
    try do
      text = List.to_string(host)
      host_text(text)
    rescue
      _ -> :error
    end
  end

  defp dns_name(name) when is_list(name) do
    dns_name(List.to_string(name))
  rescue
    _ -> option_error({:server_name_indication, :invalid})
  end

  defp dns_name(name) when is_binary(name) and byte_size(name) in 1..253 do
    if String.valid?(name) and
         Regex.match?(~r/\A[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9.])?\z/, name),
       do: {:ok, name},
       else: option_error({:server_name_indication, :invalid})
  end

  defp dns_name(_), do: option_error({:server_name_indication, :invalid})

  defp trust_source(options) do
    case {Keyword.fetch(options, :cacerts), Keyword.fetch(options, :cacertfile)} do
      {{:ok, certificates}, _} ->
        validate_trust(certificates)

      {:error, {:ok, path}} ->
        case File.read(path) do
          {:ok, pem} -> validate_trust(pem)
          {:error, _} -> option_error({:cacertfile, :unreadable})
        end

      {:error, :error} ->
        validate_trust(:public_key.cacerts_get())
    end
  rescue
    _ -> option_error({:cacerts, :invalid})
  end

  defp validate_trust(source) do
    case SSL.PKIX.normalize_trust(source) do
      {:ok, _} -> {:ok, source}
      {:error, _} -> option_error({:cacerts, :invalid})
    end
  end

  defp profile(options, context) do
    advertised_protocols = Keyword.get(options, :alpn_advertised_protocols)
    versions = Enum.map(Keyword.get(options, :versions, [:"tlsv1.3"]), &version_id/1)
    explicit_profile? = Keyword.has_key?(options, :ex_ssl)
    profile = get_in(options, [:ex_ssl, :profile]) || :default

    with {:ok, policy} <- policy_lists(options, versions),
         {:ok, profile} <-
           if(profile == :default,
             do: {:ok, default_profile(context, advertised_protocols, policy, versions)},
             else: resolve_explicit_profile(profile, advertised_protocols, explicit_profile?)
           ),
         :ok <- require_version_match(profile, versions),
         :ok <- require_policy_match(profile, policy),
         {:ok, profile} <- ticket_profile(options, profile, versions) do
      validate_profile(profile)
    end
  end

  defp ticket_identity(options, identity) do
    if Keyword.get(options, :session_tickets, :disabled) == :auto and identity != nil,
      do: option_error({:session_tickets, :client_identity_unsupported}),
      else: :ok
  end

  defp ticket_profile(options, profile, versions) do
    auto? = Keyword.get(options, :session_tickets, :disabled) == :auto
    configured = get_in(options, [:ex_ssl, :profile])
    modes = profile_extension(profile, :psk_key_exchange_modes)
    slot = List.last(profile.extensions)

    cond do
      auto? and versions != [0x0304] ->
        option_error({:session_tickets, :tls13_only})

      auto? and configured in [nil, :default] ->
        {:ok,
         %{
           profile
           | extensions:
               profile.extensions ++
                 [{:psk_key_exchange_modes, [1]}, {:pre_shared_key, :deferred}]
         }}

      auto? and modes in [[1], [:psk_dhe_ke]] and slot == {:pre_shared_key, :deferred} ->
        {:ok, profile}

      auto? ->
        option_error({:session_tickets, :profile_conflict})

      modes != nil or Enum.any?(profile.extensions, &match?({:pre_shared_key, _}, &1)) ->
        option_error({:session_tickets, :disabled})

      true ->
        {:ok, profile}
    end
  end

  defp validate_profile(profile) do
    case Profile.validate(profile, capabilities()) do
      {:ok, profile} -> require_runtime_extensions(profile)
      {:error, _} -> option_error({:ex_ssl, :unsupported_profile})
    end
  end

  defp resolve_explicit_profile(profile, nil, _explicit_profile?), do: {:ok, profile}

  defp resolve_explicit_profile(profile, protocols, true) do
    if profile_alpn(profile) == protocols do
      {:ok, profile}
    else
      option_error({:alpn_advertised_protocols, :profile_conflict})
    end
  end

  defp default_profile(context, alpn_protocols, policy, versions) do
    capabilities = capabilities()
    groups = policy.supported_groups || Enum.filter(capabilities.groups, &is_integer/1)
    ciphers = policy.ciphers || Enum.flat_map(versions, &Capabilities.cipher_ids/1)

    signatures =
      policy.signature_algs || default_signatures(versions, capabilities.signature_algorithms)

    certificate_signatures =
      if policy.signature_algs_cert,
        do: [{:signature_algorithms_cert, policy.signature_algs_cert}],
        else: []

    %WireProfile{
      name: :default,
      session_id: if(versions == [0x0303], do: :empty, else: :random_32),
      cipher_suites: ciphers,
      extensions:
        if(Map.has_key?(context, :server_name), do: [{:server_name, :from_connection}], else: []) ++
          [
            {:supported_versions, versions},
            {:supported_groups, groups},
            {:signature_algorithms, signatures}
          ] ++
          if(0x0304 in versions, do: [{:key_share, Enum.take(groups, 1)}], else: []) ++
          if(0x0303 in versions,
            do: [
              {:ec_point_formats, [0]},
              {:extended_master_secret, <<>>},
              {:renegotiation_info, <<0>>}
            ],
            else: []
          ) ++ certificate_signatures ++ alpn_extension(alpn_protocols)
    }
  end

  defp policy_lists(options, versions) do
    with {:ok, ciphers} <- policy_list(options, :ciphers, :cipher_suite, versions),
         {:ok, signatures} <- policy_list(options, :signature_algs, :signature_algorithm),
         {:ok, cert_signatures} <-
           policy_list(options, :signature_algs_cert, :certificate_signature_algorithm),
         {:ok, groups} <- policy_list(options, :supported_groups, :group) do
      {:ok,
       %{
         versions: versions,
         ciphers: ciphers,
         signature_algs: signatures,
         signature_algs_cert: cert_signatures,
         supported_groups: groups
       }}
    end
  end

  defp policy_list(options, key, kind, versions \\ nil) do
    case Keyword.fetch(options, key) do
      :error ->
        {:ok, nil}

      {:ok, values} ->
        allowed =
          if kind == :cipher_suite,
            do: Enum.flat_map(versions, &Capabilities.cipher_ids/1),
            else: Map.fetch!(capabilities(), capability_key(kind))

        result =
          Enum.reduce_while(values, {:ok, [], MapSet.new()}, fn value, {:ok, ids, seen} ->
            with {:ok, value} <- documented_identifier(kind, value),
                 %{id: id} <- Capabilities.resolve(kind, value),
                 true <- id in allowed and not MapSet.member?(seen, id) do
              {:cont, {:ok, [id | ids], MapSet.put(seen, id)}}
            else
              _ -> {:halt, :error}
            end
          end)

        case result do
          {:ok, ids, _seen} when ids != [] ->
            ids = Enum.reverse(ids)

            if kind != :cipher_suite or
                 Enum.all?(versions, &cipher_version_available?(ids, &1)),
               do: {:ok, ids},
               else: option_error({key, :unsupported_or_invalid})

          _ ->
            option_error({key, :unsupported_or_invalid})
        end
    end
  end

  defp documented_identifier(
         :cipher_suite,
         %{key_exchange: exchange, cipher: _, mac: :aead, prf: _} = suite
       )
       when map_size(suite) == 4 and exchange in [:any, :ecdhe_rsa, :ecdhe_ecdsa],
       do: {:ok, suite}

  defp documented_identifier(:cipher_suite, name) when is_binary(name), do: {:ok, name}

  defp documented_identifier(:cipher_suite, name) when is_list(name) do
    if proper_list?(name) and Enum.all?(name, &is_integer/1) do
      try do
        {:ok, List.to_string(name)}
      rescue
        _ -> :error
      end
    else
      :error
    end
  end

  defp documented_identifier(kind, name)
       when kind in [:signature_algorithm, :certificate_signature_algorithm, :group] and
              is_atom(name),
       do: {:ok, name}

  defp documented_identifier(_, _), do: :error

  defp proper_list?([]), do: true
  defp proper_list?([_ | rest]), do: proper_list?(rest)
  defp proper_list?(_), do: false

  defp capability_key(:signature_algorithm), do: :signature_algorithms
  defp capability_key(:certificate_signature_algorithm), do: :certificate_signature_algorithms
  defp capability_key(:group), do: :groups

  defp require_policy_match(profile, policy) do
    Enum.reduce_while(
      [
        {:ciphers, profile.cipher_suites},
        {:signature_algs, profile_extension(profile, :signature_algorithms)},
        {:signature_algs_cert, profile_extension(profile, :signature_algorithms_cert)},
        {:supported_groups, profile_extension(profile, :supported_groups)}
      ],
      :ok,
      fn {key, actual}, :ok ->
        requested = Map.fetch!(policy, key)

        if requested == nil or canonical_list(actual, policy_kind(key)) == requested,
          do: {:cont, :ok},
          else: {:halt, option_error({key, :profile_conflict})}
      end
    )
  end

  defp policy_kind(:ciphers), do: :cipher_suite
  defp policy_kind(:signature_algs), do: :signature_algorithm
  defp policy_kind(:signature_algs_cert), do: :certificate_signature_algorithm
  defp policy_kind(:supported_groups), do: :group

  defp version_id(:"tlsv1.3"), do: 0x0304
  defp version_id(:"tlsv1.2"), do: 0x0303

  defp default_signatures(versions, available) do
    ids = Enum.filter(available, &is_integer/1)

    if versions == [0x0303], do: Enum.reject(ids, &(&1 == 0x0807)), else: ids
  end

  defp tls12_signature_available?(profile) do
    Enum.any?(profile_extension(profile, :signature_algorithms) || [], fn scheme ->
      case Capabilities.signature(scheme) do
        %{key: key} -> key in [:rsa, :rsa_pss, :ecdsa]
        _ -> false
      end
    end)
  end

  defp require_version_match(profile, versions) do
    actual = profile_versions(profile)

    cond do
      actual != versions ->
        option_error({:versions, :profile_conflict})

      0x0303 in versions and not tls12_signature_available?(profile) ->
        option_error({:signature_algs, :unsupported_or_invalid})

      versions == [0x0303] and profile_extension(profile, :key_share) != nil ->
        option_error({:versions, :profile_conflict})

      versions == [0x0304] and
          Enum.any?(
            [:extended_master_secret, :renegotiation_info],
            &(profile_extension(profile, &1) != nil)
          ) ->
        option_error({:versions, :profile_conflict})

      not Enum.all?(versions, fn version ->
        Enum.any?(profile.cipher_suites, fn cipher ->
          case Capabilities.resolve(:cipher_suite, cipher) do
            %{version: ^version} -> true
            _ -> false
          end
        end)
      end) ->
        option_error({:ciphers, :profile_conflict})

      Enum.any?(profile.cipher_suites, fn cipher ->
        case Capabilities.resolve(:cipher_suite, cipher) do
          %{version: version} -> version not in versions
          _ -> not match?({:grease, _}, cipher)
        end
      end) ->
        option_error({:ciphers, :profile_conflict})

      true ->
        :ok
    end
  end

  defp profile_extension(profile, name) do
    case List.keyfind(profile.extensions, name, 0) do
      {^name, values} -> values
      nil -> nil
    end
  end

  defp canonical_list(values, kind) when is_list(values) do
    Enum.map(values, fn value ->
      case Capabilities.resolve(kind, value) do
        %{id: id} -> id
        _ -> nil
      end
    end)
  end

  defp canonical_list(_, _), do: nil

  defp alpn_extension(nil), do: []
  defp alpn_extension(protocols), do: [{:alpn, protocols}]

  defp profile_alpn(%WireProfile{extensions: extensions}) do
    Enum.find_value(extensions, fn
      {:alpn, protocols} -> protocols
      _extension -> nil
    end)
  end

  defp profile_alpn(_profile), do: nil

  defp valid_alpn_protocols?(protocols) when is_list(protocols) and protocols != [] do
    Enum.all?(protocols, &(is_binary(&1) and byte_size(&1) in 1..255)) and
      Enum.reduce(protocols, 2, fn protocol, size -> size + 1 + byte_size(protocol) end) <= 0xFFFF
  end

  defp valid_alpn_protocols?(_protocols), do: false

  defp require_runtime_extensions(profile) do
    versions = profile_extension(profile, :supported_versions) || []

    required =
      [:supported_versions, :supported_groups, :signature_algorithms] ++
        if(Enum.any?(versions, &(&1 in [0x0304, :tlsv1_3])), do: [:key_share], else: []) ++
        if(Enum.any?(versions, &(&1 in [0x0303, :tlsv1_2])),
          do: [:ec_point_formats, :extended_master_secret, :renegotiation_info],
          else: []
        )

    if Enum.all?(required, fn name ->
         Enum.any?(profile.extensions, fn
           {^name, [_ | _]} -> true
           {^name, _} when name in [:extended_master_secret, :renegotiation_info] -> true
           _ -> false
         end)
       end),
       do: {:ok, profile},
       else: option_error({:ex_ssl, :incomplete_profile})
  end

  defp option_error(reason), do: {:error, {:options, reason}}

  defp cipher_version_available?(ids, version) do
    Enum.any?(ids, &(Capabilities.resolve(:cipher_suite, &1).version == version))
  end

  defp profile_versions(profile) do
    profile_extension(profile, :supported_versions)
    |> case do
      nil ->
        nil

      values ->
        values
        |> Enum.reject(&match?({:grease, _}, &1))
        |> Enum.map(fn
          :tlsv1_3 -> 0x0304
          :tlsv1_2 -> 0x0303
          value -> value
        end)
    end
  end
end
