defmodule SSL.ServerOptions do
  @moduledoc false
  alias SSL.{Capabilities, ClientIdentity, PKIX}
  alias SSL.QUIC.Config

  @type sni ::
          nil
          | {:hosts, %{charlist() => keyword()}}
          | {:fun, (charlist() -> keyword() | :undefined)}
  @type t :: %{
          ciphers: [non_neg_integer()],
          groups: [non_neg_integer()],
          alpn: nil | [binary()],
          signature_algorithms: [non_neg_integer()],
          identity: term(),
          limits: keyword(),
          transport_parameters: nil,
          sni: sni(),
          client_auth: nil | %{trust: term(), require: boolean(), depth: pos_integer()},
          tcp: keyword()
        }

  @identity_keys [:certfile, :keyfile, :cert, :key, :password]
  @own_keys @identity_keys ++
              [
                :certs_keys,
                :alpn_preferred_protocols,
                :ciphers,
                :versions,
                :sni_hosts,
                :sni_fun,
                :verify,
                :cacerts,
                :cacertfile,
                :fail_if_no_peer_cert,
                :depth
              ]
  # OTP :ssl-only options. Every other unknown key is a carrier (:gen_tcp) option.
  @unsupported [
    :verify_fun,
    :partial_chain,
    :honor_cipher_order,
    :honor_ecc_order,
    :secure_renegotiate,
    :secure_renegotiation,
    :signature_algs,
    :signature_algs_cert,
    :eccs,
    :supported_groups,
    :log_level,
    :customize_hostname_check,
    :crl_check,
    :crl_cache,
    :middlebox_comp_mode,
    :early_data,
    :anti_replay,
    :client_renegotiation,
    :padding_check,
    :beast_mitigation,
    :psk_identity,
    :user_lookup_fun,
    :srp_identity,
    :keep_secrets,
    :dhfile,
    :dh,
    :hibernate_after,
    :handshake,
    :max_handshake_size,
    :cert_policy_opts,
    :ocsp_stapling,
    :ocsp_nonce,
    :ocsp_responder_certs,
    :ocsp_responder_timeout,
    :keylog,
    :stateless_tickets_seed,
    :certificate_authorities,
    :receiver_spawn_opts,
    :sender_spawn_opts,
    :renegotiate_at,
    :alpn_advertised_protocols,
    :next_protocols_advertised,
    :server_name_indication,
    :use_ticket,
    :max_fragment_length,
    :cb_info,
    :protocol,
    :fallback,
    :cookie,
    :log_alert,
    :reuse_session,
    :key_update_at
  ]

  @spec build(keyword()) :: {:ok, t()} | {:error, term()}
  def build(options) when is_list(options) do
    with :ok <- check_shape(options),
         :ok <- reject_unsupported(options),
         :ok <- versions(Keyword.get(options, :versions)),
         {:ok, identity_opts} <- identity_options(options),
         {:ok, identity} <- load_identity(identity_opts),
         {:ok, sni} <- sni(options),
         :ok <- identity_present(identity, sni),
         {:ok, ciphers} <- ciphers(Keyword.get(options, :ciphers)),
         {:ok, groups} <- Config.algorithms([], :groups, :group, Config.ids(:group)),
         {:ok, signatures} <-
           Config.algorithms(
             [],
             :signature_algorithms,
             :signature_algorithm,
             Config.ids(:signature_algorithm)
           ),
         {:ok, limits} <- Config.limits([]),
         {:ok, alpn} <- alpn(Keyword.get(options, :alpn_preferred_protocols)),
         {:ok, client_auth} <- client_auth(options) do
      {:ok,
       %{
         ciphers: ciphers,
         groups: groups,
         alpn: alpn,
         signature_algorithms: filter_signatures(signatures, identity),
         identity: identity,
         limits: limits,
         transport_parameters: nil,
         sni: sni,
         client_auth: client_auth,
         tcp: Keyword.drop(options, @own_keys ++ [:session_tickets, :reuse_sessions])
       }}
    end
  end

  def build(_), do: {:error, {:invalid_option, :options}}

  defp check_shape(options) do
    if Keyword.keyword?(options), do: :ok, else: {:error, {:invalid_option, :options}}
  end

  defp reject_unsupported(options) do
    cond do
      key = Enum.find(@unsupported, &Keyword.has_key?(options, &1)) ->
        {:error, {:unsupported_option, key}}

      Keyword.get(options, :session_tickets, :disabled) != :disabled ->
        {:error, {:unsupported_option, :session_tickets}}

      Keyword.get(options, :reuse_sessions, false) not in [false, nil] ->
        {:error, {:unsupported_option, :reuse_sessions}}

      true ->
        :ok
    end
  end

  defp versions(nil), do: :ok
  defp versions([:"tlsv1.3"]), do: :ok
  defp versions(_), do: {:error, {:unsupported_option, :versions}}

  defp identity_options(options) do
    base = Keyword.take(options, @identity_keys)

    case Keyword.fetch(options, :certs_keys) do
      {:ok, [entry | _]} when is_map(entry) ->
        {:ok, base |> Keyword.drop(Map.keys(entry)) |> Kernel.++(Map.to_list(entry))}

      {:ok, _} ->
        {:error, {:invalid_option, :certs_keys}}

      :error ->
        {:ok, base}
    end
  end

  defp load_identity(opts) do
    case ClientIdentity.load(opts) do
      {:ok, %ClientIdentity{} = identity} -> {:ok, identity}
      {:ok, nil} -> {:ok, nil}
      {:error, _} = error -> error
      _ -> {:error, {:invalid_option, :certs_keys}}
    end
  end

  defp sni(options) do
    case {Keyword.get(options, :sni_hosts), Keyword.get(options, :sni_fun)} do
      {nil, nil} -> {:ok, nil}
      {hosts, nil} when is_list(hosts) -> sni_hosts(hosts)
      {nil, fun} when is_function(fun, 1) -> {:ok, {:fun, fun}}
      {nil, _} -> {:error, {:invalid_option, :sni_fun}}
      {_, nil} -> {:error, {:invalid_option, :sni_hosts}}
      _ -> {:error, {:invalid_option, :sni_fun}}
    end
  end

  defp sni_hosts(hosts) do
    if Enum.all?(hosts, &match?({host, opts} when is_list(host) and is_list(opts), &1)) do
      {:ok, {:hosts, Map.new(hosts)}}
    else
      {:error, {:invalid_option, :sni_hosts}}
    end
  end

  defp identity_present(nil, nil), do: {:error, :server_identity_required}
  defp identity_present(_, _), do: :ok

  defp ciphers(nil), do: {:ok, tls13_ids()}

  defp ciphers(list) when is_list(list) and list != [] do
    ids = Enum.map(list, &(Capabilities.resolve(:cipher_suite, &1) || %{id: nil}).id)

    if ids == Enum.uniq(ids) and Enum.all?(ids, &(&1 in tls13_ids())),
      do: {:ok, ids},
      else: {:error, {:invalid_option, :ciphers}}
  end

  defp ciphers(_), do: {:error, {:invalid_option, :ciphers}}

  defp tls13_ids, do: Capabilities.cipher_ids(0x0304)

  defp alpn(nil), do: {:ok, nil}

  defp alpn(list) when is_list(list) and list != [] do
    if Enum.all?(list, &(is_binary(&1) and byte_size(&1) in 1..255)) and
         list == Enum.uniq(list),
       do: {:ok, list},
       else: {:error, {:invalid_option, :alpn_preferred_protocols}}
  end

  defp alpn(_), do: {:error, {:invalid_option, :alpn_preferred_protocols}}

  defp filter_signatures(signatures, nil), do: signatures

  defp filter_signatures(signatures, identity),
    do: Enum.filter(signatures, &(&1 in identity.signature_schemes))

  defp client_auth(options) do
    case Keyword.get(options, :verify, :verify_none) do
      :verify_none -> {:ok, nil}
      :verify_peer -> verify_peer(options)
      _ -> {:error, {:invalid_option, :verify}}
    end
  end

  defp verify_peer(options) do
    source = Keyword.get(options, :cacerts) || cacertfile(Keyword.get(options, :cacertfile))
    require? = Keyword.get(options, :fail_if_no_peer_cert, false)
    depth = Keyword.get(options, :depth, 10)

    with true <- not is_nil(source) or {:error, {:invalid_option, :cacerts}},
         true <- is_boolean(require?) or {:error, {:invalid_option, :fail_if_no_peer_cert}},
         true <- (is_integer(depth) and depth > 0) or {:error, {:invalid_option, :depth}},
         {:ok, trust} <- PKIX.normalize_trust(source) do
      {:ok, %{trust: trust, require: require?, depth: depth}}
    else
      {:error, {:invalid_option, _}} = error -> error
      {:error, _} -> {:error, {:invalid_option, :cacerts}}
    end
  end

  defp cacertfile(nil), do: nil

  defp cacertfile(path) do
    case File.read(path) do
      {:ok, pem} -> pem
      {:error, _} -> :unreadable
    end
  end
end
