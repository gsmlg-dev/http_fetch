defmodule SSL.ServerOptions do
  @moduledoc false
  alias SSL.{Capabilities, ClientIdentity, PKIX}
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.QUIC.Config

  # sni_hosts identities are loaded at build time; sni_fun results per handshake.
  # sni_hosts keys are ASCII-lowercased (RFC 4343); sni_fun sees the name as sent.
  # Each name maps to its certs_keys identities in preference order.
  @type sni ::
          nil
          | {:hosts, %{charlist() => [ClientIdentity.t(), ...]}}
          | {:fun, (charlist() -> keyword() | :undefined)}
  @type t :: %{
          ciphers: [non_neg_integer()],
          groups: [non_neg_integer()],
          alpn: nil | [binary()],
          signature_algorithms: [non_neg_integer()],
          identity: term(),
          identities: [ClientIdentity.t()],
          limits: keyword(),
          transport_parameters: nil,
          sni: sni(),
          client_auth: nil | %{trust: term(), require: boolean(), depth: pos_integer()},
          active_chunk_size: pos_integer() | :infinity,
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
                :depth,
                :active_chunk_size
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
    :key_update_at,
    # Remaining OTP 28 ssl_config:ssl_options/0 and split_options/2 keys.
    :allow_any_ca_purpose,
    :client_preferred_next_protocols,
    :erl_dist,
    :ktls,
    :next_protocol_selector,
    :psk_groups,
    :ssl_imp,
    :stapling,
    :use_srtp
  ]

  @tls_keys @own_keys ++ [:session_tickets, :reuse_sessions]
  # Bare `:gen_tcp` address-family atoms, passed to the carrier in order.
  @carrier_atoms [:inet, :inet6, :local]

  @spec build([atom() | {atom(), term()}]) :: {:ok, t()} | {:error, term()}
  def build(options) when is_list(options) do
    # The carrier is always passive binary; a bare `:binary` is redundant.
    carrier = Enum.reject(options, &(&1 == :binary))
    options = Enum.reject(carrier, &(&1 in @carrier_atoms))

    with :ok <- check_shape(options),
         :ok <- reject_unsupported(options),
         :ok <- versions(Keyword.get(options, :versions)),
         {:ok, identities} <- identities(options),
         {:ok, sni} <- sni(options),
         :ok <- identity_present(identities, sni),
         {:ok, ciphers} <- ciphers(Keyword.get(options, :ciphers)),
         {:ok, groups} <- Config.algorithms([], :groups, :group, Config.ids(:group)),
         {:ok, signatures} <- signatures(),
         {:ok, limits} <- Config.limits([]),
         {:ok, alpn} <- alpn(Keyword.get(options, :alpn_preferred_protocols)),
         {:ok, client_auth} <- client_auth(options),
         {:ok, chunk} <- active_chunk_size(Keyword.get(options, :active_chunk_size, :infinity)) do
      identity = List.first(identities)

      {:ok,
       %{
         ciphers: ciphers,
         groups: groups,
         alpn: alpn,
         signature_algorithms: filter_signatures(signatures, identity),
         identity: identity,
         identities: identities,
         limits: limits,
         transport_parameters: nil,
         sni: sni,
         client_auth: client_auth,
         active_chunk_size: chunk,
         tcp: carrier_options(carrier)
       }}
    end
  end

  def build(_), do: {:error, {:invalid_option, :options}}

  defp carrier_options(options),
    do: Enum.reject(options, &match?({key, _} when key in @tls_keys, &1))

  @doc """
  Selects the identity for a ClientHello `server_name` (`nil` when absent).

  Order: `sni_hosts[name]`, then `sni_fun.(name)` (`:undefined` selects the
  default), then the default identities. `sni_hosts` matching is ASCII
  case-insensitive (RFC 4343); `sni_fun` receives the name as sent.

  Among the selected `certs_keys` identities, the first that can sign one of
  the offered `:signature_schemes` wins, preferring one whose chain also fits
  `:certificate_signature_schemes` (RFC 8446 §4.4.2.2); with no such identity
  the first is kept and the handshake fails with `no_shared_signature`. The
  returned config carries the selected identity and the schemes it can sign.

  `sni_fun` runs in a monitored helper process that is killed after
  `:timeout` (default `:infinity`), which then returns `{:error, :timeout}`.
  A raise, throw, exit or invalid result is an `internal_error`.
  """
  @spec select_identity(t(), charlist() | nil, keyword()) ::
          {:ok, t()} | {:error, :timeout | {atom(), term()}}
  def select_identity(config, name, offer \\ []) do
    case lookup(config.sni, name, Keyword.get(offer, :timeout, :infinity)) do
      {:ok, identities} -> choose(config, identities, offer)
      :default when config.identities != [] -> choose(config, config.identities, offer)
      :default -> {:error, {:unrecognized_name, :no_server_identity}}
      {:error, :timeout} -> {:error, :timeout}
      {:error, reason} -> {:error, {:internal_error, reason}}
    end
  end

  defp choose(config, identities, offer) do
    with {:ok, signatures} <- signatures() do
      identity = preferred(identities, signatures, offer)

      {:ok,
       %{
         config
         | identity: identity,
           signature_algorithms: filter_signatures(signatures, identity)
       }}
    end
  end

  defp preferred([identity], _signatures, _offer), do: identity

  defp preferred(identities, signatures, offer) do
    case Keyword.fetch(offer, :signature_schemes) do
      {:ok, offered} when is_list(offered) ->
        accepted = Keyword.get(offer, :certificate_signature_schemes) || offered

        signable =
          Enum.filter(identities, fn identity ->
            Enum.any?(filter_signatures(signatures, identity), &(&1 in offered))
          end)

        Enum.find(signable, &CertificateSignaturePolicy.compatible?(&1.chain, nil, accepted)) ||
          List.first(signable) || hd(identities)

      _ ->
        hd(identities)
    end
  end

  defp lookup(nil, _name, _timeout), do: :default
  defp lookup(_sni, nil, _timeout), do: :default

  defp lookup({:hosts, hosts}, name, _timeout) do
    case Map.fetch(hosts, ascii_downcase(name)) do
      {:ok, identities} -> {:ok, identities}
      :error -> :default
    end
  end

  # A blocking sni_fun must not outlive the handshake deadline: it runs in a
  # monitored helper that is killed when `timeout` expires.
  defp lookup({:fun, fun}, name, timeout) do
    parent = self()
    tag = make_ref()

    {pid, monitor} =
      spawn_monitor(fn ->
        Process.flag(:sensitive, true)
        send(parent, {tag, call_sni_fun(fun, name)})
      end)

    receive do
      {^tag, result} ->
        Process.demonitor(monitor, [:flush])
        result

      {:DOWN, ^monitor, :process, ^pid, _reason} ->
        {:error, {:sni_fun, :exit}}
    after
      timeout ->
        Process.exit(pid, :kill)
        Process.demonitor(monitor, [:flush])

        receive do
          {^tag, _result} -> :ok
        after
          0 -> :ok
        end

        {:error, :timeout}
    end
  end

  defp call_sni_fun(fun, name) do
    case fun.(name) do
      :undefined -> :default
      options -> host_identity(options)
    end
  catch
    kind, _ -> {:error, {:sni_fun, kind}}
  else
    {:error, _} -> {:error, {:sni_fun, :invalid_result}}
    result -> result
  end

  defp host_identity(options) do
    with true <- is_list(options) and Keyword.keyword?(options),
         true <- Enum.all?(Keyword.keys(options), &(&1 in [:certs_keys | @identity_keys])),
         {:ok, [_ | _] = identities} <- identities(options) do
      {:ok, identities}
    else
      _ -> {:error, :invalid_identity}
    end
  end

  defp signatures,
    do:
      Config.algorithms(
        [],
        :signature_algorithms,
        :signature_algorithm,
        Config.ids(:signature_algorithm)
      )

  defp check_shape(options) do
    cond do
      :list in options -> {:error, {:unsupported_option, :mode}}
      Keyword.keyword?(options) -> :ok
      true -> {:error, {:invalid_option, :options}}
    end
  end

  defp reject_unsupported(options) do
    cond do
      key = Enum.find(@unsupported, &Keyword.has_key?(options, &1)) ->
        {:error, {:unsupported_option, key}}

      Enum.any?(Keyword.get_values(options, :active), &(&1 != false)) ->
        {:error, {:unsupported_option, :active}}

      Enum.any?(Keyword.get_values(options, :mode), &(&1 != :binary)) ->
        {:error, {:unsupported_option, :mode}}

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

  # Every certs_keys entry is loaded and validated, in preference order.
  defp identities(options) do
    base = Keyword.take(options, @identity_keys)

    case Keyword.fetch(options, :certs_keys) do
      {:ok, [_ | _] = entries} ->
        load_entries(base, entries, [])

      {:ok, _} ->
        {:error, {:invalid_option, :certs_keys}}

      :error ->
        with {:ok, identity} <- load_identity(base), do: {:ok, List.wrap(identity)}
    end
  end

  defp load_entries(_base, [], acc), do: {:ok, Enum.reverse(acc)}

  defp load_entries(base, [entry | rest], acc) when is_map(entry) do
    options = base |> Keyword.drop(Map.keys(entry)) |> Kernel.++(Map.to_list(entry))

    case load_identity(options) do
      {:ok, %ClientIdentity{} = identity} -> load_entries(base, rest, [identity | acc])
      {:ok, nil} -> {:error, {:invalid_option, :certs_keys}}
      {:error, _} = error -> error
    end
  end

  defp load_entries(_base, _entries, _acc), do: {:error, {:invalid_option, :certs_keys}}

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

  # Names that differ only in ASCII case are duplicates.
  defp sni_hosts(hosts) do
    names = Enum.map(hosts, &elem_or_nil/1)

    with true <- Enum.all?(names, &is_list/1),
         keys = Enum.map(names, &ascii_downcase/1),
         true <- keys == Enum.uniq(keys),
         {:ok, identities} <- load_hosts(hosts, []) do
      {:ok, {:hosts, Map.new(identities)}}
    else
      _ -> {:error, {:invalid_option, :sni_hosts}}
    end
  end

  defp elem_or_nil({host, _options}), do: host
  defp elem_or_nil(_), do: nil

  defp ascii_downcase(name), do: Enum.map(name, &if(&1 in ?A..?Z, do: &1 + 32, else: &1))

  defp load_hosts([], acc), do: {:ok, acc}

  defp load_hosts([{host, options} | rest], acc) do
    with {:ok, identities} <- host_identity(options),
         do: load_hosts(rest, [{ascii_downcase(host), identities} | acc])
  end

  defp identity_present([], nil), do: {:error, :server_identity_required}

  defp identity_present([], {:hosts, hosts}) when map_size(hosts) == 0,
    do: {:error, :server_identity_required}

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

  defp active_chunk_size(:infinity), do: {:ok, :infinity}
  defp active_chunk_size(size) when is_integer(size) and size > 0, do: {:ok, size}
  defp active_chunk_size(_), do: {:error, {:invalid_option, :active_chunk_size}}

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
