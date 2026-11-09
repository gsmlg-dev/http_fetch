defmodule SSL.Protocol.ServerHandshake do
  @moduledoc """
  Record-free TLS 1.3 full-certificate server handshake operations.

  A non-nil `config.transport_parameters` selects QUIC rules: the ClientHello
  must carry ext 57 and ALPN and an empty legacy session id, and
  EncryptedExtensions echoes the local transport parameters. With `nil` (TCP),
  ALPN is optional and a middlebox-compatibility session id is echoed.

  A non-nil `config.client_auth` on a full TCP handshake requests a client
  certificate (RFC 8446 §4.3.2). The phase then advances
  `:client_certificate -> :client_certificate_verify -> :finished`, and only
  `:finished` admits the client Finished.
  """
  alias SSL.Capabilities
  alias SSL.Crypto.{Finished, KeySchedule, Signature}
  alias SSL.PKIX
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.Protocol.{ClientOffer, HandshakeCore, ServerFlight, Transcript}

  @hrr_random Base.decode16!("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

  defmodule State do
    @moduledoc false
    @derive {Inspect, only: [:phase, :suite, :group, :alpn]}
    defstruct [
      :phase,
      :suite,
      :group,
      :alpn,
      :scheme,
      :offer,
      :transcript,
      :secrets,
      :peer_parameters,
      :first_offer,
      :application_secrets,
      :session,
      :client_auth,
      :client_schemes,
      :peer,
      early_data: false
    ]

    @type t :: %__MODULE__{}
  end

  @spec accept_hello(map(), binary(), State.t() | nil) ::
          {:ok, State.t()} | {:retry, State.t(), binary()} | {:error, term()}
  def accept_hello(config, encoded, previous) do
    quic? = not is_nil(config.transport_parameters)

    with {:ok, offer} <- parse_offer(encoded, config.limits),
         :ok <- validate_offer(offer, quic?),
         :ok <- validate_retry(previous, offer),
         {:ok, suite} <- select(config.ciphers, offer.cipher_suites, :no_shared_cipher),
         {:ok, group} <- select(config.groups, offer.supported_groups, :no_shared_group),
         {:ok, alpn} <- select_alpn(config.alpn, offer.alpn_protocols, quic?),
         {:ok, scheme} <-
           select(config.signature_algorithms, offer.signature_schemes, :no_shared_signature),
         true <- not quic? or chain_compatible?(config, offer),
         {:ok, parameters} <- if(quic?, do: parameters(offer.extensions), else: {:ok, nil}) do
      spec = Capabilities.resolve(:cipher_suite, suite)
      transcript = if previous, do: previous.transcript, else: Transcript.new(spec.hash)

      state = %State{
        phase: :hello,
        session: if(previous, do: previous.session),
        suite: suite,
        group: group,
        alpn: alpn,
        scheme: scheme,
        offer: offer,
        transcript: Transcript.append(transcript, encoded),
        peer_parameters: parameters
      }

      if Enum.any?(offer.key_shares, &(&1.group == group)) do
        {:ok, state}
      else
        if previous do
          {:error, {:illegal_parameter, :missing_retry_key_share}}
        else
          bytes =
            hello(@hrr_random, offer.legacy_session_id, suite, [
              {43, <<0x0304::16>>},
              {51, <<group::16>>}
            ])

          transcript =
            state.transcript
            |> Transcript.apply_hello_retry_request_rewrite()
            |> Transcript.append(bytes)

          {:retry, %{state | phase: :retry, first_offer: offer, transcript: transcript}, bytes}
        end
      end
    else
      false -> {:error, {:handshake_failure, :certificate_signature_policy}}
      {:error, _} = error -> error
    end
  end

  # RFC 8446 §4.4.2.2: a TCP server whose chain does not match the client's
  # signature_algorithms(_cert) SHOULD continue with it; QUIC keeps the hard check.
  defp chain_compatible?(config, offer) do
    CertificateSignaturePolicy.compatible?(
      config.identity.chain,
      nil,
      offer.certificate_signature_schemes || offer.signature_schemes
    )
  end

  @spec flight(State.t(), map(), SSL.Crypto.KeyExchange.KeyPair.t(), binary()) ::
          {:ok, State.t(), binary(), [binary()]} | {:error, term()}
  def flight(state, config, pair, random) do
    %{key_exchange: public} = Enum.find(state.offer.key_shares, &(&1.group == state.group))
    spec = Capabilities.resolve(:cipher_suite, state.suite)

    hello =
      hello(
        random,
        state.offer.legacy_session_id,
        state.suite,
        [
          {43, <<0x0304::16>>},
          {51, <<state.group::16, byte_size(pair.public_key)::16, pair.public_key::binary>>}
        ] ++ if(state.session, do: [{41, <<0::16>>}], else: [])
      )

    transcript = Transcript.append(state.transcript, hello)

    ee =
      message(
        8,
        extensions(
          alpn_extension(state.alpn) ++
            transport_parameters_extension(config.transport_parameters) ++
            if(state.early_data, do: [{42, <<>>}], else: [])
        )
      )

    psk = if state.session, do: state.session.psk
    # QUIC servers do not authenticate clients (SSL.QUIC reports server_mtls: false).
    client_auth =
      if state.session || config.transport_parameters,
        do: nil,
        else: Map.get(config, :client_auth)

    client_schemes = if client_auth, do: client_schemes()

    with {:ok, secrets} <- HandshakeCore.derive_secrets(pair, public, spec.name, transcript, psk),
         transcript = Transcript.append(transcript, ee),
         {:ok, request} <- certificate_request(client_auth, client_schemes),
         transcript = Enum.reduce(request, transcript, &Transcript.append(&2, &1)),
         {:ok, transcript, authentication} <- authentication(state, config, spec, transcript),
         {:ok, verify_data} <-
           Finished.client_verify_data(
             spec.hash,
             secrets.server_handshake_secret,
             Transcript.digest(transcript)
           ),
         {:ok, finished} <- ServerFlight.encode_finished(verify_data, hash: spec.hash),
         transcript = Transcript.append(transcript, finished),
         {:ok, client_application} <-
           KeySchedule.client_application_traffic_secret(
             spec.hash,
             secrets.master_secret,
             Transcript.digest(transcript)
           ),
         {:ok, server_application} <-
           KeySchedule.server_application_traffic_secret(
             spec.hash,
             secrets.master_secret,
             Transcript.digest(transcript)
           ) do
      # Only the client handshake secret is needed after exporting the other epochs.
      next = %{
        state
        | phase: if(client_auth, do: :client_certificate, else: :finished),
          client_auth: client_auth,
          client_schemes: client_schemes,
          transcript: transcript,
          secrets: secrets,
          application_secrets: %{client: client_application, server: server_application}
      }

      {:ok, next, hello, [ee] ++ request ++ authentication ++ [finished]}
    end
  end

  # The CertificateRequest advertises every locally verifiable TLS 1.3 scheme,
  # independent of the server identity; certificate_authorities only when small.
  defp client_schemes,
    do:
      :signature_algorithm
      |> Capabilities.identifiers()
      |> Enum.filter(&Capabilities.tls13_signature_scheme?/1)

  defp certificate_request(nil, _schemes), do: {:ok, []}

  defp certificate_request(client_auth, schemes) do
    algorithms = for scheme <- schemes, into: <<>>, do: <<scheme::16>>

    extensions =
      [{13, <<byte_size(algorithms)::16, algorithms::binary>>}] ++
        authorities_extension(client_auth.trust)

    with {:ok, request} <- ServerFlight.encode_certificate_request(<<>>, extensions),
         do: {:ok, [request]}
  end

  @max_authorities 64
  @max_authorities_bytes 16_384

  defp authorities_extension(trust) when length(trust) > @max_authorities, do: []

  defp authorities_extension(trust) do
    names =
      for %{der: der} <- trust, into: <<>> do
        {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(der, :plain)
        name = :public_key.der_encode(:Name, elem(tbs, 6))
        <<byte_size(name)::16, name::binary>>
      end

    if byte_size(names) <= @max_authorities_bytes,
      do: [{47, <<byte_size(names)::16, names::binary>>}],
      else: []
  end

  defp alpn_extension(nil), do: []

  defp alpn_extension(alpn),
    do: [{16, <<byte_size(alpn) + 1::16, byte_size(alpn), alpn::binary>>}]

  defp transport_parameters_extension(nil), do: []
  defp transport_parameters_extension(parameters), do: [{57, parameters}]

  defp authentication(%{session: session}, _config, _spec, transcript) when not is_nil(session),
    do: {:ok, transcript, []}

  defp authentication(state, config, spec, transcript) do
    with {:ok, certificate} <-
           ServerFlight.encode_client_certificate(<<>>, config.identity.chain),
         transcript = Transcript.append(transcript, certificate),
         {:ok, signature} <-
           Signature.sign_server(
             state.scheme,
             config.identity.private_key,
             spec.hash,
             Transcript.digest(transcript)
           ),
         {:ok, cv} <- ServerFlight.encode_client_certificate_verify(state.scheme, signature) do
      {:ok, Transcript.append(transcript, cv), [certificate, cv]}
    end
  end

  @doc """
  Accepts the client Certificate answering a CertificateRequest.

  An empty list is `certificate_required` when the certificate is required and
  otherwise skips CertificateVerify. A non-empty chain is validated against the
  configured trust anchors and `depth`, with no service identity check.
  """
  @spec accept_client_certificate(State.t(), binary()) :: {:ok, State.t()} | {:error, term()}
  def accept_client_certificate(%State{phase: :client_certificate} = state, encoded) do
    {:ok, empty} = ServerFlight.encode_empty_certificate(<<>>)

    cond do
      encoded != empty ->
        verify_client_certificate(state, encoded)

      state.client_auth.require ->
        {:error, {:certificate_required, :empty_client_certificate}}

      true ->
        {:ok,
         %{state | phase: :finished, transcript: Transcript.append(state.transcript, encoded)}}
    end
  end

  def accept_client_certificate(_state, _encoded),
    do: {:error, {:unexpected_message, :unexpected_client_certificate}}

  defp verify_client_certificate(state, encoded) do
    with {:ok, %ServerFlight.Certificate{entries: entries}} <-
           decode(encoded, ServerFlight.Certificate, hash: state.secrets.hash),
         :ok <- no_entry_extensions(entries),
         {:ok, peer} <- client_peer(Enum.map(entries, & &1.der), state.client_auth) do
      {:ok,
       %{
         state
         | phase: :client_certificate_verify,
           peer: peer,
           transcript: Transcript.append(state.transcript, encoded)
       }}
    end
  end

  # No CertificateRequest extension solicits per-entry client extensions.
  defp no_entry_extensions(entries) do
    if Enum.all?(entries, &(&1.extensions == [])),
      do: :ok,
      else: {:error, {:unsupported_extension, :unsolicited_certificate_extension}}
  end

  defp client_peer(chain, client_auth) do
    case PKIX.client_peer(chain, client_auth.trust, depth: client_auth.depth) do
      {:ok, peer} -> {:ok, peer}
      {:error, reason} -> HandshakeCore.certificate_alert(reason)
    end
  end

  @doc """
  Accepts the client CertificateVerify over the transcript through the client
  Certificate. Its scheme must be one the CertificateRequest offered.
  """
  @spec accept_client_certificate_verify(State.t(), binary()) ::
          {:ok, State.t()} | {:error, term()}
  def accept_client_certificate_verify(%State{phase: :client_certificate_verify} = state, encoded) do
    options = [hash: state.secrets.hash, allowed_signature_schemes: state.client_schemes]

    with {:ok, %ServerFlight.CertificateVerify{} = verify} <-
           decode(encoded, ServerFlight.CertificateVerify, options),
         :ok <- verify_client_signature(state, verify) do
      {:ok, %{state | phase: :finished, transcript: Transcript.append(state.transcript, encoded)}}
    end
  end

  def accept_client_certificate_verify(_state, _encoded),
    do: {:error, {:unexpected_message, :unexpected_client_certificate_verify}}

  defp verify_client_signature(state, verify) do
    case Signature.verify_client(
           verify.signature_scheme,
           state.peer.public_key,
           state.transcript.hash,
           Transcript.digest(state.transcript),
           verify.signature
         ) do
      :ok -> :ok
      {:error, reason} -> {:error, {signature_alert(reason), reason}}
    end
  end

  # A scheme that does not fit the client certificate key is illegal_parameter;
  # a signature that does not verify is decrypt_error (RFC 8446 §4.4.3).
  defp signature_alert({:key_type_mismatch, _}), do: :illegal_parameter
  defp signature_alert({:unsupported_ec_curve, _}), do: :illegal_parameter
  defp signature_alert(:invalid_public_key), do: :illegal_parameter
  defp signature_alert(:invalid_rsa_pss_parameters), do: :illegal_parameter
  defp signature_alert(_reason), do: :decrypt_error

  defp decode(encoded, module, options) do
    case ServerFlight.decode(encoded, options) do
      {:ok, %{__struct__: ^module} = message, <<>>} ->
        {:ok, message}

      {:ok, _message, <<>>} ->
        {:error, {:unexpected_message, {:expected, module}}}

      {:error, {:unsupported_signature_scheme, scheme}} ->
        {:error, {:illegal_parameter, {:signature_scheme_not_offered, scheme}}}

      {:error, reason} ->
        HandshakeCore.decode_alert(reason)

      _ ->
        {:error, {:decode_error, :malformed_handshake_message}}
    end
  end

  @spec finish(State.t(), binary()) :: :ok | {:error, term()}
  def finish(%State{phase: phase}, _encoded) when phase != :finished,
    do: {:error, {:unexpected_message, :expected_client_authentication}}

  def finish(state, encoded) do
    with {:ok, %ServerFlight.Finished{verify_data: verify_data}, <<>>} <-
           ServerFlight.decode(encoded, hash: state.secrets.hash),
         :ok <-
           Finished.verify_server(
             state.secrets.hash,
             state.secrets.client_handshake_secret,
             Transcript.digest(state.transcript),
             verify_data
           ) do
      :ok
    else
      {:error, reason} -> {:error, {:decrypt_error, reason}}
      _ -> {:error, {:unexpected_message, :expected_client_finished}}
    end
  end

  @spec parameters(list()) :: {:ok, binary()} | {:error, term()}
  def parameters(extensions) do
    case List.keyfind(extensions, 57, 0) do
      {57, bytes} -> {:ok, bytes}
      nil -> {:error, {:missing_extension, :quic_transport_parameters}}
    end
  end

  defp parse_offer(encoded, limits) do
    case ClientOffer.from_client_hello(encoded) do
      {:ok, offer} ->
        size = Enum.reduce(offer.extensions, 0, fn {_, bytes}, n -> n + 4 + byte_size(bytes) end)

        if size <= limits[:max_extension_bytes],
          do: {:ok, offer},
          else: {:error, {:decode_error, :extension_length_exceeded}}

      {:error, reason} ->
        {:error, {:decode_error, reason}}
    end
  end

  defp select(local, offered, reason) do
    case Enum.find(local, &(&1 in offered)) do
      nil ->
        {:error,
         {if(reason == :no_application_protocol, do: reason, else: :handshake_failure), reason}}

      value ->
        {:ok, value}
    end
  end

  # RFC 7301 §3.2: an ALPN offer without overlap is fatal; no offer selects none.
  # QUIC (RFC 9001 §8.1) always requires ALPN.
  defp select_alpn(nil, _offered, _quic?), do: {:ok, nil}
  defp select_alpn(_local, [], false), do: {:ok, nil}
  defp select_alpn(local, offered, _quic?), do: select(local, offered, :no_application_protocol)

  defp validate_offer(offer, quic?) do
    shares = Enum.map(offer.key_shares, & &1.group)

    cond do
      0x0304 not in offer.offered_versions ->
        {:error, {:protocol_version, :tls13_required}}

      quic? and offer.legacy_session_id != <<>> ->
        {:error, {:quic, :quic_session_id}}

      missing_negotiation_extensions?(offer) ->
        {:error, {:missing_extension, :negotiation_extensions}}

      shares != Enum.uniq(shares) ->
        {:error, {:illegal_parameter, :duplicate_key_share}}

      shares != Enum.filter(offer.supported_groups, &(&1 in shares)) ->
        {:error, {:illegal_parameter, :key_share_groups}}

      41 in offer.extension_ids and
          (List.last(offer.extension_ids) != 41 or 45 not in offer.extension_ids) ->
        {:error, {:illegal_parameter, :invalid_psk_offer}}

      42 in offer.extension_ids and
          (41 not in offer.extension_ids or List.keyfind(offer.extensions, 42, 0) != {42, <<>>}) ->
        {:error, {:illegal_parameter, :invalid_early_data_offer}}

      true ->
        :ok
    end
  end

  defp validate_retry(nil, offer) do
    if 44 in offer.extension_ids,
      do: {:error, {:illegal_parameter, :unsolicited_cookie}},
      else: :ok
  end

  defp validate_retry(previous, offer) do
    first = previous.first_offer

    cond do
      random(first.encoded) != random(offer.encoded) or
          first.legacy_session_id != offer.legacy_session_id ->
        {:error, {:illegal_parameter, :retry_client_hello_changed}}

      first.cipher_suites != offer.cipher_suites or
          stable_extensions(first) != stable_extensions(offer) ->
        {:error, {:illegal_parameter, :retry_client_hello_changed}}

      Enum.map(offer.key_shares, & &1.group) != [previous.group] ->
        {:error, {:illegal_parameter, :retry_key_share_changed}}

      42 in offer.extension_ids or 44 in offer.extension_ids ->
        {:error, {:illegal_parameter, :retry_extension}}

      not valid_retry_psk?(first, offer) ->
        {:error, {:illegal_parameter, :retry_psk_changed}}

      true ->
        :ok
    end
  end

  defp stable_extensions(offer),
    do: Enum.reject(offer.extensions, &(elem(&1, 0) in [21, 41, 42, 51]))

  defp random(<<1, _::24, _::16, random::binary-size(32), _::binary>>), do: random

  defp valid_retry_psk?(first, second) do
    original = psk_identities(first)
    offered = psk_identities(second)
    # Binders and ticket ages can change; remaining identities keep their order.
    offered == Enum.filter(original, &(&1 in offered))
  end

  defp psk_identities(offer) do
    case List.keyfind(offer.extensions, 41, 0) do
      nil -> []
      {41, <<size::16, identities::binary-size(size), _::binary>>} -> identities(identities)
    end
  end

  defp identities(<<>>), do: []

  defp identities(<<size::16, value::binary-size(size), _age::32, rest::binary>>),
    do: [value | identities(rest)]

  defp hello(random, session, suite, extensions) do
    message(
      2,
      <<0x0303::16, random::binary, byte_size(session), session::binary, suite::16, 0,
        extensions(extensions)::binary>>
    )
  end

  defp extensions(values) do
    bytes =
      IO.iodata_to_binary(
        Enum.map(values, fn {id, payload} ->
          <<id::16, byte_size(payload)::16, payload::binary>>
        end)
      )

    <<byte_size(bytes)::16, bytes::binary>>
  end

  defp message(type, body), do: <<type, byte_size(body)::24, body::binary>>

  defp missing_negotiation_extensions?(offer) do
    51 not in offer.extension_ids or 10 not in offer.extension_ids or
      offer.signature_schemes == [] or offer.supported_groups == []
  end
end
