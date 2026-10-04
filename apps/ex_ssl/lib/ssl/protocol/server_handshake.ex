defmodule SSL.Protocol.ServerHandshake do
  @moduledoc "Record-free TLS 1.3 full-certificate server handshake operations."
  alias SSL.Capabilities
  alias SSL.Crypto.{Finished, KeySchedule, Signature}
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
      :application_secrets
    ]

    @type t :: %__MODULE__{}
  end

  @spec accept_hello(map(), binary(), State.t() | nil) ::
          {:ok, State.t()} | {:retry, State.t(), binary()} | {:error, term()}
  def accept_hello(config, encoded, previous) do
    with {:ok, offer} <- parse_offer(encoded, config.limits),
         :ok <- validate_offer(offer),
         :ok <- validate_retry(previous, offer),
         {:ok, suite} <- select(config.ciphers, offer.cipher_suites, :no_shared_cipher),
         {:ok, group} <- select(config.groups, offer.supported_groups, :no_shared_group),
         {:ok, alpn} <- select(config.alpn, offer.alpn_protocols, :no_application_protocol),
         {:ok, scheme} <-
           select(config.signature_algorithms, offer.signature_schemes, :no_shared_signature),
         true <-
           SSL.PKIX.CertificateSignaturePolicy.compatible?(
             config.identity.chain,
             nil,
             offer.certificate_signature_schemes || offer.signature_schemes
           ),
         {:ok, parameters} <- parameters(offer.extensions) do
      spec = Capabilities.resolve(:cipher_suite, suite)
      transcript = if previous, do: previous.transcript, else: Transcript.new(spec.hash)

      state = %State{
        phase: :hello,
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

  @spec flight(State.t(), map(), SSL.Crypto.KeyExchange.KeyPair.t(), binary()) ::
          {:ok, State.t(), binary(), [binary()]} | {:error, term()}
  def flight(state, config, pair, random) do
    %{key_exchange: public} = Enum.find(state.offer.key_shares, &(&1.group == state.group))
    spec = Capabilities.resolve(:cipher_suite, state.suite)

    hello =
      hello(random, state.offer.legacy_session_id, state.suite, [
        {43, <<0x0304::16>>},
        {51, <<state.group::16, byte_size(pair.public_key)::16, pair.public_key::binary>>}
      ])

    transcript = Transcript.append(state.transcript, hello)

    ee =
      message(
        8,
        extensions([
          {16, <<byte_size(state.alpn) + 1::16, byte_size(state.alpn), state.alpn::binary>>},
          {57, config.transport_parameters}
        ])
      )

    with {:ok, secrets} <- HandshakeCore.derive_secrets(pair, public, spec.name, transcript),
         chain = config.identity.chain,
         {:ok, certificate} <- ServerFlight.encode_client_certificate(<<>>, chain),
         transcript = transcript |> Transcript.append(ee) |> Transcript.append(certificate),
         {:ok, signature} <-
           Signature.sign_server(
             state.scheme,
             config.identity.private_key,
             spec.hash,
             Transcript.digest(transcript)
           ),
         {:ok, cv} <- ServerFlight.encode_client_certificate_verify(state.scheme, signature),
         transcript = Transcript.append(transcript, cv),
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
        | phase: :finished,
          transcript: transcript,
          secrets: secrets,
          application_secrets: %{client: client_application, server: server_application}
      }

      {:ok, next, hello, [ee, certificate, cv, finished]}
    end
  end

  @spec finish(State.t(), binary()) :: :ok | {:error, term()}
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

  defp validate_offer(offer) do
    shares = Enum.map(offer.key_shares, & &1.group)

    cond do
      0x0304 not in offer.offered_versions ->
        {:error, {:protocol_version, :tls13_required}}

      offer.legacy_session_id != <<>> ->
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
