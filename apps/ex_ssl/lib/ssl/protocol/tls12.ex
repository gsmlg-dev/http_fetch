defmodule SSL.Protocol.TLS12 do
  @moduledoc "Pure, bounded TLS 1.2 ECDHE/EMS client protocol engine."

  alias SSL.Crypto.{KeyExchange, Signature, TLS12KeySchedule}
  alias SSL.Protocol.{ClientAuthentication, HandshakeFramer, TLS12Codec, TLS12Record, Transcript}
  alias SSL.Protocol.ServerFlight.CertificateRequest

  @ccs <<20, 3, 3, 0, 1, 1>>
  @maximum_transcript 1_048_576
  @derive {Inspect, only: [:phase, :suite, :negotiated_protocol]}
  defstruct [
    :offer,
    :trust,
    :identity,
    :client_identity,
    :client_random,
    :server_random,
    :suite,
    :peer,
    :pending_chain,
    :status_negotiated,
    :key_pair,
    :premaster,
    :master_secret,
    :session,
    :session_id,
    :read_state,
    :write_state,
    :request,
    :negotiated_protocol,
    :transcript,
    :framer,
    resumed: false,
    save_session: false,
    phase: :await_server_hello,
    options: []
  ]

  @type t :: %__MODULE__{}

  @spec new(binary(), SSL.Protocol.ClientOffer.t(), term(), term(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def new(
        <<1, _::24, 3, 3, random::binary-size(32), _::binary>> = hello,
        offer,
        trust,
        identity,
        options
      ) do
    if 0x0303 in offer.offered_versions do
      {:ok,
       %__MODULE__{
         offer: offer,
         trust: trust,
         identity: identity,
         client_random: random,
         client_identity: Keyword.get(options, :client_identity),
         session: Keyword.get(options, :tls12_session),
         save_session: Keyword.get(options, :enable_session, false),
         options: Keyword.drop(options, [:client_identity, :tls12_session, :enable_session]),
         transcript: Transcript.new(:sha256) |> Transcript.append(hello),
         framer: HandshakeFramer.new()
       }}
    else
      fatal(:protocol_version, :tls12_not_offered)
    end
  end

  def new(_, _, _, _, _), do: fatal(:decode_error, :invalid_client_hello)

  @spec feed(t(), binary()) :: {:ok, t(), [binary()], [term()]} | {:error, term()}
  def feed(state, record), do: elem(feed_with_progress(state, record), 0)

  @doc false
  def feed_with_progress(state, record),
    do: progress(state, feed_record(state, record))

  defp feed_record(%{phase: :await_server_ccs} = state, @ccs) do
    if HandshakeFramer.buffered_size(state.framer) == 0,
      do: {:ok, %{state | phase: :await_server_finished}, [], []},
      else: fatal(:unexpected_message, :fragment_across_ccs)
  end

  defp feed_record(_state, <<20, _::binary>>),
    do: fatal(:unexpected_message, :invalid_change_cipher_spec)

  defp feed_record(%{phase: phase} = state, record)
       when phase in [:await_server_finished, :connected, :closed] do
    case TLS12Record.decrypt(state.read_state, record) do
      {:ok, :handshake, bytes, read} when phase == :await_server_finished ->
        handshake_bytes(%{state | read_state: read}, bytes)

      {:ok, :application_data, bytes, read} when phase == :connected ->
        {:ok, %{state | read_state: read}, [], [{:application_data, bytes}]}

      {:ok, :alert, <<level, 0>>, read} when level in [1, 2] and phase == :connected ->
        {:ok, %{state | read_state: read, phase: :closed}, [], [:closed]}

      {:ok, :alert, <<level, description>>, _} ->
        {:error, {:peer_alert, level, description}}

      {:ok, _, _, _} ->
        fatal(:unexpected_message, :unexpected_tls12_record)

      {:error, reason} ->
        record_error(reason)
    end
  end

  defp feed_record(_state, <<21, 3, 3, 2::16, level, description>>),
    do: {:error, {:peer_alert, level, description}}

  defp feed_record(state, <<22, 3, 3, length::16, bytes::binary-size(length)>>)
       when length <= 16_384,
       do: handshake_bytes(state, bytes)

  defp feed_record(_, _), do: fatal(:unexpected_message, :invalid_tls12_record)

  defp handshake_bytes(state, bytes) do
    case HandshakeFramer.feed(state.framer, bytes, max_handshake_length: 524_336) do
      {:ok, messages, framer} ->
        run_handshakes(state, messages, framer)

      {:error, reason} ->
        fatal(:decode_error, reason)
    end
  end

  @doc false
  def feed_handshakes(state, messages, framer),
    do: elem(feed_handshakes_with_progress(state, messages, framer), 0)

  @doc false
  def feed_handshakes_with_progress(state, messages, framer),
    do: progress(state, run_handshakes(state, messages, framer))

  defp run_handshakes(state, messages, framer) do
    Enum.reduce_while(messages, {:ok, %{state | framer: framer}, [], []}, fn encoded,
                                                                             {:ok, current, out,
                                                                              events} ->
      with true <-
             current.transcript != nil and
               current.transcript.length + byte_size(encoded) <= @maximum_transcript,
           {:ok, message} <- TLS12Codec.decode(encoded),
           {:ok, next, records, emitted} <- process(current, message) do
        {:cont, {:ok, next, out ++ records, events ++ emitted}}
      else
        false ->
          {:halt,
           failed(current, fatal(:unexpected_message, :tls12_transcript_limit_or_complete))}

        {:error, {:fatal_alert, _, _}} = error ->
          {:halt, failed(current, error)}

        {:error, reason} ->
          {:halt, failed(current, fatal(:decode_error, reason))}
      end
    end)
    |> check_boundary()
  end

  defp check_boundary({:ok, %{phase: phase, framer: framer} = state, _, _} = result)
       when phase in [:await_server_ccs, :connected] do
    if HandshakeFramer.buffered_size(framer) == 0,
      do: result,
      else: failed(state, fatal(:unexpected_message, :fragment_across_epoch))
  end

  defp check_boundary(result), do: result

  defp progress(_state, {:ok, next, _out, _events} = result),
    do: {result, accepted_hello?(next)}

  defp progress(_state, {:error, reason, accepted}), do: {{:error, reason}, accepted}
  defp progress(state, result), do: {result, accepted_hello?(state)}

  defp failed(state, {:error, reason}), do: {:error, reason, accepted_hello?(state)}

  defp accepted_hello?(%__MODULE__{suite: suite, server_random: random}),
    do: not is_nil(suite) and is_binary(random) and byte_size(random) == 32

  defp accepted_hello?(_), do: false

  defp process(%{phase: :await_server_hello} = state, %{type: :server_hello} = hello) do
    with {:ok, suite} <- TLS12KeySchedule.suite(hello.cipher_suite),
         :ok <- validate_hello(state, hello),
         {:ok, alpn} <- server_extensions(state.offer, hello.extensions) do
      next = %{
        state
        | suite: suite,
          server_random: hello.random,
          negotiated_protocol: alpn,
          status_negotiated: {5, <<>>} in hello.extensions,
          session_id: hello.session_id,
          transcript: %{state.transcript | hash: suite.hash},
          phase: :await_certificate
      }

      select_session(append(next, hello.encoded), hello)
    else
      {:error, {:fatal_alert, _, _}} = error -> error
      {:error, reason} -> fatal(:illegal_parameter, reason)
    end
  end

  defp process(
         %{phase: :await_certificate} = state,
         %{type: :certificate, chain: chain} = message
       ) do
    state = append(state, message.encoded)

    if 5 in state.offer.extension_ids do
      {:ok, %{state | pending_chain: chain, phase: :await_certificate_status}, [], []}
    else
      verify_certificate(state, chain, [])
    end
  end

  defp process(
         %{phase: :await_certificate_status, status_negotiated: true} = state,
         %{type: :certificate_status, response: response} = message
       ) do
    verify_certificate(append(state, message.encoded), state.pending_chain, [
      {hd(state.pending_chain), response}
    ])
  end

  defp process(
         %{phase: :await_certificate_status} = state,
         %{type: :server_key_exchange} = message
       ) do
    with {:ok, next, [], []} <- verify_certificate(state, state.pending_chain, []),
         do: process(next, message)
  end

  defp process(
         %{phase: :await_server_key_exchange} = state,
         %{type: :server_key_exchange} = message
       ) do
    with true <- message.group in state.offer.supported_groups,
         true <- message.scheme in state.offer.signature_schemes,
         %{key: key} <- SSL.Capabilities.signature(message.scheme, :tls12),
         true <- signature_key_matches?(state.suite.key_exchange, key),
         %{name: group} <- SSL.Capabilities.resolve(:group, message.group),
         :ok <-
           Signature.verify_message(
             message.scheme,
             state.peer.public_key,
             state.client_random <> state.server_random <> message.parameters,
             message.signature
           ),
         {:ok, pair} <- KeyExchange.generate(group),
         {:ok, secret} <- KeyExchange.shared_secret(pair, message.public_key) do
      {:ok,
       append(
         %{state | key_pair: pair, premaster: secret, phase: :await_request_or_done},
         message.encoded
       ), [], []}
    else
      _ -> fatal(:decrypt_error, :invalid_server_key_exchange)
    end
  end

  defp process(%{phase: :await_request_or_done} = state, %{type: :certificate_request} = request),
    do:
      {:ok, append(%{state | request: request, phase: :await_server_hello_done}, request.encoded),
       [], []}

  defp process(%{phase: phase} = state, %{type: :server_hello_done} = message)
       when phase in [:await_request_or_done, :await_server_hello_done],
       do: client_flight(append(state, message.encoded))

  defp process(
         %{phase: :await_server_finished} = state,
         %{type: :finished, verify_data: received} = message
       ) do
    with {:ok, expected} <-
           TLS12KeySchedule.finished(state.suite.id, state.master_secret, :server, bytes(state)),
         true <- :crypto.hash_equals(expected, received) do
      finish_connection(state, message.encoded)
    else
      _ -> fatal(:decrypt_error, :invalid_finished)
    end
  end

  defp process(_, _), do: fatal(:unexpected_message, :unexpected_tls12_handshake)

  defp select_session(state, hello) do
    if hello.session_id != <<>> and hello.session_id == state.offer.legacy_session_id do
      case state.session do
        %SSL.TLS12Session{id: id, suite: suite} = session
        when id == hello.session_id and suite == hello.cipher_suite ->
          with :ok <- SSL.TLS12Session.validate(session),
               {:ok, keys} <-
                 TLS12KeySchedule.resume(
                   suite,
                   session.master_secret,
                   state.client_random,
                   state.server_random
                 ) do
            {:ok,
             %{
               state
               | read_state: keys.read_state,
                 write_state: keys.write_state,
                 master_secret: keys.master_secret,
                 peer: session.peer,
                 # RFC 7301 section 3.1: only this handshake's ALPN applies.
                 session: %{session | alpn: state.negotiated_protocol},
                 client_identity: nil,
                 resumed: true,
                 phase: :await_server_ccs
             }, [], []}
          else
            _ -> fatal(:illegal_parameter, :invalid_tls12_session)
          end

        _ ->
          fatal(:illegal_parameter, :tls12_session_mismatch)
      end
    else
      {:ok, %{state | session: nil}, [], []}
    end
  end

  defp finish_connection(%{resumed: true} = state, server_finished) do
    state = append(state, server_finished)

    with {:ok, finished} <-
           TLS12KeySchedule.finished(state.suite.id, state.master_secret, :client, bytes(state)),
         {:ok, encoded} <- TLS12Codec.encode_finished(finished),
         {:ok, protected, write} <- TLS12Record.encrypt(state.write_state, :handshake, encoded) do
      saved = if state.save_session, do: [{:tls12_session, state.session}], else: []

      {:ok, complete(%{state | write_state: write}), [@ccs, protected],
       saved ++ [{:connected, state.negotiated_protocol}]}
    else
      {:error, reason} -> fatal(:handshake_failure, reason)
    end
  end

  defp finish_connection(state, _server_finished) do
    events =
      if state.save_session and is_binary(state.session_id) and state.session_id != <<>> do
        [
          {:tls12_session,
           %{
             id: state.session_id,
             master_secret: state.master_secret,
             suite: state.suite.id,
             peer: state.peer,
             alpn: state.negotiated_protocol
           }}
        ]
      else
        []
      end

    {:ok, complete(state), [], events ++ [{:connected, state.negotiated_protocol}]}
  end

  defp complete(state) do
    %{
      state
      | phase: :connected,
        master_secret: nil,
        session: nil,
        transcript: nil,
        trust: nil,
        client_identity: nil,
        key_pair: nil,
        premaster: nil,
        request: nil,
        options: Keyword.drop(state.options, [:verify_fun, :certificate_policy])
    }
  end

  defp verify_certificate(state, chain, staples) do
    options =
      Keyword.take(state.options, [:depth, :customize_hostname_check, :verify_fun]) ++
        [certificate_signature_schemes: state.offer.certificate_signature_schemes]

    options =
      if Keyword.get(state.options, :certificate_policy),
        do: Keyword.put(options, :policy_staples, staples),
        else: options

    verifier = Keyword.get(state.options, :certificate_policy) || (&SSL.PKIX.peer/6)

    case verifier.(
           chain,
           state.trust,
           state.identity,
           Keyword.get(state.options, :verify, :verify_peer),
           options,
           :tls12
         ) do
      {:ok, peer} ->
        {:ok, %{state | peer: peer, pending_chain: nil, phase: :await_server_key_exchange}, [],
         []}

      {:error, reason} ->
        fatal(:bad_certificate, reason)
    end
  end

  defp client_flight(state) do
    with {:ok, selection} <- select_identity(state),
         {:ok, certificate} <- client_certificate(state.request, selection),
         {:ok, exchange} <- TLS12Codec.encode_client_key_exchange(state.key_pair.public_key),
         true <-
           state.transcript.length + byte_size(certificate) + byte_size(exchange) + 16_408 <=
             @maximum_transcript,
         state = state |> append(certificate) |> append(exchange),
         {:ok, secrets} <-
           TLS12KeySchedule.derive(
             state.suite.id,
             state.premaster,
             bytes(state),
             state.client_random,
             state.server_random
           ),
         {:ok, verify} <- client_verify(selection, state),
         state = append(state, verify),
         {:ok, finished} <-
           TLS12KeySchedule.finished(state.suite.id, secrets.master_secret, :client, bytes(state)),
         {:ok, encoded} <- TLS12Codec.encode_finished(finished),
         {:ok, protected, write} <- TLS12Record.encrypt(secrets.write_state, :handshake, encoded) do
      next =
        append(
          %{
            state
            | phase: :await_server_ccs,
              read_state: secrets.read_state,
              write_state: write,
              master_secret: secrets.master_secret,
              premaster: nil,
              key_pair: nil,
              client_identity: nil
          },
          encoded
        )

      {:ok, next, plaintext_records(certificate <> exchange <> verify) ++ [@ccs, protected], []}
    else
      false -> fatal(:handshake_failure, :tls12_transcript_limit)
      {:error, reason} -> fatal(:handshake_failure, reason)
    end
  end

  defp select_identity(%{request: nil}), do: {:ok, nil}

  defp select_identity(state) do
    request = %CertificateRequest{
      encoded: state.request.encoded,
      request_context: <<>>,
      extensions: [
        signature_algorithms: state.request.signature_schemes,
        signature_algorithms_cert: state.request.signature_schemes,
        certificate_authorities: state.request.authorities
      ]
    }

    ClientAuthentication.select(request, state.client_identity, :tls12,
      signature_schemes: state.offer.signature_schemes,
      certificate_types: state.request.certificate_types,
      trust_source: state.trust
    )
  end

  defp client_certificate(nil, _), do: {:ok, <<>>}
  defp client_certificate(_, nil), do: TLS12Codec.encode_certificate([])
  defp client_certificate(_, {identity, _}), do: TLS12Codec.encode_certificate(identity.chain)
  defp client_verify(nil, _), do: {:ok, <<>>}

  defp client_verify({identity, scheme}, state) do
    with {:ok, signature} <- Signature.sign_message(scheme, identity.private_key, bytes(state)),
         do: TLS12Codec.encode_certificate_verify(scheme, signature)
  end

  @spec encrypt(t(), :application_data | :alert, iodata()) ::
          {:ok, binary(), t()} | {:error, term()}
  def encrypt(%{write_state: write} = state, :alert, data) when not is_nil(write),
    do: protect(state, :alert, data)

  def encrypt(state, :alert, <<level, code>>), do: {:ok, <<21, 3, 3, 2::16, level, code>>, state}

  def encrypt(%{phase: :connected} = state, :application_data, data),
    do: protect(state, :application_data, data)

  def encrypt(_, _, _), do: {:error, :not_connected}

  defp protect(state, type, data) do
    with {:ok, wire, write} <- TLS12Record.encrypt(state.write_state, type, data),
         do: {:ok, wire, %{state | write_state: write}}
  end

  defp validate_hello(state, hello) do
    cond do
      hello.session_id != <<>> and hello.session_id == state.offer.legacy_session_id and
          state.session == nil ->
        {:error, :tls12_resumption_unsupported}

      hello.cipher_suite not in state.offer.cipher_suites ->
        {:error, :unoffered_cipher_suite}

      hello.compression != 0 ->
        {:error, :unsupported_compression}

      0x0304 in state.offer.offered_versions and
          binary_part(hello.random, 24, 8) in ["DOWNGRD" <> <<1>>, "DOWNGRD" <> <<0>>] ->
        {:error, :downgrade_detected}

      true ->
        :ok
    end
  end

  defp server_extensions(offer, extensions) do
    cond do
      not List.keymember?(extensions, 23, 0) ->
        fatal(:handshake_failure, :extended_master_secret_required)

      {0xFF01, <<0>>} not in extensions ->
        fatal(:handshake_failure, :secure_renegotiation_required)

      not Enum.all?(extensions, fn {id, _} -> id in offer.extension_ids end) ->
        fatal(:unsupported_extension, :unsolicited_server_extension)

      not Enum.all?(extensions, &valid_server_extension?(&1, offer)) ->
        fatal(:illegal_parameter, :invalid_tls12_extensions)

      true ->
        case List.keyfind(extensions, 16, 0) do
          {16, <<_::16, size, protocol::binary-size(size)>>} -> {:ok, protocol}
          nil -> {:ok, nil}
        end
    end
  end

  defp valid_server_extension?({23, <<>>}, _), do: true
  defp valid_server_extension?({5, <<>>}, _), do: true
  defp valid_server_extension?({0xFF01, <<0>>}, _), do: true
  defp valid_server_extension?({0, <<>>}, _), do: true

  defp valid_server_extension?({11, <<length, formats::binary>>}, _)
       when length == byte_size(formats),
       do: 0 in :binary.bin_to_list(formats)

  defp valid_server_extension?({16, <<length::16, size, protocol::binary-size(size)>>}, offer),
    do: length == size + 1 and protocol in offer.alpn_protocols

  defp valid_server_extension?(_, _), do: false
  defp signature_key_matches?(:rsa, key), do: key in [:rsa, :rsa_pss]
  defp signature_key_matches?(:ecdsa, key), do: key == :ecdsa
  defp append(state, <<>>), do: state

  defp append(state, encoded),
    do: %{state | transcript: Transcript.append(state.transcript, encoded)}

  defp bytes(state), do: state.transcript.messages |> Enum.reverse() |> IO.iodata_to_binary()
  defp plaintext_records(<<>>), do: []

  defp plaintext_records(bytes) do
    size = min(byte_size(bytes), 16_384)
    <<chunk::binary-size(^size), rest::binary>> = bytes
    [<<22, 3, 3, size::16, chunk::binary>> | plaintext_records(rest)]
  end

  defp record_error(:authentication_failed), do: fatal(:bad_record_mac, :authentication_failed)
  defp record_error(:record_length_exceeded), do: fatal(:record_overflow, :record_length_exceeded)

  defp record_error(:unsupported_content_type),
    do: fatal(:unexpected_message, :unsupported_content_type)

  defp record_error(reason) when reason in [:sequence_exhausted, :invalid_traffic_state],
    do: fatal(:internal_error, reason)

  defp record_error(reason), do: fatal(:decode_error, reason)
  defp fatal(alert, reason), do: {:error, {:fatal_alert, alert, reason}}
end
