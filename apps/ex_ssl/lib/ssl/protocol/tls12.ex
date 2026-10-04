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
    :key_pair,
    :premaster,
    :master_secret,
    :read_state,
    :write_state,
    :request,
    :negotiated_protocol,
    :transcript,
    :framer,
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
         options: Keyword.delete(options, :client_identity),
         transcript: Transcript.new(:sha256) |> Transcript.append(hello),
         framer: HandshakeFramer.new()
       }}
    else
      fatal(:protocol_version, :tls12_not_offered)
    end
  end

  def new(_, _, _, _, _), do: fatal(:decode_error, :invalid_client_hello)

  @spec feed(t(), binary()) :: {:ok, t(), [binary()], [term()]} | {:error, term()}
  def feed(%{phase: :await_server_ccs} = state, @ccs) do
    if HandshakeFramer.buffered_size(state.framer) == 0,
      do: {:ok, %{state | phase: :await_server_finished}, [], []},
      else: fatal(:unexpected_message, :fragment_across_ccs)
  end

  def feed(_state, <<20, _::binary>>), do: fatal(:unexpected_message, :invalid_change_cipher_spec)

  def feed(%{phase: phase} = state, record)
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

  def feed(_state, <<21, 3, 3, 2::16, level, description>>),
    do: {:error, {:peer_alert, level, description}}

  def feed(state, <<22, 3, 3, length::16, bytes::binary-size(length)>>) when length <= 16_384,
    do: handshake_bytes(state, bytes)

  def feed(_, _), do: fatal(:unexpected_message, :invalid_tls12_record)

  defp handshake_bytes(state, bytes) do
    case HandshakeFramer.feed(state.framer, bytes, max_handshake_length: 524_336) do
      {:ok, messages, framer} ->
        feed_handshakes(state, messages, framer)

      {:error, reason} ->
        fatal(:decode_error, reason)
    end
  end

  @doc false
  def feed_handshakes(state, messages, framer) do
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
        false -> {:halt, fatal(:unexpected_message, :tls12_transcript_limit_or_complete)}
        {:error, {:fatal_alert, _, _}} = error -> {:halt, error}
        {:error, reason} -> {:halt, fatal(:decode_error, reason)}
      end
    end)
    |> check_boundary()
  end

  defp check_boundary({:ok, %{phase: phase, framer: framer}, _, _} = result)
       when phase in [:await_server_ccs, :connected] do
    if HandshakeFramer.buffered_size(framer) == 0,
      do: result,
      else: fatal(:unexpected_message, :fragment_across_epoch)
  end

  defp check_boundary(result), do: result

  defp process(%{phase: :await_server_hello} = state, %{type: :server_hello} = hello) do
    with {:ok, suite} <- TLS12KeySchedule.suite(hello.cipher_suite),
         :ok <- validate_hello(state, hello),
         {:ok, alpn} <- server_extensions(state.offer, hello.extensions) do
      next = %{
        state
        | suite: suite,
          server_random: hello.random,
          negotiated_protocol: alpn,
          transcript: %{state.transcript | hash: suite.hash},
          phase: :await_certificate
      }

      {:ok, append(next, hello.encoded), [], []}
    else
      {:error, {:fatal_alert, _, _}} = error -> error
      {:error, reason} -> fatal(:illegal_parameter, reason)
    end
  end

  defp process(
         %{phase: :await_certificate} = state,
         %{type: :certificate, chain: chain} = message
       ) do
    options =
      Keyword.take(state.options, [:depth, :customize_hostname_check]) ++
        [certificate_signature_schemes: state.offer.certificate_signature_schemes]

    case SSL.PKIX.verify(chain, state.trust, state.identity, options) do
      {:ok, peer} ->
        {:ok, append(%{state | peer: peer, phase: :await_server_key_exchange}, message.encoded),
         [], []}

      {:error, reason} ->
        fatal(:bad_certificate, reason)
    end
  end

  defp process(
         %{phase: :await_server_key_exchange} = state,
         %{type: :server_key_exchange} = message
       ) do
    with true <- message.group in state.offer.supported_groups,
         true <- message.scheme in state.offer.signature_schemes,
         %{key: key} <- SSL.Capabilities.signature(message.scheme),
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

  defp process(%{phase: :await_server_finished} = state, %{type: :finished, verify_data: received}) do
    with {:ok, expected} <-
           TLS12KeySchedule.finished(state.suite.id, state.master_secret, :server, bytes(state)),
         true <- :crypto.hash_equals(expected, received) do
      {:ok,
       %{
         state
         | phase: :connected,
           master_secret: nil,
           transcript: nil,
           trust: nil,
           client_identity: nil,
           key_pair: nil,
           premaster: nil,
           request: nil
       }, [], [{:connected, state.negotiated_protocol}]}
    else
      _ -> fatal(:decrypt_error, :invalid_finished)
    end
  end

  defp process(_, _), do: fatal(:unexpected_message, :unexpected_tls12_handshake)

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

    with {:ok, selection} <- ClientAuthentication.select(request, state.client_identity) do
      case selection do
        nil ->
          {:ok, nil}

        {_, scheme} ->
          key = SSL.Capabilities.signature(scheme).key
          type = if key == :ecdsa, do: 64, else: 1
          if type in state.request.certificate_types, do: {:ok, selection}, else: {:ok, nil}
      end
    end
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
      hello.session_id != <<>> and hello.session_id == state.offer.legacy_session_id ->
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
