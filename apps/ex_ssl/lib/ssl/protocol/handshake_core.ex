defmodule SSL.Protocol.HandshakeCore do
  @moduledoc """
  Shared TLS 1.3 authentication and secret derivation over exact handshake bytes.

  This core never constructs record keys, encrypts records, or accesses sockets.
  Transport adapters own framing, delivery barriers and record/packet epochs.
  Inputs contain already loaded trust and fresh connection key material.
  """

  alias SSL.Crypto.{KeyExchange, KeySchedule, Signature}
  alias SSL.Crypto.Finished, as: CryptoFinished
  alias SSL.Crypto.KeyExchange.KeyPair
  alias SSL.PKIX

  alias SSL.Protocol.{
    ClientOffer,
    ClientAuthentication,
    ServerFlight,
    ServerHello,
    Transcript
  }

  alias SSL.Protocol.ServerFlight.{
    Certificate,
    CertificateRequest,
    CertificateVerify,
    EncryptedExtensions
  }

  alias SSL.Protocol.ServerFlight.Finished, as: ServerFinished

  defmodule Input do
    @moduledoc false
    @derive {Inspect, only: [:identity]}
    @enforce_keys [:client_hello, :server_hello, :client_key_pair, :trust_source, :identity]
    defstruct @enforce_keys ++ [client_identity: nil, ticket: nil, enable_tickets: false]
    @type t :: %__MODULE__{}
  end

  defmodule Result do
    @moduledoc false
    @derive {Inspect, only: [:suite, :hash, :negotiated_protocol, :resumed]}
    defstruct [
      :verified_peer,
      :suite,
      :hash,
      :client_application_secret,
      :server_application_secret,
      :transcript,
      :negotiated_protocol,
      resumption_master: nil,
      resumed: false
    ]

    @type t :: %__MODULE__{}
  end

  defmodule Incremental do
    @moduledoc false
    @derive {Inspect, only: [:phase, :negotiated_protocol]}
    defstruct [
      :input,
      :offer,
      :secrets,
      :config,
      :phase,
      :transcript,
      verified_peer: nil,
      certificate_request: nil,
      negotiated_protocol: nil
    ]

    @type t :: %__MODULE__{}
  end

  @default_max_records 64
  @maximum_handshake_length 1_048_576
  @server_flight_option_keys [
    :max_handshake_length,
    :max_certificate_count,
    :max_total_certificate_bytes,
    :max_certificate_bytes,
    :max_extension_bytes,
    :max_signature_bytes,
    :offered_extension_ids,
    :allowed_signature_schemes
  ]
  @option_keys [:max_records, :depth, :customize_hostname_check | @server_flight_option_keys]

  @type fatal_alert ::
          :bad_record_mac
          | :record_overflow
          | :unknown_ca
          | :bad_certificate
          | :certificate_expired
          | :certificate_unknown
          | :decrypt_error
          | :unexpected_message
          | :unsupported_extension
          | :decode_error
          | :illegal_parameter
          | :internal_error

  @doc false
  @spec start_client(map(), keyword(), Transcript.t() | nil) ::
          {:ok, Incremental.t()} | {:error, {:fatal_alert, atom(), term()}}
  def start_client(input, options, transcript \\ nil)

  def start_client(input, options, transcript) when is_map(input) do
    input =
      struct(
        Input,
        Map.take(
          input,
          Map.keys(%Input{
            client_hello: nil,
            server_hello: nil,
            client_key_pair: nil,
            trust_source: nil,
            identity: nil
          })
        )
      )

    case do_start_incremental(input, options, transcript) do
      {:ok, incremental} -> {:ok, incremental}
      {:error, {alert, reason}} -> {:error, {:fatal_alert, alert, reason}}
    end
  end

  def start_client(_, _, _),
    do: {:error, {:fatal_alert, :decode_error, {:invalid_input, :verifier}}}

  @doc false
  def verify_messages(%Incremental{} = state, messages) do
    with :ok <- reject_batch_resumption(state.input),
         {:ok, peer, transcript, alpn, request} <-
           verify_messages(messages, state.input, state.secrets, state.config, state.offer),
         {:ok, result, outbound} <-
           finish_incremental(
             %{
               state
               | verified_peer: peer,
                 negotiated_protocol: alpn,
                 certificate_request: request
             },
             transcript
           ) do
      {:ok, result, outbound}
    else
      {:error, {alert, reason}} -> {:error, {:fatal_alert, alert, reason}}
    end
  end

  @doc false
  @spec process_message(Incremental.t(), binary()) ::
          {:ok, Incremental.t()}
          | {:connected, Result.t(), [binary()]}
          | {:error, {:fatal_alert, fatal_alert(), term()}}
  def process_message(%Incremental{} = state, encoded) when is_binary(encoded) do
    case do_process_message(state, encoded) do
      {:error, {alert, reason}} -> {:error, {:fatal_alert, alert, reason}}
      result -> result
    end
  end

  def process_message(_state, _encoded),
    do: {:error, {:fatal_alert, :decode_error, {:invalid_input, :incremental_message}}}

  defp do_start_incremental(input, options, transcript_prefix) do
    with {:ok, config} <- validate_options(options),
         {:ok, offer, server_hello} <- validate_input(input),
         {:ok, config} <- bind_offer(config, offer),
         input = %{input | server_hello: server_hello},
         {:ok, suite, hash, peer_public_key} <- negotiate(input, offer),
         :ok <- validate_selected_ticket(input, offer, hash),
         {:ok, secrets} <-
           derive_handshake_secrets(input, suite, hash, peer_public_key, transcript_prefix) do
      {:ok,
       %Incremental{
         input: %{input | client_key_pair: nil},
         offer: offer,
         secrets: secrets,
         config: config,
         phase: :encrypted_extensions,
         transcript: secrets.transcript,
         verified_peer: if(selected_ticket?(input), do: input.ticket.peer, else: nil)
       }}
    end
  end

  defp do_process_message(%Incremental{phase: :encrypted_extensions} = state, encoded) do
    options = [{:hash, state.secrets.hash} | state.config.server_flight_options]

    with {:ok, %EncryptedExtensions{} = message} <-
           decode_message(encoded, EncryptedExtensions, options),
         :ok <- validate_encrypted_extensions(message, state.offer),
         :ok <- resumed_alpn(state.input, selected_alpn(message)) do
      {:ok,
       %{
         state
         | phase: if(selected_ticket?(state.input), do: :finished, else: :certificate_or_request),
           negotiated_protocol: selected_alpn(message),
           transcript: Transcript.append(state.transcript, encoded)
       }}
    end
  end

  defp do_process_message(
         %Incremental{phase: :certificate_or_request} = state,
         <<13, _::binary>> = encoded
       ) do
    options = [{:hash, state.secrets.hash} | state.config.server_flight_options]

    with {:ok, %CertificateRequest{} = request} <-
           decode_message(encoded, CertificateRequest, options) do
      {:ok,
       %{
         state
         | phase: :certificate,
           certificate_request: request,
           transcript: Transcript.append(state.transcript, encoded)
       }}
    end
  end

  defp do_process_message(%Incremental{phase: phase} = state, encoded)
       when phase in [:certificate_or_request, :certificate] do
    options = [{:hash, state.secrets.hash} | state.config.server_flight_options]

    with {:ok, %Certificate{} = certificate} <- decode_message(encoded, Certificate, options),
         :ok <- validate_certificate_extensions(certificate, state.offer),
         {:ok, verified_peer} <- verify_peer(certificate, state.input, state.config) do
      {:ok,
       %{
         state
         | phase: :certificate_verify,
           verified_peer: verified_peer,
           transcript: Transcript.append(state.transcript, encoded)
       }}
    end
  end

  defp do_process_message(%Incremental{phase: :certificate_verify} = state, encoded) do
    options = [{:hash, state.secrets.hash} | state.config.server_flight_options]

    with {:ok, %CertificateVerify{} = certificate_verify} <-
           decode_message(encoded, CertificateVerify, options),
         :ok <-
           verify_certificate_signature(certificate_verify, state.verified_peer, state.transcript) do
      {:ok, %{state | phase: :finished, transcript: Transcript.append(state.transcript, encoded)}}
    end
  end

  defp do_process_message(%Incremental{phase: :finished} = state, encoded) do
    options = [{:hash, state.secrets.hash} | state.config.server_flight_options]

    with {:ok, %ServerFinished{} = finished} <- decode_message(encoded, ServerFinished, options),
         :ok <- verify_server_finished(finished, state.transcript, state.secrets),
         server_transcript = Transcript.append(state.transcript, encoded),
         {:ok, result, outbound} <- finish_incremental(state, server_transcript) do
      {:connected, result, outbound}
    end
  end

  defp do_process_message(%Incremental{} = state, encoded),
    do:
      alert(
        :unexpected_message,
        {:invalid_server_flight_order, state.phase, message_types([encoded])}
      )

  defp reject_batch_resumption(%Input{server_hello: %ServerHello{extensions: extensions}}) do
    if List.keymember?(extensions, :pre_shared_key, 0),
      do: alert(:illegal_parameter, :incremental_resumption_required),
      else: :ok
  end

  defp validate_input(%Input{} = input) do
    with :ok <- validate_client_identity(input.client_identity),
         {:ok, offer} <- client_offer(input.client_hello),
         {:ok, server_hello} <- reparse_server_hello(input.server_hello, offer),
         :ok <- compare_server_hello(input.server_hello, server_hello),
         :ok <- validate_server_hello_kind(server_hello),
         :ok <- validate_key_pair(input.client_key_pair, offer, server_hello) do
      {:ok, offer, server_hello}
    else
      {:error, {_alert, _reason}} = error -> error
    end
  end

  defp validate_client_identity(nil), do: :ok
  defp validate_client_identity(%SSL.ClientIdentity{}), do: :ok
  defp validate_client_identity(_), do: alert(:illegal_parameter, :invalid_client_identity)

  defp client_offer(encoded) do
    case ClientOffer.from_client_hello(encoded) do
      {:ok, offer} -> {:ok, offer}
      {:error, reason} -> alert(:decode_error, reason)
    end
  end

  defp reparse_server_hello(%ServerHello{encoded: encoded}, offer) do
    expectations = %{
      legacy_session_id: offer.legacy_session_id,
      offered_ciphers: offer.cipher_suites,
      offered_versions: offer.offered_versions,
      offered_groups: offer.supported_groups,
      offered_key_share_groups: Enum.map(offer.key_shares, & &1.group),
      offered_extension_ids: offer.extension_ids,
      offered_psk_key_exchange_modes: offer.psk_key_exchange_modes,
      offered_psk_count: offer.psk_count
    }

    case ServerHello.decode(encoded, expectations) do
      {:ok, %ServerHello{} = server_hello, <<>>} ->
        {:ok, server_hello}

      {:ok, %ServerHello{}, remainder} ->
        alert(:decode_error, {:trailing_server_hello, byte_size(remainder)})

      {:more, bytes} ->
        alert(:decode_error, {:incomplete_server_hello, bytes})

      {:error, reason} ->
        alert(:illegal_parameter, reason)
    end
  end

  defp reparse_server_hello(_server_hello, _offer),
    do: alert(:decode_error, {:invalid_input, :server_hello})

  defp validate_server_hello_kind(%ServerHello{kind: :server_hello}), do: :ok

  defp validate_server_hello_kind(%ServerHello{kind: :hello_retry_request}),
    do: alert(:unexpected_message, {:unsupported, :hello_retry_request})

  defp compare_server_hello(supplied, parsed) do
    fields = [
      :cipher_suite,
      :random,
      :legacy_session_id_echo,
      :legacy_version,
      :compression_method,
      :kind
    ]

    case Enum.find(fields, &(Map.get(supplied, &1) != Map.get(parsed, &1))) do
      nil -> compare_server_hello_extensions(supplied.extensions, parsed.extensions)
      field -> alert(:illegal_parameter, {:server_hello_semantics_mismatch, field})
    end
  end

  defp compare_server_hello_extensions(supplied, parsed) do
    cond do
      not proper_extension_list?(supplied) ->
        alert(:illegal_parameter, :malformed_server_hello_extensions)

      server_extension(supplied, :supported_versions) !=
          server_extension(parsed, :supported_versions) ->
        alert(:illegal_parameter, {:server_hello_semantics_mismatch, :version})

      server_extension(supplied, :key_share) != server_extension(parsed, :key_share) ->
        alert(:illegal_parameter, {:server_hello_semantics_mismatch, :key_share})

      supplied != parsed ->
        alert(:illegal_parameter, {:server_hello_semantics_mismatch, :extensions})

      true ->
        :ok
    end
  end

  defp server_extension(extensions, name) when is_list(extensions),
    do:
      Enum.find(extensions, fn
        {^name, _value} -> true
        _extension -> false
      end)

  defp server_extension(_extensions, _name), do: :malformed

  defp proper_extension_list?([]), do: true
  defp proper_extension_list?([{_name, _value} | rest]), do: proper_extension_list?(rest)
  defp proper_extension_list?(_extensions), do: false

  defp validate_key_pair(%KeyPair{} = key_pair, offer, server_hello) do
    with {:ok, selected_group, _peer_public} <- server_key_share(server_hello.extensions),
         :ok <- key_pair_result(KeyExchange.validate_key_pair(key_pair)),
         :ok <- bind_key_share_group(selected_group, key_pair.group),
         {:ok, offered_public} <- offered_key_share(offer, selected_group),
         true <- :crypto.hash_equals(offered_public, key_pair.public_key) do
      :ok
    else
      false -> alert(:illegal_parameter, :client_key_pair_public_mismatch)
      {:error, {_alert, _reason}} = error -> error
    end
  end

  defp validate_key_pair(_key_pair, _offer, _server_hello),
    do: alert(:illegal_parameter, :invalid_key_pair)

  defp offered_key_share(offer, selected_group) do
    case Enum.find(offer.key_shares, &(&1.group == selected_group)) do
      %{key_exchange: public_key} -> {:ok, public_key}
      nil -> alert(:illegal_parameter, {:client_key_share_not_offered, selected_group})
    end
  end

  defp key_pair_result(:ok), do: :ok
  defp key_pair_result({:error, reason}), do: alert(:illegal_parameter, reason)

  defp selected_ticket?(input), do: {:pre_shared_key, 0} in input.server_hello.extensions

  defp validate_selected_ticket(input, offer, hash) do
    if selected_ticket?(input) do
      with %SSL.SessionTicket{hash: ^hash} = ticket <- input.ticket,
           :ok <- SSL.SessionTicket.validate(ticket),
           true <-
             input.client_identity == nil and offer.psk_count == 1 and
               offer.psk_key_exchange_modes == [1],
           {41, <<size::16, identity::binary-size(size), _::binary>>} <-
             List.keyfind(offer.extensions, 41, 0),
           <<length::16, bytes::binary-size(length), _age::32>> <- identity,
           true <- bytes == ticket.ticket do
        :ok
      else
        _ -> alert(:illegal_parameter, :invalid_resumption_selection)
      end
    else
      :ok
    end
  end

  defp resumed_alpn(input, selected) do
    if selected_ticket?(input) and input.ticket.alpn != selected,
      do: alert(:illegal_parameter, :resumption_alpn_changed),
      else: :ok
  end

  defp negotiate(%Input{server_hello: server_hello, client_key_pair: client_key_pair}, _offer) do
    with {:ok, suite, hash} <- cipher_suite(server_hello.cipher_suite),
         {:ok, group, peer_public_key} <- server_key_share(server_hello.extensions),
         :ok <- bind_key_share_group(group, client_key_pair.group) do
      {:ok, suite, hash, peer_public_key}
    end
  end

  defp cipher_suite(cipher_suite) do
    case SSL.Capabilities.resolve(:cipher_suite, cipher_suite) do
      %{version: 0x0304, name: name, hash: hash} -> {:ok, name, hash}
      _ -> alert(:illegal_parameter, {:unsupported_cipher_suite, cipher_suite})
    end
  end

  defp server_key_share(extensions), do: server_key_share(extensions, nil)

  defp server_key_share([], nil), do: alert(:illegal_parameter, :missing_key_share)
  defp server_key_share([], {group, key_exchange}), do: {:ok, group, key_exchange}

  defp server_key_share([{:supported_versions, 0x0304} | rest], key_share),
    do: server_key_share(rest, key_share)

  defp server_key_share([{:pre_shared_key, 0} | rest], key_share),
    do: server_key_share(rest, key_share)

  defp server_key_share(
         [{:key_share, %{group: group, key_exchange: key_exchange}} | rest],
         nil
       )
       when is_integer(group) and is_binary(key_exchange),
       do: server_key_share(rest, {group, key_exchange})

  defp server_key_share([{:key_share, _key_share} | _rest], nil),
    do: alert(:illegal_parameter, :malformed_key_share)

  defp server_key_share([{:key_share, _key_share} | _rest], {_group, _key_exchange}),
    do: alert(:illegal_parameter, :duplicate_key_share)

  defp server_key_share([_invalid_extension | _rest], _key_share),
    do: alert(:illegal_parameter, :malformed_server_hello_extensions)

  defp server_key_share(_improper_tail, _key_share),
    do: alert(:illegal_parameter, :malformed_server_hello_extensions)

  defp bind_key_share_group(group, client_group) do
    case SSL.Capabilities.resolve(:group, group) do
      %{name: ^client_group} -> :ok
      _ -> alert(:illegal_parameter, {:key_share_group_mismatch, group, client_group})
    end
  end

  defp derive_handshake_secrets(input, suite, hash, peer_public_key, transcript_prefix) do
    transcript =
      (transcript_prefix || Transcript.new(hash) |> Transcript.append(input.client_hello))
      |> Transcript.append(input.server_hello.encoded)

    derive_secrets(
      input.client_key_pair,
      peer_public_key,
      suite,
      transcript,
      if(selected_ticket?(input), do: input.ticket.psk, else: nil)
    )
  end

  @doc false
  @spec derive_secrets(KeyPair.t(), binary(), atom(), Transcript.t(), binary() | nil) ::
          {:ok, map()} | {:error, term()}
  def derive_secrets(pair, peer_public_key, suite, transcript, psk \\ nil) do
    hash = transcript.hash

    with {:ok, shared} <-
           crypto_result(KeyExchange.shared_secret(pair, peer_public_key), :illegal_parameter),
         {:ok, early} <- crypto_result(KeySchedule.early_secret(hash, psk)),
         {:ok, handshake} <- crypto_result(KeySchedule.handshake_secret(hash, early, shared)),
         digest = Transcript.digest(transcript),
         {:ok, client} <-
           crypto_result(KeySchedule.client_handshake_traffic_secret(hash, handshake, digest)),
         {:ok, server} <-
           crypto_result(KeySchedule.server_handshake_traffic_secret(hash, handshake, digest)),
         {:ok, master} <- crypto_result(KeySchedule.master_secret(hash, handshake)) do
      {:ok,
       %{
         suite: suite,
         hash: hash,
         transcript: transcript,
         client_handshake_secret: client,
         server_handshake_secret: server,
         master_secret: master
       }}
    end
  end

  defp verify_messages(
         [encrypted_extensions, certificate, certificate_verify, finished],
         input,
         secrets,
         config,
         offer
       ),
       do:
         verify_messages_with_request(
           {encrypted_extensions, nil, certificate, certificate_verify, finished},
           input,
           secrets,
           config,
           offer
         )

  defp verify_messages(
         [encrypted_extensions, certificate_request, certificate, certificate_verify, finished],
         input,
         secrets,
         config,
         offer
       ),
       do:
         verify_messages_with_request(
           {encrypted_extensions, certificate_request, certificate, certificate_verify, finished},
           input,
           secrets,
           config,
           offer
         )

  defp verify_messages(messages, _input, _secrets, _config, _offer),
    do: alert(:unexpected_message, {:invalid_server_flight_order, message_types(messages)})

  defp verify_messages_with_request(
         {encrypted_extensions, certificate_request, certificate, certificate_verify, finished},
         input,
         secrets,
         config,
         offer
       ) do
    options = [{:hash, secrets.hash} | config.server_flight_options]

    with {:ok, %EncryptedExtensions{} = encrypted_extensions} <-
           decode_message(encrypted_extensions, EncryptedExtensions, options),
         :ok <- validate_encrypted_extensions(encrypted_extensions, offer),
         transcript = Transcript.append(secrets.transcript, encrypted_extensions.encoded),
         {:ok, request, transcript} <-
           maybe_decode_certificate_request(certificate_request, transcript, options),
         {:ok, %Certificate{} = certificate} <-
           decode_message(certificate, Certificate, options),
         :ok <- validate_certificate_extensions(certificate, offer),
         transcript = Transcript.append(transcript, certificate.encoded),
         {:ok, verified_peer} <- verify_peer(certificate, input, config),
         {:ok, %CertificateVerify{} = certificate_verify} <-
           decode_message(certificate_verify, CertificateVerify, options),
         :ok <- verify_certificate_signature(certificate_verify, verified_peer, transcript),
         transcript = Transcript.append(transcript, certificate_verify.encoded),
         {:ok, %ServerFinished{} = finished} <-
           decode_message(finished, ServerFinished, options),
         :ok <- verify_server_finished(finished, transcript, secrets) do
      transcript = Transcript.append(transcript, finished.encoded)
      {:ok, verified_peer, transcript, selected_alpn(encrypted_extensions), request}
    end
  end

  defp maybe_decode_certificate_request(nil, transcript, _options),
    do: {:ok, nil, transcript}

  defp maybe_decode_certificate_request(encoded, transcript, options) do
    with {:ok, %CertificateRequest{} = request} <-
           decode_message(encoded, CertificateRequest, options) do
      {:ok, request, Transcript.append(transcript, encoded)}
    end
  end

  defp decode_message(encoded, expected_module, options) do
    case ServerFlight.decode(encoded, options) do
      {:ok, %{__struct__: ^expected_module} = message, <<>>} ->
        {:ok, message}

      {:ok, message, <<>>} ->
        alert(:unexpected_message, {:expected, expected_module, message.__struct__})

      {:ok, _message, remainder} ->
        alert(:decode_error, {:trailing_handshake_bytes, byte_size(remainder)})

      {:more, bytes} ->
        alert(:decode_error, {:incomplete_handshake_message, bytes})

      {:error, reason} ->
        decode_alert(reason)
    end
  end

  defp validate_encrypted_extensions(%EncryptedExtensions{extensions: extensions}, offer) do
    Enum.reduce_while(extensions, :ok, fn extension, :ok ->
      case validate_encrypted_extension(extension, offer) do
        :ok -> {:cont, :ok}
        {:error, {_alert, _reason}} = error -> {:halt, error}
      end
    end)
  end

  defp validate_encrypted_extension({:early_data}, offer) do
    if 42 in offer.extension_ids do
      alert(:illegal_parameter, {:early_data_not_permitted, :non_psk})
    else
      alert(:unsupported_extension, {:unsolicited_extension, 42})
    end
  end

  defp validate_encrypted_extension({:alpn, protocol}, offer) do
    cond do
      16 not in offer.extension_ids ->
        alert(:unsupported_extension, {:unsolicited_extension, 16})

      protocol not in offer.alpn_protocols ->
        alert(:illegal_parameter, {:alpn_not_offered, protocol})

      true ->
        :ok
    end
  end

  defp validate_encrypted_extension(_extension, _offer), do: :ok

  defp validate_certificate_extensions(%Certificate{entries: entries}, offer) do
    entries
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {entry, index}, :ok ->
      case validate_certificate_entry_extensions(entry.extensions, offer, index) do
        :ok -> {:cont, :ok}
        {:error, {_alert, _reason}} = error -> {:halt, error}
      end
    end)
  end

  defp validate_certificate_entry_extensions(extensions, offer, index) do
    Enum.reduce_while(extensions, :ok, fn extension, :ok ->
      case certificate_extension_id(extension) do
        id when id in [5, 18] ->
          if id in offer.extension_ids do
            {:cont, :ok}
          else
            {:halt,
             alert(:unsupported_extension, {:unsolicited_certificate_extension, id, index})}
          end

        _id ->
          {:cont, :ok}
      end
    end)
  end

  defp certificate_extension_id({:status_request, _response}), do: 5
  defp certificate_extension_id({:signed_certificate_timestamps, _timestamps}), do: 18
  defp certificate_extension_id(_extension), do: nil

  @doc false
  @spec decode_alert(term()) ::
          {:error,
           {
             :bad_certificate
             | :certificate_expired
             | :certificate_unknown
             | :decode_error
             | :decrypt_error
             | :illegal_parameter
             | :internal_error
             | :unexpected_message
             | :unknown_ca
             | :unsupported_extension,
             term()
           }}
  def decode_alert({:extension_not_offered, id}),
    do: alert(:unsupported_extension, {:unsolicited_extension, id})

  def decode_alert({:unsupported_extension, context, id}),
    do: alert(:unsupported_extension, {:unsupported_extension, context, id})

  def decode_alert({:forbidden_extension, context, id}),
    do: alert(:illegal_parameter, {:forbidden_extension, context, id})

  def decode_alert({:signature_scheme_not_allowed, scheme}),
    do: alert(:illegal_parameter, {:signature_scheme_not_offered, scheme})

  def decode_alert(reason), do: alert(:decode_error, reason)

  defp verify_peer(%Certificate{entries: entries}, input, config) do
    chain = Enum.map(entries, & &1.der)

    case PKIX.verify(chain, input.trust_source, input.identity,
           customize_hostname_check: config.hostname_check,
           depth: config.depth,
           certificate_signature_schemes: config.certificate_signature_schemes
         ) do
      {:ok, verified_peer} ->
        {:ok, verified_peer}

      {:error, {:invalid_identity, _identity} = reason} ->
        alert(:illegal_parameter, reason)

      {:error, :hostname_mismatch = reason} ->
        alert(:certificate_unknown, reason)

      {:error, {:path_validation_failed, {:bad_cert, :cert_expired}} = reason} ->
        alert(:certificate_expired, reason)

      {:error, {:path_validation_failed, _path_reason} = reason} ->
        alert(:unknown_ca, reason)

      {:error, reason} ->
        alert(:bad_certificate, reason)
    end
  end

  defp finish_incremental(state, server_transcript) do
    transcript_hash = Transcript.digest(server_transcript)

    with {:ok, client_application_secret} <-
           crypto_result(
             KeySchedule.client_application_traffic_secret(
               state.secrets.hash,
               state.secrets.master_secret,
               transcript_hash
             )
           ),
         {:ok, server_application_secret} <-
           crypto_result(
             KeySchedule.server_application_traffic_secret(
               state.secrets.hash,
               state.secrets.master_secret,
               transcript_hash
             )
           ),
         {:ok, transcript, certificate_messages} <-
           client_auth_result(
             ClientAuthentication.messages(
               state.certificate_request,
               state.input.client_identity,
               server_transcript
             )
           ),
         {:ok, client_verify_data} <-
           crypto_result(
             CryptoFinished.client_verify_data(
               state.secrets.hash,
               state.secrets.client_handshake_secret,
               Transcript.digest(transcript)
             )
           ),
         {:ok, client_finished} <-
           crypto_result(
             ServerFlight.encode_finished(client_verify_data, hash: state.secrets.hash)
           ) do
      result = %Result{
        verified_peer: state.verified_peer,
        suite: state.secrets.suite,
        hash: state.secrets.hash,
        client_application_secret: client_application_secret,
        server_application_secret: server_application_secret,
        negotiated_protocol: state.negotiated_protocol,
        transcript: Transcript.append(transcript, client_finished),
        resumed: selected_ticket?(state.input)
      }

      result =
        if state.input.enable_tickets do
          {:ok, secret} =
            KeySchedule.resumption_master_secret(
              state.secrets.hash,
              state.secrets.master_secret,
              Transcript.digest(result.transcript)
            )

          %{result | resumption_master: secret}
        else
          result
        end

      {:ok, result, certificate_messages ++ [client_finished]}
    end
  end

  defp client_auth_result({:ok, transcript, messages}),
    do: {:ok, transcript, messages}

  defp client_auth_result({:error, reason}), do: alert(:internal_error, reason)

  defp verify_certificate_signature(certificate_verify, verified_peer, transcript) do
    case Signature.verify_server(
           certificate_verify.signature_scheme,
           verified_peer.public_key,
           transcript.hash,
           Transcript.digest(transcript),
           certificate_verify.signature
         ) do
      :ok -> :ok
      {:error, reason} -> alert(:decrypt_error, reason)
    end
  end

  defp verify_server_finished(finished, transcript, secrets) do
    case CryptoFinished.verify_server(
           secrets.hash,
           secrets.server_handshake_secret,
           Transcript.digest(transcript),
           finished.verify_data
         ) do
      :ok -> :ok
      {:error, reason} -> alert(:decrypt_error, reason)
    end
  end

  defp selected_alpn(%EncryptedExtensions{extensions: extensions}) do
    Enum.find_value(extensions, fn
      {:alpn, protocol} -> protocol
      _extension -> nil
    end)
  end

  defp message_types(messages) do
    Enum.map(messages, fn
      <<type, _rest::binary>> -> type
      _message -> :malformed
    end)
  end

  defp validate_options(options) when is_list(options) do
    if Keyword.keyword?(options) do
      validate_keyword_options(options)
    else
      alert(:decode_error, {:invalid_options, :verifier})
    end
  end

  defp validate_options(_options),
    do: alert(:decode_error, {:invalid_options, :verifier})

  defp validate_keyword_options(options) do
    keys = Keyword.keys(options)

    if length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in @option_keys)) do
      case Keyword.get(options, :max_records, @default_max_records) do
        maximum when is_integer(maximum) and maximum > 0 ->
          server_flight_options =
            Keyword.drop(options, [:max_records, :depth, :customize_hostname_check])

          with :ok <- validate_signature_policy_option(server_flight_options),
               :ok <- validate_hostname_check_option(options),
               :ok <- validate_depth_option(options) do
            {:ok,
             %{
               max_records: maximum,
               depth: Keyword.get(options, :depth, 10),
               hostname_check: Keyword.get(options, :customize_hostname_check, []),
               max_handshake_length:
                 Keyword.get(options, :max_handshake_length, @maximum_handshake_length),
               server_flight_options: server_flight_options
             }}
          end

        _maximum ->
          alert(:decode_error, {:invalid_options, :verifier})
      end
    else
      alert(:decode_error, {:invalid_options, :verifier})
    end
  end

  defp validate_signature_policy_option(options) do
    case Keyword.fetch(options, :allowed_signature_schemes) do
      :error ->
        :ok

      {:ok, policy} ->
        if valid_identifier_list?(policy, %{}) do
          :ok
        else
          alert(:decode_error, {:invalid_options, :allowed_signature_schemes})
        end
    end
  end

  defp validate_hostname_check_option(options) do
    case Keyword.get(options, :customize_hostname_check, []) do
      [] -> :ok
      [match_fun: fun] when is_function(fun, 2) -> :ok
      _other -> alert(:decode_error, {:invalid_options, :customize_hostname_check})
    end
  end

  defp validate_depth_option(options) do
    case Keyword.get(options, :depth, 10) do
      depth when is_integer(depth) and depth >= 0 -> :ok
      _depth -> alert(:decode_error, {:invalid_options, :depth})
    end
  end

  defp valid_identifier_list?([], _seen), do: true

  defp valid_identifier_list?([identifier | rest], seen)
       when is_integer(identifier) and identifier in 0..0xFFFF do
    if Map.has_key?(seen, identifier) do
      false
    else
      valid_identifier_list?(rest, Map.put(seen, identifier, true))
    end
  end

  defp valid_identifier_list?(_policy, _seen), do: false

  defp bind_offer(config, offer) do
    supplied_extensions = Keyword.fetch(config.server_flight_options, :offered_extension_ids)
    supplied_signatures = Keyword.fetch(config.server_flight_options, :allowed_signature_schemes)

    with :ok <-
           reject_offer_conflict(supplied_extensions, offer.extension_ids, :offered_extension_ids),
         {:ok, allowed_signatures} <-
           signature_policy(supplied_signatures, offer.signature_schemes) do
      options =
        config.server_flight_options
        |> Keyword.put(:offered_extension_ids, offer.extension_ids)
        |> Keyword.put(:allowed_signature_schemes, allowed_signatures)

      {:ok,
       config
       |> Map.put(:server_flight_options, options)
       |> Map.put(:certificate_signature_schemes, offer.certificate_signature_schemes)}
    end
  end

  defp reject_offer_conflict(:error, _actual, _field), do: :ok
  defp reject_offer_conflict({:ok, actual}, actual, _field), do: :ok

  defp reject_offer_conflict({:ok, _claimed}, _actual, field),
    do: alert(:illegal_parameter, {:offer_override_conflict, field})

  defp signature_policy(:error, offered), do: {:ok, offered}

  defp signature_policy({:ok, policy}, offered) do
    if Enum.all?(policy, &(&1 in offered)) do
      {:ok, policy}
    else
      alert(:illegal_parameter, {:offer_override_conflict, :allowed_signature_schemes})
    end
  end

  defp crypto_result({:ok, value}, _alert), do: {:ok, value}
  defp crypto_result({:error, reason}, alert), do: alert(alert, reason)
  defp crypto_result(result), do: crypto_result(result, :internal_error)

  defp alert(alert, reason), do: {:error, {alert, reason}}
end
