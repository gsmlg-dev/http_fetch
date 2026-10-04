defmodule SSL.Protocol.HandshakeMachine do
  @moduledoc "Pure TLS client coordinator consuming one complete record at a time."

  alias SSL.ClientHello.Materializer.Materialized
  alias SSL.Crypto.{KeySchedule, TrafficState}

  alias SSL.Protocol.{
    ClientHandshake,
    HandshakeFramer,
    Record,
    ServerFlight,
    ServerFlightVerifier,
    ServerHello,
    TLS12,
    TLS12Codec
  }

  alias SSL.Protocol.ServerFlightVerifier.{Incremental, Input}

  @max_handshake_length 1_048_576
  @ccs <<20, 3, 3, 0, 1, 1>>

  @derive {Inspect,
           except: [
             :client_hello,
             :client_ast,
             :offer,
             :key_pair,
             :key_pairs,
             :read_state,
             :write_state,
             :verifier,
             :client_identity,
             :ticket,
             :resumption_master,
             :pending_tickets
           ]}
  defstruct [
    :client_hello,
    :client_ast,
    :key_pair,
    :key_pairs,
    :trust_source,
    :identity,
    :client_identity,
    :offer,
    :server_hello,
    :read_state,
    :write_state,
    :negotiated_protocol,
    :verified_peer,
    :ticket,
    :resumption_master,
    :phase,
    :framer,
    :verifier,
    :hrr,
    :hrr_transcript,
    resumed: false,
    enable_tickets: false,
    ticket_count: 0,
    pending_tickets: [],
    options: []
  ]

  @type event ::
          {:connected, binary() | nil} | {:application_data, binary()} | :closed
  @type t :: %__MODULE__{} | TLS12.t()

  @spec init(Materialized.t(), term(), SSL.PKIX.identity(), keyword()) ::
          {:ok, t(), [binary()]} | {:error, term()}
  def init(materialized, trust_source, identity, opts \\ [])

  def init(%Materialized{} = materialized, trust_source, identity, opts) when is_list(opts) do
    with {:ok, fields, bytes} <-
           ClientHandshake.prepare(materialized, trust_source, identity, opts) do
      state = struct!(__MODULE__, Map.put(fields, :framer, HandshakeFramer.new()))
      {:ok, state, plaintext_handshake_records(bytes)}
    end
  end

  def init(_, _, _, _), do: {:error, {:invalid_input, :handshake_machine}}

  @spec feed(t(), binary()) ::
          {:ok, t(), [binary()], [event()]}
          | {:error, {:fatal_alert, atom(), term()} | {:peer_alert, byte(), byte()}}
  def feed(%TLS12{} = state, record), do: TLS12.feed(state, record)

  def feed(%__MODULE__{phase: phase} = state, @ccs)
      when phase in [:await_server_hello, :await_server_hello_after_retry, :await_server_flight],
      do:
        if(0x0304 in state.offer.offered_versions,
          do: {:ok, state, [], []},
          else: fatal(:unexpected_message, :unexpected_tls12_change_cipher_spec)
        )

  def feed(%__MODULE__{phase: phase}, <<20, _::binary>>)
      when phase in [:await_server_hello, :await_server_hello_after_retry, :await_server_flight],
      do: fatal(:unexpected_message, :invalid_change_cipher_spec)

  def feed(%__MODULE__{phase: phase}, <<21, 3, _minor, 2::16, level, description>>)
      when phase in [:await_server_hello, :await_server_hello_after_retry],
      do: {:error, {:peer_alert, level, description}}

  def feed(
        %__MODULE__{phase: :await_server_flight},
        <<21, 3, _minor, 2::16, _level, _description>>
      ),
      do: fatal(:unexpected_message, :unprotected_alert_after_server_hello)

  def feed(%__MODULE__{phase: phase} = state, record)
      when phase in [:await_server_hello, :await_server_hello_after_retry] and is_binary(record) do
    with {:ok, bytes} <- plaintext_handshake_payload(record),
         {:ok, messages, framer} <-
           HandshakeFramer.feed(state.framer, bytes, max_handshake_length: @max_handshake_length) do
      case {messages, HandshakeFramer.buffered_size(framer)} do
        {[], _buffered} ->
          {:ok, %{state | framer: framer}, [], []}

        {[handshake | _] = handshakes, _buffered} ->
          case TLS12Codec.decode(handshake) do
            {:ok, %{type: :server_hello, cipher_suite: suite}} ->
              if match?(%{version: 0x0303}, SSL.Capabilities.resolve(:cipher_suite, suite)) do
                accept_initial_tls12(state, suite, handshakes, framer)
              else
                accept_initial_tls13(state, handshakes, framer)
              end

            _ ->
              accept_initial_tls13(state, handshakes, framer)
          end
      end
    else
      {:error, {:record_length_exceeded, _, _} = reason} -> fatal(:record_overflow, reason)
      {:error, reason} -> fatal(:decode_error, reason)
    end
  end

  def feed(%__MODULE__{phase: :await_server_flight} = state, record) when is_binary(record) do
    case decrypt_handshake(state.read_state, record) do
      {:ok, :handshake, bytes, read_state} ->
        feed_server_handshake(state, bytes, read_state)

      {:ok, :alert, <<level, description>>, _read_state} ->
        {:error, {:peer_alert, level, description}}

      {:ok, type, _bytes, _read_state} ->
        fatal(:unexpected_message, {:unexpected_inner_content_type, type})

      {:error, reason} ->
        record_error(reason)
    end
  end

  def feed(%__MODULE__{phase: :connected} = state, record)
      when is_binary(record),
      do: feed_connected(state, record)

  def feed(%__MODULE__{phase: :closed}, _record), do: {:error, :closed}

  def feed(_, _), do: fatal(:decode_error, :invalid_record)

  defp accept_initial_tls13(state, [handshake], framer) do
    if HandshakeFramer.buffered_size(framer) == 0 do
      case ClientHandshake.decode_server_hello(handshake, state.offer, state.hrr) do
        {:ok, hello} ->
          accept_server_hello(%{state | framer: HandshakeFramer.new()}, hello)

        {:error, {:fatal_alert, _, _}} = error ->
          error

        {:error, reason} ->
          fatal(:illegal_parameter, reason)
      end
    else
      fatal(:unexpected_message, :invalid_server_hello_flight)
    end
  end

  defp accept_initial_tls13(_, _, _), do: fatal(:unexpected_message, :invalid_server_hello_flight)

  defp feed_server_handshake(state, bytes, read_state) do
    with {:ok, messages, framer} <-
           HandshakeFramer.feed(state.framer, bytes, max_handshake_length: @max_handshake_length),
         verifier = %{state.verifier | server_handshake_state: read_state},
         next = %{state | read_state: read_state, framer: framer, verifier: verifier},
         {:ok, next, outbound, events} <- process_server_messages(next, messages) do
      {:ok, next, outbound, events}
    else
      {:error, {:fatal_alert, _, _}} = error -> error
      {:error, reason} -> fatal(:decode_error, reason)
    end
  end

  @spec encrypt(t(), :application_data | :alert, iodata()) ::
          {:ok, binary(), t()} | {:error, term()}
  def encrypt(%TLS12{} = state, type, data), do: TLS12.encrypt(state, type, data)

  def encrypt(%__MODULE__{phase: :connected, write_state: write} = state, :application_data, data) do
    with {:ok, updates, write} <-
           maybe_update_write(write, TrafficState.key_update_required?(write)),
         {:ok, record, next} <- encrypt_record(state, write, :application_data, data) do
      {:ok, IO.iodata_to_binary([updates, record]), next}
    else
      {:error, {:fatal_alert, _, _}} = error -> error
      {:error, reason} -> fatal(:internal_error, reason)
    end
  end

  def encrypt(%__MODULE__{phase: :closed, write_state: write} = state, :alert, data)
      when not is_nil(write),
      do: encrypt_record(state, write, :alert, data)

  def encrypt(%__MODULE__{write_state: write} = state, :alert, data) when not is_nil(write),
    do: encrypt_record(state, write, :alert, data)

  def encrypt(%__MODULE__{} = state, :alert, data) do
    with {:ok, bytes} <- iodata(data), true <- byte_size(bytes) == 2 do
      {:ok, <<21, 3, 3, 2::16, bytes::binary>>, state}
    else
      false -> {:error, :invalid_alert}
      {:error, _} = error -> error
    end
  end

  def encrypt(_, _, _), do: {:error, :not_connected}

  defp accept_server_hello(state, %ServerHello{kind: :hello_retry_request} = hrr) do
    with {:ok, next, bytes} <- ClientHandshake.retry(state, hrr) do
      {:ok, next, plaintext_handshake_records(bytes), []}
    end
  end

  defp accept_server_hello(state, %ServerHello{kind: :server_hello} = hello) do
    with :ok <- ClientHandshake.validate_hrr_selection(state.hrr, hello),
         {:ok, key_pair} <-
           ClientHandshake.selected_key_pair(state.key_pairs, state.key_pair, hello),
         input = %Input{
           client_hello: state.client_hello,
           server_hello: hello,
           client_key_pair: key_pair,
           records: [],
           trust_source: state.trust_source,
           identity: state.identity,
           client_identity: state.client_identity,
           ticket: state.ticket,
           enable_tickets: state.enable_tickets
         },
         {:ok, %Incremental{} = verifier} <-
           start_verifier(input, verifier_options(state.options), state.hrr_transcript) do
      {:ok,
       %{
         state
         | server_hello: hello,
           key_pair: key_pair,
           read_state: verifier.secrets.server_handshake_state,
           write_state: verifier.secrets.client_handshake_state,
           verifier: verifier,
           phase: :await_server_flight
       }, [], []}
    end
  end

  defp process_server_messages(state, messages) do
    Enum.reduce_while(messages, {:ok, state, [], []}, fn encoded, {:ok, current, out, events} ->
      if current.phase == :connected do
        {:halt, fatal(:unexpected_message, :trailing_handshake_after_finished)}
      else
        case ServerFlightVerifier.process_message(current.verifier, encoded) do
          {:ok, verifier} ->
            {:cont, {:ok, %{current | verifier: verifier}, out, events}}

          {:connected, result, records} ->
            connected = %{
              current
              | phase: :connected,
                verifier: nil,
                key_pair: nil,
                key_pairs: [],
                client_hello: nil,
                client_ast: nil,
                offer: nil,
                client_identity: nil,
                ticket: nil,
                trust_source: nil,
                resumption_master: result.resumption_master,
                resumed: result.resumed,
                hrr_transcript: nil,
                read_state: result.server_application_state,
                write_state: result.client_application_state,
                negotiated_protocol: result.negotiated_protocol,
                verified_peer: result.verified_peer
            }

            {:cont,
             {:ok, connected, out ++ records,
              events ++ [{:connected, result.negotiated_protocol}]}}

          {:error, _} = error ->
            {:halt, error}
        end
      end
    end)
    |> reject_partial_after_finished()
  end

  defp reject_partial_after_finished({:ok, %{phase: :connected, framer: framer}, _, _} = result) do
    if HandshakeFramer.buffered_size(framer) == 0 do
      {:ok, state, records, events} = result
      {:ok, %{state | framer: HandshakeFramer.new()}, records, events}
    else
      fatal(:decode_error, :incomplete_handshake_after_finished)
    end
  end

  defp reject_partial_after_finished(result), do: result

  defp feed_connected(state, record) do
    case Record.decrypt(state.read_state, record) do
      {:ok, :application_data, data, read} ->
        if HandshakeFramer.buffered_size(state.framer) == 0,
          do: {:ok, %{state | read_state: read}, [], [{:application_data, data}]},
          else: fatal(:unexpected_message, :interleaved_post_handshake_record)

      {:ok, :alert, <<1, 0>>, read} ->
        {:ok, %{state | read_state: read, phase: :closed}, [], [:closed]}

      {:ok, :alert, <<level, description>>, _read} ->
        {:error, {:peer_alert, level, description}}

      {:ok, :handshake, bytes, read} ->
        with {:ok, messages, framer} <-
               HandshakeFramer.feed(state.framer, bytes,
                 max_handshake_length: @max_handshake_length
               ),
             :ok <- validate_post_handshake_epoch(messages, framer),
             {:ok, next, records} <-
               process_post_handshake(
                 %{state | read_state: read, framer: framer},
                 messages
               ) do
          events = Enum.map(Enum.reverse(next.pending_tickets), &{:session_ticket, &1})
          {:ok, %{next | pending_tickets: []}, records, events}
        else
          {:error, {:fatal_alert, _, _}} = error -> error
          {:error, reason} -> fatal(:decode_error, reason)
        end

      {:ok, type, _data, _read} ->
        fatal(:unexpected_message, {:unexpected_inner_content_type, type})

      {:error, reason} ->
        record_error(reason)
    end
  end

  defp process_post_handshake(state, messages) do
    Enum.reduce_while(messages, {:ok, state, []}, fn
      # RFC 9846 §4.7.1: no resumption support means no ticket semantic decoding.
      # HandshakeFramer has already checked completeness and the global size bound.
      <<4, _length::24, _body::binary>>, {:ok, %{enable_tickets: false}, _} = result ->
        {:cont, result}

      <<4, _length::24, _body::binary>>, {:ok, %{ticket_count: count}, _} = result
      when count >= 8 ->
        {:cont, result}

      message, {:ok, current, out} ->
        case ServerFlight.decode(message, hash: hash_for(current.write_state)) do
          {:ok, %ServerFlight.NewSessionTicket{} = ticket, <<>>} ->
            case receive_ticket(current, ticket) do
              {:ok, next} -> {:cont, {:ok, next, out}}
              {:error, _} = error -> {:halt, error}
            end

          {:ok, %ServerFlight.KeyUpdate{request_update: request?}, <<>>} ->
            case apply_key_update(current, request?) do
              {:ok, next, records} -> {:cont, {:ok, next, out ++ records}}
              {:error, _} = error -> {:halt, error}
            end

          {:ok, decoded, <<>>} ->
            {:halt, fatal(:unexpected_message, {:unsupported_post_handshake, decoded.__struct__})}

          {:error, reason} ->
            {:halt, fatal(:unexpected_message, reason)}
        end
    end)
  end

  defp receive_ticket(state, %{ticket_lifetime: 0}), do: {:ok, state}

  defp receive_ticket(state, ticket) do
    hash = hash_for(state.write_state)

    case KeySchedule.resumption_secret(hash, state.resumption_master, ticket.ticket_nonce) do
      {:ok, psk} ->
        material = %{
          ticket: ticket.ticket,
          psk: psk,
          hash: hash,
          age_add: ticket.ticket_age_add,
          lifetime: ticket.ticket_lifetime,
          peer: state.verified_peer,
          alpn: state.negotiated_protocol
        }

        count = state.ticket_count + 1

        {:ok,
         %{
           state
           | pending_tickets: [material | state.pending_tickets],
             ticket_count: count,
             resumption_master: if(count == 8, do: nil, else: state.resumption_master)
         }}

      {:error, reason} ->
        fatal(:internal_error, reason)
    end
  end

  defp validate_post_handshake_epoch(messages, framer) do
    key_update_index = Enum.find_index(messages, &match?(<<24, _::binary>>, &1))

    cond do
      is_nil(key_update_index) -> :ok
      key_update_index != length(messages) - 1 -> {:error, :trailing_message_after_key_update}
      HandshakeFramer.buffered_size(framer) != 0 -> {:error, :partial_message_after_key_update}
      true -> :ok
    end
  end

  # A reciprocal update is encrypted with the old write key before switching epochs.
  defp apply_key_update(state, request?) do
    with {:ok, read} <- update_traffic_state(state.read_state),
         {:ok, records, write} <- maybe_update_write(state.write_state, request?) do
      {:ok, %{state | read_state: read, write_state: write}, records}
    end
  end

  defp maybe_update_write(write, false), do: {:ok, [], write}

  defp maybe_update_write(write, true) do
    with true <- TrafficState.may_update_write?(write),
         {:ok, encoded} <- ServerFlight.encode_key_update(false),
         # Compute the candidate before encryption so derivation failure cannot
         # consume the last old-key operation. Install it only after protecting
         # KeyUpdate with the old key; the returned wire order is unchanged.
         {:ok, updated} <- update_traffic_state(write),
         {:ok, record, _advanced_old} <- Record.encrypt(write, :handshake, encoded) do
      {:ok, [record], updated}
    else
      false -> fatal(:internal_error, :generation_exhausted)
      {:error, reason} -> fatal(:internal_error, reason)
    end
  end

  defp update_traffic_state(state) do
    with {:ok, secret} <- KeySchedule.traffic_update(hash_for(state), state.secret),
         {:ok, next} <- KeySchedule.traffic_state(state.cipher_suite, secret) do
      {:ok, %{next | generation: state.generation + 1}}
    end
  end

  defp plaintext_handshake_payload(<<22, 3, 3, length::16, bytes::binary-size(length)>>),
    do:
      if(length <= 16_384,
        do: {:ok, bytes},
        else: {:error, {:record_length_exceeded, length, 16_384}}
      )

  defp plaintext_handshake_payload(_), do: {:error, :expected_plaintext_handshake_record}

  defp plaintext_handshake_records(handshake), do: plaintext_handshake_records(handshake, [])
  defp plaintext_handshake_records(<<>>, records), do: Enum.reverse(records)

  defp plaintext_handshake_records(bytes, records) do
    size = min(byte_size(bytes), 16_384)
    <<chunk::binary-size(^size), rest::binary>> = bytes
    plaintext_handshake_records(rest, [plaintext_handshake_record(chunk) | records])
  end

  defp plaintext_handshake_record(chunk),
    do: <<22, 3, 3, byte_size(chunk)::16, chunk::binary>>

  defp decrypt_handshake(read, record) do
    case Record.decrypt(read, record) do
      {:ok, type, bytes, next} -> {:ok, type, bytes, next}
      {:error, reason} -> {:error, reason}
    end
  end

  defp encrypt_record(state, write, type, data) do
    with {:ok, bytes} <- iodata(data),
         {:ok, record, next} <- Record.encrypt(write, type, bytes) do
      {:ok, record, %{state | write_state: next}}
    end
  end

  defp iodata(data) do
    {:ok, IO.iodata_to_binary(data)}
  rescue
    ArgumentError -> {:error, :invalid_iodata}
  end

  defp verifier_options(options),
    do:
      Keyword.take(options, [
        :customize_hostname_check,
        :depth,
        :max_handshake_length,
        :max_certificate_count,
        :max_total_certificate_bytes,
        :max_certificate_bytes,
        :max_extension_bytes,
        :max_signature_bytes
      ])

  defp start_verifier(input, options, nil),
    do: ServerFlightVerifier.start_incremental(input, options)

  defp start_verifier(input, options, transcript),
    do: ServerFlightVerifier.start_incremental(input, options, transcript)

  defp hash_for(%{cipher_suite: suite}), do: SSL.Capabilities.resolve(:cipher_suite, suite).hash

  defp record_error(reason) when reason in [:authentication_failed, :decryption_failed],
    do: fatal(:bad_record_mac, reason)

  defp record_error({:record_length_exceeded, _, _} = reason), do: fatal(:record_overflow, reason)
  defp record_error(reason), do: fatal(:decode_error, reason)
  defp fatal(alert, reason), do: {:error, {:fatal_alert, alert, reason}}

  defp accept_initial_tls12(state, suite, handshakes, framer) do
    if 0x0303 in state.offer.offered_versions and suite in state.offer.cipher_suites and
         state.phase == :await_server_hello do
      with {:ok, tls12} <-
             TLS12.new(
               state.client_hello,
               state.offer,
               state.trust_source,
               state.identity,
               [client_identity: state.client_identity] ++ state.options
             ) do
        TLS12.feed_handshakes(tls12, handshakes, framer)
      end
    else
      fatal(:illegal_parameter, :unoffered_tls12_selection)
    end
  end
end
