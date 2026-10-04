defmodule SSL.Protocol.ServerFlightVerifier do
  @moduledoc "TLS record adapter for the shared record-free handshake core."
  alias SSL.Crypto.KeySchedule
  alias SSL.Protocol.{HandshakeCore, HandshakeFramer, Record, Transcript}

  defmodule Input do
    @moduledoc """
    Exact public handshake inputs and fresh per-connection client key material.
    """

    alias SSL.Crypto.KeyExchange.KeyPair
    alias SSL.Protocol.ServerHello

    @derive {Inspect,
             except: [:client_hello, :client_key_pair, :trust_source, :client_identity, :ticket]}
    @enforce_keys [
      :client_hello,
      :server_hello,
      :client_key_pair,
      :records,
      :trust_source,
      :identity
    ]
    defstruct @enforce_keys ++ [client_identity: nil, ticket: nil, enable_tickets: false]

    @type t :: %__MODULE__{
            client_hello: binary(),
            server_hello: ServerHello.t(),
            client_key_pair: KeyPair.t(),
            records: [binary()],
            trust_source: term(),
            identity: SSL.PKIX.identity(),
            client_identity: SSL.ClientIdentity.t() | nil
          }
  end

  defmodule Result do
    @moduledoc """
    Verified peer and traffic epochs ready for later connection orchestration.
    """

    alias SSL.Crypto.TrafficState
    alias SSL.PKIX.VerifiedPeer
    alias SSL.Protocol.Transcript

    @derive {Inspect,
             except: [
               :server_handshake_state,
               :client_handshake_state,
               :client_application_state,
               :server_application_state,
               :client_auth_records,
               :resumption_master,
               :transcript
             ]}
    @enforce_keys [
      :verified_peer,
      :server_handshake_state,
      :client_handshake_state,
      :client_finished_record,
      :client_application_state,
      :server_application_state,
      :transcript,
      :negotiated_protocol
    ]
    defstruct @enforce_keys ++ [client_auth_records: [], resumption_master: nil, resumed: false]

    @type t :: %__MODULE__{
            verified_peer: VerifiedPeer.t(),
            server_handshake_state: TrafficState.t(),
            client_handshake_state: TrafficState.t(),
            client_finished_record: binary(),
            client_application_state: TrafficState.t(),
            server_application_state: TrafficState.t(),
            transcript: Transcript.t(),
            negotiated_protocol: binary() | nil
          }
  end

  defmodule Incremental do
    @moduledoc false
    @derive {Inspect, only: []}
    defstruct [:core, :secrets, :server_handshake_state]
    @type t :: %__MODULE__{}
  end

  @spec verify(term(), keyword()) :: {:ok, Result.t()} | {:error, term()}
  def verify(input, options \\ []) do
    with {:ok, state} <- start_incremental(input, options),
         {:ok, messages, read} <-
           decrypt_records(input.records, state.server_handshake_state, state.core.config),
         {:ok, result, messages} <- HandshakeCore.verify_messages(state.core, messages),
         {:ok, result, _records} <-
           adapt_result(%{state | server_handshake_state: read}, result, messages) do
      {:ok, result}
    else
      {:error, {:fatal_alert, _, _}} = error -> error
      {:error, {alert, reason}} -> {:error, {:fatal_alert, alert, reason}}
    end
  end

  def start_incremental(input, options \\ []), do: start_incremental(input, options, nil)

  def start_incremental(%Input{} = input, options, transcript) do
    with {:ok, core} <- HandshakeCore.start_client(Map.from_struct(input), options, transcript),
         {:ok, client} <-
           KeySchedule.traffic_state(core.secrets.suite, core.secrets.client_handshake_secret),
         {:ok, server} <-
           KeySchedule.traffic_state(core.secrets.suite, core.secrets.server_handshake_secret) do
      {:ok,
       %Incremental{
         core: core,
         server_handshake_state: server,
         secrets: %{client_handshake_state: client, server_handshake_state: server}
       }}
    end
  end

  def start_incremental(_, _, _),
    do: {:error, {:fatal_alert, :decode_error, {:invalid_input, :verifier}}}

  def process_message(%Incremental{} = state, encoded) do
    case HandshakeCore.process_message(state.core, encoded) do
      {:ok, core} ->
        {:ok, %{state | core: core}}

      {:connected, result, messages} ->
        case adapt_result(state, result, messages) do
          {:ok, result, records} -> {:connected, result, records}
          error -> error
        end

      error ->
        error
    end
  end

  def process_message(_, _),
    do: {:error, {:fatal_alert, :decode_error, {:invalid_input, :incremental_message}}}

  defp adapt_result(state, result, messages) do
    with {:ok, client} <-
           KeySchedule.traffic_state(result.suite, result.client_application_secret),
         {:ok, server} <-
           KeySchedule.traffic_state(result.suite, result.server_application_secret),
         {:ok, records, write} <- encrypt_messages(state.secrets.client_handshake_state, messages) do
      {auth, [finished]} = Enum.split(records, -1)

      {:ok,
       %Result{
         verified_peer: result.verified_peer,
         server_handshake_state: state.server_handshake_state,
         client_handshake_state: write,
         client_finished_record: finished,
         client_auth_records: auth,
         client_application_state: client,
         server_application_state: server,
         transcript: result.transcript,
         negotiated_protocol: result.negotiated_protocol,
         resumption_master: result.resumption_master,
         resumed: result.resumed
       }, records}
    else
      {:error, reason} -> {:error, {:fatal_alert, :internal_error, reason}}
    end
  end

  defp encrypt_messages(state, messages) do
    Enum.reduce_while(messages, {:ok, [], state}, fn bytes, {:ok, out, write} ->
      case encrypt_chunks(write, bytes, []) do
        {:ok, records, next} -> {:cont, {:ok, out ++ records, next}}
        error -> {:halt, error}
      end
    end)
  end

  defp encrypt_chunks(state, <<>>, records), do: {:ok, Enum.reverse(records), state}

  defp encrypt_chunks(state, bytes, records) do
    size = min(byte_size(bytes), 16_384)
    <<chunk::binary-size(^size), rest::binary>> = bytes

    with {:ok, record, next} <- Record.encrypt(state, :handshake, chunk) do
      encrypt_chunks(next, rest, [record | records])
    end
  end

  defp decrypt_records(records, state, config) do
    with :ok <- validate_record_count(records, config.max_records) do
      records
      |> Enum.reduce_while({:ok, [], HandshakeFramer.new(), state}, fn
        record, {:ok, messages, framer, current_state} ->
          case decrypt_record(record, current_state, framer, config) do
            {:ok, decoded, next_framer, next_state} ->
              updated_messages = Enum.reverse(decoded, messages)

              if length(updated_messages) > 4 do
                {:halt, alert(:unexpected_message, {:trailing_handshake_messages, 5})}
              else
                {:cont, {:ok, updated_messages, next_framer, next_state}}
              end

            {:error, {_alert, _reason}} = error ->
              {:halt, error}
          end
      end)
      |> complete_handshake_stream()
    end
  end

  defp validate_record_count([], _maximum),
    do: alert(:unexpected_message, :empty_server_flight)

  defp validate_record_count(records, maximum),
    do: validate_record_count(records, maximum, 0)

  defp validate_record_count([], _maximum, _count), do: :ok

  defp validate_record_count([_record | _rest], maximum, maximum),
    do: alert(:decode_error, {:record_count_limit_exceeded, maximum + 1, maximum})

  defp validate_record_count([_record | rest], maximum, count),
    do: validate_record_count(rest, maximum, count + 1)

  defp validate_record_count(_records, _maximum, _count),
    do: alert(:decode_error, {:invalid_input, :records})

  defp decrypt_record(record, state, framer, config) do
    case Record.decrypt(state, record) do
      {:ok, :handshake, plaintext, next_state} ->
        case HandshakeFramer.feed(
               framer,
               plaintext,
               max_handshake_length: config.max_handshake_length
             ) do
          {:ok, decoded, next_framer} -> {:ok, decoded, next_framer, next_state}
          {:error, reason} -> alert(:decode_error, reason)
        end

      {:ok, content_type, _content, _next_state} ->
        alert(:unexpected_message, {:unexpected_inner_content_type, content_type})

      {:error, reason} when reason in [:authentication_failed, :decryption_failed] ->
        alert(:bad_record_mac, reason)

      {:error, {:record_length_exceeded, _length, _maximum} = reason} ->
        alert(:record_overflow, reason)

      {:error, {:inner_plaintext_length_exceeded, _length, _maximum} = reason} ->
        alert(:record_overflow, reason)

      {:error, {:content_length_exceeded, _length, _maximum} = reason} ->
        alert(:record_overflow, reason)

      {:error, {:unexpected_outer_content_type, _content_type} = reason} ->
        alert(:unexpected_message, reason)

      {:error, {:unsupported_inner_content_type, _content_type} = reason} ->
        alert(:unexpected_message, reason)

      {:error, {:empty_content, content_type} = reason}
      when content_type in [:handshake, :alert] ->
        alert(:unexpected_message, reason)

      {:error, reason} when reason in [:empty_inner_plaintext, :missing_inner_content_type] ->
        alert(:unexpected_message, reason)

      {:error, reason} ->
        alert(:decode_error, reason)
    end
  end

  defp complete_handshake_stream({:error, {_alert, _reason}} = error), do: error

  defp complete_handshake_stream({:ok, messages, framer, state}) do
    case HandshakeFramer.buffered_size(framer) do
      0 -> {:ok, Enum.reverse(messages), state}
      bytes -> alert(:decode_error, {:incomplete_handshake, bytes})
    end
  end

  defp alert(alert, reason), do: {:error, {alert, reason}}
end
