defmodule SSL.QUIC do
  @moduledoc """
  Caller-owned TLS 1.3 certificate/PSK-DHE handshake for QUIC CRYPTO streams.

  Feed only new contiguous handshake bytes at the level reported by `info/1`.
  Process returned actions in list order. Emitted bytes are committed to the
  caller's reliable send queue; retransmission reuses them without another TLS
  call. This API implements no sockets, records, QUIC packets or HANDSHAKE_DONE.
  See `docs/QUIC_TLS_INTERFACE.md` for the ownership and authentication boundary.
  """
  alias SSL.Capabilities
  alias SSL.Crypto.KeyExchange

  alias SSL.Protocol.{
    ClientHandshake,
    HandshakeCore,
    HandshakeFramer,
    ServerFlight,
    ServerHandshake
  }

  alias SSL.QUIC.{Config, Request, Resumption, Session}

  defmodule Secret do
    @moduledoc "A directional TLS traffic secret. Inspection never reveals its bytes."
    @derive {Inspect, only: [:level, :direction, :cipher_suite, :aead, :hkdf]}
    @enforce_keys [:level, :direction, :cipher_suite, :aead, :hkdf, :secret]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            level: :early_data | :handshake | :application,
            direction: :read | :write,
            cipher_suite: non_neg_integer(),
            aead: atom(),
            hkdf: :sha256 | :sha384,
            secret: binary()
          }
  end

  defmodule Error do
    @moduledoc "Redacted TLS, QUIC integration, or local API error."
    @derive {Inspect, only: [:kind, :alert, :reason]}
    defstruct [:kind, :alert, :reason]

    @type t :: %__MODULE__{
            kind: :tls | :quic | :configuration | :closed,
            alert: atom() | nil,
            reason: atom()
          }
  end

  defmodule State do
    @moduledoc false
    @derive {Inspect,
             only: [:role, :phase, :receive_level, :handshake_complete, :peer_authenticated]}
    defstruct [
      :role,
      :phase,
      :receive_level,
      :config,
      :core,
      :hello,
      :framer,
      :limits,
      :peer_parameters,
      :cipher_suite,
      :alpn,
      :allowed_algorithms,
      :session,
      :pending,
      :continuation_nonce,
      :ticket_metadata,
      continuation_sequence: 0,
      ticket_receipts: 0,
      early_status: :disabled,
      resumed: false,
      peer_parameters_authenticated: false,
      total_bytes: 0,
      handshake_complete: false,
      peer_authenticated: false
    ]

    @type t :: %__MODULE__{}
  end

  @type level :: :initial | :handshake | :application
  @opaque state :: State.t()
  @type action ::
          Secret.t()
          | {:emit, level(), binary()}
          | {:peer_transport_parameters, binary(), :unverified | :authenticated}
          | {:peer_authenticated, :server}
          | {:negotiated_alpn, binary()}
          | {:session_lookup, Request.t()}
          | {:session_commit, Request.t()}
          | {:session_store, Request.t()}
          | {:session_ticket, Session.t()}
          | {:early_data, :accepted | :rejected}
          | :handshake_complete
          | {:error, Error.t()}
  @type result :: {:ok, state(), [action()]} | {:error, Error.t(), state(), [action()]}

  @spec capabilities() :: %{
          cipher_suites: [any()],
          groups: [map()],
          hello_retry_request: true,
          quic_packet_protection: false,
          resumption: true,
          roles: %{client: map(), server: map()},
          server_mtls: false,
          signatures: [map()],
          tls_records: false,
          tls_versions: [772, ...],
          zero_rtt: true
        }
  def capabilities do
    %{
      tls_versions: [0x0304],
      roles: %{
        client: %{certificate_handshake: true, client_identity: true},
        server: %{certificate_handshake: true, client_identity: false}
      },
      cipher_suites: Enum.filter(Capabilities.describe(:cipher_suite), &(&1.version == 0x0304)),
      groups: Capabilities.describe(:group),
      signatures: Capabilities.describe(:signature_algorithm),
      resumption: true,
      zero_rtt: true,
      server_mtls: false,
      hello_retry_request: true,
      tls_records: false,
      quic_packet_protection: false
    }
  end

  @spec new(:client | :server, keyword()) :: {:ok, state(), [action()]} | {:error, Error.t()}
  def new(role, options) do
    with {:ok, config} <- Config.build(role, options),
         {:ok, state, actions} <- initialize(role, config) do
      {:ok, state, actions}
    else
      {:error, _} -> {:error, %Error{kind: :configuration, reason: :invalid_configuration}}
    end
  end

  @spec info(state()) :: map()
  def info(%State{} = state) do
    Map.take(state, [
      :role,
      :phase,
      :receive_level,
      :handshake_complete,
      :peer_authenticated,
      :cipher_suite,
      :alpn,
      :allowed_algorithms,
      :peer_parameters_authenticated,
      :resumed,
      :early_status
    ])
  end

  @spec abort(state(), atom()) :: state()
  def abort(%State{} = state, _reason), do: terminal(state, :aborted)

  @doc "Resolve the state's single outstanding private authority request."
  @spec continue(state(), term(), term()) :: result()
  def continue(%State{phase: phase} = state, _, _) when phase in [:failed, :aborted],
    do: {:error, %Error{kind: :closed, reason: :terminal}, state, []}

  def continue(%State{pending: %{request: %{id: id}}} = state, id, result) do
    pending = state.pending
    next = %{state | pending: nil}

    case resume(next, pending, result) do
      {:ok, next, actions} ->
        case account_output(next, actions) do
          {:ok, next} -> {:ok, next, actions}
          {:error, reason} -> fail(next, :tls, :internal_error, reason)
        end

      {:error, {alert, reason}} when is_atom(alert) ->
        fail(next, :tls, alert, reason)

      {:error, reason} ->
        fail(next, :tls, :internal_error, reason)

      :invalid ->
        fail(next, :configuration, nil, :invalid_continuation_result)
    end
  end

  def continue(%State{} = state, _, _),
    do: {:error, %Error{kind: :configuration, reason: :invalid_continuation}, state, []}

  @spec feed(state(), level(), binary()) :: result()
  def feed(%State{phase: phase} = state, _level, _bytes) when phase in [:failed, :aborted] do
    {:error, %Error{kind: :closed, reason: :terminal}, state, []}
  end

  def feed(%State{pending: pending} = state, _, bytes) when not is_nil(pending) and bytes != <<>>,
    do: {:error, %Error{kind: :configuration, reason: :continuation_pending}, state, []}

  def feed(%State{} = state, level, bytes) when is_binary(bytes) do
    cond do
      level != state.receive_level ->
        fail(state, :quic, nil, :wrong_encryption_level)

      bytes == <<>> ->
        {:ok, state, []}

      state.total_bytes + byte_size(bytes) > state.limits[:max_total_handshake_bytes] ->
        fail(state, :tls, :decode_error, :handshake_budget_exceeded)

      true ->
        with :ok <- hello_extension_limit(state, bytes),
             {:ok, messages, framer} <-
               HandshakeFramer.feed(state.framer, bytes,
                 max_handshake_length: state.limits[:max_handshake_length]
               ) do
          consume(
            %{state | framer: framer, total_bytes: state.total_bytes + byte_size(bytes)},
            level,
            messages,
            []
          )
        else
          {:error, reason} ->
            fail(state, :tls, :decode_error, reason)
        end
    end
  end

  def feed(%State{} = state, _, _), do: fail(state, :configuration, nil, :invalid_input)

  # A valid ServerHello extension length is available in at most 76 bytes,
  # including the largest legacy session ID. Inspect only that bounded prefix;
  # do not flatten an accumulating payload on every fragmented feed.
  defp hello_extension_limit(%State{role: :client, phase: :hello} = state, bytes) do
    size = HandshakeFramer.buffered_size(state.framer)

    if size < 76 do
      prefix = HandshakeFramer.buffered_bytes(state.framer)
      incoming = binary_part(bytes, 0, min(byte_size(bytes), 76 - size))

      SSL.Protocol.ServerHello.check_extension_limit(
        prefix <> incoming,
        state.limits[:max_extension_bytes]
      )
    else
      :ok
    end
  end

  defp hello_extension_limit(_, _), do: :ok

  defp initialize(:server, config), do: {:ok, base(:server, config), []}

  defp initialize(:client, config) do
    with {:ok, materialized} <- Config.materialize(config),
         session = Resumption.client_session(config),
         {:ok, materialized} <- Resumption.offer(config, materialized, session),
         {:ok, hello, bytes} <-
           ClientHandshake.prepare(
             materialized,
             config.trust,
             config.reference_identity,
             [
               client_identity: config.identity,
               ticket: if(session, do: Resumption.ticket(session)),
               enable_tickets: config.resumption != nil
             ] ++ config.verifier_options
           ) do
      early = Resumption.early?(config, session)

      state = %{
        base(:client, config)
        | hello: hello,
          session: session,
          early_status: if(early, do: :offered, else: :disabled)
      }

      actions =
        [{:emit, :initial, bytes}] ++
          if early do
            {:ok, traffic} = Resumption.early_secret(session, bytes)
            [secret(%{state | cipher_suite: session.cipher_suite}, :early_data, :write, traffic)]
          else
            []
          end

      with {:ok, state} <- account_output(state, actions) do
        {:ok, state, actions}
      end
    end
  end

  defp base(role, config),
    do: %State{
      role: role,
      continuation_nonce: :crypto.strong_rand_bytes(16),
      phase: :hello,
      receive_level: :initial,
      config: config,
      limits: config.limits,
      allowed_algorithms: Map.take(config, [:ciphers, :groups, :signature_algorithms]),
      framer: HandshakeFramer.new()
    }

  defp consume(state, _level, [], actions), do: {:ok, state, actions}

  defp consume(state, level, [message | rest], actions) do
    case step(state, message) do
      {:ok, next, emitted} ->
        case account_output(next, emitted) do
          {:ok, next} ->
            if (next.receive_level != level or next.pending != nil) and
                 (rest != [] or HandshakeFramer.buffered_size(next.framer) != 0) do
              fail(next, :quic, nil, :cross_level_handshake)
            else
              consume(next, level, rest, actions ++ emitted)
            end

          {:error, reason} ->
            fail(next, :tls, :internal_error, reason)
        end

      {:error, {:quic, reason}} ->
        fail(state, :quic, nil, reason)

      {:error, {:fatal_alert, alert, reason}} ->
        fail(state, :tls, alert, reason)

      {:error, {alert, reason}}
      when alert in [
             :illegal_parameter,
             :decode_error,
             :unexpected_message,
             :missing_extension,
             :unsupported_extension,
             :decrypt_error,
             :handshake_failure,
             :no_application_protocol,
             :protocol_version,
             :internal_error
           ] ->
        fail(state, :tls, alert, reason)

      {:error, reason} ->
        fail(state, :tls, :decode_error, reason)
    end
  end

  defp step(%State{role: :client, phase: :connected}, <<13, _::binary>>),
    do: {:error, {:quic, :post_handshake_authentication}}

  defp step(%State{role: :client, phase: :hello} = state, <<2, _::binary>> = encoded) do
    with {:ok, hello} <-
           ClientHandshake.decode_server_hello(
             encoded,
             state.hello.offer,
             state.hello.hrr,
             max_extension_bytes: state.limits[:max_extension_bytes]
           ) do
      case hello.kind do
        :hello_retry_request ->
          with {:ok, next, bytes} <- ClientHandshake.retry(state.hello, hello) do
            {state, early} = reject_early(state)

            {:ok, %{state | hello: next, session: if(next.ticket, do: state.session)},
             early ++ [{:emit, :initial, bytes}]}
          end

        :server_hello ->
          with :ok <- ClientHandshake.validate_hrr_selection(state.hello.hrr, hello),
               {:ok, pair} <-
                 ClientHandshake.selected_key_pair(
                   state.hello.key_pairs,
                   state.hello.key_pair,
                   hello
                 ),
               input = %{
                 client_hello: state.hello.client_hello,
                 server_hello: hello,
                 client_key_pair: pair,
                 trust_source: state.config.trust,
                 identity: state.config.reference_identity,
                 client_identity: state.config.identity,
                 ticket: state.hello.ticket,
                 enable_tickets: state.config.resumption != nil,
                 allow_early_data: state.early_status == :offered and state.hello.hrr == nil
               },
               {:ok, core} <-
                 HandshakeCore.start_client(
                   input,
                   state.config.verifier_options,
                   state.hello.hrr_transcript
                 ) do
            next = %{
              state
              | core: core,
                hello: nil,
                phase: :server_flight,
                cipher_suite: hello.cipher_suite,
                resumed: {:pre_shared_key, 0} in hello.extensions,
                receive_level: :handshake
            }

            {:ok, next,
             [
               secret(next, :handshake, :read, core.secrets.server_handshake_secret),
               secret(next, :handshake, :write, core.secrets.client_handshake_secret)
             ]}
          end
      end
    end
  end

  defp step(%State{role: :client, phase: :server_flight} = state, encoded) do
    with {:ok, parameters, early_events} <- client_parameters(state, encoded) do
      case HandshakeCore.process_message(state.core, encoded) do
        {:ok, core} ->
          with {:ok, state, disposition} <- early_disposition(state, encoded) do
            {:ok, %{state | core: core, peer_parameters: parameters}, early_events ++ disposition}
          end

        {:connected, result, messages} ->
          next =
            complete(%{
              state
              | peer_parameters: parameters,
                peer_authenticated: true,
                alpn: result.negotiated_protocol,
                ticket_metadata: ticket_metadata(state, result, parameters)
            })

          actions =
            [
              secret(state, :application, :read, result.server_application_secret),
              {:peer_authenticated, :server},
              {:peer_transport_parameters, parameters, :authenticated},
              {:negotiated_alpn, result.negotiated_protocol}
            ] ++
              Enum.map(messages, &{:emit, :handshake, &1}) ++
              [
                secret(state, :application, :write, result.client_application_secret),
                :handshake_complete
              ]

          {:ok, next, early_events ++ actions}

        error ->
          error
      end
    end
  end

  defp step(%State{role: :server, phase: :hello} = state, <<1, _::binary>> = encoded) do
    case ServerHandshake.accept_hello(state.config, encoded, state.core) do
      {kind, core} when kind == :ok -> server_hello(state, {:ok, core})
      {:retry, core, bytes} -> server_hello(state, {:retry, core, bytes})
      error -> error
    end
  end

  defp step(%State{role: :server, phase: :client_finished} = state, <<20, _::binary>> = encoded) do
    with :ok <- ServerHandshake.finish(state.core, encoded) do
      completed = complete(state)

      actions = [
        {:peer_transport_parameters, state.peer_parameters, :authenticated},
        {:negotiated_alpn, state.alpn},
        :handshake_complete
      ]

      if state.config && state.config.resumption do
        transcript = SSL.Protocol.Transcript.append(state.core.transcript, encoded)

        {session, ticket} =
          Resumption.new_ticket(
            state.config,
            state.cipher_suite,
            state.alpn,
            state.core.secrets.master_secret,
            transcript
          )

        session = %{session | server_name: Resumption.server_name(state.core.offer)}

        if Session.validate(session) == :ok do
          {next, action} = request(completed, :store, %{session: session}, %{ticket: ticket})
          {:ok, next, actions ++ [action]}
        else
          {:ok, completed, actions}
        end
      else
        {:ok, completed, actions}
      end
    end
  end

  defp step(%State{role: :client, phase: :connected} = state, <<4, _::binary>> = encoded) do
    # Decode even disabled/excess receipts; peer syntax violations remain fatal.
    spec = Capabilities.resolve(:cipher_suite, state.cipher_suite)

    case ServerFlight.decode(
           encoded,
           [hash: spec.hash] ++ Keyword.delete(state.limits, :max_total_handshake_bytes)
         ) do
      {:ok, %ServerFlight.NewSessionTicket{} = ticket, <<>>} ->
        cond do
          not Resumption.valid_ticket_early_data?(ticket) ->
            {:error, {:quic, :invalid_quic_early_data_maximum}}

          state.ticket_metadata && state.ticket_receipts < 4 ->
            case Resumption.receive_ticket(ticket, state.ticket_metadata) do
              {:ok, session} -> {:ok, ticket_received(state), [{:session_ticket, session}]}
              :skip -> {:ok, ticket_received(state), []}
              error -> error
            end

          true ->
            {:ok, state, []}
        end

      {:error, reason} ->
        HandshakeCore.decode_alert(reason)

      _ ->
        {:error, {:decode_error, :invalid_ticket}}
    end
  end

  defp step(_, _), do: {:error, {:unexpected_message, :unexpected_handshake}}

  defp server_hello(state, prepared) do
    core = elem(prepared, 1)

    cond do
      state.core && state.core.session ->
        with :ok <- Resumption.verify(state.core.session, core.offer, state.core),
             true <-
               state.core.session.hash == Capabilities.resolve(:cipher_suite, core.suite).hash do
          dispatch_server(state, prepared)
        else
          _ -> {:error, {:decrypt_error, :invalid_psk_binder}}
        end

      state.config.resumption && 1 in core.offer.psk_key_exchange_modes ->
        case Resumption.first_identity(core.offer) do
          {:ok, identity, _} ->
            {next, action} =
              request(
                state,
                :lookup,
                %{identity: identity, context: state.config.resumption.context},
                %{prepared: prepared}
              )

            {:ok, next, [action]}

          :none ->
            dispatch_server(state, prepared)
        end

      true ->
        dispatch_server(state, prepared)
    end
  end

  defp request(state, operation, fields, private) do
    count = state.continuation_sequence + 1
    id = {state.continuation_nonce, count}
    request = struct(Request, Map.merge(%{id: id, operation: operation}, fields))
    pending = Map.put(private, :request, request)

    action =
      {Map.fetch!(
         %{lookup: :session_lookup, commit: :session_commit, store: :session_store},
         operation
       ), request}

    {%{state | pending: pending, continuation_sequence: count}, action}
  end

  defp resume(
         state,
         %{request: %{operation: :lookup}, prepared: prepared},
         {:ok, %Session{} = session, lease, now}
       )
       when not is_nil(lease) and is_integer(now) do
    core = elem(prepared, 1)
    {:ok, identity, _} = Resumption.first_identity(core.offer)

    eligible =
      Resumption.eligible?(session, state.config, now) and session.identity == identity and
        session.server_name == Resumption.server_name(core.offer) and session.alpn == core.alpn and
        session.hash == Capabilities.resolve(:cipher_suite, core.suite).hash

    if eligible do
      case Resumption.verify(session, core.offer, state.core) do
        :ok ->
          early =
            tuple_size(prepared) == 2 and Resumption.early?(state.config, session) and
              42 in core.offer.extension_ids and core.suite == session.cipher_suite and
              Resumption.early_age_valid?(session, core.offer, now)

          config = %{state.config | resumption: %{state.config.resumption | now: now}}

          {next, action} =
            request(
              %{state | config: config},
              :commit,
              %{session: session, lease: lease, early_data: early},
              %{prepared: prepared}
            )

          {:ok, next, [action]}

        _ ->
          {:error, {:decrypt_error, :invalid_psk_binder}}
      end
    else
      dispatch_server(state, prepared)
    end
  end

  defp resume(state, %{request: %{operation: op}, prepared: prepared}, result)
       when op in [:lookup, :commit] and
              (result == :miss or
                 (is_tuple(result) and tuple_size(result) == 2 and elem(result, 0) == :error)),
       do: dispatch_server(state, prepared)

  defp resume(state, %{request: %{operation: :commit} = req, prepared: prepared}, {:ok, decision})
       when decision in [:resumed, :early_data] do
    if decision == :early_data and not req.early_data do
      :invalid
    else
      core = %{elem(prepared, 1) | session: req.session, early_data: decision == :early_data}
      prepared = put_elem(prepared, 1, core)
      dispatch_server(%{state | resumed: true}, prepared)
    end
  end

  defp resume(state, %{request: %{operation: :store}, ticket: ticket}, :ok),
    do: {:ok, state, [{:emit, :application, ticket}]}

  defp resume(state, %{request: %{operation: :store}}, result)
       when result == :miss or
              (is_tuple(result) and tuple_size(result) == 2 and elem(result, 0) == :error),
       do: {:ok, state, []}

  defp resume(_, _, _), do: :invalid

  defp dispatch_server(state, {:retry, core, bytes}) do
    {state, early} = server_early_rejection(state, core.offer)
    {:ok, %{state | core: core}, early ++ [{:emit, :initial, bytes}]}
  end

  defp dispatch_server(state, {:ok, core}) do
    group = Capabilities.resolve(:group, core.group).name

    with {:ok, pair} <- KeyExchange.generate(group),
         {:ok, core, hello, messages} <-
           ServerHandshake.flight(core, state.config, pair, :crypto.strong_rand_bytes(32)) do
      next = %{
        state
        | core: core,
          phase: :client_finished,
          receive_level: :handshake,
          cipher_suite: core.suite,
          alpn: core.alpn,
          peer_parameters: core.peer_parameters
      }

      {next, early} = server_early(next, core)

      actions =
        early ++
          [
            {:peer_transport_parameters, core.peer_parameters, :unverified},
            {:emit, :initial, hello},
            secret(next, :handshake, :read, core.secrets.client_handshake_secret),
            secret(next, :handshake, :write, core.secrets.server_handshake_secret)
          ] ++
          Enum.map(messages, &{:emit, :handshake, &1}) ++
          [
            secret(next, :application, :write, core.application_secrets.server),
            secret(next, :application, :read, core.application_secrets.client)
          ]

      keys =
        if state.config.resumption,
          do: [:hash, :client_handshake_secret, :master_secret],
          else: [:hash, :client_handshake_secret]

      core = %{
        core
        | secrets: Map.take(core.secrets, keys),
          application_secrets: nil,
          session: nil,
          first_offer: nil
      }

      config = if state.config.resumption, do: state.config
      {:ok, %{next | core: core, config: config}, actions}
    end
  end

  defp server_early(state, %{early_data: true, session: session, offer: offer}) do
    {:ok, traffic} = Resumption.early_secret(session, offer.encoded)

    {%{state | early_status: :accepted},
     [secret(state, :early_data, :read, traffic), {:early_data, :accepted}]}
  end

  defp server_early(state, core), do: server_early_rejection(state, core.offer)

  defp server_early_rejection(%{early_status: :disabled} = state, offer) do
    if 42 in offer.extension_ids,
      do: {%{state | early_status: :rejected}, [{:early_data, :rejected}]},
      else: {state, []}
  end

  defp server_early_rejection(state, _), do: {state, []}

  defp reject_early(%{early_status: :offered} = state),
    do: {%{state | early_status: :rejected}, [{:early_data, :rejected}]}

  defp reject_early(state), do: {state, []}

  defp early_disposition(%{early_status: :offered} = state, <<8, _::binary>> = encoded) do
    {:ok, ee, <<>>} =
      ServerFlight.decode(encoded,
        hash: state.core.secrets.hash,
        offered_extension_ids: state.core.offer.extension_ids
      )

    if {:early_data} in ee.extensions do
      if state.resumed and not is_nil(state.session) and
           state.session.cipher_suite == state.cipher_suite,
         do: {:ok, %{state | early_status: :accepted}, [{:early_data, :accepted}]},
         else: {:error, {:illegal_parameter, :invalid_early_data_selection}}
    else
      {state, actions} = reject_early(state)
      {:ok, state, actions}
    end
  end

  defp early_disposition(state, _), do: {:ok, state, []}

  defp ticket_received(state) do
    count = state.ticket_receipts + 1
    %{state | ticket_receipts: count, ticket_metadata: if(count < 4, do: state.ticket_metadata)}
  end

  defp ticket_metadata(%{config: %{resumption: nil}}, _, _), do: nil

  defp ticket_metadata(state, result, parameters) do
    %{
      master: result.resumption_master,
      peer: result.verified_peer,
      hash: result.hash,
      suite: state.cipher_suite,
      alpn: result.negotiated_protocol,
      parameters: parameters,
      context: state.config.resumption.context,
      now: state.config.resumption.now,
      server_name: state.config.server_name
    }
  end

  defp client_parameters(%{core: %{phase: :encrypted_extensions}} = state, encoded) do
    options =
      [hash: state.core.secrets.hash, offered_extension_ids: state.core.offer.extension_ids] ++
        Keyword.delete(state.limits, :max_total_handshake_bytes)

    with {:ok, %ServerFlight.EncryptedExtensions{extensions: extensions}, <<>>} <-
           ServerFlight.decode(encoded, options),
         {:quic_transport_parameters, bytes} <-
           List.keyfind(extensions, :quic_transport_parameters, 0),
         {:alpn, protocol} <- List.keyfind(extensions, :alpn, 0),
         true <- protocol in state.core.offer.alpn_protocols do
      {:ok, bytes, [{:peer_transport_parameters, bytes, :unverified}]}
    else
      nil -> {:error, {:missing_extension, :quic_parameters_or_alpn}}
      false -> {:error, {:illegal_parameter, :unoffered_alpn}}
      {:error, reason} -> HandshakeCore.decode_alert(reason)
      _ -> {:error, {:unexpected_message, :expected_encrypted_extensions}}
    end
  end

  defp client_parameters(state, _), do: {:ok, state.peer_parameters, []}

  defp account_output(state, actions) do
    messages = for {:emit, _, bytes} <- actions, do: bytes
    total = state.total_bytes + Enum.reduce(messages, 0, &(byte_size(&1) + &2))

    cond do
      total > state.limits[:max_total_handshake_bytes] ->
        {:error, :handshake_budget_exceeded}

      Enum.any?(messages, &(byte_size(&1) - 4 > state.limits[:max_handshake_length])) ->
        {:error, :handshake_length_exceeded}

      true ->
        {:ok, %{state | total_bytes: total}}
    end
  end

  defp secret(state, level, direction, bytes) do
    spec = Capabilities.resolve(:cipher_suite, state.cipher_suite)

    %Secret{
      level: level,
      direction: direction,
      cipher_suite: spec.id,
      aead: spec.cipher,
      hkdf: spec.hash,
      secret: bytes
    }
  end

  defp complete(state),
    do: %{
      state
      | phase: :connected,
        receive_level: :application,
        handshake_complete: true,
        peer_parameters_authenticated: true,
        core: nil,
        hello: nil,
        config: nil,
        session: nil
    }

  defp terminal(state, phase),
    do: %{
      state
      | phase: phase,
        receive_level: nil,
        core: nil,
        hello: nil,
        config: nil,
        peer_parameters: nil,
        session: nil,
        pending: nil,
        ticket_metadata: nil,
        framer: HandshakeFramer.new()
    }

  defp fail(state, kind, alert, reason) do
    error = %Error{kind: kind, alert: alert, reason: reason_code(reason)}
    {:error, error, terminal(state, :failed), [{:error, error}]}
  end

  defp reason_code(reason) when is_atom(reason), do: reason

  defp reason_code(reason) when is_tuple(reason) and tuple_size(reason) > 0,
    do: reason_code(elem(reason, 0))

  defp reason_code(_), do: :invalid_peer_input
end
