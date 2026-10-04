defmodule SSL.QUIC do
  @moduledoc """
  Caller-owned TLS 1.3 certificate handshake for QUIC CRYPTO streams.

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

  alias SSL.QUIC.Config

  defmodule Secret do
    @moduledoc "A directional TLS traffic secret. Inspection never reveals its bytes."
    @derive {Inspect, only: [:level, :direction, :cipher_suite, :aead, :hkdf]}
    @enforce_keys [:level, :direction, :cipher_suite, :aead, :hkdf, :secret]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            level: :handshake | :application,
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
          | :handshake_complete
          | {:error, Error.t()}
  @type result :: {:ok, state(), [action()]} | {:error, Error.t(), state(), [action()]}

  @spec capabilities() :: %{
          cipher_suites: [any()],
          groups: [map()],
          hello_retry_request: true,
          quic_packet_protection: false,
          resumption: false,
          roles: %{client: map(), server: map()},
          server_mtls: false,
          signatures: [map()],
          tls_records: false,
          tls_versions: [772, ...],
          zero_rtt: false
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
      resumption: false,
      zero_rtt: false,
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
      :peer_parameters_authenticated
    ])
  end

  @spec abort(state(), atom()) :: state()
  def abort(%State{} = state, _reason), do: terminal(state, :aborted)

  @spec feed(state(), level(), binary()) :: result()
  def feed(%State{phase: phase} = state, _level, _bytes) when phase in [:failed, :aborted] do
    {:error, %Error{kind: :closed, reason: :terminal}, state, []}
  end

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
         {:ok, hello, bytes} <-
           ClientHandshake.prepare(
             materialized,
             config.trust,
             config.reference_identity,
             [client_identity: config.identity] ++ config.verifier_options
           ) do
      state = %{base(:client, config) | hello: hello}
      actions = [{:emit, :initial, bytes}]

      with {:ok, state} <- account_output(state, actions) do
        {:ok, state, actions}
      end
    end
  end

  defp base(role, config),
    do: %State{
      role: role,
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
            if next.receive_level != level and
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
            {:ok, %{state | hello: next}, [{:emit, :initial, bytes}]}
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
                 client_identity: state.config.identity
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
          {:ok, %{state | core: core, peer_parameters: parameters}, early_events}

        {:connected, result, messages} ->
          next =
            complete(%{
              state
              | peer_parameters: parameters,
                peer_authenticated: true,
                alpn: result.negotiated_protocol
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
      {:retry, core, bytes} ->
        {:ok, %{state | core: core}, [{:emit, :initial, bytes}]}

      {:ok, core} ->
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

          actions =
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

          core = %{
            core
            | secrets: Map.take(core.secrets, [:hash, :client_handshake_secret]),
              application_secrets: nil,
              offer: nil,
              first_offer: nil
          }

          {:ok, %{next | core: core, config: nil}, actions}
        end

      error ->
        error
    end
  end

  defp step(%State{role: :server, phase: :client_finished} = state, <<20, _::binary>> = encoded) do
    with :ok <- ServerHandshake.finish(state.core, encoded) do
      {:ok, complete(state),
       [
         {:peer_transport_parameters, state.peer_parameters, :authenticated},
         {:negotiated_alpn, state.alpn},
         :handshake_complete
       ]}
    end
  end

  defp step(%State{role: :client, phase: :connected} = state, <<4, _::binary>> = encoded) do
    # Tickets are bounded, structurally decoded and deliberately not retained.
    spec = Capabilities.resolve(:cipher_suite, state.cipher_suite)

    case ServerFlight.decode(
           encoded,
           [hash: spec.hash] ++ Keyword.delete(state.limits, :max_total_handshake_bytes)
         ) do
      {:ok, %ServerFlight.NewSessionTicket{}, <<>>} -> {:ok, state, []}
      {:error, reason} -> HandshakeCore.decode_alert(reason)
      _ -> {:error, {:decode_error, :invalid_ticket}}
    end
  end

  defp step(_, _), do: {:error, {:unexpected_message, :unexpected_handshake}}

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
        config: nil
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
