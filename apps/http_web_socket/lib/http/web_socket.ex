defmodule HTTP.WebSocket do
  @moduledoc """
  Browser-like WebSocket client API for Elixir.

  Events are delivered as messages to the owner process:

      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Open{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Message{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Error{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Close{}}

  HTTP/1 is the default. Select `http_version: :http2`, `:h2c`, or `:auto`
  explicitly. `http_version: :http3` selects an RFC 9220 tunnel for `wss`,
  with explicit QUIC CA trust in `ssl` and no fallback. TCP
  `tls_backend`, socket options and connection-address pins are rejected for H3.
  `http_version/1` reports the negotiated HTTP version, while
  `protocol/1` continues to report the selected WebSocket subprotocol.

  No WebSocket extension is supported: `permessage-deflate` (RFC 7692) is not
  negotiated, `extensions/1` is always `""`, and a handshake response carrying
  `Sec-WebSocket-Extensions` fails the upgrade. A Close frame without a status
  code is reported as code 1005, and `close/3` while connecting emits an Error
  event followed by an abnormal (1006) Close, as in the WHATWG API.

  With `delivery: :ack`, message events include a delivery reference:

      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Message{}, ref}

  Call `acknowledge/2` after consuming each message. Open, Error, and Close
  retain their three-element event envelopes. Receive queues, pending sends,
  and fragmented messages have finite configurable limits. Established sessions
  default to `idle_timeout: :infinity`; opening and close deadlines are separate.

  `connect_address: {127, 0, 0, 1}` (or an IPv6 tuple) pins this connection's
  literal dial address. The URL still supplies Host, HTTP/2 authority, SNI and
  certificate reference identity. DNS and alternate-address retries are disabled
  for a pinned dial; connection failures and upgrades are never replayed. Pins
  cannot be combined with Unix sockets or conflicting TLS identities. Protocol
  selection with `http_version: :auto` retains its explicit H2/H1 negotiation
  policy, with every dial using the same pin.

  Open and Error events have `handshake: %{status: status, headers: headers,
  truncated?: boolean}` once a final response head has been parsed, or nil before
  that point. `headers` is an `HTTP.Headers` containing only `retry-after` and
  `x-codex-websocket-max-unfragmented-message-bytes`. Each is retained only when
  it occurs exactly once and its value is at most 1024 bytes; otherwise it is
  omitted and `truncated?` is true. Values are copied, so this metadata retains
  at most 2048 value bytes and no other response headers. Failed upgrades retain
  their original Error reason. This applies to HTTP/1, HTTP/2 and HTTP/3.

  Receive limits are independent: `max_message_size` bounds each reassembled
  message (16 MiB by default); `max_frame_bytes` bounds each frame payload
  (defaults to the larger of the message limit and 125). Declared lengths are
  checked before awaiting payload bytes, including continuations. A message may
  span many bounded frames. `max_read_bytes` bounds queued raw bytes plus the
  parser's incomplete frame and each incoming transport chunk, including bytes
  coalesced with the upgrade. Its default is the existing raw queue allowance
  (1 MiB plus the H2 profile's initial stream window) plus the larger of the
  message limit and 125, plus ten header bytes. It excludes reassembled fragments
  and delivered events, which have their own message and delivery bounds. It
  does not bound kernel or VM transport allocations. All three options require
  positive integers. Choose a read limit that accommodates a full frame header
  and payload, and any coalesced frames you intend to accept.

  Limit failures emit Error reasons `:frame_too_big`, `:message_too_big`, or
  `:read_buffer_too_big`, followed by an abnormal Close with code 1009. An
  individually declared payload above the message limit keeps the existing
  `:message_too_big` reason; otherwise the frame bound is checked before the
  accumulated message bound. Read admission precedes parsing. These receive
  options do not fragment outgoing sends; send queues keep their existing bounds.

  Telemetry URLs omit query, userinfo, authority, and fragment by default.
  Pass `telemetry_url: nil` to omit all URL-derived telemetry metadata, or a
  URI/string containing only caller-approved fields to replace the telemetry
  URL (for example, `telemetry_url: "ws://127.0.0.1:8080"` omits a private
  path). Invalid replacements reject construction; replacement credentials
  are always stripped. This option applies to every lifecycle/message event
  and never changes the transport URL or handshake.

  ## HTTP/1 WebSocket proxy boundary

  For frame forwarding, select `mode: :proxy`, `http_version: :http1`,
  `delivery: :ack` and `automatic_pong: false`. Proxy mode delivers
  `%HTTP.WebSocket.Event.Frame{opcode: opcode, data: binary}` for text, binary,
  ping and pong, with the same delivery reference/`acknowledge/2` contract.
  `binary_type` does not alter proxy frame data. Close retains its lifecycle
  event and automatic reply. `send_frame/2` and `send_frame_ack/2` accept
  `{opcode, binary}` for those four opcodes. Automatic pong defaults to true;
  disabling it requires proxy mode. Proxy `close/3` accepts nil with an empty
  reason, 1000-1014 except 1004/1005/1006, and 3000-4999. Reserved/non-wire
  codes, invalid UTF-8 and reasons over 123 bytes remain rejected.

  Proxy HTTP/2, h2c and auto selection return `{:error, :proxy_requires_http1}`.
  Wait for successful completion of **every** `send_frame_ack/2` reference
  before initiating Close: local close discards queued application frames in
  both HTTP versions. This provides ordered local write completion over HTTP/1;
  proxy mode supplies no HTTP/2 drain contract. Control sends share the bounded
  application send FIFO, including zero-length payloads. Control delivery uses
  the receive limits too; ACK capacity must accommodate at least 132 bytes.

  Use this public client for the upstream half of a WebSocket proxy. Select
  `http_version: :http1` and `delivery: :ack`; acknowledge each Message only
  after downstream consumption. Set finite `opening_timeout`, `idle_timeout`,
  `write_timeout` and `close_timeout`, and size/count limits for messages,
  receive queues and pending sends. `send_ack/2` reports local transport
  completion for each admitted frame. `send/2` reports admission only.

  The client validates status 101, Upgrade/Connection tokens, exactly one
  matching Sec-WebSocket-Accept and the selected subprotocol. Bytes coalesced
  after the response head enter the frame parser. Redirects and uncertain
  operations are never replayed. Ping is answered with Pong automatically;
  Close is exchanged with the peer. This interface proxies WebSocket messages,
  not raw TCP bytes or exact frame fragmentation. Forward binary messages
  with `array_buffer/1` and configure the upstream protocols explicitly.

  WSS retains the selected TLS backend's CA, hostname and SNI verification;
  supply trusted `ssl: [cacertfile: ...]` for private CAs. Owner death closes
  the connection. `close/1` signals cancellation; use `completion/1` with
  `HTTP.ClientCompletion.await/2` to confirm cleanup, including a cancelled
  opening. The receipt remains readable after the socket process exits.

  Over HTTP/3, `:ok` additionally requires the tunnel relay to prove that its
  connection owner retired the CONNECT stream: no owner demux entry, native
  session request or queued/pending/suspended action remains for it (Close,
  peer reset, deadline and cancellation all reach this check), or the owner
  process was observed down. A shared pooled QUIC connection stays open and
  its native endpoint is not certified by this receipt. With `http3_reuse:
  false` the exclusive connection's `Quic.Cleanup` scope must also confirm
  that its endpoint, connection, IO actor and UDP port were joined. Missing
  evidence is reported as `{:error, :cleanup_unconfirmed}`. A
  Close event describes the handshake result; it does not prove peer
  application receipt of earlier writes. Terminal cancellation discards
  pending transport bytes, so a failed write may have reached the peer partly.

  Plain Elixir binaries are sent as text frames. Use `array_buffer/1` or
  `HTTP.Blob` for binary frames.

  For `wss` connections, `tls_backend: :ex_ssl` (or the equivalent string in a map)
  selects the TLS provider. When omitted, the shared `:http_core` TLS backend
  setting defaults to `:ex_ssl` and is captured when the socket is created.
  Legacy OTP `:ssl` selections are rejected.
  """

  alias HTTP.WebSocket.ArrayBuffer
  alias HTTP.WebSocket.Connection
  alias HTTP.WebSocket.Frame
  alias HTTP.WebSocket.Options

  defstruct pid: nil, ref: nil, url: nil, completion: nil

  @connecting 0
  @open 1
  @closing 2
  @closed 3
  @call_timeout 5_000

  @type t :: %__MODULE__{
          pid: pid() | nil,
          ref: reference() | nil,
          url: String.t() | nil,
          completion: HTTP.ClientCompletion.t() | nil
        }

  @type handshake :: %{
          status: non_neg_integer(),
          headers: HTTP.Headers.t(),
          truncated?: boolean()
        }

  @spec connecting() :: 0
  def connecting, do: @connecting

  @spec open() :: 1
  def open, do: @open

  @spec closing() :: 2
  def closing, do: @closing

  @spec closed() :: 3
  def closed, do: @closed

  @spec new(String.t() | URI.t(), String.t() | [String.t()], keyword() | map()) ::
          t() | {:error, term()}
  def new(url, protocols \\ [], init \\ []) do
    ref = make_ref()

    with {:ok, options} <- Options.new(url, protocols, put_ref(init, ref)) do
      receipt = HTTP.ClientCompletion.new(:client)

      case DynamicSupervisor.start_child(
             HTTP.WebSocket.ConnectionSupervisor,
             {Connection, {options, receipt}}
           ) do
        {:ok, pid} ->
          %__MODULE__{pid: pid, ref: ref, url: options.url, completion: receipt}

        error ->
          Kernel.send(HTTP.ClientCompletion.tracker(receipt), :launch_failed)
          error
      end
    end
  end

  @doc "Returns the durable cleanup receipt without contacting the connection."
  @spec completion(t()) :: HTTP.ClientCompletion.t() | nil
  def completion(%__MODULE__{completion: receipt}), do: receipt

  @spec array_buffer(binary()) :: ArrayBuffer.t() | {:error, :invalid_array_buffer}
  def array_buffer(data) when is_binary(data), do: ArrayBuffer.new(data)
  def array_buffer(_data), do: {:error, :invalid_array_buffer}

  @spec url(t()) :: String.t() | nil
  def url(%__MODULE__{url: url}), do: url

  @spec ready_state(t()) :: 0 | 1 | 2 | 3
  def ready_state(socket), do: connection_call(socket, :ready_state, @closed)

  @spec buffered_amount(t()) :: non_neg_integer()
  def buffered_amount(socket), do: connection_call(socket, :buffered_amount, 0)

  @spec extensions(t()) :: String.t()
  def extensions(socket), do: connection_call(socket, :extensions, "")

  @spec protocol(t()) :: String.t()
  def protocol(socket), do: connection_call(socket, :protocol, "")

  @doc "Returns the negotiated HTTP version, or nil before establishment."
  @spec http_version(t()) :: :http1 | :http2 | :http3 | nil
  def http_version(socket), do: connection_call(socket, :http_version, nil)

  @doc "Returns connection state and bounded delivery and send queue usage."
  @spec status(t()) :: map()
  def status(socket) do
    connection_call(socket, :status, %{
      http_version: nil,
      ready_state: @closed,
      buffered_amount: 0,
      queued_bytes: 0,
      queued_events: 0,
      inflight?: false,
      raw_bytes: 0,
      pending_send_frames: 0,
      control_frames: 0,
      fallback?: false
    })
  end

  @doc "Acknowledges an ACK-mode message delivery reference."
  @spec acknowledge(t(), reference()) :: :ok | {:error, term()}
  def acknowledge(socket, ref), do: connection_call(socket, {:acknowledge, ref}, :ok)

  @spec binary_type(t()) :: :blob | :array_buffer
  def binary_type(socket), do: connection_call(socket, :binary_type, :blob)

  @spec set_binary_type(t(), :blob | :array_buffer) :: :ok | {:error, term()}
  def set_binary_type(socket, binary_type) when binary_type in [:blob, :array_buffer] do
    connection_call(socket, {:set_binary_type, binary_type}, {:error, :closed})
  end

  def set_binary_type(_socket, _binary_type), do: {:error, :invalid_binary_type}

  @spec send(t(), String.t() | HTTP.Blob.t() | ArrayBuffer.t()) :: :ok | {:error, term()}
  def send(socket, data), do: connection_call(socket, {:send, data}, {:error, :closed})

  @doc """
  Admits a bounded send and returns its completion reference.

  The owner receives `{HTTP.WebSocket, socket, {:send_result, ref, result}}`,
  where `result` is `:ok` only after the complete frame was accepted by the
  transport, or `{:error, reason}` on cancellation/failure. This confirms local
  write completion, not peer application receipt. Failed/uncertain writes are
  never replayed. Unlike `send/2`, a closed connection rejects admission.
  Queuing and writing share the finite `write_timeout` (default 5 seconds).
  """
  @spec send_ack(t(), String.t() | HTTP.Blob.t() | ArrayBuffer.t()) ::
          {:ok, reference()} | {:error, term()}
  def send_ack(socket, data),
    do: connection_call(socket, {:send_ack, data}, {:error, :closed})

  @doc """
  Admits an explicit text, binary, ping or pong frame in `mode: :proxy`.

  Control payloads are limited to 125 bytes; text must be valid UTF-8. Frames
  share the bounded FIFO send queue and write deadline with `send/2`. This
  reports admission only; use `send_frame_ack/2` before forwarding Close.
  Send Close using `close/3`, preserving the connection's close deadline.
  """
  @spec send_frame(t(), {:text | :binary | :ping | :pong, binary()}) :: :ok | {:error, term()}
  def send_frame(socket, frame),
    do: connection_call(socket, {:send_frame, frame, false}, {:error, :closed})

  @doc """
  Admits an explicit proxy frame and returns a local write completion reference.

  The owner receives the same `{:send_result, ref, result}` event as `send_ack/2`.
  Wait for `:ok` for every admitted frame before calling `close/3` to preserve
  prior writes. Completion does not prove peer application receipt.
  """
  @spec send_frame_ack(t(), {:text | :binary | :ping | :pong, binary()}) ::
          {:ok, reference()} | {:error, term()}
  def send_frame_ack(socket, frame),
    do: connection_call(socket, {:send_frame, frame, true}, {:error, :closed})

  @doc """
  Migrates an open HTTP/3 WebSocket's exclusive QUIC connection to a new local
  address (beta).

  Requires `http_version: :http3` with `http3_reuse: false`, so the tunnel owns
  its QUIC connection and endpoint. Pass `local: {ip, port}` with a concrete
  (non-wildcard) IP; port `0` selects an ephemeral port. `timeout` (default
  5000 ms) is the absolute deadline for admission and path validation.

  Returns `{:ok, %{local: {ip, port}}}` once the peer validated the new path and
  traffic moved to it, or `{:error, reason}`. Refusals include
  `:migration_requires_http3`, `:not_exclusive_owner` (pooled connections),
  `:shared_endpoint`, `:migration_busy`, `:invalid_local_address`,
  `:peer_disabled_migration`, `:no_unused_connection_id`,
  `{:bind_failed, reason}` and `:validation_timeout`; a failed migration keeps
  the original path. An outcome unknown at the deadline (plus a one-second
  grace) returns `{:error, {:indeterminate_operation, ref}}` and is never
  replayed. `Quic.capabilities().migration.local` is `[:client]` (exclusive
  standalone client port and address migration); this function remains beta.
  """
  @spec migrate(t(), keyword()) ::
          {:ok, %{local: {tuple(), :inet.port_number()}}} | {:error, term()}
  def migrate(%__MODULE__{pid: pid}, opts) when is_pid(pid) and is_list(opts) do
    timeout = Keyword.get(opts, :timeout, 5_000)

    cond do
      not is_integer(timeout) or timeout <= 0 ->
        {:error, :invalid_timeout}

      not match?({ip, port} when is_tuple(ip) and is_integer(port), opts[:local]) ->
        {:error, :invalid_local_address}

      true ->
        try do
          GenServer.call(pid, {:migrate, opts[:local], timeout}, timeout + 2_000)
        catch
          :exit, {:timeout, _} -> {:error, :timeout}
          :exit, _reason -> {:error, :closed}
        end
    end
  end

  def migrate(_socket, _opts), do: {:error, :closed}

  @spec close(t()) :: :ok | {:error, term()}
  def close(socket), do: close(socket, nil, "")

  @spec close(t(), non_neg_integer()) :: :ok | {:error, term()}
  def close(socket, code), do: close(socket, code, "")

  @spec close(t(), non_neg_integer() | nil, String.t()) :: :ok | {:error, term()}
  def close(socket, code, reason) when is_binary(reason) do
    with {:ok, payload} <- Frame.protocol_close_payload(code, reason) do
      connection_call(socket, {:close, code, reason, payload}, {:error, :closed})
    end
  end

  def close(_socket, _code, _reason), do: {:error, :invalid_close_reason}

  defp connection_call(%__MODULE__{pid: pid}, request, default) when is_pid(pid) do
    GenServer.call(pid, request, @call_timeout)
  catch
    :exit, _reason -> default
  end

  defp connection_call(_socket, _request, default), do: default

  defp put_ref(init, ref) when is_map(init), do: Map.put(init, :ref, ref)
  defp put_ref(init, ref) when is_list(init), do: Keyword.put(init, :ref, ref)
end
