defmodule HTTP.WebSocket do
  @moduledoc """
  Browser-like WebSocket client API for Elixir.

  Events are delivered as messages to the owner process:

      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Open{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Message{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Error{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Close{}}

  HTTP/1 is the default. Select `http_version: :http2`, `:h2c`, or `:auto`
  explicitly; `http_version/1` reports the negotiated HTTP version, while
  `protocol/1` continues to report the selected WebSocket subprotocol.

  With `delivery: :ack`, message events include a delivery reference:

      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Message{}, ref}

  Call `acknowledge/2` after consuming each message. Open, Error, and Close
  retain their three-element event envelopes. Receive queues, pending sends,
  and fragmented messages have finite configurable limits. Established sessions
  default to `idle_timeout: :infinity`; opening and close deadlines are separate.

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
  the connection. `close/1` signals cancellation; monitor the socket's public
  `pid` for `:DOWN` to confirm cleanup, including a cancelled opening. A
  Close event describes the handshake result; it does not prove peer
  application receipt of earlier writes. Terminal cancellation discards
  pending transport bytes, so a failed write may have reached the peer partly.

  Plain Elixir binaries are sent as text frames. Use `array_buffer/1` or
  `HTTP.Blob` for binary frames.

  For `wss` connections, pass `tls_backend: :ssl | :ex_ssl` (or the equivalent
  string in a map). When omitted, the shared `:http_core` TLS backend setting is
  captured when the socket is created.
  """

  alias HTTP.WebSocket.ArrayBuffer
  alias HTTP.WebSocket.Connection
  alias HTTP.WebSocket.Frame
  alias HTTP.WebSocket.Options

  defstruct pid: nil, ref: nil, url: nil

  @connecting 0
  @open 1
  @closing 2
  @closed 3
  @call_timeout 5_000

  @type t :: %__MODULE__{pid: pid() | nil, ref: reference() | nil, url: String.t() | nil}

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

    with {:ok, options} <- Options.new(url, protocols, put_ref(init, ref)),
         {:ok, pid} <-
           DynamicSupervisor.start_child(
             HTTP.WebSocket.ConnectionSupervisor,
             {Connection, options}
           ) do
      %__MODULE__{pid: pid, ref: ref, url: options.url}
    end
  end

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
  @spec http_version(t()) :: :http1 | :http2 | nil
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
