defmodule HTTP.EventSource do
  @moduledoc """
  Browser-like EventSource client API for Elixir.

  Events are delivered as messages to the owner process:

      {HTTP.EventSource, source, %HTTP.EventSource.Event.Open{}}
      {HTTP.EventSource, source, %HTTP.EventSource.Event.Message{}}
      {HTTP.EventSource, source, %HTTP.EventSource.Event.Error{}}

  HTTP/1 is the default. Select `http_version: :h2c` for cleartext prior
  knowledge, `:http2` for required TLS h2, or `:auto` for TLS ALPN negotiation.
  Automatic fallback to HTTP/1 occurs only when ALPN selects HTTP/1 before
  establishment and no explicit `http2_profile` is supplied. The TLS backend
  remains fixed. `http2_scope` and `http2_reuse` follow the shared runtime's
  connection policy; established sessions have no Fetch total-request deadline.

  Select `http_version: :http3` for required HTTPS over QUIC, with no protocol
  downgrade. Supply CA trust and optional reference identity through `ssl:`;
  HTTP/3 uses its QUIC TLS engine and rejects `tls_backend:`. `http3_profile`
  selects `:ordered` (default) or `:compact`, and `http3_reuse` controls pooling.
  The same parser, reconnect cursor, idle timeout and delivery limits apply.
  HTTP/3 requires a finite `connect_timeout`; established streams have no total
  request deadline. UNIX sockets, proxies and TCP `socket_opts` are unsupported.

  Parser limits default to `max_line_size: 65_536`, `max_event_size: 1_048_576`
  and `max_event_parts: 16_384`. The event byte cap includes retained data,
  event type, cursor and unfinished input; invalid UTF-8 completed lines remain
  fatal. Redirects default to `max_redirects: 5`; TLS downgrades are rejected,
  cross-origin credentials are removed, and client identity cannot cross origins.

  `delivery: :ack` emits Message events as
  `{HTTP.EventSource, source, message, delivery_ref}`. Call `acknowledge/2` to
  receive the next delivery. Open and Error retain their ordinary envelopes.
  The finite FIFO defaults to `max_queue_bytes: 2_097_152` and
  `max_queue_events: 64`, including the in-flight message. Acknowledged mode
  requires `max_queue_bytes >= max_event_size + 7` to reserve a complete event.
  Parked transport input is capped at 1 MiB plus the HTTP/2 profile's advertised
  stream receive window, or one 16 KiB relay chunk for HTTP/3, and 128 chunks. Transport
  credit returns on safe bounded raw/parser admission; excessive retained chunk
  counts terminate explicitly. Accepted deliveries drain before a fatal parser
  error is reported. Idle timing
  pauses while an application delivery is awaiting acknowledgement.

  Legacy delivery preserves the original envelope and terminates with
  `:consumer_overloaded` when the owner's mailbox reaches the configured count
  or a message exceeds its byte limit. It does not bound unrelated producers
  in that mailbox. Overload is fatal and does not reconnect.

  The reconnect cursor advances on parser dispatch, independently of application
  acknowledgement. Reconnection can replay events and does not guarantee
  exactly-once delivery. Incomplete events at EOF are discarded; an empty ID
  removes the Last-Event-ID header on subsequent requests.

  Custom server-sent event names are delivered through the message event's
  `type` field.

  For HTTP/1 and HTTP/2 `https` connections, pass `tls_backend: :ssl | :ex_ssl` (or the equivalent
  string in a map). When omitted, the shared `:http_core` TLS backend setting is
  captured when the source is created and retained across reconnects.
  """

  alias HTTP.EventSource.Connection
  alias HTTP.EventSource.Options

  defstruct pid: nil, ref: nil, url: nil, with_credentials: false

  @connecting 0
  @open 1
  @closed 2
  @call_timeout 5_000

  @type t :: %__MODULE__{
          pid: pid() | nil,
          ref: reference() | nil,
          url: String.t() | nil,
          with_credentials: boolean()
        }

  @spec connecting() :: 0
  def connecting, do: @connecting

  @spec open() :: 1
  def open, do: @open

  @spec closed() :: 2
  def closed, do: @closed

  @spec new(String.t() | URI.t(), keyword() | map()) :: t() | {:error, term()}
  def new(url, init \\ []) do
    ref = make_ref()

    with {:ok, options} <- Options.new(url, put_ref(init, ref)),
         {:ok, pid} <-
           DynamicSupervisor.start_child(
             HTTP.EventSource.ConnectionSupervisor,
             {Connection, options}
           ) do
      %__MODULE__{
        pid: pid,
        ref: ref,
        url: options.url,
        with_credentials: options.with_credentials
      }
    end
  end

  @spec url(t()) :: String.t() | nil
  def url(%__MODULE__{url: url}), do: url

  @spec with_credentials(t()) :: boolean()
  def with_credentials(%__MODULE__{with_credentials: with_credentials}), do: with_credentials

  @spec ready_state(t()) :: 0 | 1 | 2
  def ready_state(source), do: connection_call(source, :ready_state, @closed)

  @spec last_event_id(t()) :: String.t()
  def last_event_id(source), do: connection_call(source, :last_event_id, "")

  @spec reconnect_time(t()) :: non_neg_integer()
  def reconnect_time(source), do: connection_call(source, :reconnect_time, 0)

  @doc "Returns the negotiated HTTP version, or nil before establishment."
  @spec http_version(t()) :: :http1 | :http2 | :http3 | nil
  def http_version(source), do: connection_call(source, :http_version, nil)

  @doc "Returns current delivery and parser usage and the logical stream handle, when available."
  @spec status(t()) :: map()
  def status(source), do: connection_call(source, :status, %{ready_state: @closed})

  @doc "Settles an acknowledged Message delivery. Unknown and duplicate references are harmless."
  @spec acknowledge(t(), reference()) :: :ok
  def acknowledge(source, ref), do: connection_call(source, {:acknowledge, ref}, :ok)

  @spec close(t()) :: :ok
  def close(source), do: connection_call(source, :close, :ok)

  defp connection_call(%__MODULE__{pid: pid}, request, default) when is_pid(pid) do
    GenServer.call(pid, request, @call_timeout)
  catch
    :exit, _reason -> default
  end

  defp connection_call(_source, _request, default), do: default

  defp put_ref(init, ref) when is_map(init), do: Map.put(init, :ref, ref)
  defp put_ref(init, ref) when is_list(init), do: Keyword.put(init, :ref, ref)
end
