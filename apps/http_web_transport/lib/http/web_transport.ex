defmodule HTTP.WebTransport do
  @moduledoc """
  Browser-like WebTransport client API for Elixir.

  This module provides the public API shape and lifecycle management for
  WebTransport sessions. The default backend, `HTTP.WebTransport.Transport.QUIC`,
  speaks the draft-ietf-webtrans-http3-17 profile on one exclusive HTTP/3
  connection and requires the server's draft-17 SETTINGS, extended CONNECT,
  H3 DATAGRAM, QUIC DATAGRAM and reliable stream reset (draft-11). A server
  missing any of them is refused explicitly; there is no legacy fallback.
  This is beta: independent interoperability acceptance has not passed, so
  `HTTP.WebTransport.Profile.supported?/0` remains false.

  `close/2` takes effect while the session is still connecting: the pending
  connect is cancelled, QUIC resources are released and the session never opens.

  `new/2` returns `{:error, reason}` for an invalid URL. Unknown option keys,
  malformed init and invalid option values raise `ArgumentError` naming the key
  or reason, as `HTTP.fetch/2` does.

  Option support:

    * `server_certificate_hashes` (non-empty), `allow_pooling: true` and a
      non-empty `socket_opts` raise `ArgumentError` (`:unsupported_server_certificate_hashes`,
      `:pooling_unsupported`, `:socket_opts_unsupported`).
    * `require_unreliable: true` fails the session unless the backend reports
      `"supports-unreliable"` (the QUIC backend always does).
    * `idle_timeout` (milliseconds) is passed to the QUIC owner.
    * `anticipated_concurrent_incoming_*_streams` and `congestion_control` are
      W3C hints and are stored and reported but not applied.
    * `datagrams_readable_type` `:default` and `:bytes` are equivalent: datagrams
      are always delivered as binaries.
    * Datagram `incoming_max_age`/`outgoing_max_age` drop stale datagrams (incoming
      ones when read, outgoing ones buffered while connecting) and count them in
      `get_stats/1`. `send_order` other than 0 and any `send_group` are rejected
      with `:send_order_unsupported` / `:send_group_unsupported`.

  `get_stats/1` reports counters kept by the session at its API boundary:
  application payload bytes sent and received (stream data and datagrams),
  datagram counts, and datagrams dropped (oversized, or expired by max age).
  They are not QUIC wire counters: packet, retransmission and RTT statistics
  are not measured.

  QUIC TLS configuration is separate from TCP TLS.
  """

  alias HTTP.WebTransport.CloseInfo
  alias HTTP.WebTransport.DatagramDuplexStream
  alias HTTP.WebTransport.Operation
  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.Promise
  alias HTTP.WebTransport.SendGroup
  alias HTTP.WebTransport.Session
  alias HTTP.WebTransport.StreamQueue

  defstruct [:pid, :ref, :url]

  @type state :: :connecting | :connected | :draining | :closed | :failed
  @type reliability :: String.t()
  @type congestion_control :: :default | :throughput | :low_latency
  @type t :: %__MODULE__{pid: pid() | nil, ref: reference() | nil, url: String.t() | nil}

  @call_timeout 5_000

  @spec new(String.t() | URI.t(), keyword() | map()) :: t() | {:error, term()}
  def new(url, init \\ []) do
    ref = make_ref()

    with {:ok, options} <- Options.new(url, put_ref(init, ref)),
         {:ok, pid} <-
           DynamicSupervisor.start_child(
             HTTP.WebTransport.SessionSupervisor,
             {Session, options}
           ) do
      %__MODULE__{pid: pid, ref: ref, url: options.url}
    end
  end

  @spec ready(t()) :: Promise.t()
  def ready(%__MODULE__{pid: pid}), do: %Promise{pid: pid, kind: :ready}

  @spec closed(t()) :: Promise.t()
  def closed(%__MODULE__{pid: pid}), do: %Promise{pid: pid, kind: :closed}

  @spec draining(t()) :: Promise.t()
  def draining(%__MODULE__{pid: pid}), do: %Promise{pid: pid, kind: :draining}

  @spec await_ready(t(), timeout()) :: :ok | {:error, term()}
  def await_ready(transport, timeout \\ :infinity),
    do: transport |> ready() |> Promise.await(timeout)

  @spec await_closed(t(), timeout()) :: {:ok, CloseInfo.t()} | {:error, term()}
  def await_closed(transport, timeout \\ :infinity),
    do: transport |> closed() |> Promise.await(timeout)

  @spec await_draining(t(), timeout()) :: :ok | {:error, term()}
  def await_draining(transport, timeout \\ :infinity),
    do: transport |> draining() |> Promise.await(timeout)

  @spec datagrams(t()) :: DatagramDuplexStream.t()
  def datagrams(%__MODULE__{} = transport), do: %DatagramDuplexStream{transport: transport}

  @spec incoming_bidirectional_streams(t()) :: StreamQueue.t()
  def incoming_bidirectional_streams(%__MODULE__{} = transport) do
    %StreamQueue{transport: transport, kind: :incoming_bidirectional}
  end

  @spec incoming_unidirectional_streams(t()) :: StreamQueue.t()
  def incoming_unidirectional_streams(%__MODULE__{} = transport) do
    %StreamQueue{transport: transport, kind: :incoming_unidirectional}
  end

  @spec url(t()) :: String.t() | nil
  def url(%__MODULE__{url: url}), do: url

  @spec state(t()) :: state()
  def state(transport), do: connection_call(transport, :state, :closed)

  @spec reliability(t()) :: reliability()
  def reliability(transport), do: connection_call(transport, :reliability, "pending")

  @spec congestion_control(t()) :: congestion_control()
  def congestion_control(transport), do: connection_call(transport, :congestion_control, :default)

  @spec response_headers(t()) :: [{String.t(), String.t()}] | nil
  def response_headers(transport), do: connection_call(transport, :response_headers, nil)

  @spec protocol(t()) :: String.t()
  def protocol(transport), do: connection_call(transport, :protocol, "")

  @spec supports_reliable_only?() :: false
  def supports_reliable_only?, do: false

  @spec create_send_group(t()) :: SendGroup.t()
  def create_send_group(%__MODULE__{} = transport) do
    %SendGroup{transport: transport, ref: make_ref()}
  end

  @spec create_bidirectional_stream(t(), keyword() | map()) ::
          {:ok, HTTP.WebTransport.BidirectionalStream.t()} | {:error, term()}
  def create_bidirectional_stream(transport, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options
    connection_call(transport, {:create_bidirectional_stream, options}, {:error, :closed})
  end

  @spec create_unidirectional_stream(t(), keyword() | map()) ::
          {:ok, HTTP.WebTransport.SendStream.t()} | {:error, term()}
  def create_unidirectional_stream(transport, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options
    connection_call(transport, {:create_unidirectional_stream, options}, {:error, :closed})
  end

  @spec get_stats(t()) :: {:ok, HTTP.WebTransport.Stats.t()} | {:error, term()}
  def get_stats(transport), do: connection_call(transport, :get_stats, {:error, :closed})

  @doc """
  Migrates the session's exclusive QUIC connection to a new local address (beta).

  Pass `local: {ip, port}` with a concrete (non-wildcard) IP; port `0` selects
  an ephemeral port. `timeout` (default 5000 ms) is the absolute deadline for
  admission and path validation. Returns `{:ok, %{local: {ip, port}}}` once the
  peer validated the new path and traffic moved to it, or `{:error, reason}`,
  for example `:invalid_state`, `:migration_busy`, `:invalid_local_address`,
  `:peer_disabled_migration`, `:no_unused_connection_id`, `{:bind_failed,
  reason}` or `:validation_timeout`; a failed migration keeps the original
  path. An outcome unknown at the deadline (plus a one-second grace) returns
  `{:error, {:indeterminate_operation, ref}}` and is never replayed.
  `Quic.capabilities().migration.local` is `[:client]`; this function remains
  beta and `HTTP.WebTransport.Profile.supported?/0` stays false.
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

  def migrate(_transport, _opts), do: {:error, :closed}

  @doc """
  Reads the local callback result for a mutation whose caller timed out.

  The last 128 results are retained; eviction or an unavailable session returns
  `:unknown`. A callback result does not establish remote delivery. Never retry
  an indeterminate operation automatically.
  """
  @spec operation_status(t(), reference()) :: term()
  def operation_status(%__MODULE__{pid: pid}, ref) when is_reference(ref) do
    GenServer.call(pid, {:operation_status, ref}, @call_timeout)
  catch
    :exit, _ -> :unknown
  end

  @spec close(t()) :: :ok | {:error, term()}
  def close(transport), do: close(transport, [])

  @spec close(t(), keyword() | map()) :: :ok | {:error, term()}
  def close(transport, options) do
    options = if is_map(options), do: Map.to_list(options), else: options

    with {:ok, close_info} <- close_info(options) do
      # A session still connecting is blocked in its backend; this wakes it.
      with %__MODULE__{pid: pid} when is_pid(pid) <- transport, do: send(pid, :wt_cancel_connect)
      connection_call(transport, {:close, close_info}, :ok)
    end
  end

  defp close_info(options) do
    reason = Keyword.get(options, :reason, "")
    close_code = Keyword.get(options, :close_code, 0)

    cond do
      not is_integer(close_code) or close_code < 0 or close_code > 0xFFFFFFFF ->
        {:error, :invalid_close_code}

      not is_binary(reason) or not String.valid?(reason) ->
        {:error, :invalid_close_reason}

      byte_size(reason) > 1_024 ->
        {:error, :close_reason_too_long}

      true ->
        {:ok, %CloseInfo{close_code: close_code, reason: reason}}
    end
  end

  defp connection_call(%__MODULE__{pid: pid}, request, default) when is_pid(pid) do
    if mutation?(request) do
      Operation.call(pid, request, @call_timeout)
    else
      GenServer.call(pid, request, @call_timeout)
    end
  catch
    :exit, _reason -> default
  end

  defp connection_call(_transport, _request, default), do: default

  defp mutation?({kind, _})
       when kind in [:create_bidirectional_stream, :create_unidirectional_stream, :close],
       do: true

  defp mutation?(_), do: false

  defp put_ref(init, ref) when is_map(init), do: Map.put(init, :ref, ref)
  defp put_ref(init, ref) when is_list(init), do: Keyword.put(init, :ref, ref)
  defp put_ref(init, _ref), do: init
end
