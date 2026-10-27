defmodule HTTP.ProtocolClient do
  @moduledoc """
  Explicitly owned, connection-scoped HTTP/1 and prior-knowledge HTTP/2 client.

  This API is intended for protocol peers and tests that must retain one exact
  cleartext connection. It accepts `http://` origins only and never reconnects,
  redirects, retries or replays requests. `connection_info/1` returns a stable
  connection ID and both TCP addresses; every request uses that connection.

  `connect/2` accepts `protocol: :http1 | :http2` (default `:http2`), a finite
  `timeout` in milliseconds (default 5,000), and HTTP/2 `settings` entries using
  the standard atom names or numeric IDs. Server push is always disabled.

  `request/5` returns a request reference. `recv/2` returns a nonempty list of:

    * `{:headers, ref, status, headers}`
    * `{:data, ref, binary}`
    * `{:trailers, ref, headers}`
    * `{:done, ref}`
    * `{:error, ref, reason}`
    * `{:closed, reason}`

  Headers are ordered name/value pairs. A receive timeout does not cancel a
  request. Call `cancel/2` explicitly: HTTP/2 resets only that stream; HTTP/1
  cancellation closes its connection because framing cannot safely be resumed.
  HTTP/1 admits one request at a time, and the complete response must arrive
  before another request is submitted. Request bodies are buffered binaries;
  HTTP/2 bodies must fit the currently available peer flow-control credit.

  HTTP/2 DATA never automatically replenishes stream receive credit. Call
  `acknowledge/2` after consuming a DATA event, or withhold it to exercise real
  backpressure. `put_settings/2` changes live settings on the same connection,
  including the receive windows of existing streams. Success confirms a local
  write, not the peer's SETTINGS acknowledgement. Connection credit may be
  replenished by the bounded HTTP/2 delivery buffers independently.

  A session admits at most 16 requests and buffers at most 256 events / 1 MiB.
  Unconsumed events exhausting either bound close the connection. Consume events
  promptly. `close/2` uses a finite timeout, joins owned protocol processes and
  closes the actual TCP socket; uncertain completion returns an error. The
  creating process is monitored, so its exit also closes the session. This
  contract confirms owned resource closure, not native allocator reclamation or
  remote receipt. Sessions own no DNS cache, pool or automatic maintenance loop.

      {:ok, client} = HTTP.ProtocolClient.connect("http://127.0.0.1:8080",
        protocol: :http2, settings: [initial_window_size: 1])
      {:ok, ref} = HTTP.ProtocolClient.request(client, :get, "/audio")
      {:ok, events} = HTTP.ProtocolClient.recv(client, 1_000)
      :ok = HTTP.ProtocolClient.cancel(client, ref)
      :ok = HTTP.ProtocolClient.put_settings(client, initial_window_size: 65_535)
      {:ok, _health} = HTTP.ProtocolClient.request(client, :get, "/health")
      :ok = HTTP.ProtocolClient.close(client)
  """

  alias HTTP.ProtocolClient.Session

  @opaque t :: %__MODULE__{pid: pid(), id: reference(), timeout: pos_integer()}
  defstruct [:pid, :id, :timeout]

  @type event ::
          {:headers, reference(), non_neg_integer(), [{binary(), binary()}]}
          | {:data, reference(), binary()}
          | {:trailers, reference(), [{binary(), binary()}]}
          | {:done, reference()}
          | {:error, reference(), term()}
          | {:closed, term()}

  @doc "Opens one retained TCP connection using finite connection/write deadlines."
  @spec connect(String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def connect(url, options \\ []) do
    with {:ok, config} <- Session.config(url, options),
         {:ok, pid} <- GenServer.start(Session, {self(), config}, timeout: config.timeout) do
      {:ok, %__MODULE__{pid: pid, id: config.id, timeout: config.timeout}}
    end
  catch
    :exit, _ -> {:error, :connect_unconfirmed}
  end

  @doc "Submits one request on the retained connection without reconnect or replay."
  @spec request(t(), atom() | String.t(), String.t(), list(), binary()) ::
          {:ok, reference()} | {:error, term()}
  def request(client, method, path, headers \\ [], body \\ ""),
    do: call(client, {:request, method, path, headers, body}, client.timeout)

  @doc "Receives a finite batch of protocol events; a timeout leaves requests active."
  @spec recv(t(), non_neg_integer()) :: {:ok, [event()]} | {:error, term()}
  def recv(client, timeout \\ 5_000) when is_integer(timeout) and timeout >= 0,
    do: call(client, :recv, timeout)

  @doc "Resets one HTTP/2 stream, or closes an in-flight HTTP/1 connection."
  @spec cancel(t(), reference()) :: :ok | {:error, term()}
  def cancel(client, ref), do: call(client, {:cancel, ref}, client.timeout)

  @doc "Acknowledges the oldest DATA delivery for this request, restoring stream credit."
  @spec acknowledge(t(), reference()) :: :ok | {:error, term()}
  def acknowledge(client, ref), do: call(client, {:acknowledge, ref}, client.timeout)

  @doc "Writes new SETTINGS on the existing HTTP/2 connection."
  @spec put_settings(t(), list()) :: :ok | {:error, term()}
  def put_settings(client, entries), do: call(client, {:put_settings, entries}, client.timeout)

  @doc "Returns the stable connection ID, protocol and actual TCP addresses."
  @spec connection_info(t()) :: {:ok, map()} | {:error, term()}
  def connection_info(client), do: call(client, :connection_info, client.timeout)

  @doc "Closes the socket and joins the owned protocol process within one finite timeout."
  @spec close(t(), non_neg_integer()) :: :ok | {:error, term()}
  def close(client, timeout \\ 5_000) when is_integer(timeout) and timeout >= 0,
    do: call(client, :close, timeout)

  defp call(%__MODULE__{} = client, operation, timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    GenServer.call(client.pid, {client.id, operation, deadline}, timeout + 100)
  catch
    :exit, {:timeout, _} -> {:error, :operation_unconfirmed}
    :exit, _ -> {:error, :closed}
  end
end
