defmodule HTTP.WebTransport do
  @moduledoc """
  Browser-like WebTransport client API for Elixir.

  This module implements the public API shape and lifecycle management for
  WebTransport sessions. Browser-compatible network interoperability requires a
  backend that speaks WebTransport over HTTP/3; the default backend is currently
  a placeholder that reports `:quic_backend_unavailable`.
  """

  alias HTTP.WebTransport.CloseInfo
  alias HTTP.WebTransport.DatagramDuplexStream
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

  @spec close(t()) :: :ok | {:error, term()}
  def close(transport), do: close(transport, [])

  @spec close(t(), keyword() | map()) :: :ok | {:error, term()}
  def close(transport, options) do
    options = if is_map(options), do: Map.to_list(options), else: options

    with {:ok, close_info} <- close_info(options) do
      connection_call(transport, {:close, close_info}, :ok)
    end
  end

  defp close_info(options) do
    reason = Keyword.get(options, :reason, "")
    close_code = Keyword.get(options, :close_code, 0)

    cond do
      not is_integer(close_code) or close_code < 0 ->
        {:error, :invalid_close_code}

      not is_binary(reason) ->
        {:error, :invalid_close_reason}

      byte_size(reason) > 1_024 ->
        {:error, :close_reason_too_long}

      true ->
        {:ok, %CloseInfo{close_code: close_code, reason: reason}}
    end
  end

  defp connection_call(%__MODULE__{pid: pid}, request, default) when is_pid(pid) do
    GenServer.call(pid, request, @call_timeout)
  catch
    :exit, _reason -> default
  end

  defp connection_call(_transport, _request, default), do: default

  defp put_ref(init, ref) when is_map(init), do: Map.put(init, :ref, ref)
  defp put_ref(init, ref) when is_list(init), do: Keyword.put(init, :ref, ref)
end
