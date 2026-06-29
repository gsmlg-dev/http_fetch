defmodule HTTP.WebSocket do
  @moduledoc """
  Browser-like WebSocket client API for Elixir.

  Events are delivered as messages to the owner process:

      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Open{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Message{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Error{}}
      {HTTP.WebSocket, socket, %HTTP.WebSocket.Event.Close{}}

  Plain Elixir binaries are sent as text frames. Use `array_buffer/1` or
  `HTTP.Blob` for binary frames.
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

  @spec binary_type(t()) :: :blob | :array_buffer
  def binary_type(socket), do: connection_call(socket, :binary_type, :blob)

  @spec set_binary_type(t(), :blob | :array_buffer) :: :ok | {:error, term()}
  def set_binary_type(socket, binary_type) when binary_type in [:blob, :array_buffer] do
    connection_call(socket, {:set_binary_type, binary_type}, {:error, :closed})
  end

  def set_binary_type(_socket, _binary_type), do: {:error, :invalid_binary_type}

  @spec send(t(), String.t() | HTTP.Blob.t() | ArrayBuffer.t()) :: :ok | {:error, term()}
  def send(socket, data), do: connection_call(socket, {:send, data}, {:error, :closed})

  @spec close(t()) :: :ok | {:error, term()}
  def close(socket), do: close(socket, nil, "")

  @spec close(t(), non_neg_integer()) :: :ok | {:error, term()}
  def close(socket, code), do: close(socket, code, "")

  @spec close(t(), non_neg_integer() | nil, String.t()) :: :ok | {:error, term()}
  def close(socket, code, reason) when is_binary(reason) do
    with {:ok, payload} <- Frame.close_payload(code, reason) do
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
