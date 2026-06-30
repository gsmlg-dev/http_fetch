defmodule HTTP.WebTransport.SendStream do
  @moduledoc """
  Writable byte stream owned by a WebTransport session.
  """

  defstruct [:transport, :ref]

  @type t :: %__MODULE__{transport: HTTP.WebTransport.t(), ref: term()}

  @call_timeout 5_000

  @spec write(t(), iodata(), keyword() | map()) :: :ok | {:error, term()}
  def write(%__MODULE__{transport: transport, ref: stream_ref}, data, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options

    GenServer.call(transport.pid, {:send_stream, stream_ref, data, options}, @call_timeout)
  catch
    :exit, _reason -> {:error, :closed}
  end

  @spec close(t()) :: :ok | {:error, term()}
  def close(%__MODULE__{transport: transport, ref: stream_ref}) do
    GenServer.call(transport.pid, {:close_send_stream, stream_ref}, @call_timeout)
  catch
    :exit, _reason -> {:error, :closed}
  end

  @spec abort(t(), keyword() | map()) :: :ok | {:error, term()}
  def abort(%__MODULE__{transport: transport, ref: stream_ref}, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options
    code = Keyword.get(options, :code, 0)

    GenServer.call(transport.pid, {:abort_send_stream, stream_ref, code}, @call_timeout)
  catch
    :exit, _reason -> {:error, :closed}
  end
end
