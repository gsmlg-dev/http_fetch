defmodule HTTP.WebTransport.ReceiveStream do
  @moduledoc """
  Readable byte stream owned by a WebTransport session.
  """

  defstruct [:transport, :ref]

  @type t :: %__MODULE__{transport: HTTP.WebTransport.t(), ref: term()}

  @call_timeout 5_000

  @spec read(t(), keyword() | map()) :: {:ok, binary()} | :fin | {:error, term()}
  def read(%__MODULE__{transport: transport, ref: stream_ref}, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options
    timeout = Keyword.get(options, :timeout, :infinity)

    GenServer.call(transport.pid, {:read_stream, stream_ref, timeout}, call_timeout(timeout))
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, _reason -> {:error, :closed}
  end

  @spec cancel(t(), keyword() | map()) :: :ok | {:error, term()}
  def cancel(%__MODULE__{transport: transport, ref: stream_ref}, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options
    code = Keyword.get(options, :code, 0)

    GenServer.call(transport.pid, {:cancel_receive_stream, stream_ref, code}, @call_timeout)
  catch
    :exit, _reason -> {:error, :closed}
  end

  defp call_timeout(:infinity), do: :infinity
  defp call_timeout(timeout) when is_integer(timeout) and timeout >= 0, do: timeout + 1_000
  defp call_timeout(_timeout), do: @call_timeout
end
