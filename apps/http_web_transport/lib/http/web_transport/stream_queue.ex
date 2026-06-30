defmodule HTTP.WebTransport.StreamQueue do
  @moduledoc """
  Queue handle for incoming WebTransport streams.
  """

  defstruct [:transport, :kind]

  @type kind :: :incoming_bidirectional | :incoming_unidirectional
  @type t :: %__MODULE__{transport: HTTP.WebTransport.t(), kind: kind()}

  @call_timeout 5_000

  @spec read(t(), keyword() | map()) ::
          {:ok, HTTP.WebTransport.BidirectionalStream.t() | HTTP.WebTransport.ReceiveStream.t()}
          | {:error, term()}
  def read(%__MODULE__{transport: transport, kind: kind}, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options
    timeout = Keyword.get(options, :timeout, :infinity)

    GenServer.call(transport.pid, {:read_stream_queue, kind, timeout}, call_timeout(timeout))
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, _reason -> {:error, :closed}
  end

  defp call_timeout(:infinity), do: :infinity
  defp call_timeout(timeout) when is_integer(timeout) and timeout >= 0, do: timeout + 1_000
  defp call_timeout(_timeout), do: @call_timeout
end
