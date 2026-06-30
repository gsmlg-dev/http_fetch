defmodule HTTP.WebTransport.DatagramDuplexStream do
  @moduledoc """
  Browser-like datagram duplex stream for a WebTransport session.
  """

  alias HTTP.WebTransport.DatagramsWritable

  defstruct [:transport]

  @type t :: %__MODULE__{transport: HTTP.WebTransport.t()}

  @call_timeout 5_000

  @spec create_writable(t(), keyword() | map()) :: DatagramsWritable.t()
  def create_writable(%__MODULE__{} = datagrams, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options

    %DatagramsWritable{
      datagrams: datagrams,
      send_group: Keyword.get(options, :send_group),
      send_order: Keyword.get(options, :send_order, 0)
    }
  end

  @spec read(t(), keyword() | map()) :: {:ok, binary()} | {:error, term()}
  def read(%__MODULE__{transport: transport}, options \\ []) do
    options = if is_map(options), do: Map.to_list(options), else: options
    timeout = Keyword.get(options, :timeout, :infinity)
    call_timeout = call_timeout(timeout)

    GenServer.call(transport.pid, {:read_datagram, timeout}, call_timeout)
  catch
    :exit, {:timeout, _call} -> {:error, :timeout}
    :exit, _reason -> {:error, :closed}
  end

  @spec max_datagram_size(t()) :: non_neg_integer()
  def max_datagram_size(%__MODULE__{transport: transport}) do
    connection_call(transport, :max_datagram_size, 0)
  end

  @spec incoming_max_age(t()) :: non_neg_integer() | nil
  def incoming_max_age(%__MODULE__{transport: transport}) do
    connection_call(transport, :incoming_datagrams_max_age, nil)
  end

  @spec set_incoming_max_age(t(), non_neg_integer() | nil) :: :ok | {:error, term()}
  def set_incoming_max_age(%__MODULE__{transport: transport}, age) do
    connection_call(transport, {:set_incoming_datagrams_max_age, age}, {:error, :closed})
  end

  @spec outgoing_max_age(t()) :: non_neg_integer() | nil
  def outgoing_max_age(%__MODULE__{transport: transport}) do
    connection_call(transport, :outgoing_datagrams_max_age, nil)
  end

  @spec set_outgoing_max_age(t(), non_neg_integer() | nil) :: :ok | {:error, term()}
  def set_outgoing_max_age(%__MODULE__{transport: transport}, age) do
    connection_call(transport, {:set_outgoing_datagrams_max_age, age}, {:error, :closed})
  end

  defp connection_call(%{pid: pid}, request, default) when is_pid(pid) do
    GenServer.call(pid, request, @call_timeout)
  catch
    :exit, _reason -> default
  end

  defp call_timeout(:infinity), do: :infinity
  defp call_timeout(timeout) when is_integer(timeout) and timeout >= 0, do: timeout + 1_000
  defp call_timeout(_timeout), do: @call_timeout
end
