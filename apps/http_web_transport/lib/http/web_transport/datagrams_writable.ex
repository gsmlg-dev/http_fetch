defmodule HTTP.WebTransport.DatagramsWritable do
  @moduledoc """
  Writable side of a WebTransport datagram duplex stream.
  """

  defstruct [:datagrams, :send_group, send_order: 0]

  @type t :: %__MODULE__{
          datagrams: HTTP.WebTransport.DatagramDuplexStream.t(),
          send_group: HTTP.WebTransport.SendGroup.t() | nil,
          send_order: integer()
        }

  @call_timeout 5_000

  @spec write(t(), binary()) :: :ok | {:error, term()}
  def write(%__MODULE__{datagrams: %{transport: transport}} = writable, bytes)
      when is_binary(bytes) do
    GenServer.call(
      transport.pid,
      {:send_datagram, bytes, send_group: writable.send_group, send_order: writable.send_order},
      @call_timeout
    )
  catch
    :exit, _reason -> {:error, :closed}
  end

  def write(_writable, _bytes), do: {:error, :invalid_datagram}
end
