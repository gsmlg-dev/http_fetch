defmodule HTTP.WebTransport.BidirectionalStream do
  @moduledoc """
  Browser-like bidirectional WebTransport stream.
  """

  defstruct [:transport, :readable, :writable]

  @type t :: %__MODULE__{
          transport: HTTP.WebTransport.t(),
          readable: HTTP.WebTransport.ReceiveStream.t(),
          writable: HTTP.WebTransport.SendStream.t()
        }
end
