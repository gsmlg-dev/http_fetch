defmodule HTTP.WebTransport.SendGroup do
  @moduledoc """
  Sender-side grouping handle for stream and datagram ordering hints.
  """

  defstruct [:transport, :ref]

  @type t :: %__MODULE__{transport: HTTP.WebTransport.t(), ref: reference()}
end
