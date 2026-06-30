defmodule HTTP.WebTransport.Stats do
  @moduledoc """
  Minimal WebTransport connection statistics.
  """

  defstruct bytes_sent: 0,
            bytes_received: 0,
            datagrams: %{sent: 0, received: 0, dropped: 0}

  @type t :: %__MODULE__{
          bytes_sent: non_neg_integer(),
          bytes_received: non_neg_integer(),
          datagrams: map()
        }
end
