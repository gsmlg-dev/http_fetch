defmodule HTTP.WebSocket.Event.Open do
  @moduledoc """
  Browser-compatible WebSocket open event.
  """

  defstruct target: nil, type: "open"

  @type t :: %__MODULE__{target: HTTP.WebSocket.t() | nil, type: String.t()}
end

defmodule HTTP.WebSocket.Event.Message do
  @moduledoc """
  Browser-compatible WebSocket message event.
  """

  defstruct target: nil, type: "message", data: nil, origin: nil

  @type t :: %__MODULE__{
          target: HTTP.WebSocket.t() | nil,
          type: String.t(),
          data: binary() | HTTP.Blob.t() | HTTP.WebSocket.ArrayBuffer.t() | nil,
          origin: String.t() | nil
        }
end

defmodule HTTP.WebSocket.Event.Error do
  @moduledoc """
  Browser-compatible WebSocket error event.
  """

  defstruct target: nil, type: "error", reason: nil

  @type t :: %__MODULE__{
          target: HTTP.WebSocket.t() | nil,
          type: String.t(),
          reason: term()
        }
end

defmodule HTTP.WebSocket.Event.Close do
  @moduledoc """
  Browser-compatible WebSocket close event.
  """

  defstruct target: nil, type: "close", code: nil, reason: "", was_clean: false

  @type t :: %__MODULE__{
          target: HTTP.WebSocket.t() | nil,
          type: String.t(),
          code: non_neg_integer() | nil,
          reason: String.t(),
          was_clean: boolean()
        }
end
