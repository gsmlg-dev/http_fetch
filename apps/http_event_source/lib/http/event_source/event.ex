defmodule HTTP.EventSource.Event.Open do
  @moduledoc """
  Browser-compatible EventSource open event.
  """

  defstruct target: nil, type: "open"

  @type t :: %__MODULE__{target: HTTP.EventSource.t() | nil, type: String.t()}
end

defmodule HTTP.EventSource.Event.Message do
  @moduledoc """
  Browser-compatible EventSource message event.
  """

  defstruct target: nil, type: "message", data: "", origin: "", last_event_id: ""

  @type t :: %__MODULE__{
          target: HTTP.EventSource.t() | nil,
          type: String.t(),
          data: String.t(),
          origin: String.t(),
          last_event_id: String.t()
        }
end

defmodule HTTP.EventSource.Event.Error do
  @moduledoc """
  Browser-compatible EventSource error event.
  """

  defstruct target: nil, type: "error", reason: nil

  @type t :: %__MODULE__{
          target: HTTP.EventSource.t() | nil,
          type: String.t(),
          reason: term()
        }
end
