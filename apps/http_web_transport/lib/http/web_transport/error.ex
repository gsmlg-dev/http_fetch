defmodule HTTP.WebTransport.Error do
  @moduledoc """
  Error metadata for WebTransport failures.
  """

  defstruct source: "session", reason: nil

  @type t :: %__MODULE__{source: String.t(), reason: term()}
end
