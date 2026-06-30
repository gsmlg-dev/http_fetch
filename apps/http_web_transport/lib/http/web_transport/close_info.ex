defmodule HTTP.WebTransport.CloseInfo do
  @moduledoc """
  Close metadata for a WebTransport session.
  """

  defstruct close_code: 0, reason: ""

  @type t :: %__MODULE__{close_code: non_neg_integer(), reason: String.t()}
end
