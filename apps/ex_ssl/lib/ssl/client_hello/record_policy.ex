defmodule SSL.ClientHello.RecordPolicy do
  @moduledoc """
  Declares record handling for a ClientHello wire profile.

  TCP uses `:default`; the record-free QUIC profile uses `:none`. Validation
  accepts only the modes explicitly allowed by the selected transport.
  """

  @type t :: %__MODULE__{mode: :default | :none}

  defstruct mode: :default
end
