defmodule SSL.ClientHello.GreasePolicy do
  @moduledoc """
  Declares GREASE behavior for a ClientHello wire profile.

  Concrete GREASE selection occurs once per materialization. Symbolic slots are
  reused consistently across registries within that ClientHello.
  """

  @type mode :: :disabled | :random | {:deterministic, non_neg_integer()}
  @type t :: %__MODULE__{mode: mode()}

  defstruct mode: :disabled
end
