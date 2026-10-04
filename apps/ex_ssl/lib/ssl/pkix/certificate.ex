defmodule SSL.PKIX.Certificate do
  @moduledoc """
  A bounded X.509 certificate retaining both its exact DER and decoded OTP form.
  """

  @enforce_keys [:der, :decoded]
  defstruct [:der, :decoded]

  @type t :: %__MODULE__{der: binary(), decoded: term()}
end
