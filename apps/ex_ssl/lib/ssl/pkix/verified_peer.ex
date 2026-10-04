defmodule SSL.PKIX.VerifiedPeer do
  @moduledoc """
  The authenticated leaf material needed by later handshake verification.
  """

  @enforce_keys [:leaf_der, :leaf, :public_key]
  defstruct [:leaf_der, :leaf, :public_key, chain: []]

  @type t :: %__MODULE__{
          leaf_der: binary(),
          leaf: term(),
          public_key: term(),
          chain: [binary()]
        }
end
