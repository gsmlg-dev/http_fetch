defmodule SSL.PKIX.VerifiedPeer do
  @moduledoc """
  Leaf credential material needed by later handshake verification.

  The legacy name does not establish certificate trust, reference identity, or
  possession of the private key. `SSL.PKIX.verify/4` returns validated PKIX
  material; explicit `verify_none` paths use the same container for bounded,
  decoded untrusted credentials. Protocol CertificateVerify/ServerKeyExchange and
  Finished checks must still complete before the connection succeeds.
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
