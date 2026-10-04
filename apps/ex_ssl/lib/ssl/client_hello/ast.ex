defmodule SSL.ClientHello.AST do
  @moduledoc """
  Public, fully materialized ClientHello fields in exact wire order.

  This structure contains public wire material only. Ephemeral private keys are
  retained separately by `SSL.ClientHello.Materializer.Materialized`.
  """

  @type extension :: {0..0xFFFF, binary()}
  @type t :: %__MODULE__{
          legacy_version: 0..0xFFFF,
          random: binary(),
          session_id: binary(),
          cipher_suites: [0..0xFFFF],
          compression_methods: [0..0xFF],
          extensions: [extension()]
        }

  @enforce_keys [
    :legacy_version,
    :random,
    :session_id,
    :cipher_suites,
    :compression_methods,
    :extensions
  ]
  defstruct @enforce_keys
end
