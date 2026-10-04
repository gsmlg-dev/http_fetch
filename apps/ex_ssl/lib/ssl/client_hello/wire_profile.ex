defmodule SSL.ClientHello.WireProfile do
  @moduledoc """
  Ordered, declarative configuration for a TLS ClientHello.

  This structure contains policy only. Per-connection random values and fresh
  key exchange material must be supplied by the later materialization stage.
  """

  alias SSL.ClientHello.{GreasePolicy, RecordPolicy}

  @type session_id_policy :: :random_32 | :empty | {:fixed, binary()}
  @type grease_slot :: {:grease, atom()}
  @type cipher_suite :: atom() | 0..0xFFFF | grease_slot()
  @type version :: atom() | 0..0xFFFF | grease_slot()
  @type group :: atom() | 0..0xFFFF | grease_slot()

  @type extension_spec ::
          {:server_name, :from_connection}
          | {:supported_groups, [group()]}
          | {:ec_point_formats, [0..0xFF]}
          | {:extended_master_secret, binary()}
          | {:renegotiation_info, binary()}
          | {:signature_algorithms, [term()]}
          | {:signature_algorithms_cert, [term()]}
          | {:alpn, [binary() | grease_slot()]}
          | {:supported_versions, [version()]}
          | {:psk_key_exchange_modes, [atom() | 0..0xFF | grease_slot()]}
          | {:key_share, [group()]}
          | {:pre_shared_key, term()}
          | {:padding, :none | non_neg_integer() | {:fixed, non_neg_integer()}}
          | {:grease, atom()}
          | {:raw, 0..0xFFFF, binary()}

  @type t :: %__MODULE__{
          name: atom() | String.t() | nil,
          legacy_version: 0x0303,
          session_id: session_id_policy(),
          cipher_suites: [cipher_suite()],
          compression_methods: [0],
          extensions: [extension_spec()],
          grease: GreasePolicy.t(),
          record: RecordPolicy.t()
        }

  defstruct name: nil,
            legacy_version: 0x0303,
            session_id: :random_32,
            cipher_suites: [0x1301],
            compression_methods: [0],
            extensions: [],
            grease: %GreasePolicy{},
            record: %RecordPolicy{}
end
