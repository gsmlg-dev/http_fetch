defmodule SSL.QUIC.Session do
  @moduledoc "Bounded, private QUIC resumption material; never an address-validation token."
  @derive {Inspect, only: [:hash, :cipher_suite, :alpn, :issued_at, :expires_at, :max_early_data]}
  @enforce_keys [
    :identity,
    :psk,
    :hash,
    :cipher_suite,
    :age_add,
    :issued_at,
    :expires_at,
    :alpn,
    :context,
    :transport_parameters
  ]
  defstruct @enforce_keys ++ [server_name: nil, peer: nil, max_early_data: 0]

  @opaque t :: %__MODULE__{
            identity: binary(),
            psk: binary(),
            hash: :sha256 | :sha384,
            cipher_suite: non_neg_integer(),
            age_add: non_neg_integer(),
            issued_at: integer(),
            expires_at: integer(),
            alpn: binary(),
            context: binary(),
            server_name: binary() | nil,
            peer: map() | nil,
            transport_parameters: binary(),
            max_early_data: 0 | 0xFFFFFFFF
          }

  @spec validate(term()) :: :ok | {:error, :invalid_session}
  def validate(%__MODULE__{} = s) do
    spec = SSL.Capabilities.resolve(:cipher_suite, s.cipher_suite)

    if valid_identity?(s) and valid_key_material?(s, spec) and valid_lifetime?(s) and
         valid_context?(s) and
         is_binary(s.transport_parameters) and byte_size(s.transport_parameters) <= 65_000 and
         s.max_early_data in [0, 0xFFFFFFFF] and :erlang.external_size(s) <= 32_768,
       do: :ok,
       else: {:error, :invalid_session}
  end

  def validate(_), do: {:error, :invalid_session}

  defp valid_identity?(s), do: is_binary(s.identity) and byte_size(s.identity) in 1..16_384

  defp valid_key_material?(s, spec) do
    s.hash in [:sha256, :sha384] and is_binary(s.psk) and
      byte_size(s.psk) == if(s.hash == :sha256, do: 32, else: 48) and
      match?(%{version: 0x0304, hash: hash} when hash == s.hash, spec)
  end

  defp valid_lifetime?(s) do
    is_integer(s.age_add) and s.age_add in 0..0xFFFFFFFF and
      is_integer(s.issued_at) and is_integer(s.expires_at) and
      s.expires_at > s.issued_at and s.expires_at - s.issued_at <= 604_800_000
  end

  defp valid_context?(s) do
    is_binary(s.context) and byte_size(s.context) in 1..256 and
      is_binary(s.alpn) and byte_size(s.alpn) in 1..255 and
      (is_nil(s.server_name) or
         (is_binary(s.server_name) and byte_size(s.server_name) in 1..253))
  end
end

defmodule SSL.QUIC.Request do
  @moduledoc "One private runtime authority request; inspection omits IDs, leases and sessions."
  @derive {Inspect, only: [:operation, :early_data]}
  @enforce_keys [:id, :operation]
  defstruct @enforce_keys ++ [:identity, :context, :session, :lease, early_data: false]

  @type t :: %__MODULE__{
          id: term(),
          operation: :lookup | :commit | :store,
          identity: binary() | nil,
          context: binary() | nil,
          session: SSL.QUIC.Session.t() | nil,
          lease: term(),
          early_data: boolean()
        }
end
