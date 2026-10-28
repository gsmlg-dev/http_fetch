defmodule SSL.TLS12Session do
  @moduledoc "Bounded, memory-only EMS session material. Inspect never reveals the master secret."

  @derive {Inspect, only: [:suite, :issued_at, :expires_at, :alpn]}
  @enforce_keys [:id, :master_secret, :suite, :peer, :alpn, :issued_at, :expires_at]
  defstruct @enforce_keys ++ [auto: false, data: nil]

  @type t :: %__MODULE__{
          id: binary(),
          master_secret: binary(),
          suite: non_neg_integer(),
          peer: map(),
          alpn: binary() | nil,
          issued_at: integer(),
          expires_at: integer(),
          auto: boolean(),
          data: binary() | nil
        }

  @spec validate(term()) :: :ok | {:error, :invalid_session}
  def validate(%__MODULE__{} = session) do
    if is_binary(session.id) and byte_size(session.id) in 1..32 and
         is_binary(session.master_secret) and byte_size(session.master_secret) == 48 and
         match?({:ok, _}, SSL.Crypto.TLS12KeySchedule.suite(session.suite)) and
         valid_peer?(session.peer) and
         (session.alpn == nil or (is_binary(session.alpn) and byte_size(session.alpn) in 1..255)) and
         is_integer(session.issued_at) and is_integer(session.expires_at) and
         session.expires_at > session.issued_at and
         session.expires_at - session.issued_at <= 600_000 and is_boolean(session.auto) and
         (session.data == nil or valid_capability?(session.data)) and
         :erlang.external_size(session) <= 262_144,
       do: :ok,
       else: {:error, :invalid_session}
  end

  def validate(_), do: {:error, :invalid_session}

  @doc false
  @spec valid_reference?(term()) :: boolean()
  def valid_reference?(id) when is_binary(id), do: byte_size(id) in 1..32

  def valid_reference?({id, data}),
    do: is_binary(id) and byte_size(id) in 1..32 and valid_capability?(data)

  def valid_reference?(_), do: false

  @doc false
  @spec valid_capability?(term()) :: boolean()
  def valid_capability?(<<"EXSSL12", 1, _token::binary-size(32)>>), do: true
  def valid_capability?(_), do: false

  defp valid_peer?(%{chain: [_ | _] = chain}) when length(chain) <= 128,
    do: Enum.all?(chain, &(is_binary(&1) and byte_size(&1) in 1..262_144))

  defp valid_peer?(_), do: false
end
