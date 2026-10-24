defmodule SSL.ClientIdentity.Candidates do
  @moduledoc false
  alias SSL.ClientIdentity

  @derive {Inspect, only: [:count]}
  @enforce_keys [:identities, :count]
  defstruct [:identities, :count]
  @type t :: %__MODULE__{identities: [ClientIdentity.t()], count: 1..16}

  def new(identities) do
    with {:ok, count, bytes} <- measure(identities, 0, 0),
         true <- count > 0 and bytes <= 8_388_608 do
      {:ok, %__MODULE__{identities: identities, count: count}}
    else
      _ -> {:error, {:options, :identity_bytes_or_count_limit}}
    end
  end

  def valid?(%__MODULE__{identities: identities, count: count}) do
    case measure(identities, 0, 0) do
      {:ok, ^count, bytes} -> count in 1..16 and bytes <= 8_388_608
      _ -> false
    end
  end

  def encoded_size(%ClientIdentity{chain: chain, private_key: key}) do
    case chain_size(chain, 0, 0) do
      {:ok, bytes} -> bytes + :erlang.external_size(key)
      :error -> 8_388_609
    end
  end

  defp chain_size([], count, bytes) when count > 0, do: {:ok, bytes}

  defp chain_size([der | rest], count, bytes)
       when is_binary(der) and byte_size(der) <= 262_144 and count < 16 and
              bytes + byte_size(der) <= 524_288,
       do: chain_size(rest, count + 1, bytes + byte_size(der))

  defp chain_size(_, _, _), do: :error

  def ordered(nil, _), do: []
  def ordered(%ClientIdentity{} = identity, _), do: [identity]

  def ordered(%__MODULE__{identities: identities}, version),
    do: Enum.sort_by(identities, &priority(&1.public_key, version))

  defp measure([], count, bytes), do: {:ok, count, bytes}

  defp measure([%ClientIdentity{} = identity | rest], count, bytes) when count < 16 do
    next = bytes + encoded_size(identity)
    if next <= 8_388_608, do: measure(rest, count + 1, next), else: :error
  end

  defp measure(_, _, _), do: :error

  defp priority({{1, 3, 101, 112}, _, _}, :tls13), do: {0, 0}
  defp priority({_, {:namedCurve, {1, 3, 132, 0, 34}}}, _), do: {1, 0}
  defp priority({_, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}}, _), do: {1, 1}

  defp priority({{1, 2, 840, 113_549, 1, 1, 10}, {:RSAPublicKey, modulus, _}, _}, _),
    do: {2, modulus}

  defp priority({:RSAPublicKey, modulus, _}, _), do: {3, modulus}
  defp priority(_, _), do: {4, 0}
end
