defmodule SSL.ClientHello.Identifiers do
  @moduledoc false
  alias SSL.Capabilities

  @uint16 %{
    version: %{tlsv1_3: 0x0304, tlsv1_2: 0x0303}
  }

  @uint8 %{psk_mode: %{psk_ke: 0, psk_dhe_ke: 1}}

  @spec uint16(atom(), term()) :: {:ok, 0..0xFFFF} | {:error, term()}
  def uint16(_kind, value) when is_integer(value) and value in 0..0xFFFF, do: {:ok, value}

  def uint16(kind, value) do
    case Capabilities.resolve(kind, value) do
      %{id: identifier} ->
        {:ok, identifier}

      nil ->
        case get_in(@uint16, [kind, value]) do
          nil -> {:error, {:unsupported_identifier, kind, value}}
          identifier -> {:ok, identifier}
        end
    end
  end

  @spec uint8(atom(), term()) :: {:ok, 0..0xFF} | {:error, term()}
  def uint8(_kind, value) when is_integer(value) and value in 0..0xFF, do: {:ok, value}

  def uint8(kind, value) do
    case get_in(@uint8, [kind, value]) do
      nil -> {:error, {:unsupported_identifier, kind, value}}
      identifier -> {:ok, identifier}
    end
  end

  @spec key_exchange_group(term()) :: {:ok, :x25519 | :secp256r1 | :secp384r1} | {:error, term()}
  def key_exchange_group(group) do
    case Capabilities.resolve(:group, group) do
      %{name: name} -> {:ok, name}
      nil -> {:error, {:unsupported_key_share_group, group}}
    end
  end
end
