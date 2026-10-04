defmodule SSL.Diagnostics do
  @moduledoc false

  alias SSL.Capabilities
  alias SSL.PKIX.VerifiedPeer
  alias SSL.Protocol.{HandshakeMachine, TLS12}

  @keys [:protocol, :selected_cipher_suite, :session_resumption]

  @spec keys() :: [:protocol | :selected_cipher_suite | :session_resumption, ...]
  def keys, do: @keys

  @spec validate_keys(term()) ::
          :ok
          | {:error,
             {:options,
              :duplicate_connection_information_key
              | :invalid_connection_information_keys
              | :unsupported_connection_information_key}}
  def validate_keys(keys), do: validate_keys(keys, %{})

  defp validate_keys([], _seen), do: :ok

  defp validate_keys([key | rest], seen) when key in @keys do
    if Map.has_key?(seen, key) do
      {:error, {:options, :duplicate_connection_information_key}}
    else
      validate_keys(rest, Map.put(seen, key, true))
    end
  end

  defp validate_keys([_ | _], _seen),
    do: {:error, {:options, :unsupported_connection_information_key}}

  defp validate_keys(_, _seen), do: {:error, {:options, :invalid_connection_information_keys}}

  @spec connection_information(HandshakeMachine.t(), [atom()]) ::
          {:ok, keyword()} | {:error, term()}
  def connection_information(machine, keys) do
    with {:ok, suite} <- suite(machine) do
      values = %{
        protocol: protocol(machine),
        selected_cipher_suite: %{
          key_exchange: if(protocol(machine) == :"tlsv1.3", do: :any, else: suite.key_exchange),
          cipher: suite.cipher,
          mac: :aead,
          prf: suite.hash
        },
        session_resumption: Map.get(machine, :resumed, false) == true
      }

      {:ok, Enum.map(keys, &{&1, Map.fetch!(values, &1)})}
    end
  end

  @spec peercert(HandshakeMachine.t()) :: {:ok, binary()} | {:error, :no_peercert}
  def peercert(%TLS12{peer: %VerifiedPeer{leaf_der: der}}) when is_binary(der),
    do: {:ok, der}

  def peercert(%HandshakeMachine{verified_peer: %VerifiedPeer{leaf_der: der}})
      when is_binary(der),
      do: {:ok, der}

  def peercert(_), do: {:error, :no_peercert}

  defp protocol(%TLS12{}), do: :"tlsv1.2"
  defp protocol(%HandshakeMachine{}), do: :"tlsv1.3"

  defp suite(%TLS12{suite: %{id: id}}), do: resolve_suite(id, 0x0303)
  defp suite(%HandshakeMachine{server_hello: %{cipher_suite: id}}), do: resolve_suite(id, 0x0304)
  defp suite(_), do: {:error, :closed}

  defp resolve_suite(id, version) do
    case Capabilities.resolve(:cipher_suite, id) do
      %{version: ^version} = suite -> {:ok, suite}
      _ -> {:error, :closed}
    end
  end
end
