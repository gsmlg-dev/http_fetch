defmodule SSL.Crypto.KeyExchange do
  @moduledoc """
  Fresh ephemeral key generation and shared-secret computation for TLS groups.

  Runtime support is determined by the crypto provider linked to OTP.
  """

  defmodule KeyPair do
    @moduledoc """
    Ephemeral key material for one key exchange.

    Inspection intentionally excludes the private key.
    """

    @type group :: :x25519 | :secp256r1 | :secp384r1
    @type t :: %__MODULE__{group: group(), public_key: binary(), private_key: binary()}

    @derive {Inspect, except: [:private_key]}
    @enforce_keys [:group, :public_key, :private_key]
    defstruct [:group, :public_key, :private_key]
  end

  alias __MODULE__.KeyPair
  alias SSL.Capabilities

  @p384_order Base.decode16!(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"
              )

  @type group :: KeyPair.group()
  @type error_reason ::
          {:unsupported_group, term()}
          | {:unsupported_capability, group()}
          | {:key_generation_failed, group()}
          | {:invalid_private_key, group()}
          | {:invalid_peer_public_key, group()}
          | {:key_pair_mismatch, group()}
          | :invalid_key_pair

  @spec supported?(term()) :: boolean()
  def supported?(group), do: group in Capabilities.identifiers(:group)

  @spec generate(term()) :: {:ok, KeyPair.t()} | {:error, error_reason()}
  def generate(group) when group in [:x25519, :secp256r1, :secp384r1] do
    if supported?(group) do
      generate_supported(group)
    else
      {:error, {:unsupported_capability, group}}
    end
  end

  def generate(group), do: {:error, {:unsupported_group, group}}

  @spec shared_secret(KeyPair.t(), term()) :: {:ok, binary()} | {:error, error_reason()}
  def shared_secret(%KeyPair{group: group}, _peer_public_key)
      when group not in [:x25519, :secp256r1, :secp384r1],
      do: {:error, {:unsupported_group, group}}

  def shared_secret(%KeyPair{group: group, private_key: private_key}, peer_public_key) do
    with true <- supported?(group),
         :ok <- validate_private_key(group, private_key),
         :ok <- validate_peer_public_key(group, peer_public_key) do
      compute_shared_secret(group, peer_public_key, private_key)
    else
      false -> {:error, {:unsupported_capability, group}}
      {:error, _reason} = error -> error
    end
  end

  def shared_secret(_key_pair, _peer_public_key), do: {:error, :invalid_key_pair}

  @spec validate_key_pair(term()) :: :ok | {:error, error_reason()}
  def validate_key_pair(%KeyPair{group: group, public_key: public_key, private_key: private_key})
      when group in [:x25519, :secp256r1, :secp384r1] do
    if supported?(group) do
      with :ok <- validate_private_key(group, private_key),
           :ok <- validate_peer_public_key(group, public_key),
           {derived_public, ^private_key} <- :crypto.generate_key(:ecdh, group, private_key),
           :ok <- require_matching_public_key(derived_public, public_key, group) do
        :ok
      else
        {:error, _reason} = error -> error
        {_derived_public, _private_key} -> {:error, {:invalid_private_key, group}}
      end
    else
      {:error, {:unsupported_capability, group}}
    end
  catch
    :error, _reason -> {:error, {:invalid_private_key, group}}
  end

  def validate_key_pair(%KeyPair{group: group}), do: {:error, {:unsupported_group, group}}
  def validate_key_pair(_key_pair), do: {:error, :invalid_key_pair}

  defp generate_supported(group) do
    {public_key, private_key} = :crypto.generate_key(:ecdh, group)
    {:ok, %KeyPair{group: group, public_key: public_key, private_key: private_key}}
  catch
    :error, {:error, {_file, _line}, _message} ->
      {:error, {:key_generation_failed, group}}

    :error, {:badarg, {_file, _line}, _message} ->
      {:error, {:key_generation_failed, group}}

    :error, :badarg ->
      {:error, {:key_generation_failed, group}}
  end

  defp validate_private_key(group, private_key)
       when is_binary(private_key) and
              ((group in [:x25519, :secp256r1] and byte_size(private_key) == 32) or
                 (group == :secp384r1 and byte_size(private_key) == 48 and
                    private_key > <<0::384>> and private_key < @p384_order)) do
    case :crypto.generate_key(:ecdh, group, private_key) do
      {<<_public_key::binary-size(32)>>, ^private_key} when group == :x25519 ->
        :ok

      {<<4, _coordinates::binary-size(64)>>, ^private_key} when group == :secp256r1 ->
        :ok

      {<<4, _coordinates::binary-size(96)>>, ^private_key} when group == :secp384r1 ->
        :ok

      _invalid_key_pair ->
        {:error, {:invalid_private_key, group}}
    end
  catch
    :error, {:error, {_file, _line}, _message} ->
      {:error, {:invalid_private_key, group}}

    :error, {:badarg, {_file, _line}, _message} ->
      {:error, {:invalid_private_key, group}}

    :error, :badarg ->
      {:error, {:invalid_private_key, group}}
  end

  defp validate_private_key(group, _private_key), do: {:error, {:invalid_private_key, group}}

  defp validate_peer_public_key(:x25519, peer_public_key)
       when is_binary(peer_public_key) and byte_size(peer_public_key) == 32,
       do: :ok

  defp validate_peer_public_key(:secp256r1, <<4, _coordinates::binary-size(64)>>), do: :ok

  defp validate_peer_public_key(:secp384r1, <<4, _coordinates::binary-size(96)>>), do: :ok

  defp validate_peer_public_key(group, _peer_public_key),
    do: {:error, {:invalid_peer_public_key, group}}

  defp compute_shared_secret(group, peer_public_key, private_key) do
    case :crypto.compute_key(:ecdh, peer_public_key, private_key, group) do
      <<0::256>> when group == :x25519 ->
        {:error, {:invalid_peer_public_key, group}}

      shared_secret ->
        {:ok, shared_secret}
    end
  catch
    :error, {:error, {_file, _line}, _message} ->
      {:error, {:invalid_peer_public_key, group}}

    :error, {:badarg, {_file, _line}, _message} ->
      {:error, {:invalid_peer_public_key, group}}

    :error, :badarg ->
      {:error, {:invalid_peer_public_key, group}}
  end

  defp secure_equal(left, right)
       when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right) do
    :crypto.hash_equals(left, right)
  end

  defp secure_equal(_left, _right), do: false

  defp require_matching_public_key(derived, supplied, group) do
    if secure_equal(derived, supplied), do: :ok, else: {:error, {:key_pair_mismatch, group}}
  end
end
