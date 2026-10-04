defmodule SSL.Crypto.TLS12KeySchedule do
  @moduledoc "Pure TLS 1.2 PRF and Extended Master Secret derivation for the bounded ECDHE-GCM subset."

  alias SSL.Protocol.TLS12Record

  @max_prf_output 1_048_576
  @max_transcript 1_048_576

  @spec suite(term()) ::
          {:error, {:unsupported_cipher_suite, term()}}
          | {:ok,
             %{
               :id => term(),
               :key_exchange => :ecdsa | :rsa,
               :version => 771,
               optional(term()) => term()
             }}
  def suite(id) do
    case SSL.Capabilities.resolve(:cipher_suite, id) do
      %{version: 0x0303, id: wire_id} = suite ->
        if wire_id in SSL.Capabilities.cipher_ids(0x0303) do
          key = if suite.key_exchange == :ecdhe_rsa, do: :rsa, else: :ecdsa
          {:ok, %{suite | key_exchange: key}}
        else
          {:error, {:unsupported_cipher_suite, id}}
        end

      _ ->
        {:error, {:unsupported_cipher_suite, id}}
    end
  end

  @spec prf(:sha256 | :sha384, binary(), binary(), binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, term()}
  def prf(hash, secret, label, seed, length)
      when hash in [:sha256, :sha384] and is_binary(secret) and byte_size(secret) > 0 and
             is_binary(label) and is_binary(seed) and is_integer(length) and length >= 0 and
             length <= @max_prf_output do
    data = label <> seed
    {:ok, expand(hash, secret, data, :crypto.mac(:hmac, hash, secret, data), length, [])}
  end

  def prf(_, _, _, _, _), do: {:error, :invalid_prf_input}

  @spec derive(term(), binary(), binary(), binary(), binary()) ::
          {:ok,
           %{master_secret: binary(), read_state: TLS12Record.t(), write_state: TLS12Record.t()}}
          | {:error, term()}
  def derive(id, premaster, transcript, client_random, server_random) do
    with {:ok, suite} <- suite(id),
         :ok <- validate_premaster(premaster),
         :ok <- validate_transcript(transcript),
         :ok <- validate_random(client_random, :client_random),
         :ok <- validate_random(server_random, :server_random),
         {:ok, master} <-
           prf(
             suite.hash,
             premaster,
             "extended master secret",
             :crypto.hash(suite.hash, transcript),
             48
           ),
         {:ok, block} <-
           prf(
             suite.hash,
             master,
             "key expansion",
             server_random <> client_random,
             2 * suite.key_length + 8
           ) do
      key_length = suite.key_length

      <<client_key::binary-size(^key_length), server_key::binary-size(^key_length),
        client_iv::binary-size(4), server_iv::binary-size(4)>> = block

      with {:ok, write} <- TLS12Record.new(suite.cipher, client_key, client_iv),
           {:ok, read} <- TLS12Record.new(suite.cipher, server_key, server_iv) do
        {:ok, %{master_secret: master, read_state: read, write_state: write}}
      end
    end
  end

  @spec finished(term(), binary(), :client | :server, binary()) ::
          {:ok, <<_::96>>} | {:error, term()}
  def finished(id, master, role, transcript) when role in [:client, :server] do
    with {:ok, suite} <- suite(id),
         true <- is_binary(master) and byte_size(master) == 48,
         :ok <- validate_transcript(transcript) do
      label = if role == :client, do: "client finished", else: "server finished"
      prf(suite.hash, master, label, :crypto.hash(suite.hash, transcript), 12)
    else
      false -> {:error, :invalid_master_secret}
      {:error, _} = error -> error
    end
  end

  def finished(_, _, _, _), do: {:error, :invalid_finished_role}

  defp expand(_hash, _secret, _data, _a, 0, blocks),
    do: blocks |> Enum.reverse() |> IO.iodata_to_binary()

  defp expand(hash, secret, data, a, remaining, blocks) do
    block = :crypto.mac(:hmac, hash, secret, [a, data])
    take = min(byte_size(block), remaining)
    next_a = :crypto.mac(:hmac, hash, secret, a)
    expand(hash, secret, data, next_a, remaining - take, [binary_part(block, 0, take) | blocks])
  end

  defp validate_premaster(value) when is_binary(value) and byte_size(value) in 1..4096, do: :ok
  defp validate_premaster(_), do: {:error, :invalid_premaster_secret}

  defp validate_transcript(value) when is_binary(value) and byte_size(value) <= @max_transcript,
    do: :ok

  defp validate_transcript(_), do: {:error, :invalid_transcript}
  defp validate_random(value, _name) when is_binary(value) and byte_size(value) == 32, do: :ok
  defp validate_random(_, name), do: {:error, {:invalid_random, name}}
end
