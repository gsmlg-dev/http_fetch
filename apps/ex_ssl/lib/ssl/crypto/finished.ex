defmodule SSL.Crypto.Finished do
  @moduledoc """
  TLS 1.3 Finished verify-data calculation and constant-time verification.
  """

  alias SSL.Crypto.KeySchedule

  @type error_reason ::
          :unsupported_hash
          | :invalid_finished
          | {:invalid_input, :verify_data | :transcript_hash}
          | {:invalid_finished_length, non_neg_integer(), pos_integer()}
          | {:invalid_secret_length, atom(), pos_integer()}
          | {:invalid_transcript_hash_length, pos_integer()}

  @type verify_data_error ::
          :unsupported_hash
          | {:invalid_secret_length, :traffic_secret | :finished_key, 32 | 48}
          | {:invalid_input, :transcript_hash}
          | {:invalid_transcript_hash_length, 32 | 48}

  @spec client_verify_data(atom(), term(), term()) ::
          {:ok, binary()} | {:error, verify_data_error()}
  def client_verify_data(hash, traffic_secret, transcript_hash) do
    with {:ok, finished_key} <- KeySchedule.finished_key(hash, traffic_secret) do
      KeySchedule.finished_verify_data(hash, finished_key, transcript_hash)
    end
  end

  @spec verify_server(atom(), term(), term(), term()) :: :ok | {:error, error_reason()}
  def verify_server(hash, traffic_secret, transcript_hash, received_verify_data) do
    with {:ok, expected_verify_data} <-
           client_verify_data(hash, traffic_secret, transcript_hash),
         :ok <- validate_received(received_verify_data, byte_size(expected_verify_data)) do
      if :crypto.hash_equals(expected_verify_data, received_verify_data) do
        :ok
      else
        {:error, :invalid_finished}
      end
    end
  end

  defp validate_received(received, expected_length)
       when is_binary(received) and byte_size(received) == expected_length,
       do: :ok

  defp validate_received(received, expected_length) when is_binary(received),
    do: {:error, {:invalid_finished_length, byte_size(received), expected_length}}

  defp validate_received(_received, _expected_length),
    do: {:error, {:invalid_input, :verify_data}}
end
