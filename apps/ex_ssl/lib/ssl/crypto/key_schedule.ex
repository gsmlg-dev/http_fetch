defmodule SSL.Crypto.KeySchedule do
  @moduledoc """
  Pure TLS 1.3 key-schedule derivations.

  Callers supply exact transcript hashes at each protocol checkpoint. Derived
  traffic states start at sequence zero for a new traffic epoch.
  """

  alias SSL.Crypto.HKDF
  alias SSL.Crypto.TrafficState

  @type hash :: :sha256 | :sha384
  @type error_reason ::
          :unsupported_hash
          | {:unsupported_cipher_suite, term()}
          | {:invalid_input, :psk | :shared_secret | :ticket_nonce | :transcript_hash}
          | {:invalid_secret_length, atom(), pos_integer()}
          | {:invalid_input, :empty_shared_secret}
          | {:invalid_transcript_hash_length, pos_integer()}
          | {:ticket_nonce_too_long, 255}

  @spec early_secret(hash(), binary() | nil) :: {:ok, binary()} | {:error, error_reason()}
  def early_secret(hash, psk) do
    with {:ok, hash_length} <- hash_length(hash),
         {:ok, input_key_material} <- psk_input(psk, hash_length) do
      {:ok, HKDF.extract(hash, :binary.copy(<<0>>, hash_length), input_key_material)}
    end
  end

  @spec derived_secret(hash(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def derived_secret(hash, secret) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(secret, :secret, hash_length) do
      derive(hash, secret, "derived", :crypto.hash(hash, <<>>))
    end
  end

  @spec handshake_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def handshake_secret(hash, early_secret, shared_secret) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(early_secret, :early_secret, hash_length),
         :ok <- validate_shared_secret(shared_secret),
         {:ok, derived} <- derive(hash, early_secret, "derived", :crypto.hash(hash, <<>>)) do
      {:ok, HKDF.extract(hash, derived, shared_secret)}
    end
  end

  @spec client_handshake_traffic_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def client_handshake_traffic_secret(hash, handshake_secret, transcript_hash) do
    traffic_secret(hash, handshake_secret, :handshake_secret, "c hs traffic", transcript_hash)
  end

  @spec server_handshake_traffic_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def server_handshake_traffic_secret(hash, handshake_secret, transcript_hash) do
    traffic_secret(hash, handshake_secret, :handshake_secret, "s hs traffic", transcript_hash)
  end

  @spec master_secret(hash(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def master_secret(hash, handshake_secret) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(handshake_secret, :handshake_secret, hash_length),
         {:ok, derived} <-
           derive(hash, handshake_secret, "derived", :crypto.hash(hash, <<>>)) do
      {:ok, HKDF.extract(hash, derived, :binary.copy(<<0>>, hash_length))}
    end
  end

  @spec client_application_traffic_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def client_application_traffic_secret(hash, master_secret, transcript_hash) do
    traffic_secret(hash, master_secret, :master_secret, "c ap traffic", transcript_hash)
  end

  @spec server_application_traffic_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def server_application_traffic_secret(hash, master_secret, transcript_hash) do
    traffic_secret(hash, master_secret, :master_secret, "s ap traffic", transcript_hash)
  end

  @spec exporter_master_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def exporter_master_secret(hash, master_secret, transcript_hash) do
    traffic_secret(hash, master_secret, :master_secret, "exp master", transcript_hash)
  end

  @spec resumption_master_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def resumption_master_secret(hash, master_secret, transcript_hash) do
    traffic_secret(hash, master_secret, :master_secret, "res master", transcript_hash)
  end

  @spec resumption_secret(hash(), binary(), binary()) ::
          {:ok, binary()} | {:error, error_reason()}
  def resumption_secret(hash, resumption_master_secret, ticket_nonce) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(resumption_master_secret, :resumption_master_secret, hash_length),
         :ok <- validate_ticket_nonce(ticket_nonce) do
      expand_label(hash, resumption_master_secret, "resumption", ticket_nonce, hash_length)
    end
  end

  @spec finished_key(atom(), term()) ::
          {:ok, binary()}
          | {:error, :unsupported_hash | {:invalid_secret_length, :traffic_secret, 32 | 48}}
  def finished_key(hash, traffic_secret) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(traffic_secret, :traffic_secret, hash_length) do
      expand_label(hash, traffic_secret, "finished", <<>>, hash_length)
    end
  end

  @spec finished_verify_data(atom(), term(), term()) ::
          {:ok, binary()}
          | {:error,
             :unsupported_hash
             | {:invalid_secret_length, :finished_key, 32 | 48}
             | {:invalid_input, :transcript_hash}
             | {:invalid_transcript_hash_length, 32 | 48}}
  def finished_verify_data(hash, finished_key, transcript_hash) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(finished_key, :finished_key, hash_length),
         :ok <- validate_transcript_hash(transcript_hash, hash_length) do
      {:ok, :crypto.mac(:hmac, hash, finished_key, transcript_hash)}
    end
  end

  @spec traffic_state(TrafficState.cipher_suite(), binary()) ::
          {:ok, TrafficState.t()} | {:error, error_reason()}
  def traffic_state(cipher_suite, traffic_secret) do
    with {:ok, hash, key_length} <- cipher_suite_spec(cipher_suite),
         {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(traffic_secret, :traffic_secret, hash_length),
         {:ok, key} <- expand_label(hash, traffic_secret, "key", <<>>, key_length),
         {:ok, iv} <- expand_label(hash, traffic_secret, "iv", <<>>, 12) do
      {:ok,
       %TrafficState{
         secret: traffic_secret,
         key: key,
         iv: iv,
         cipher_suite: cipher_suite
       }}
    end
  end

  @spec traffic_update(hash(), binary()) :: {:ok, binary()} | {:error, error_reason()}
  def traffic_update(hash, traffic_secret) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(traffic_secret, :traffic_secret, hash_length) do
      expand_label(hash, traffic_secret, "traffic upd", <<>>, hash_length)
    end
  end

  defp traffic_secret(hash, secret, secret_name, label, transcript_hash) do
    with {:ok, hash_length} <- hash_length(hash),
         :ok <- validate_secret(secret, secret_name, hash_length),
         :ok <- validate_transcript_hash(transcript_hash, hash_length) do
      derive(hash, secret, label, transcript_hash)
    end
  end

  defp derive(hash, secret, label, transcript_hash) do
    case HKDF.derive_secret(hash, secret, label, transcript_hash) do
      derived when is_binary(derived) -> {:ok, derived}
      {:error, reason} -> {:error, reason}
    end
  end

  defp expand_label(hash, secret, label, context, length) do
    case HKDF.expand_label(hash, secret, label, context, length) do
      expanded when is_binary(expanded) -> {:ok, expanded}
      {:error, reason} -> {:error, reason}
    end
  end

  defp hash_length(:sha256), do: {:ok, 32}
  defp hash_length(:sha384), do: {:ok, 48}
  defp hash_length(_hash), do: {:error, :unsupported_hash}

  defp cipher_suite_spec(cipher_suite) do
    case SSL.Capabilities.resolve(:cipher_suite, cipher_suite) do
      %{version: 0x0304, hash: hash, key_length: length} -> {:ok, hash, length}
      _ -> {:error, {:unsupported_cipher_suite, cipher_suite}}
    end
  end

  defp psk_input(nil, hash_length), do: {:ok, :binary.copy(<<0>>, hash_length)}
  defp psk_input(psk, _hash_length) when is_binary(psk), do: {:ok, psk}
  defp psk_input(_psk, _hash_length), do: {:error, {:invalid_input, :psk}}

  defp validate_secret(secret, _name, expected_length)
       when is_binary(secret) and byte_size(secret) == expected_length,
       do: :ok

  defp validate_secret(_secret, name, expected_length),
    do: {:error, {:invalid_secret_length, name, expected_length}}

  defp validate_shared_secret(shared_secret)
       when is_binary(shared_secret) and byte_size(shared_secret) > 0,
       do: :ok

  defp validate_shared_secret(<<>>), do: {:error, {:invalid_input, :empty_shared_secret}}

  defp validate_shared_secret(_shared_secret), do: {:error, {:invalid_input, :shared_secret}}

  defp validate_transcript_hash(transcript_hash, expected_length)
       when is_binary(transcript_hash) and byte_size(transcript_hash) == expected_length,
       do: :ok

  defp validate_transcript_hash(transcript_hash, _expected_length)
       when not is_binary(transcript_hash),
       do: {:error, {:invalid_input, :transcript_hash}}

  defp validate_transcript_hash(_transcript_hash, expected_length),
    do: {:error, {:invalid_transcript_hash_length, expected_length}}

  defp validate_ticket_nonce(ticket_nonce)
       when is_binary(ticket_nonce) and byte_size(ticket_nonce) <= 255,
       do: :ok

  defp validate_ticket_nonce(ticket_nonce) when is_binary(ticket_nonce),
    do: {:error, {:ticket_nonce_too_long, 255}}

  defp validate_ticket_nonce(_ticket_nonce), do: {:error, {:invalid_input, :ticket_nonce}}
end
