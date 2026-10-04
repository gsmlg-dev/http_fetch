defmodule SSL.Protocol.Record do
  @moduledoc """
  Pure TLS 1.3 encrypted record protection for one complete framed record.

  Stream accumulation remains the responsibility of `SSL.Protocol.RecordFramer`.
  Successful operations return an immutable traffic state advanced by one
  record; failures return no advanced state.
  """

  alias SSL.Crypto.AEAD
  alias SSL.Crypto.TrafficState
  alias SSL.Protocol.InnerPlaintext

  @application_data 23
  @legacy_record_version 0x0303
  @tag_length 16
  @minimum_ciphertext_length @tag_length
  @maximum_ciphertext_length 16_640

  @spec encrypt(TrafficState.t(), term(), term(), keyword()) ::
          {:ok, binary(), TrafficState.t()} | {:error, term()}
  def encrypt(state, content_type, content, options \\ [])

  def encrypt(%TrafficState{} = state, content_type, content, options) do
    with :ok <- encryption_permitted(state),
         {:ok, padding_length} <- padding_length(options),
         {:ok, inner_plaintext} <- InnerPlaintext.encode(content, content_type, padding_length),
         {:ok, next_state} <- TrafficState.advance(state),
         header <- ciphertext_header(byte_size(inner_plaintext) + @tag_length),
         {:ok, ciphertext, tag} <- AEAD.encrypt(state, header, inner_plaintext) do
      {:ok, <<header::binary, ciphertext::binary, tag::binary>>, next_state}
    end
  end

  def encrypt(_state, _content_type, _content, _options),
    do: {:error, :invalid_traffic_state}

  @spec decrypt(TrafficState.t(), term()) ::
          {:ok, InnerPlaintext.content_type(), binary(), TrafficState.t()} | {:error, term()}
  def decrypt(%TrafficState{} = state, record) when is_binary(record) do
    with {:ok, header, ciphertext, tag} <- parse_ciphertext(record),
         {:ok, next_state} <- TrafficState.advance(state),
         {:ok, inner_plaintext} <- AEAD.decrypt(state, header, ciphertext, tag),
         {:ok, content_type, content, _padding_length} <-
           InnerPlaintext.decode(inner_plaintext) do
      {:ok, content_type, content, next_state}
    end
  end

  def decrypt(%TrafficState{}, _record), do: {:error, {:invalid_record, :not_binary}}
  def decrypt(_state, _record), do: {:error, :invalid_traffic_state}

  defp parse_ciphertext(record) when byte_size(record) < 5,
    do: {:error, {:malformed_record, :header}}

  defp parse_ciphertext(
         <<content_type, legacy_version::16, declared_length::16, body::binary>> = record
       ) do
    actual_length = byte_size(body)

    cond do
      content_type != @application_data ->
        {:error, {:unexpected_outer_content_type, content_type}}

      legacy_version != @legacy_record_version ->
        {:error, {:invalid_legacy_record_version, legacy_version}}

      declared_length > @maximum_ciphertext_length ->
        {:error, {:record_length_exceeded, declared_length, @maximum_ciphertext_length}}

      declared_length != actual_length ->
        {:error, {:record_length_mismatch, declared_length, actual_length}}

      declared_length < @minimum_ciphertext_length ->
        {:error, {:ciphertext_length_too_short, declared_length, @minimum_ciphertext_length}}

      true ->
        ciphertext_length = declared_length - @tag_length
        <<ciphertext::binary-size(^ciphertext_length), tag::binary-size(@tag_length)>> = body
        {:ok, binary_part(record, 0, 5), ciphertext, tag}
    end
  end

  defp ciphertext_header(ciphertext_length) do
    <<@application_data, @legacy_record_version::16, ciphertext_length::16>>
  end

  defp encryption_permitted(state) do
    cond do
      not TrafficState.valid_write_generation?(state) ->
        {:error, :generation_exhausted}

      not TrafficState.may_encrypt?(state) ->
        {:error, :key_usage_exhausted}

      true ->
        :ok
    end
  end

  defp padding_length(options) when is_list(options) do
    if Keyword.keyword?(options) and Keyword.keys(options) in [[], [:padding_length]] do
      case Keyword.get(options, :padding_length, 0) do
        value when is_integer(value) and value >= 0 -> {:ok, value}
        value -> {:error, {:invalid_padding_length, value}}
      end
    else
      {:error, {:invalid_options, :record}}
    end
  end

  defp padding_length(_options), do: {:error, {:invalid_options, :record}}
end
