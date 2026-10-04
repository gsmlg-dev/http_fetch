defmodule SSL.Protocol.InnerPlaintext do
  @moduledoc """
  Bounded TLS 1.3 inner plaintext encoding and decoding.

  The final nonzero byte carries the real record content type. Any bytes after
  it must be zero padding.
  """

  @maximum_content_length 16_384
  @maximum_inner_plaintext_length 16_385

  @type content_type :: :alert | :handshake | :application_data

  @spec encode(term(), term(), term()) :: {:ok, binary()} | {:error, term()}
  def encode(content, content_type, padding_length \\ 0) do
    with :ok <- validate_content(content),
         {:ok, encoded_type} <- encode_type(content_type),
         :ok <- validate_nonempty_content(content, content_type),
         :ok <- validate_padding_length(padding_length, byte_size(content)) do
      {:ok, <<content::binary, encoded_type, 0::size(padding_length * 8)>>}
    end
  end

  @spec decode(term()) ::
          {:error,
           :empty_inner_plaintext
           | :missing_inner_content_type
           | {:empty_content, :alert | :application_data | :handshake}
           | {:invalid_inner_plaintext, :not_binary}
           | {:unsupported_inner_content_type, 1..255}
           | {:content_length_exceeded, non_neg_integer(), 16_384}
           | {:inner_plaintext_length_exceeded, non_neg_integer(), 16_385}}
          | {:ok, :alert | :application_data | :handshake, binary(), non_neg_integer()}
  def decode(plaintext) when is_binary(plaintext) do
    plaintext_length = byte_size(plaintext)

    cond do
      plaintext_length == 0 ->
        {:error, :empty_inner_plaintext}

      plaintext_length > @maximum_inner_plaintext_length ->
        {:error,
         {:inner_plaintext_length_exceeded, plaintext_length, @maximum_inner_plaintext_length}}

      true ->
        find_content_type(plaintext, plaintext_length - 1, 0)
    end
  end

  def decode(_plaintext), do: {:error, {:invalid_inner_plaintext, :not_binary}}

  defp find_content_type(_plaintext, -1, _padding_length),
    do: {:error, :missing_inner_content_type}

  defp find_content_type(plaintext, index, padding_length) do
    case :binary.at(plaintext, index) do
      0 ->
        find_content_type(plaintext, index - 1, padding_length + 1)

      encoded_type ->
        with {:ok, content_type} <- decode_type(encoded_type) do
          decoded_content(plaintext, index, padding_length, content_type)
        end
    end
  end

  defp decoded_content(plaintext, content_length, padding_length, content_type) do
    cond do
      content_length > @maximum_content_length ->
        {:error, {:content_length_exceeded, content_length, @maximum_content_length}}

      content_length == 0 and content_type in [:handshake, :alert] ->
        {:error, {:empty_content, content_type}}

      true ->
        {:ok, content_type, binary_part(plaintext, 0, content_length), padding_length}
    end
  end

  defp validate_content(content) when is_binary(content) do
    content_length = byte_size(content)

    if content_length <= @maximum_content_length do
      :ok
    else
      {:error, {:content_length_exceeded, content_length, @maximum_content_length}}
    end
  end

  defp validate_content(_content), do: {:error, {:invalid_content, :not_binary}}

  defp validate_nonempty_content(<<>>, content_type) when content_type in [:handshake, :alert],
    do: {:error, {:empty_content, content_type}}

  defp validate_nonempty_content(_content, _content_type), do: :ok

  defp validate_padding_length(padding_length, content_length)
       when is_integer(padding_length) and padding_length >= 0 do
    maximum_padding_length = @maximum_inner_plaintext_length - content_length - 1

    if padding_length <= maximum_padding_length do
      :ok
    else
      {:error, {:padding_length_exceeded, padding_length, maximum_padding_length}}
    end
  end

  defp validate_padding_length(padding_length, _content_length),
    do: {:error, {:invalid_padding_length, padding_length}}

  defp encode_type(:alert), do: {:ok, 21}
  defp encode_type(:handshake), do: {:ok, 22}
  defp encode_type(:application_data), do: {:ok, 23}
  defp encode_type(content_type), do: {:error, {:unsupported_inner_content_type, content_type}}

  defp decode_type(21), do: {:ok, :alert}
  defp decode_type(22), do: {:ok, :handshake}
  defp decode_type(23), do: {:ok, :application_data}
  defp decode_type(content_type), do: {:error, {:unsupported_inner_content_type, content_type}}
end
