defmodule HTTP.Blob do
  @moduledoc """
  Represents a blob of binary data, similar to JavaScript's Blob.

  A Blob contains raw data along with metadata about its MIME type and size.
  This module implements the Browser Fetch API Blob interface for Elixir.

  ## Examples

      # Create a blob
      blob = HTTP.Blob.new(<<1, 2, 3, 4>>, "application/octet-stream")

      # Access properties
      HTTP.Blob.size(blob)  # 4
      HTTP.Blob.type(blob)  # "application/octet-stream"

      # Convert to binary
      data = HTTP.Blob.to_binary(blob)
  """

  defstruct data: <<>>,
            type: "application/octet-stream",
            size: 0

  @type t :: %__MODULE__{
          data: binary(),
          type: String.t(),
          size: non_neg_integer()
        }

  @doc """
  Creates a new Blob from binary data with a specified MIME type.

  ## Parameters
    - `data` - Binary data to store in the blob
    - `type` - MIME type string (default: "application/octet-stream")

  ## Examples

      iex> blob = HTTP.Blob.new(<<1, 2, 3>>, "image/png")
      iex> blob.type
      "image/png"
      iex> blob.size
      3
  """
  @spec new(binary(), String.t()) :: t()
  def new(data, type \\ "application/octet-stream") when is_binary(data) do
    %__MODULE__{
      data: data,
      type: type,
      size: byte_size(data)
    }
  end

  @doc """
  Converts the Blob to a binary, extracting the raw data.

  ## Examples

      iex> blob = HTTP.Blob.new(<<1, 2, 3>>, "application/octet-stream")
      iex> HTTP.Blob.to_binary(blob)
      <<1, 2, 3>>
  """
  @spec to_binary(t()) :: binary()
  def to_binary(%__MODULE__{data: data}), do: data

  @doc """
  Returns the Blob's MIME type.

  ## Examples

      iex> blob = HTTP.Blob.new(<<>>, "text/plain")
      iex> HTTP.Blob.type(blob)
      "text/plain"
  """
  @spec type(t()) :: String.t()
  def type(%__MODULE__{type: type}), do: type

  @doc """
  Returns the Blob's size in bytes.

  ## Examples

      iex> blob = HTTP.Blob.new(<<1, 2, 3, 4, 5>>, "application/octet-stream")
      iex> HTTP.Blob.size(blob)
      5
  """
  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{size: size}), do: size
end
