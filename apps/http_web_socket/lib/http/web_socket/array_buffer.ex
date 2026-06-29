defmodule HTTP.WebSocket.ArrayBuffer do
  @moduledoc """
  Explicit binary frame payload wrapper for `HTTP.WebSocket.send/2`.

  Plain Elixir binaries are also strings, so `HTTP.WebSocket.send/2` treats a
  bare binary as text. Wrap binary data with this struct when the WebSocket
  frame opcode must be binary.
  """

  defstruct data: <<>>, byte_length: 0

  @type t :: %__MODULE__{data: binary(), byte_length: non_neg_integer()}

  @doc """
  Creates a new array buffer wrapper.
  """
  @spec new(binary()) :: t()
  def new(data) when is_binary(data) do
    %__MODULE__{data: data, byte_length: byte_size(data)}
  end
end
