defmodule QuicHttp3.Stream do
  @moduledoc """
  Pure HTTP/3 classification for QUIC stream identifiers and type prefixes.

  Stream payload ownership remains with the transport implementation. This
  module only validates the identifier bits and decodes the first varint on a
  unidirectional stream.
  """

  import Bitwise, only: [band: 2]

  alias QuicHttp3.Varint

  @control 0x00
  @push 0x01
  @qpack_encoder 0x02
  @qpack_decoder 0x03

  @type role :: :client | :server
  @type initiator :: :client | :server
  @type direction :: :bidi | :uni
  @type stream_type ::
          :control | :push | :qpack_encoder | :qpack_decoder | {:unknown, pos_integer()}

  @spec direction(non_neg_integer()) :: direction() | {:error, :invalid_stream_id}
  def direction(id) when is_integer(id) and id >= 0 do
    if band(id, 0b10) == 0, do: :bidi, else: :uni
  end

  def direction(_id), do: {:error, :invalid_stream_id}

  @spec initiator(non_neg_integer()) :: initiator() | {:error, :invalid_stream_id}
  def initiator(id) when is_integer(id) and id >= 0 do
    if band(id, 0b01) == 0, do: :client, else: :server
  end

  def initiator(_id), do: {:error, :invalid_stream_id}

  @spec local?(non_neg_integer(), role()) :: boolean()
  def local?(id, role) when role in [:client, :server] do
    initiator(id) == role
  end

  def local?(_id, _role), do: false

  @spec classify(non_neg_integer(), role()) ::
          {:ok, :request | :unidirectional | :peer_bidi} | {:error, term()}
  def classify(id, role) when role in [:client, :server] do
    with direction when direction in [:bidi, :uni] <- direction(id) do
      cond do
        direction == :bidi and local?(id, role) -> {:ok, :request}
        direction == :bidi -> {:ok, :peer_bidi}
        true -> {:ok, :unidirectional}
      end
    end
  end

  def classify(_id, _role), do: {:error, :invalid_role}

  @spec decode_type(binary()) :: {:ok, stream_type(), binary()} | :more
  def decode_type(data) when is_binary(data) do
    case Varint.decode(data) do
      {:ok, @control, rest} -> {:ok, :control, rest}
      {:ok, @push, rest} -> {:ok, :push, rest}
      {:ok, @qpack_encoder, rest} -> {:ok, :qpack_encoder, rest}
      {:ok, @qpack_decoder, rest} -> {:ok, :qpack_decoder, rest}
      {:ok, type, rest} -> {:ok, {:unknown, type}, rest}
      :more -> :more
    end
  end

  @spec type_id(stream_type()) :: non_neg_integer()
  def type_id(:control), do: @control
  def type_id(:push), do: @push
  def type_id(:qpack_encoder), do: @qpack_encoder
  def type_id(:qpack_decoder), do: @qpack_decoder
  def type_id({:unknown, type}) when is_integer(type) and type >= 0, do: type
end
