defmodule HTTP.HTTP2.Frame do
  @moduledoc false

  import Bitwise

  @type type ::
          :data
          | :headers
          | :priority
          | :rst_stream
          | :settings
          | :push_promise
          | :ping
          | :goaway
          | :window_update
          | :continuation
          | non_neg_integer()

  @type t :: %__MODULE__{
          type: type(),
          flags: non_neg_integer(),
          stream_id: non_neg_integer(),
          payload: binary()
        }

  defstruct [:type, :flags, :stream_id, :payload]

  @max_frame_length 16_777_215

  @spec encode(type(), non_neg_integer(), non_neg_integer(), iodata()) :: binary()
  def encode(type, flags, stream_id, payload) do
    payload = IO.iodata_to_binary(payload)
    length = byte_size(payload)

    if length > @max_frame_length do
      raise ArgumentError, "HTTP/2 frame payload exceeds 24-bit length"
    end

    <<length::24, type_id(type)::8, flags::8, 0::1, stream_id::31, payload::binary>>
  end

  @spec decode(binary()) :: {:ok, t(), binary()} | :more
  def decode(buffer) when byte_size(buffer) < 9, do: :more

  def decode(<<length::24, type::8, flags::8, _reserved::1, stream_id::31, rest::binary>>) do
    if byte_size(rest) < length do
      :more
    else
      <<payload::binary-size(length), remaining::binary>> = rest

      {:ok,
       %__MODULE__{
         type: type_atom(type),
         flags: flags,
         stream_id: stream_id,
         payload: payload
       }, remaining}
    end
  end

  def type_id(:data), do: 0x0
  def type_id(:headers), do: 0x1
  def type_id(:priority), do: 0x2
  def type_id(:rst_stream), do: 0x3
  def type_id(:settings), do: 0x4
  def type_id(:push_promise), do: 0x5
  def type_id(:ping), do: 0x6
  def type_id(:goaway), do: 0x7
  def type_id(:window_update), do: 0x8
  def type_id(:continuation), do: 0x9
  def type_id(type) when is_integer(type) and type >= 0 and type <= 0xFF, do: type

  @spec type_atom(non_neg_integer()) :: type()
  def type_atom(0x0), do: :data
  def type_atom(0x1), do: :headers
  def type_atom(0x2), do: :priority
  def type_atom(0x3), do: :rst_stream
  def type_atom(0x4), do: :settings
  def type_atom(0x5), do: :push_promise
  def type_atom(0x6), do: :ping
  def type_atom(0x7), do: :goaway
  def type_atom(0x8), do: :window_update
  def type_atom(0x9), do: :continuation
  def type_atom(type), do: type

  @spec flag?(non_neg_integer(), non_neg_integer()) :: boolean()
  def flag?(flags, flag), do: (flags &&& flag) == flag
end
