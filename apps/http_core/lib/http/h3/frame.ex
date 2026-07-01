defmodule HTTP.H3.Frame do
  @moduledoc false

  alias HTTP.H3.Varint

  defstruct type: nil, payload: <<>>

  @data 0x00
  @headers 0x01
  @cancel_push 0x03
  @settings 0x04
  @push_promise 0x05
  @goaway 0x07
  @max_push_id 0x0D
  @wt_stream 0x41

  @type frame_type :: non_neg_integer()
  @type t :: %__MODULE__{type: frame_type(), payload: binary()}
  @type decode_result :: {:ok, t(), binary()} | :more

  @spec data() :: 0
  def data, do: @data

  @spec headers() :: 1
  def headers, do: @headers

  @spec cancel_push() :: 3
  def cancel_push, do: @cancel_push

  @spec settings() :: 4
  def settings, do: @settings

  @spec push_promise() :: 5
  def push_promise, do: @push_promise

  @spec goaway() :: 7
  def goaway, do: @goaway

  @spec max_push_id() :: 13
  def max_push_id, do: @max_push_id

  @spec wt_stream() :: 65
  def wt_stream, do: @wt_stream

  @spec name(frame_type()) :: atom() | nil
  def name(@data), do: :data
  def name(@headers), do: :headers
  def name(@cancel_push), do: :cancel_push
  def name(@settings), do: :settings
  def name(@push_promise), do: :push_promise
  def name(@goaway), do: :goaway
  def name(@max_push_id), do: :max_push_id
  def name(@wt_stream), do: :wt_stream
  def name(_type), do: nil

  @spec type(atom() | frame_type()) :: {:ok, frame_type()} | {:error, :unknown_frame_type}
  def type(:data), do: {:ok, @data}
  def type(:headers), do: {:ok, @headers}
  def type(:cancel_push), do: {:ok, @cancel_push}
  def type(:settings), do: {:ok, @settings}
  def type(:push_promise), do: {:ok, @push_promise}
  def type(:goaway), do: {:ok, @goaway}
  def type(:max_push_id), do: {:ok, @max_push_id}
  def type(:wt_stream), do: {:ok, @wt_stream}
  def type(value) when is_integer(value) and value >= 0, do: {:ok, value}
  def type(_value), do: {:error, :unknown_frame_type}

  @spec encode(t()) :: {:ok, binary()} | {:error, term()}
  def encode(%__MODULE__{type: frame_type, payload: payload}) do
    encode(frame_type, payload)
  end

  @spec encode(atom() | frame_type(), binary()) :: {:ok, binary()} | {:error, term()}
  def encode(frame_type, payload) when is_binary(payload) do
    with {:ok, frame_type} <- type(frame_type),
         {:ok, type_bytes} <- Varint.encode(frame_type),
         {:ok, length_bytes} <- Varint.encode(byte_size(payload)) do
      {:ok, IO.iodata_to_binary([type_bytes, length_bytes, payload])}
    end
  end

  def encode(_frame_type, _payload), do: {:error, :invalid_frame_payload}

  @spec encode!(t() | atom() | frame_type(), binary() | nil) :: binary()
  def encode!(frame_or_type, payload \\ nil)

  def encode!(%__MODULE__{} = frame, nil) do
    case encode(frame) do
      {:ok, encoded} -> encoded
      {:error, reason} -> raise ArgumentError, "invalid HTTP/3 frame: #{inspect(reason)}"
    end
  end

  def encode!(frame_type, payload) when is_binary(payload) do
    case encode(frame_type, payload) do
      {:ok, encoded} -> encoded
      {:error, reason} -> raise ArgumentError, "invalid HTTP/3 frame: #{inspect(reason)}"
    end
  end

  @spec decode(binary()) :: decode_result()
  def decode(data) when is_binary(data) do
    with {:ok, frame_type, rest} <- Varint.decode(data),
         {:ok, length, rest} <- Varint.decode(rest) do
      decode_payload(frame_type, length, rest)
    end
  end

  defp decode_payload(frame_type, length, data) when byte_size(data) >= length do
    <<payload::binary-size(length), rest::binary>> = data
    {:ok, %__MODULE__{type: frame_type, payload: payload}, rest}
  end

  defp decode_payload(_frame_type, _length, _data), do: :more
end
