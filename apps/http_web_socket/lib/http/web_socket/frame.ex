defmodule HTTP.WebSocket.Frame do
  @moduledoc false

  import Bitwise

  @continuation 0x0
  @text 0x1
  @binary 0x2
  @close 0x8
  @ping 0x9
  @pong 0xA

  @default_max_message_size 16 * 1024 * 1024

  defstruct buffer: <<>>,
            fragmented_opcode: nil,
            fragmented_chunks: [],
            fragmented_size: 0,
            max_message_size: @default_max_message_size

  @type opcode :: :text | :binary | :close | :ping | :pong
  @type event ::
          {:message, :text | :binary, binary()}
          | {:close, non_neg_integer() | nil, binary()}
          | {:ping, binary()}
          | {:pong, binary()}
  @type close_error :: {non_neg_integer(), atom()}
  @type t :: %__MODULE__{}

  def new_parser(opts \\ []) do
    %__MODULE__{max_message_size: Keyword.get(opts, :max_message_size, @default_max_message_size)}
  end

  @spec encode(opcode(), binary(), keyword()) :: {:ok, binary()} | {:error, term()}
  def encode(opcode, payload, opts \\ []) when is_binary(payload) do
    with {:ok, opcode} <- opcode_number(opcode),
         :ok <- validate_control_payload(opcode, payload) do
      mask? = Keyword.get(opts, :client?, true)
      {:ok, encode_frame(opcode, payload, mask?)}
    end
  end

  @spec close_payload(non_neg_integer() | nil, binary()) :: {:ok, binary()} | {:error, term()}
  def close_payload(nil, ""), do: {:ok, <<>>}

  def close_payload(code, reason) when is_integer(code) and is_binary(reason) do
    cond do
      code != 1000 and code not in 3000..4999 ->
        {:error, :invalid_close_code}

      byte_size(reason) > 123 ->
        {:error, :close_reason_too_long}

      not String.valid?(reason) ->
        {:error, :invalid_close_reason}

      true ->
        {:ok, <<code::16, reason::binary>>}
    end
  end

  def close_payload(_code, _reason), do: {:error, :invalid_close_code}

  @spec parse(t(), binary()) :: {:ok, t(), [event()]} | {:error, close_error()}
  def parse(%__MODULE__{} = parser, data) when is_binary(data) do
    parser
    |> append(data)
    |> parse_frames([])
  end

  defp opcode_number(:text), do: {:ok, @text}
  defp opcode_number(:binary), do: {:ok, @binary}
  defp opcode_number(:close), do: {:ok, @close}
  defp opcode_number(:ping), do: {:ok, @ping}
  defp opcode_number(:pong), do: {:ok, @pong}
  defp opcode_number(_opcode), do: {:error, :invalid_opcode}

  defp validate_control_payload(opcode, payload) when opcode in [@close, @ping, @pong] do
    if byte_size(payload) <= 125, do: :ok, else: {:error, :control_payload_too_large}
  end

  defp validate_control_payload(_opcode, _payload), do: :ok

  defp encode_frame(opcode, payload, true) do
    mask_key = :crypto.strong_rand_bytes(4)

    [
      <<0x80 ||| opcode>>,
      encode_length(byte_size(payload), true),
      mask_key,
      mask(payload, mask_key)
    ]
    |> IO.iodata_to_binary()
  end

  defp encode_frame(opcode, payload, false) do
    [<<0x80 ||| opcode>>, encode_length(byte_size(payload), false), payload]
    |> IO.iodata_to_binary()
  end

  defp encode_length(length, mask?) when length <= 125 do
    <<mask_bit(mask?) ||| length>>
  end

  defp encode_length(length, mask?) when length <= 65_535 do
    <<mask_bit(mask?) ||| 126, length::16>>
  end

  defp encode_length(length, mask?) do
    <<mask_bit(mask?) ||| 127, length::64>>
  end

  defp mask_bit(true), do: 0x80
  defp mask_bit(false), do: 0x00

  defp append(%__MODULE__{buffer: buffer} = parser, data) do
    %{parser | buffer: buffer <> data}
  end

  defp parse_frames(%__MODULE__{buffer: buffer} = parser, events) when byte_size(buffer) < 2 do
    {:ok, parser, Enum.reverse(events)}
  end

  defp parse_frames(%__MODULE__{buffer: buffer} = parser, events) do
    with {:ok, frame, rest} <- take_frame(buffer),
         {:ok, parser, new_events} <- handle_frame(%{parser | buffer: rest}, frame) do
      parse_frames(parser, Enum.reverse(new_events) ++ events)
    else
      :more -> {:ok, parser, Enum.reverse(events)}
      {:error, reason} -> {:error, reason}
    end
  end

  defp take_frame(<<first, second, rest::binary>>) do
    fin? = (first &&& 0x80) != 0
    rsv = first &&& 0x70
    opcode = first &&& 0x0F
    masked? = (second &&& 0x80) != 0
    length_code = second &&& 0x7F

    with :ok <- validate_header(rsv, opcode, masked?),
         {:ok, length, payload_rest} <- take_length(length_code, rest),
         {:ok, payload, rest} <- take_payload(payload_rest, length) do
      {:ok, %{fin?: fin?, opcode: opcode, payload: payload}, rest}
    end
  end

  defp take_length(length, rest) when length <= 125, do: {:ok, length, rest}

  defp take_length(126, <<length::16, rest::binary>>) do
    if length < 126, do: {:error, {1002, :non_minimal_length}}, else: {:ok, length, rest}
  end

  defp take_length(126, _rest), do: :more

  defp take_length(127, <<0::1, length::63, rest::binary>>) do
    if length <= 65_535, do: {:error, {1002, :non_minimal_length}}, else: {:ok, length, rest}
  end

  defp take_length(127, <<1::1, _length::63, _rest::binary>>),
    do: {:error, {1002, :invalid_length}}

  defp take_length(127, _rest), do: :more

  defp take_payload(rest, length) when byte_size(rest) < length, do: :more

  defp take_payload(rest, length) do
    <<payload::binary-size(length), remaining::binary>> = rest
    {:ok, payload, remaining}
  end

  defp validate_header(_rsv, opcode, _masked?) when opcode not in [0, 1, 2, 8, 9, 10],
    do: {:error, {1002, :unknown_opcode}}

  defp validate_header(rsv, _opcode, _masked?) when rsv != 0,
    do: {:error, {1002, :unexpected_rsv}}

  defp validate_header(_rsv, _opcode, true), do: {:error, {1002, :masked_server_frame}}
  defp validate_header(_rsv, _opcode, false), do: :ok

  defp handle_frame(_parser, %{opcode: opcode, fin?: false})
       when opcode in [@close, @ping, @pong] do
    {:error, {1002, :fragmented_control_frame}}
  end

  defp handle_frame(_parser, %{opcode: opcode, payload: payload})
       when opcode in [@close, @ping, @pong] and byte_size(payload) > 125 do
    {:error, {1002, :control_payload_too_large}}
  end

  defp handle_frame(parser, %{opcode: @text, fin?: true, payload: payload}) do
    with :ok <- validate_size(parser, byte_size(payload)),
         :ok <- validate_text(payload) do
      {:ok, parser, [{:message, :text, payload}]}
    end
  end

  defp handle_frame(parser, %{opcode: @binary, fin?: true, payload: payload}) do
    with :ok <- validate_size(parser, byte_size(payload)) do
      {:ok, parser, [{:message, :binary, payload}]}
    end
  end

  defp handle_frame(%__MODULE__{fragmented_opcode: nil} = parser, %{
         opcode: opcode,
         fin?: false,
         payload: payload
       })
       when opcode in [@text, @binary] do
    with :ok <- validate_size(parser, byte_size(payload)) do
      {:ok,
       %{
         parser
         | fragmented_opcode: opcode,
           fragmented_chunks: [payload],
           fragmented_size: byte_size(payload)
       }, []}
    end
  end

  defp handle_frame(_parser, %{opcode: opcode, fin?: false}) when opcode in [@text, @binary] do
    {:error, {1002, :fragment_already_started}}
  end

  defp handle_frame(%__MODULE__{fragmented_opcode: nil}, %{opcode: @continuation}) do
    {:error, {1002, :unexpected_continuation}}
  end

  defp handle_frame(%__MODULE__{fragmented_opcode: opcode} = parser, %{
         opcode: @continuation,
         fin?: fin?,
         payload: payload
       }) do
    size = parser.fragmented_size + byte_size(payload)

    with :ok <- validate_size(parser, size) do
      chunks = [payload | parser.fragmented_chunks]

      if fin? do
        message = chunks |> Enum.reverse() |> IO.iodata_to_binary()
        parser = %{parser | fragmented_opcode: nil, fragmented_chunks: [], fragmented_size: 0}
        emit_fragmented_message(parser, opcode, message)
      else
        {:ok, %{parser | fragmented_chunks: chunks, fragmented_size: size}, []}
      end
    end
  end

  defp handle_frame(parser, %{opcode: @close, payload: payload}) do
    with {:ok, code, reason} <- parse_close_payload(payload) do
      {:ok, parser, [{:close, code, reason}]}
    end
  end

  defp handle_frame(parser, %{opcode: @ping, payload: payload}),
    do: {:ok, parser, [{:ping, payload}]}

  defp handle_frame(parser, %{opcode: @pong, payload: payload}),
    do: {:ok, parser, [{:pong, payload}]}

  defp emit_fragmented_message(parser, @text, message) do
    with :ok <- validate_text(message) do
      {:ok, parser, [{:message, :text, message}]}
    end
  end

  defp emit_fragmented_message(parser, @binary, message) do
    {:ok, parser, [{:message, :binary, message}]}
  end

  defp validate_size(parser, size) do
    if size <= parser.max_message_size, do: :ok, else: {:error, {1009, :message_too_big}}
  end

  defp validate_text(payload) do
    if String.valid?(payload), do: :ok, else: {:error, {1007, :invalid_utf8}}
  end

  defp parse_close_payload(<<>>), do: {:ok, nil, ""}
  defp parse_close_payload(<<_one_byte>>), do: {:error, {1002, :invalid_close_payload}}

  defp parse_close_payload(<<code::16, reason::binary>>) do
    cond do
      not valid_received_close_code?(code) ->
        {:error, {1002, :invalid_close_code}}

      not String.valid?(reason) ->
        {:error, {1007, :invalid_close_reason}}

      true ->
        {:ok, code, reason}
    end
  end

  defp valid_received_close_code?(code) when code in [1005, 1006, 1015], do: false
  defp valid_received_close_code?(code) when code < 1000, do: false
  defp valid_received_close_code?(code) when code in 1000..1014, do: true
  defp valid_received_close_code?(code) when code in 3000..4999, do: true
  defp valid_received_close_code?(_code), do: false

  defp mask(payload, <<a, b, c, d>>) do
    payload
    |> :binary.bin_to_list()
    |> Enum.with_index()
    |> Enum.map(fn {byte, index} ->
      bxor(byte, Enum.at([a, b, c, d], rem(index, 4)))
    end)
    |> :binary.list_to_bin()
  end
end
