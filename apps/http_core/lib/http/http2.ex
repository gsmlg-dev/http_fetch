defmodule HTTP.HTTP2 do
  @moduledoc false

  import Bitwise

  alias HTTP.Headers
  alias HTTP.HTTP2.Frame
  alias HTTP.HTTP2.HPACK
  alias HTTP.Request

  @connection_preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
  @client_stream_id 1
  @initial_window_size 65_535
  @initial_max_frame_size 16_384

  @flag_end_stream 0x1
  @flag_ack 0x1
  @flag_end_headers 0x4
  @flag_padded 0x8
  @flag_priority 0x20

  defstruct method: :get,
            buffer: <<>>,
            hpack: HPACK.new_decoder(),
            continuation: nil,
            status: nil,
            connection_receive_window: @initial_window_size,
            stream_receive_window: @initial_window_size,
            outbound: [],
            done?: false

  @type event :: {:headers, non_neg_integer(), Headers.t()} | {:body, binary()} | :done
  @type t :: %__MODULE__{}

  @spec new(atom()) :: t()
  def new(method), do: %__MODULE__{method: method}

  def connection_preface, do: @connection_preface

  def serialize_request(%Request{} = request) do
    {headers, body} = request |> request_headers() |> Request.put_body_headers(request)
    body = IO.iodata_to_binary(body)
    header_block = request |> pseudo_headers() |> Kernel.++(regular_headers(headers))
    encoded_headers = HPACK.encode_headers(header_block)

    header_flags =
      @flag_end_headers |||
        if(body == "", do: @flag_end_stream, else: 0)

    [
      @connection_preface,
      Frame.encode(:settings, 0, 0, ""),
      Frame.encode(:headers, header_flags, @client_stream_id, encoded_headers),
      data_frames(body)
    ]
  end

  @spec stream(t(), binary()) :: {:ok, t(), [event()]} | {:error, term()}
  def stream(%__MODULE__{} = conn, data) when is_binary(data) do
    conn
    |> append_buffer(data)
    |> parse([])
  end

  @spec close(t()) :: {:ok, t(), [event()]} | {:error, term()}
  def close(%__MODULE__{done?: true} = conn), do: {:ok, conn, []}
  def close(_conn), do: {:error, :closed}

  @spec take_outbound(t()) :: {t(), iodata()}
  def take_outbound(%__MODULE__{outbound: outbound} = conn) do
    {%{conn | outbound: []}, Enum.reverse(outbound)}
  end

  defp append_buffer(%__MODULE__{buffer: buffer} = conn, data) do
    %{conn | buffer: buffer <> data}
  end

  defp parse(%__MODULE__{} = conn, events) do
    case Frame.decode(conn.buffer) do
      :more ->
        {:ok, conn, Enum.reverse(events)}

      {:ok, frame, rest} ->
        with {:ok, conn, frame_events} <- handle_frame(%{conn | buffer: rest}, frame) do
          parse(conn, append_events(events, frame_events))
        end
    end
  end

  defp append_events(events, frame_events) do
    Enum.reduce(frame_events, events, fn event, acc -> [event | acc] end)
  end

  defp handle_frame(%__MODULE__{continuation: continuation}, %Frame{type: type})
       when not is_nil(continuation) and type != :continuation do
    {:error, :expected_continuation}
  end

  defp handle_frame(conn, %Frame{type: :settings, stream_id: 0, flags: flags, payload: payload}) do
    cond do
      Frame.flag?(flags, @flag_ack) and payload != "" ->
        {:error, :invalid_settings_ack}

      Frame.flag?(flags, @flag_ack) ->
        {:ok, conn, []}

      rem(byte_size(payload), 6) != 0 ->
        {:error, :invalid_settings_frame}

      true ->
        {:ok, enqueue(conn, Frame.encode(:settings, @flag_ack, 0, "")), []}
    end
  end

  defp handle_frame(_conn, %Frame{type: :settings}), do: {:error, :invalid_settings_stream}

  defp handle_frame(conn, %Frame{type: :headers, stream_id: @client_stream_id} = frame) do
    with {:ok, fragment} <- headers_fragment(frame) do
      end_stream? = Frame.flag?(frame.flags, @flag_end_stream)

      if Frame.flag?(frame.flags, @flag_end_headers) do
        decode_response_headers(conn, fragment, end_stream?)
      else
        continuation = %{
          stream_id: frame.stream_id,
          fragments: [fragment],
          end_stream?: end_stream?
        }

        {:ok, %{conn | continuation: continuation}, []}
      end
    end
  end

  defp handle_frame(_conn, %Frame{type: :headers}), do: {:error, :invalid_headers_stream}

  defp handle_frame(
         %__MODULE__{continuation: %{stream_id: stream_id} = continuation} = conn,
         %Frame{type: :continuation, stream_id: stream_id} = frame
       ) do
    fragments = [frame.payload | continuation.fragments]

    if Frame.flag?(frame.flags, @flag_end_headers) do
      header_block = fragments |> Enum.reverse() |> IO.iodata_to_binary()

      conn
      |> Map.put(:continuation, nil)
      |> decode_response_headers(header_block, continuation.end_stream?)
    else
      {:ok, %{conn | continuation: %{continuation | fragments: fragments}}, []}
    end
  end

  defp handle_frame(_conn, %Frame{type: :continuation}), do: {:error, :unexpected_continuation}

  defp handle_frame(conn, %Frame{type: :data, stream_id: @client_stream_id} = frame) do
    with {:ok, data, flow_controlled_size} <- data_payload(frame),
         {:ok, conn} <- consume_receive_window(conn, flow_controlled_size) do
      end_stream? = Frame.flag?(frame.flags, @flag_end_stream)
      forbidden? = response_body_forbidden?(conn)
      conn = if end_stream?, do: %{conn | done?: true}, else: conn

      events =
        []
        |> maybe_body_event(data, forbidden?)
        |> maybe_done_event(end_stream?)

      {:ok, conn, events}
    end
  end

  defp handle_frame(_conn, %Frame{type: :data}), do: {:error, :invalid_data_stream}

  defp handle_frame(_conn, %Frame{
         type: :rst_stream,
         stream_id: @client_stream_id,
         payload: <<code::32>>
       }) do
    {:error, {:stream_reset, error_code(code)}}
  end

  defp handle_frame(_conn, %Frame{type: :rst_stream, stream_id: @client_stream_id}) do
    {:error, :invalid_rst_stream}
  end

  defp handle_frame(conn, %Frame{type: :rst_stream}), do: {:ok, conn, []}

  defp handle_frame(%__MODULE__{done?: true} = conn, %Frame{type: :goaway}), do: {:ok, conn, []}

  defp handle_frame(_conn, %Frame{
         type: :goaway,
         stream_id: 0,
         payload: <<_reserved::1, last_stream_id::31, code::32, debug::binary>>
       })
       when last_stream_id < @client_stream_id do
    {:error, {:goaway, error_code(code), debug}}
  end

  defp handle_frame(conn, %Frame{
         type: :goaway,
         stream_id: 0,
         payload: <<_reserved::1, _last_stream_id::31, _code::32, _debug::binary>>
       }) do
    {:ok, conn, []}
  end

  defp handle_frame(_conn, %Frame{type: :goaway}), do: {:error, :invalid_goaway}

  defp handle_frame(conn, %Frame{type: :ping, stream_id: 0, flags: flags, payload: payload})
       when byte_size(payload) == 8 do
    if Frame.flag?(flags, @flag_ack) do
      {:ok, conn, []}
    else
      {:ok, enqueue(conn, Frame.encode(:ping, @flag_ack, 0, payload)), []}
    end
  end

  defp handle_frame(_conn, %Frame{type: :ping}), do: {:error, :invalid_ping}

  defp handle_frame(_conn, %Frame{type: :window_update, payload: <<_reserved::1, 0::31>>}) do
    {:error, :invalid_window_update_increment}
  end

  defp handle_frame(conn, %Frame{type: :window_update, payload: <<_reserved::1, _increment::31>>}) do
    {:ok, conn, []}
  end

  defp handle_frame(_conn, %Frame{type: :window_update}), do: {:error, :invalid_window_update}

  defp handle_frame(conn, %Frame{}), do: {:ok, conn, []}

  defp decode_response_headers(%__MODULE__{} = conn, header_block, end_stream?) do
    with {:ok, hpack, headers} <- HPACK.decode(conn.hpack, header_block),
         {:ok, status, regular_headers} <- response_headers(headers) do
      conn = %{conn | hpack: hpack}

      if status in 100..199 do
        {:ok, conn, []}
      else
        headers = Headers.new(regular_headers)
        done? = end_stream? or HTTP.HTTP1.body_forbidden?(conn.method, status)
        conn = %{conn | status: status, done?: done?}
        events = [{:headers, status, headers}] |> maybe_done_event(done?)

        {:ok, conn, events}
      end
    end
  end

  defp response_headers(headers) do
    status = Enum.find_value(headers, fn {name, value} -> if name == ":status", do: value end)

    regular_headers =
      Enum.reject(headers, fn {name, _value} -> String.starts_with?(name, ":") end)

    with true <- is_binary(status),
         {status, ""} <- Integer.parse(status) do
      {:ok, status, regular_headers}
    else
      _ -> {:error, :invalid_response_headers}
    end
  end

  defp headers_fragment(%Frame{flags: flags, payload: payload}) do
    with {:ok, payload, pad_length} <- unpad_payload(payload, Frame.flag?(flags, @flag_padded)),
         {:ok, payload} <- drop_priority(payload, Frame.flag?(flags, @flag_priority)) do
      take_padding(payload, pad_length)
    end
  end

  defp data_payload(%Frame{flags: flags, payload: payload}) do
    with {:ok, payload, pad_length} <- unpad_payload(payload, Frame.flag?(flags, @flag_padded)) do
      with {:ok, data} <- take_padding(payload, pad_length) do
        {:ok, data, byte_size(payload) + if(Frame.flag?(flags, @flag_padded), do: 1, else: 0)}
      end
    end
  end

  defp consume_receive_window(conn, 0), do: {:ok, conn}

  defp consume_receive_window(
         %__MODULE__{
           connection_receive_window: connection_window,
           stream_receive_window: stream_window
         } = conn,
         size
       ) do
    if size > connection_window or size > stream_window do
      {:error, :flow_control_error}
    else
      conn =
        conn
        |> Map.update!(:connection_receive_window, &(&1 - size))
        |> Map.update!(:stream_receive_window, &(&1 - size))
        |> restore_receive_window(size)

      {:ok, conn}
    end
  end

  defp restore_receive_window(%__MODULE__{} = conn, size) do
    conn
    |> Map.update!(:connection_receive_window, &(&1 + size))
    |> Map.update!(:stream_receive_window, &(&1 + size))
    |> enqueue(window_update_frame(0, size))
    |> enqueue(window_update_frame(@client_stream_id, size))
  end

  defp window_update_frame(stream_id, increment) do
    Frame.encode(:window_update, 0, stream_id, <<0::1, increment::31>>)
  end

  defp unpad_payload(<<pad_length, rest::binary>>, true), do: {:ok, rest, pad_length}
  defp unpad_payload(<<>>, true), do: {:error, :invalid_padding}
  defp unpad_payload(payload, false), do: {:ok, payload, 0}

  defp take_padding(payload, 0), do: {:ok, payload}

  defp take_padding(payload, pad_length) when byte_size(payload) >= pad_length do
    body_length = byte_size(payload) - pad_length
    <<body::binary-size(body_length), _padding::binary-size(pad_length)>> = payload
    {:ok, body}
  end

  defp take_padding(_payload, _pad_length), do: {:error, :invalid_padding}

  defp drop_priority(<<_exclusive::1, _dependency::31, _weight::8, rest::binary>>, true) do
    {:ok, rest}
  end

  defp drop_priority(_payload, true), do: {:error, :invalid_priority}
  defp drop_priority(payload, false), do: {:ok, payload}

  defp maybe_body_event(events, _data, true), do: events
  defp maybe_body_event(events, "", false), do: events
  defp maybe_body_event(events, data, false), do: events ++ [{:body, data}]

  defp maybe_done_event(events, false), do: events
  defp maybe_done_event(events, true), do: events ++ [:done]

  defp response_body_forbidden?(%__MODULE__{status: nil}), do: false

  defp response_body_forbidden?(%__MODULE__{method: method, status: status}) do
    HTTP.HTTP1.body_forbidden?(method, status)
  end

  defp enqueue(%__MODULE__{outbound: outbound} = conn, iodata) do
    %{conn | outbound: [iodata | outbound]}
  end

  defp data_frames(""), do: []

  defp data_frames(body) do
    body
    |> chunk_binary(@initial_max_frame_size)
    |> Enum.with_index()
    |> Enum.map(fn {chunk, index} ->
      flags =
        if index == div(byte_size(body) - 1, @initial_max_frame_size),
          do: @flag_end_stream,
          else: 0

      Frame.encode(:data, flags, @client_stream_id, chunk)
    end)
  end

  defp chunk_binary(binary, size) when byte_size(binary) <= size, do: [binary]

  defp chunk_binary(binary, size) do
    <<chunk::binary-size(size), rest::binary>> = binary
    [chunk | chunk_binary(rest, size)]
  end

  defp pseudo_headers(%Request{} = request) do
    [
      {":method", Request.method_token(request.method)},
      {":scheme", request.url.scheme || "http"},
      {":authority", Request.authority(request.url)},
      {":path", Request.origin_form(request.url)}
    ]
  end

  defp request_headers(%Request{} = request) do
    request.headers
    |> Request.reject_unsupported_request_framing!()
    |> Headers.set_default("User-Agent", Headers.user_agent())
  end

  defp regular_headers(%Headers{} = headers) do
    headers.headers
    |> Enum.reduce([], fn {name, value}, acc ->
      name = String.downcase(to_string(name))
      value = to_string(value)

      if request_header_allowed?(name, value) do
        [{valid_header_name!(name), valid_header_value!(value)} | acc]
      else
        acc
      end
    end)
    |> Enum.reverse()
  end

  defp request_header_allowed?(name, _value)
       when name in [
              "connection",
              "host",
              "keep-alive",
              "proxy-connection",
              "transfer-encoding",
              "upgrade"
            ] do
    false
  end

  defp request_header_allowed?("te", value), do: String.downcase(String.trim(value)) == "trailers"
  defp request_header_allowed?(_name, _value), do: true

  defp valid_header_name!(name) do
    if valid_token?(name) do
      name
    else
      raise ArgumentError, "invalid HTTP header name: #{inspect(name)}"
    end
  end

  defp valid_header_value!(value) do
    if safe_header_value?(value) do
      value
    else
      raise ArgumentError, "invalid HTTP header value for wire serialization"
    end
  end

  defp valid_token?(value) when is_binary(value) do
    value != "" and Enum.all?(:binary.bin_to_list(value), &token_char?/1)
  end

  defp token_char?(char) when char in ?0..?9, do: true
  defp token_char?(char) when char in ?a..?z, do: true
  defp token_char?(char) when char in ~c"!#$%&'*+-.^_`|~", do: true
  defp token_char?(_char), do: false

  defp safe_header_value?(value) do
    value
    |> :binary.bin_to_list()
    |> Enum.all?(fn char -> char == ?\t or (char >= 32 and char != 127) end)
  end

  defp error_code(0x0), do: :no_error
  defp error_code(0x1), do: :protocol_error
  defp error_code(0x2), do: :internal_error
  defp error_code(0x3), do: :flow_control_error
  defp error_code(0x4), do: :settings_timeout
  defp error_code(0x5), do: :stream_closed
  defp error_code(0x6), do: :frame_size_error
  defp error_code(0x7), do: :refused_stream
  defp error_code(0x8), do: :cancel
  defp error_code(0x9), do: :compression_error
  defp error_code(0xA), do: :connect_error
  defp error_code(0xB), do: :enhance_your_calm
  defp error_code(0xC), do: :inadequate_security
  defp error_code(0xD), do: :http_1_1_required
  defp error_code(code), do: {:unknown_error, code}
end
