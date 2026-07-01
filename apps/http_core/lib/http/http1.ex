defmodule HTTP.HTTP1 do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.Request

  @max_head_bytes 64 * 1024
  @max_trailer_bytes 64 * 1024
  @max_line_bytes 8 * 1024
  @max_chunk_emit_bytes 64 * 1024

  defstruct method: :get,
            state: :head,
            buffer: <<>>,
            status: nil,
            headers: %Headers{},
            remaining: nil,
            chunk_size: nil

  @type event :: {:headers, non_neg_integer(), Headers.t()} | {:body, binary()} | :done
  @type t :: %__MODULE__{}

  @spec new(atom()) :: t()
  def new(method), do: %__MODULE__{method: method}

  @spec serialize_request(Request.t()) :: iolist()
  def serialize_request(%Request{} = request) do
    method = Request.method_token(request.method)
    target = Request.origin_form(request.url)

    {headers, body} = request |> request_headers() |> Request.put_body_headers(request)
    header_lines = Enum.map(headers.headers, fn {name, value} -> header_line(name, value) end)

    [method, " ", target, " HTTP/1.1\r\n", header_lines, "\r\n", body]
  end

  @spec stream(t(), binary()) :: {:ok, t(), [event()]} | {:error, term()}
  def stream(%__MODULE__{} = conn, data) when is_binary(data) do
    conn
    |> append_buffer(data)
    |> parse([])
  end

  @spec close(t()) :: {:ok, t(), [event()]} | {:error, term()}
  def close(%__MODULE__{state: :done} = conn), do: {:ok, conn, []}

  def close(%__MODULE__{state: :body_eof, buffer: buffer} = conn) do
    events =
      if byte_size(buffer) > 0 do
        [{:body, buffer}, :done]
      else
        [:done]
      end

    {:ok, %{conn | state: :done, buffer: <<>>}, events}
  end

  def close(%__MODULE__{state: :content_length, remaining: 0} = conn) do
    {:ok, %{conn | state: :done}, [:done]}
  end

  def close(%__MODULE__{state: :head, buffer: <<>>}), do: {:error, :closed}
  def close(_conn), do: {:error, :closed}

  defp append_buffer(%__MODULE__{buffer: buffer} = conn, data) do
    %{conn | buffer: buffer <> data}
  end

  defp parse(%__MODULE__{state: :done} = conn, events), do: {:ok, conn, Enum.reverse(events)}

  defp parse(%__MODULE__{state: :head, buffer: buffer} = conn, events) do
    case :binary.match(buffer, "\r\n\r\n") do
      {index, 4} ->
        if index > @max_head_bytes do
          {:error, :headers_too_large}
        else
          head = binary_part(buffer, 0, index)
          body = binary_part(buffer, index + 4, byte_size(buffer) - index - 4)

          with {:ok, status, headers} <- parse_head(head) do
            parse_head_response(conn, status, headers, body, events)
          end
        end

      :nomatch ->
        if byte_size(buffer) > @max_head_bytes do
          {:error, :headers_too_large}
        else
          {:ok, conn, Enum.reverse(events)}
        end
    end
  end

  defp parse(%__MODULE__{state: :content_length, buffer: <<>>} = conn, events) do
    {:ok, conn, Enum.reverse(events)}
  end

  defp parse(
         %__MODULE__{state: :content_length, buffer: buffer, remaining: remaining} = conn,
         events
       ) do
    take_size = min(byte_size(buffer), remaining)
    <<chunk::binary-size(take_size), rest::binary>> = buffer
    remaining = remaining - take_size

    conn = %{conn | buffer: rest, remaining: remaining}
    events = if take_size > 0, do: [{:body, chunk} | events], else: events

    if remaining == 0 do
      parse(%{conn | state: :done}, [:done | events])
    else
      {:ok, conn, Enum.reverse(events)}
    end
  end

  defp parse(%__MODULE__{state: :body_eof, buffer: <<>>} = conn, events) do
    {:ok, conn, Enum.reverse(events)}
  end

  defp parse(%__MODULE__{state: :body_eof, buffer: buffer} = conn, events) do
    {:ok, %{conn | buffer: <<>>}, Enum.reverse([{:body, buffer} | events])}
  end

  defp parse(%__MODULE__{state: :chunk_size, buffer: buffer} = conn, events) do
    case read_line(buffer) do
      {:ok, line, rest} ->
        case parse_chunk_size(line) do
          {:ok, 0} ->
            parse(%{conn | state: :chunk_trailers, buffer: rest}, events)

          {:ok, size} ->
            parse(%{conn | state: :chunk_data, buffer: rest, chunk_size: size}, events)

          {:error, reason} ->
            {:error, reason}
        end

      :more ->
        {:ok, conn, Enum.reverse(events)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse(%__MODULE__{state: :chunk_data, buffer: <<>>} = conn, events) do
    {:ok, conn, Enum.reverse(events)}
  end

  defp parse(%__MODULE__{state: :chunk_data, buffer: buffer, chunk_size: size} = conn, events) do
    take_size = min(min(byte_size(buffer), size), @max_chunk_emit_bytes)
    <<chunk::binary-size(take_size), rest::binary>> = buffer

    conn = %{conn | buffer: rest, chunk_size: size - take_size}
    events = if take_size > 0, do: [{:body, chunk} | events], else: events

    cond do
      conn.chunk_size == 0 ->
        parse(%{conn | state: :chunk_crlf, chunk_size: nil}, events)

      byte_size(conn.buffer) > 0 ->
        parse(conn, events)

      true ->
        {:ok, conn, Enum.reverse(events)}
    end
  end

  defp parse(%__MODULE__{state: :chunk_crlf, buffer: buffer} = conn, events) do
    case buffer do
      <<"\r\n", rest::binary>> ->
        parse(%{conn | state: :chunk_size, buffer: rest}, events)

      <<>> ->
        {:ok, conn, Enum.reverse(events)}

      <<"\r">> ->
        {:ok, conn, Enum.reverse(events)}

      _ ->
        {:error, :invalid_chunk}
    end
  end

  defp parse(%__MODULE__{state: :chunk_trailers, buffer: buffer} = conn, events) do
    case trailer_end(buffer) do
      {:ok, rest} ->
        parse(%{conn | state: :done, buffer: rest}, [:done | events])

      :more ->
        {:ok, conn, Enum.reverse(events)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_head_response(_conn, 101, _headers, _body, _events) do
    {:error, :unsupported_protocol_switch}
  end

  defp parse_head_response(conn, status, _headers, body, events) when status in 100..199 do
    parse(%{conn | state: :head, buffer: body, status: nil, headers: %Headers{}}, events)
  end

  defp parse_head_response(conn, status, headers, body, events) do
    conn = Map.merge(conn, %{status: status, headers: headers, buffer: body})

    with {:ok, conn} <- set_body_framing(conn) do
      events = [{:headers, status, headers} | events]
      parse(conn, maybe_done_event(conn, events))
    end
  end

  defp parse_head(head) do
    case String.split(head, "\r\n") do
      [status_line | header_lines] ->
        with {:ok, status} <- parse_status_line(status_line),
             {:ok, headers} <- parse_headers(header_lines) do
          {:ok, status, headers}
        end

      _ ->
        {:error, :invalid_http_response}
    end
  end

  defp parse_status_line(line) do
    case String.split(line, " ", parts: 3) do
      ["HTTP/" <> _version, status_code | _] ->
        case Integer.parse(status_code) do
          {status, ""} -> {:ok, status}
          _ -> {:error, :invalid_status_line}
        end

      _ ->
        {:error, :invalid_status_line}
    end
  end

  defp parse_headers(lines) do
    lines
    |> Enum.reduce_while({:ok, []}, fn line, {:ok, acc} ->
      case String.split(line, ":", parts: 2) do
        [name, value] ->
          name = String.trim(name)

          if name == "" do
            {:halt, {:error, :invalid_header}}
          else
            {:cont, {:ok, [{name, String.trim(value)} | acc]}}
          end

        _ ->
          {:halt, {:error, :invalid_header}}
      end
    end)
    |> case do
      {:ok, headers} -> {:ok, headers |> Enum.reverse() |> Headers.new()}
      {:error, reason} -> {:error, reason}
    end
  end

  defp set_body_framing(%__MODULE__{} = conn) do
    content_lengths = Headers.get_all(conn.headers, "content-length")

    if HTTP.HTTP1.body_forbidden?(conn.method, conn.status) do
      {:ok, %{conn | state: :done, remaining: 0}}
    else
      case response_body_framing(conn.headers) do
        :chunked ->
          {:ok, %{conn | state: :chunk_size}}

        :identity ->
          if content_lengths != [] do
            with {:ok, length} <- parse_content_lengths(content_lengths) do
              {:ok, set_content_length_framing(conn, length)}
            end
          else
            {:ok, %{conn | state: :body_eof}}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp parse_content_lengths(values) do
    lengths = Enum.map(values, &String.trim/1)

    if lengths == [] or Enum.any?(lengths, &invalid_content_length_value?/1) do
      {:error, :invalid_content_length}
    else
      lengths
      |> Enum.reduce_while({:ok, []}, fn value, {:ok, acc} ->
        case parse_content_length(value) do
          {:ok, length} -> {:cont, {:ok, [length | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
      |> case do
        {:ok, parsed_lengths} ->
          case Enum.uniq(parsed_lengths) do
            [length] -> {:ok, length}
            _ -> {:error, :invalid_content_length}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp invalid_content_length_value?(value), do: value == "" or String.contains?(value, ",")

  defp parse_content_length(value) do
    if digits_only?(value) do
      {:ok, String.to_integer(value)}
    else
      {:error, :invalid_content_length}
    end
  end

  defp set_content_length_framing(conn, 0), do: %{conn | state: :done, remaining: 0}

  defp set_content_length_framing(conn, length) when length > 0,
    do: %{conn | state: :content_length, remaining: length}

  defp maybe_done_event(%__MODULE__{state: :done}, events), do: [:done | events]
  defp maybe_done_event(_conn, events), do: events

  @doc false
  @spec body_forbidden?(atom(), non_neg_integer()) :: boolean()
  def body_forbidden?(:head, _status), do: true
  def body_forbidden?(_method, status) when status in 100..199, do: true
  def body_forbidden?(_method, status) when status in [204, 304], do: true
  def body_forbidden?(_, _), do: false

  @doc false
  @spec response_body_framing(Headers.t()) ::
          :identity
          | :chunked
          | {:error, :invalid_transfer_encoding}
          | {:error, {:unsupported_transfer_encoding, [String.t()]}}
  def response_body_framing(%Headers{} = headers) do
    case transfer_codings(headers) do
      [] -> :identity
      ["chunked"] -> :chunked
      {:error, reason} -> {:error, reason}
      codings -> {:error, {:unsupported_transfer_encoding, codings}}
    end
  end

  defp transfer_codings(headers) do
    case Headers.get_all(headers, "transfer-encoding") do
      [] ->
        []

      values ->
        codings =
          values
          |> Enum.flat_map(&String.split(&1, ","))
          |> Enum.map(&(&1 |> String.trim() |> String.downcase()))

        if Enum.any?(codings, &(&1 == "")) do
          {:error, :invalid_transfer_encoding}
        else
          codings
        end
    end
  end

  defp read_line(buffer) do
    case :binary.match(buffer, "\r\n") do
      {index, 2} ->
        line = binary_part(buffer, 0, index)
        rest = binary_part(buffer, index + 2, byte_size(buffer) - index - 2)
        {:ok, line, rest}

      :nomatch ->
        if byte_size(buffer) > @max_line_bytes do
          {:error, :line_too_long}
        else
          :more
        end
    end
  end

  defp trailer_end(buffer) do
    cond do
      String.starts_with?(buffer, "\r\n") ->
        {:ok, binary_part(buffer, 2, byte_size(buffer) - 2)}

      byte_size(buffer) > @max_trailer_bytes ->
        {:error, :trailers_too_large}

      true ->
        case :binary.match(buffer, "\r\n\r\n") do
          {index, 4} ->
            {:ok, binary_part(buffer, index + 4, byte_size(buffer) - index - 4)}

          :nomatch ->
            :more
        end
    end
  end

  defp parse_chunk_size(line) do
    chunk_size =
      line
      |> String.split(";", parts: 2)
      |> hd()
      |> String.trim()

    case Integer.parse(chunk_size, 16) do
      {size, ""} when size >= 0 -> {:ok, size}
      _ -> {:error, :invalid_chunk_size}
    end
  end

  defp request_headers(%Request{} = request) do
    request.headers
    |> Request.reject_unsupported_request_framing!()
    |> ensure_user_agent()
    |> Headers.set_default("Host", Request.authority(request.url))
    |> Headers.set("Connection", "close")
  end

  defp ensure_user_agent(headers) do
    Headers.set_default(headers, "User-Agent", Headers.user_agent())
  end

  defp header_line(name, value) do
    name = valid_header_name!(to_string(name))
    value = valid_header_value!(to_string(value))

    [name, ": ", value, "\r\n"]
  end

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
  defp token_char?(char) when char in ?A..?Z, do: true
  defp token_char?(char) when char in ?a..?z, do: true
  defp token_char?(char) when char in ~c"!#$%&'*+-.^_`|~", do: true
  defp token_char?(_char), do: false

  defp safe_header_value?(value) do
    value
    |> :binary.bin_to_list()
    |> Enum.all?(fn char -> char == ?\t or (char >= 32 and char != 127) end)
  end

  defp digits_only?(value) do
    value != "" and Enum.all?(:binary.bin_to_list(value), &(&1 in ?0..?9))
  end

  @doc false
  @spec default_port(String.t() | nil) :: 80 | 443
  defdelegate default_port(scheme), to: Request
end
