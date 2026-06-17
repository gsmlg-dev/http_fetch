defmodule HTTP.HTTP1 do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.Request

  @allowed_methods ~w(DELETE GET HEAD OPTIONS PATCH POST PUT)
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
    method = method_token(request.method)
    target = request_target(request.url)

    {headers, body} = request |> request_headers() |> add_body_headers(request)
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
        with {:ok, status} <- parse_status_line(status_line) do
          {:ok, status, parse_headers(header_lines)}
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
    |> Enum.flat_map(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] -> [{String.trim(name), String.trim(value)}]
        _ -> []
      end
    end)
    |> Headers.new()
  end

  defp set_body_framing(%__MODULE__{} = conn) do
    transfer_encoding = Headers.get(conn.headers, "transfer-encoding")
    content_lengths = Headers.get_all(conn.headers, "content-length")

    cond do
      HTTP.HTTP1.body_forbidden?(conn.method, conn.status) ->
        {:ok, %{conn | state: :done, remaining: 0}}

      chunked?(transfer_encoding) ->
        {:ok, %{conn | state: :chunk_size}}

      content_lengths != [] ->
        with {:ok, length} <- parse_content_lengths(content_lengths) do
          {:ok, set_content_length_framing(conn, length)}
        end

      true ->
        {:ok, %{conn | state: :body_eof}}
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

  defp chunked?(nil), do: false

  defp chunked?(transfer_encoding) do
    transfer_encoding
    |> String.downcase()
    |> String.split(",")
    |> Enum.any?(&(String.trim(&1) == "chunked"))
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
    |> reject_unsupported_request_framing!()
    |> ensure_user_agent()
    |> Headers.set_default("Host", host_header(request.url))
    |> Headers.set("Connection", "close")
  end

  defp add_body_headers(headers, %Request{} = request) do
    case request_body(request) do
      nil ->
        {Headers.delete(headers, "Content-Length"), ""}

      {body, content_type} ->
        headers =
          headers
          |> Headers.set(
            "Content-Length",
            body |> IO.iodata_to_binary() |> byte_size() |> to_string()
          )
          |> maybe_set_content_type(content_type)

        {headers, body}
    end
  end

  defp request_body(%Request{body: nil}), do: nil
  defp request_body(%Request{method: method}) when method in [:get, :head, :delete], do: nil

  defp request_body(%Request{body: %HTTP.FormData{} = form_data}) do
    case HTTP.FormData.to_body(form_data) do
      {:url_encoded, body} ->
        {body, "application/x-www-form-urlencoded"}

      {:multipart, body, boundary} ->
        body = IO.iodata_to_binary(body)
        {body, "multipart/form-data; boundary=#{boundary}"}
    end
  end

  defp request_body(%Request{body: body, content_type: content_type}) do
    {to_body(body), content_type || "application/octet-stream"}
  end

  defp to_body(body) when is_binary(body), do: body
  defp to_body(body) when is_list(body), do: IO.iodata_to_binary(body)
  defp to_body(body), do: to_string(body)

  defp maybe_set_content_type(headers, nil), do: headers

  defp maybe_set_content_type(headers, content_type) when is_list(content_type) do
    maybe_set_content_type(headers, to_string(content_type))
  end

  defp maybe_set_content_type(headers, content_type) do
    Headers.set_default(headers, "Content-Type", to_string(content_type))
  end

  defp ensure_user_agent(headers) do
    Headers.set_default(headers, "User-Agent", Headers.user_agent())
  end

  defp request_target(%URI{} = uri) do
    path =
      case uri.path do
        nil -> "/"
        "" -> "/"
        path -> path
      end

    if uri.query && uri.query != "" do
      valid_request_target!(path <> "?" <> uri.query)
    else
      valid_request_target!(path)
    end
  end

  defp method_token(method) do
    method = method |> to_string() |> String.upcase()

    if method in @allowed_methods and valid_token?(method) do
      method
    else
      raise ArgumentError, "unsupported HTTP method: #{inspect(method)}"
    end
  end

  defp header_line(name, value) do
    name = valid_header_name!(to_string(name))
    value = valid_header_value!(to_string(value))

    [name, ": ", value, "\r\n"]
  end

  defp valid_request_target!(target) do
    if safe_request_target?(target) do
      target
    else
      raise ArgumentError, "request target contains invalid whitespace or control characters"
    end
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

  defp safe_request_target?(target) do
    target
    |> :binary.bin_to_list()
    |> Enum.all?(fn char -> char > 32 and char != 127 end)
  end

  defp digits_only?(value) do
    value != "" and Enum.all?(:binary.bin_to_list(value), &(&1 in ?0..?9))
  end

  defp reject_unsupported_request_framing!(headers) do
    cond do
      Headers.has?(headers, "Transfer-Encoding") ->
        raise ArgumentError, "Transfer-Encoding request headers are not supported"

      Headers.has?(headers, "Trailer") ->
        raise ArgumentError, "Trailer request headers are not supported"

      true ->
        headers
    end
  end

  defp host_header(%URI{} = uri) do
    host = uri.host || "localhost"

    host =
      if String.contains?(host, ":") and !String.starts_with?(host, "["),
        do: "[#{host}]",
        else: host

    if uri.port && uri.port != HTTP.HTTP1.default_port(uri.scheme) do
      host <> ":" <> to_string(uri.port)
    else
      host
    end
  end

  @doc false
  @spec default_port(String.t() | nil) :: 80 | 443
  def default_port("https"), do: 443
  def default_port(_), do: 80
end
