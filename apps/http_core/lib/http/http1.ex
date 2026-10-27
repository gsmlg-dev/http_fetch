defmodule HTTP.HTTP1 do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.Request

  @max_line_bytes 8 * 1024
  @max_chunk_emit_bytes 64 * 1024

  defstruct method: :get,
            state: :head,
            version: nil,
            buffer: <<>>,
            status: nil,
            headers: %Headers{},
            remaining: nil,
            chunk_size: nil,
            response_header_limits: nil,
            informational_count: 0,
            informational_bytes: 0

  @type event ::
          {:headers, non_neg_integer(), Headers.t()}
          | {:body, binary()}
          | {:trailers, Headers.t()}
          | :done
  @type t :: %__MODULE__{}

  @spec new(atom()) :: t()
  def new(method, limits \\ nil),
    do: %__MODULE__{
      method: method,
      response_header_limits: HTTP.ResponseHeaderLimits.normalize(limits)
    }

  @spec serialize_request(Request.t()) :: iolist()
  def serialize_request(%Request{} = request) do
    {head, body} = prepare_request(request)

    case body do
      {:stream, _stream} ->
        raise ArgumentError, "streaming request bodies require HTTP.SocketClient"

      body ->
        [head, body]
    end
  end

  @spec prepare_request(Request.t()) :: {iolist(), iodata() | {:stream, pid()}}
  def prepare_request(%Request{} = request) do
    method = Request.method_token(request.method)
    target = HTTP.Proxy.target(request)

    {headers, body} = request |> request_headers() |> Request.put_body_headers(request)
    validate_request_trailers!(request, headers)
    header_lines = Enum.map(headers.headers, fn {name, value} -> header_line(name, value) end)

    {[method, " ", target, " HTTP/1.1\r\n", header_lines, "\r\n"], body}
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
        head = binary_part(buffer, 0, index)
        body = binary_part(buffer, index + 4, byte_size(buffer) - index - 4)

        with :ok <-
               HTTP.ResponseHeaderLimits.check(
                 conn.response_header_limits,
                 buffer,
                 :response,
                 index
               ),
             {:ok, status, headers, version} <- parse_head(head),
             :ok <- validate_response_framing(conn.method, status, headers),
             {:ok, conn} <- record_informational(conn, status, index + 4) do
          parse_head_response(%{conn | version: version}, status, headers, body, events)
        end

      :nomatch ->
        with :ok <-
               HTTP.ResponseHeaderLimits.check(conn.response_header_limits, buffer, :response),
             do: {:ok, conn, Enum.reverse(events)}
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
    <<chunk::binary-size(^take_size), rest::binary>> = buffer
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
    <<chunk::binary-size(^take_size), rest::binary>> = buffer

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
    case trailer_end(buffer, conn.headers) do
      {:ok, trailers, rest} ->
        events = if trailers.headers == [], do: events, else: [{:trailers, trailers} | events]
        parse(%{conn | state: :done, buffer: rest}, [:done | events])

      :more ->
        {:ok, conn, Enum.reverse(events)}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp record_informational(conn, status, size) when status in 100..199 do
    count = conn.informational_count + 1
    bytes = conn.informational_bytes + size

    with :ok <-
           HTTP.ResponseHeaderLimits.informational(
             conn.response_header_limits,
             :response,
             count,
             bytes
           ),
         do: {:ok, %{conn | informational_count: count, informational_bytes: bytes}}
  end

  defp record_informational(conn, _status, _size), do: {:ok, conn}

  defp parse_head_response(_conn, 101, _headers, _body, _events) do
    {:error, :unsupported_protocol_switch}
  end

  defp parse_head_response(conn, status, _headers, body, events) when status in 100..199 do
    parse(%{conn | state: :head, buffer: body, status: nil, headers: %Headers{}}, events)
  end

  defp parse_head_response(conn, status, headers, body, events) do
    conn = Map.merge(conn, %{status: status, headers: headers, buffer: body})

    with {:ok, _names} <- HTTP.Trailers.declaration(headers),
         {:ok, conn} <- set_body_framing(conn) do
      events = [{:headers, status, headers} | events]
      parse(conn, maybe_done_event(conn, events))
    end
  end

  defp parse_head(head) do
    case String.split(head, "\r\n") do
      [status_line | header_lines] ->
        with {:ok, status, version} <- parse_status_line(status_line),
             {:ok, headers} <- parse_headers(header_lines) do
          {:ok, status, headers, version}
        end

      _ ->
        {:error, :invalid_http_response}
    end
  end

  defp parse_status_line(<<"HTTP/", major, ?., minor, ?\s, a, b, c, ?\s, reason::binary>>)
       when major == ?1 and minor in ?0..?9 and a in ?1..?5 and b in ?0..?9 and
              c in ?0..?9 do
    if safe_header_value?(reason) do
      {:ok, (a - ?0) * 100 + (b - ?0) * 10 + c - ?0, <<major, ?., minor>>}
    else
      {:error, :invalid_status_line}
    end
  end

  defp parse_status_line(_line), do: {:error, :invalid_status_line}

  defp validate_response_framing(method, status, headers) do
    if Headers.has?(headers, "transfer-encoding") and Headers.has?(headers, "content-length") do
      if body_forbidden?(method, status) do
        {:error, :conflicting_response_framing}
      else
        case response_body_framing(headers) do
          {:error, reason} -> {:error, reason}
          _ -> {:error, :conflicting_response_framing}
        end
      end
    else
      :ok
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
          set_identity_body_framing(conn, content_lengths)

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  defp set_identity_body_framing(conn, content_lengths) do
    if content_lengths != [] do
      with {:ok, length} <- parse_content_lengths(content_lengths) do
        {:ok, set_content_length_framing(conn, length)}
      end
    else
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

  @doc false
  @spec response_body_framing(Headers.t()) ::
          :identity
          | :chunked
          | {:error, :conflicting_response_framing}
          | {:error, :invalid_transfer_encoding}
          | {:error, {:unsupported_transfer_encoding, [String.t()]}}
  def response_body_framing(%Headers{} = headers) do
    case transfer_codings(headers) do
      [] ->
        :identity

      ["chunked"] ->
        if Headers.has?(headers, "content-length"),
          do: {:error, :conflicting_response_framing},
          else: :chunked

      {:error, reason} ->
        {:error, reason}

      codings ->
        {:error, {:unsupported_transfer_encoding, codings}}
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
      {index, 2} when index > @max_line_bytes ->
        {:error, :line_too_long}

      {index, 2} ->
        line = binary_part(buffer, 0, index)
        rest = binary_part(buffer, index + 2, byte_size(buffer) - index - 2)
        {:ok, line, rest}

      :nomatch ->
        partial_terminator? =
          byte_size(buffer) == @max_line_bytes + 1 and :binary.last(buffer) == ?\r

        if byte_size(buffer) > @max_line_bytes and not partial_terminator? do
          {:error, :line_too_long}
        else
          :more
        end
    end
  end

  defp trailer_end(buffer, initial) do
    if String.starts_with?(buffer, "\r\n") do
      {:ok, %Headers{}, binary_part(buffer, 2, byte_size(buffer) - 2)}
    else
      case :binary.match(buffer, "\r\n\r\n") do
        {index, 4} ->
          block = binary_part(buffer, 0, index)

          with {:ok, trailers} <- HTTP.Trailers.parse(block, initial) do
            {:ok, trailers, binary_part(buffer, index + 4, byte_size(buffer) - index - 4)}
          end

        :nomatch when byte_size(buffer) > 65_536 ->
          {:error, :trailers_too_large}

        :nomatch ->
          :more
      end
    end
  end

  defp parse_chunk_size(<<first, _::binary>> = line)
       when first in ?0..?9 or first in ?a..?f or first in ?A..?F do
    {size, extensions} = Integer.parse(line, 16)

    if valid_chunk_extensions?(extensions) do
      {:ok, size}
    else
      {:error, :invalid_chunk_size}
    end
  end

  defp parse_chunk_size(_line), do: {:error, :invalid_chunk_size}

  defp valid_chunk_extensions?(<<>>), do: true

  defp valid_chunk_extensions?(extensions) do
    with <<";", rest::binary>> <- skip_bws(extensions),
         {:ok, rest} <- take_chunk_token(skip_bws(rest)),
         {:ok, rest} <- chunk_extension_value(rest) do
      valid_chunk_extensions?(rest)
    else
      _ -> false
    end
  end

  defp chunk_extension_value(rest) do
    case skip_bws(rest) do
      <<"=", value::binary>> -> take_chunk_value(skip_bws(value))
      _ -> {:ok, rest}
    end
  end

  defp take_chunk_value(<<"\"", rest::binary>>), do: take_chunk_quoted(rest)
  defp take_chunk_value(rest), do: take_chunk_token(rest)

  defp take_chunk_token(<<char, rest::binary>>) do
    if token_char?(char), do: {:ok, take_chunk_token_tail(rest)}, else: :error
  end

  defp take_chunk_token(<<>>), do: :error

  defp take_chunk_token_tail(<<char, rest::binary>> = token) do
    if token_char?(char), do: take_chunk_token_tail(rest), else: token
  end

  defp take_chunk_token_tail(<<>>), do: <<>>

  defp take_chunk_quoted(<<"\"", rest::binary>>), do: {:ok, rest}

  defp take_chunk_quoted(<<"\\", char, rest::binary>>)
       when char == ?\t or (char >= 32 and char != 127),
       do: take_chunk_quoted(rest)

  defp take_chunk_quoted(<<char, rest::binary>>)
       when char in [9, 32, 33] or char in 35..91 or char in 93..126 or char >= 128,
       do: take_chunk_quoted(rest)

  defp take_chunk_quoted(_rest), do: :error

  defp skip_bws(<<char, rest::binary>>) when char in [?\s, ?\t], do: skip_bws(rest)
  defp skip_bws(rest), do: rest

  defp request_headers(%Request{} = request) do
    %{request | headers: HTTP.Proxy.request_headers(request)}
    |> validate_request_framing!()
    |> ensure_user_agent()
    |> Headers.set_default("Host", Request.authority(request.url))
    |> Headers.set(
      "Connection",
      if(Keyword.get(request.transport_options, :http1_reuse, false),
        do: "keep-alive",
        else: "close"
      )
    )
  end

  defp validate_request_framing!(%Request{request_mode: :proxy, headers: headers} = request) do
    case Headers.get_all(headers, "Transfer-Encoding") do
      [] ->
        validate_request_framing!(%{request | request_mode: :fetch})

      [encoding] ->
        unless String.downcase(String.trim(encoding)) == "chunked" and
                 Request.streaming_body?(request) and not Headers.has?(headers, "Content-Length") do
          raise ArgumentError,
                "proxy Transfer-Encoding requires chunked streaming without Content-Length"
        end

        headers

      _ ->
        raise ArgumentError, "conflicting proxy Transfer-Encoding request headers"
    end
  end

  defp validate_request_framing!(%Request{headers: headers}) do
    _ = headers |> Headers.delete("Trailer") |> Request.reject_unsupported_request_framing!()
    headers
  end

  defp validate_request_trailers!(request, headers) do
    if Headers.has?(headers, "trailer") do
      unless Request.streaming_body?(request) and not Headers.has?(headers, "content-length") do
        raise ArgumentError, "Trailer request headers require a chunked HTTP/1 streaming body"
      end

      case HTTP.Trailers.declaration(request.headers) do
        {:ok, _names} ->
          :ok

        {:error, reason} ->
          raise ArgumentError, "invalid Trailer request declaration: #{inspect(reason)}"
      end
    end
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
