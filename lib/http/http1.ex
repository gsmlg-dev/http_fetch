defmodule HTTP.HTTP1 do
  @moduledoc false

  alias HTTP.Headers
  alias HTTP.Request

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
    method = request.method |> to_string() |> String.upcase()
    target = request_target(request.url)

    {headers, body} = request |> request_headers() |> add_body_headers(request)
    header_lines = Enum.map(headers.headers, fn {name, value} -> [name, ": ", value, "\r\n"] end)

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
        head = binary_part(buffer, 0, index)
        body = binary_part(buffer, index + 4, byte_size(buffer) - index - 4)

        with {:ok, status, headers} <- parse_head(head) do
          conn =
            conn
            |> Map.merge(%{status: status, headers: headers, buffer: body})
            |> set_body_framing()

          events = [{:headers, status, headers} | events]
          parse(conn, maybe_done_event(conn, events))
        end

      :nomatch ->
        {:ok, conn, Enum.reverse(events)}
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
    end
  end

  defp parse(%__MODULE__{state: :chunk_data, buffer: buffer, chunk_size: size} = conn, events) do
    needed = size + 2

    if byte_size(buffer) < needed do
      {:ok, conn, Enum.reverse(events)}
    else
      case buffer do
        <<chunk::binary-size(size), "\r\n", rest::binary>> ->
          conn = %{conn | state: :chunk_size, buffer: rest, chunk_size: nil}
          parse(conn, [{:body, chunk} | events])

        _ ->
          {:error, :invalid_chunk}
      end
    end
  end

  defp parse(%__MODULE__{state: :chunk_trailers, buffer: buffer} = conn, events) do
    cond do
      String.starts_with?(buffer, "\r\n") ->
        rest = binary_part(buffer, 2, byte_size(buffer) - 2)
        parse(%{conn | state: :done, buffer: rest}, [:done | events])

      match = :binary.match(buffer, "\r\n\r\n") ->
        {index, 4} = match
        rest = binary_part(buffer, index + 4, byte_size(buffer) - index - 4)
        parse(%{conn | state: :done, buffer: rest}, [:done | events])

      true ->
        {:ok, conn, Enum.reverse(events)}
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
    content_length = Headers.get(conn.headers, "content-length")

    cond do
      body_forbidden?(conn.method, conn.status) ->
        %{conn | state: :done, remaining: 0}

      chunked?(transfer_encoding) ->
        %{conn | state: :chunk_size}

      is_binary(content_length) ->
        set_content_length_framing(conn, content_length)

      true ->
        %{conn | state: :body_eof}
    end
  end

  defp set_content_length_framing(conn, content_length) do
    case Integer.parse(content_length) do
      {0, ""} -> %{conn | state: :done, remaining: 0}
      {length, ""} when length > 0 -> %{conn | state: :content_length, remaining: length}
      _ -> %{conn | state: :done, remaining: 0}
    end
  end

  defp maybe_done_event(%__MODULE__{state: :done}, events), do: [:done | events]
  defp maybe_done_event(_conn, events), do: events

  defp body_forbidden?(:head, _status), do: true
  defp body_forbidden?(_method, status) when status in 100..199, do: true
  defp body_forbidden?(_method, status) when status in [204, 304], do: true
  defp body_forbidden?(_, _), do: false

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
        :more
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
    |> ensure_user_agent()
    |> Headers.set_default("Host", host_header(request.url))
    |> Headers.set("Connection", "close")
  end

  defp add_body_headers(headers, %Request{} = request) do
    case request_body(request) do
      nil ->
        {headers, ""}

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

  defp maybe_set_content_type(headers, content_type) do
    Headers.set_default(headers, "Content-Type", content_type)
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
      path <> "?" <> uri.query
    else
      path
    end
  end

  defp host_header(%URI{} = uri) do
    host = uri.host || "localhost"

    host =
      if String.contains?(host, ":") and !String.starts_with?(host, "["),
        do: "[#{host}]",
        else: host

    if uri.port && uri.port != default_port(uri.scheme) do
      host <> ":" <> to_string(uri.port)
    else
      host
    end
  end

  defp default_port("https"), do: 443
  defp default_port(_), do: 80
end
