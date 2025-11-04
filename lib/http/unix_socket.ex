defmodule HTTP.UnixSocket do
  @moduledoc """
  Unix Domain Socket support for HTTP requests.

  This module provides HTTP communication over Unix Domain Sockets (UDS),
  commonly used for local inter-process communication with services like
  Docker daemon, systemd, and other local services.

  ## Usage

      # Connect to Docker daemon
      HTTP.fetch("http://localhost/version", unix_socket: "/var/run/docker.sock")

      # Connect to any Unix socket service
      HTTP.fetch("http://localhost/status", unix_socket: "/tmp/my-service.sock")

  ## Implementation Notes

  - Uses `:gen_tcp` with `{:local, path}` for Unix socket connections
  - Manually constructs HTTP/1.1 requests
  - Parses HTTP responses to create `HTTP.Response` structs
  - Supports all standard HTTP methods (GET, POST, PUT, DELETE, PATCH, HEAD)
  - Handles chunked transfer encoding
  - Compatible with existing `HTTP.Response` API (json/1, text/1, etc.)

  ## Limitations

  - Does not support streaming responses (buffers entire response)
  - Does not support HTTPS over Unix sockets (not applicable)
  - Request/response timeout is fixed at 30 seconds
  """

  alias HTTP.Request
  alias HTTP.Response
  alias HTTP.Headers

  @default_timeout 30_000
  @recv_timeout 30_000

  @doc """
  Executes an HTTP request over a Unix Domain Socket.

  ## Parameters

  - `socket_path` - Path to the Unix socket file
  - `request` - `HTTP.Request` struct with method, url, headers, and body
  - `timeout` - Optional timeout in milliseconds (default: 30000)

  ## Returns

  - `{:ok, %HTTP.Response{}}` on success
  - `{:error, reason}` on failure
  """
  @spec request(String.t(), Request.t(), integer()) :: {:ok, Response.t()} | {:error, term()}
  def request(socket_path, %Request{} = request, timeout \\ @default_timeout) do
    with {:ok, socket} <- connect(socket_path, timeout),
         :ok <- send_request(socket, request),
         {:ok, response} <- receive_response(socket, request.url) do
      :gen_tcp.close(socket)
      {:ok, response}
    else
      error ->
        error
    end
  end

  # Connect to Unix Domain Socket
  @spec connect(String.t(), integer()) :: {:ok, :gen_tcp.socket()} | {:error, term()}
  defp connect(socket_path, timeout) do
    # Convert string path to charlist for Erlang
    socket_charlist = String.to_charlist(socket_path)

    # Connect using gen_tcp with local (Unix socket) address family
    # :binary - receive data as binary
    # packet: :raw - no packet framing
    # active: false - use passive mode for blocking receives
    :gen_tcp.connect({:local, socket_charlist}, 0, [
      :binary,
      packet: :raw,
      active: false
    ], timeout)
  end

  # Send HTTP request over socket
  @spec send_request(:gen_tcp.socket(), Request.t()) :: :ok | {:error, term()}
  defp send_request(socket, %Request{} = request) do
    http_request = build_http_request(request)
    :gen_tcp.send(socket, http_request)
  end

  # Build HTTP/1.1 request string
  @spec build_http_request(Request.t()) :: iodata()
  defp build_http_request(%Request{} = request) do
    method = request.method |> to_string() |> String.upcase()
    path = request.url.path || "/"

    # Add query string if present
    path_with_query =
      if request.url.query do
        "#{path}?#{request.url.query}"
      else
        path
      end

    # Start with request line
    request_line = "#{method} #{path_with_query} HTTP/1.1\r\n"

    # Add Host header (required for HTTP/1.1)
    host = request.url.host || "localhost"
    headers = Headers.set(request.headers, "Host", host)

    # Add Content-Length and Content-Type for requests with body
    {headers, body} =
      if request.body && request.method not in [:get, :head, :delete] do
        body_binary = to_binary(request.body)
        body_length = byte_size(body_binary)

        headers =
          headers
          |> Headers.set("Content-Length", to_string(body_length))
          |> maybe_add_content_type(request.content_type)

        {headers, body_binary}
      else
        {headers, ""}
      end

    # Add Connection: close header
    headers = Headers.set(headers, "Connection", "close")

    # Build headers string
    headers_string =
      headers.headers
      |> Enum.map(fn {name, value} -> "#{name}: #{value}\r\n" end)
      |> Enum.join()

    # Combine all parts
    [request_line, headers_string, "\r\n", body]
  end

  # Convert body to binary
  @spec to_binary(term()) :: binary()
  defp to_binary(body) when is_binary(body), do: body
  defp to_binary(body) when is_list(body), do: IO.iodata_to_binary(body)
  defp to_binary(%HTTP.FormData{} = form_data) do
    case HTTP.FormData.to_body(form_data) do
      {:url_encoded, body} -> to_string(body)
      {:multipart, body, _boundary} -> IO.iodata_to_binary(body)
    end
  end
  defp to_binary(body), do: to_string(body)

  # Add Content-Type header if not already present
  @spec maybe_add_content_type(Headers.t(), String.t() | nil) :: Headers.t()
  defp maybe_add_content_type(headers, content_type) do
    if content_type && !Headers.has?(headers, "Content-Type") do
      Headers.set(headers, "Content-Type", content_type)
    else
      headers
    end
  end

  # Receive and parse HTTP response
  @spec receive_response(:gen_tcp.socket(), URI.t()) ::
          {:ok, Response.t()} | {:error, term()}
  defp receive_response(socket, url) do
    case recv_until_headers_end(socket, "") do
      {:ok, response_data} ->
        case parse_status_and_headers(response_data) do
          {:ok, status, headers, body_so_far} ->
            # Check if we already have the complete body
            case receive_body(socket, headers, body_so_far) do
              {:ok, body} ->
                {:ok,
                 %Response{
                   status: status,
                   headers: headers,
                   body: body,
                   url: url,
                   stream: nil
                 }}

              {:error, reason} ->
                {:error, reason}
            end

          {:error, reason} ->
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Receive data until we get the end of headers (\r\n\r\n)
  @spec recv_until_headers_end(:gen_tcp.socket(), binary()) ::
          {:ok, binary()} | {:error, term()}
  defp recv_until_headers_end(socket, acc) do
    case :gen_tcp.recv(socket, 0, @recv_timeout) do
      {:ok, data} ->
        new_acc = acc <> data

        if String.contains?(new_acc, "\r\n\r\n") do
          {:ok, new_acc}
        else
          recv_until_headers_end(socket, new_acc)
        end

      {:error, :closed} when acc != "" ->
        # Socket closed but we have some data - might be complete response
        if String.contains?(acc, "\r\n\r\n") do
          {:ok, acc}
        else
          {:error, :closed}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Parse HTTP status line and headers, returning body data that was received
  @spec parse_status_and_headers(binary()) ::
          {:ok, integer(), Headers.t(), binary()} | {:error, term()}
  defp parse_status_and_headers(data) do
    case String.split(data, "\r\n\r\n", parts: 2) do
      [headers_part, body_part] ->
        lines = String.split(headers_part, "\r\n")

        case lines do
          [status_line | header_lines] ->
            case parse_status_line(status_line) do
              {:ok, status} ->
                headers = parse_headers(header_lines)
                {:ok, status, headers, body_part}

              {:error, reason} ->
                {:error, reason}
            end

          _ ->
            {:error, :invalid_http_response}
        end

      [headers_part] ->
        # No body received yet
        lines = String.split(headers_part, "\r\n")

        case lines do
          [status_line | header_lines] ->
            case parse_status_line(status_line) do
              {:ok, status} ->
                headers = parse_headers(header_lines)
                {:ok, status, headers, ""}

              {:error, reason} ->
                {:error, reason}
            end

          _ ->
            {:error, :invalid_http_response}
        end
    end
  end

  # Parse HTTP status line (e.g., "HTTP/1.1 200 OK")
  @spec parse_status_line(String.t()) :: {:ok, integer()} | {:error, :invalid_status_line}
  defp parse_status_line(line) do
    case String.split(line, " ", parts: 3) do
      [_version, status_code | _] ->
        case Integer.parse(status_code) do
          {status, ""} -> {:ok, status}
          _ -> {:error, :invalid_status_line}
        end

      _ ->
        {:error, :invalid_status_line}
    end
  end

  # Parse HTTP headers
  @spec parse_headers([String.t()]) :: Headers.t()
  defp parse_headers(lines) do
    headers =
      lines
      |> Enum.filter(fn line -> line != "" end)
      |> Enum.map(fn line ->
        case String.split(line, ":", parts: 2) do
          [name, value] -> {String.trim(name), String.trim(value)}
          _ -> nil
        end
      end)
      |> Enum.reject(&is_nil/1)

    Headers.new(headers)
  end

  # Receive response body based on headers
  @spec receive_body(:gen_tcp.socket(), Headers.t(), binary()) :: {:ok, binary()} | {:error, term()}
  defp receive_body(socket, headers, body_so_far) do
    transfer_encoding = Headers.get(headers, "transfer-encoding")
    content_length = Headers.get(headers, "content-length")

    cond do
      # Chunked transfer encoding
      transfer_encoding && String.downcase(transfer_encoding) =~ "chunked" ->
        receive_chunked_body(socket, body_so_far)

      # Content-Length specified
      content_length ->
        case Integer.parse(content_length) do
          {length, ""} when length > 0 ->
            bytes_received = byte_size(body_so_far)

            if bytes_received >= length do
              # We already have the complete body
              {:ok, binary_part(body_so_far, 0, length)}
            else
              # Need to receive more bytes
              remaining = length - bytes_received

              case :gen_tcp.recv(socket, remaining, @recv_timeout) do
                {:ok, more_data} ->
                  {:ok, body_so_far <> more_data}

                {:error, reason} ->
                  {:error, reason}
              end
            end

          {0, ""} ->
            {:ok, ""}

          _ ->
            {:error, :invalid_content_length}
        end

      # No body or no Content-Length (read until connection closes)
      true ->
        receive_until_close(socket, body_so_far)
    end
  end

  # Receive chunked transfer encoding body
  @spec receive_chunked_body(:gen_tcp.socket(), binary()) ::
          {:ok, binary()} | {:error, term()}
  defp receive_chunked_body(socket, acc) do
    case recv_line(socket) do
      {:ok, chunk_size_line} ->
        # Parse chunk size (hex format, may include chunk extensions after semicolon)
        chunk_size_hex = chunk_size_line |> String.split(";") |> hd() |> String.trim()

        case Integer.parse(chunk_size_hex, 16) do
          {0, ""} ->
            # Last chunk - read trailing headers (if any) and return accumulated body
            _ = recv_line(socket)
            {:ok, acc}

          {chunk_size, ""} when chunk_size > 0 ->
            # Read chunk data
            case :gen_tcp.recv(socket, chunk_size, @recv_timeout) do
              {:ok, chunk_data} ->
                # Read trailing \r\n after chunk data
                _ = recv_line(socket)
                receive_chunked_body(socket, acc <> chunk_data)

              {:error, reason} ->
                {:error, reason}
            end

          _ ->
            {:error, :invalid_chunk_size}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Receive until connection closes (for responses without Content-Length)
  @spec receive_until_close(:gen_tcp.socket(), binary()) :: {:ok, binary()}
  defp receive_until_close(socket, acc) do
    case :gen_tcp.recv(socket, 0, @recv_timeout) do
      {:ok, data} ->
        receive_until_close(socket, acc <> data)

      {:error, :closed} ->
        {:ok, acc}

      {:error, _reason} ->
        # On error, return what we have
        {:ok, acc}
    end
  end

  # Receive a single line (until \r\n)
  @spec recv_line(:gen_tcp.socket()) :: {:ok, String.t()} | {:error, term()}
  defp recv_line(socket) do
    recv_line_acc(socket, "")
  end

  @spec recv_line_acc(:gen_tcp.socket(), binary()) :: {:ok, String.t()} | {:error, term()}
  defp recv_line_acc(socket, acc) do
    case :gen_tcp.recv(socket, 0, @recv_timeout) do
      {:ok, data} ->
        new_acc = acc <> data

        case String.split(new_acc, "\r\n", parts: 2) do
          [line, _rest] ->
            {:ok, line}

          _ ->
            recv_line_acc(socket, new_acc)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
