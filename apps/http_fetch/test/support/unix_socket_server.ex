defmodule HTTP.Test.UnixSocketServer do
  @moduledoc """
  Test helper for creating a simple HTTP server that listens on a Unix Domain Socket.

  This module provides a basic HTTP/1.1 server implementation for testing Unix socket
  functionality. It supports basic HTTP methods and can handle JSON requests/responses.

  ## Usage

      # Start a server with custom handler
      {:ok, socket_path, pid} = UnixSocketServer.start_link(fn request ->
        %{status: 200, headers: %{"Content-Type" => "application/json"}, body: ~s({"status":"ok"})}
      end)

      # Make request to the socket
      HTTP.fetch("http://localhost/test", unix_socket: socket_path)

      # Stop the server
      UnixSocketServer.stop(pid)
  """

  use GenServer
  require Logger

  @default_timeout 5000

  defstruct [:socket_path, :listen_socket, :handler_fun]

  @type handler_response :: %{
          status: integer(),
          headers: map(),
          body: String.t()
        }

  @type handler_fun :: (map() -> handler_response())

  ## Client API

  @doc """
  Starts a Unix socket server with a custom request handler.

  Returns `{:ok, socket_path, pid}` where socket_path is the path to the Unix socket
  and pid is the server process.

  ## Options

  - `:socket_path` - Custom path for Unix socket (optional, generates temp path if not provided)
  """
  @spec start_link(handler_fun(), keyword()) :: {:ok, String.t(), pid()} | {:error, term()}
  def start_link(handler_fun, opts \\ []) do
    socket_path = Keyword.get(opts, :socket_path, generate_socket_path())

    case GenServer.start_link(__MODULE__, {socket_path, handler_fun}) do
      {:ok, pid} ->
        {:ok, socket_path, pid}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Stops the Unix socket server.
  """
  @spec stop(pid()) :: :ok
  def stop(pid) do
    GenServer.stop(pid)
  end

  ## GenServer Callbacks

  @impl true
  def init({socket_path, handler_fun}) do
    # Ensure socket file doesn't exist
    _ = File.rm(socket_path)

    # Create Unix socket listener
    socket_charlist = String.to_charlist(socket_path)

    case :gen_tcp.listen(0, [
           :binary,
           packet: :raw,
           active: false,
           ifaddr: {:local, socket_charlist}
         ]) do
      {:ok, listen_socket} ->
        state = %__MODULE__{
          socket_path: socket_path,
          listen_socket: listen_socket,
          handler_fun: handler_fun
        }

        # Start accepting connections
        spawn_link(fn -> accept_loop(state) end)

        {:ok, state}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def terminate(_reason, state) do
    if state.listen_socket do
      _ = :gen_tcp.close(state.listen_socket)
    end

    # Clean up socket file
    _ = File.rm(state.socket_path)
    :ok
  end

  ## Private Functions

  defp generate_socket_path do
    random_id = :crypto.strong_rand_bytes(8) |> Base.encode16() |> String.downcase()
    Path.join(System.tmp_dir!(), "http_fetch_test_#{random_id}.sock")
  end

  defp accept_loop(state) do
    case :gen_tcp.accept(state.listen_socket, @default_timeout) do
      {:ok, client_socket} ->
        # Spawn a process to handle this client
        spawn(fn -> handle_client(client_socket, state.handler_fun) end)
        # Continue accepting connections
        accept_loop(state)

      {:error, :timeout} ->
        # Timeout is normal, continue accepting
        accept_loop(state)

      {:error, :closed} ->
        # Listen socket closed, stop accepting
        :ok

      {:error, reason} ->
        Logger.error("Accept error: #{inspect(reason)}")
        :ok
    end
  end

  defp handle_client(socket, handler_fun) do
    case recv_request(socket) do
      {:ok, request} ->
        response = handler_fun.(request)
        handle_send_response(socket, response)

      {:error, reason} ->
        Logger.error("Error receiving request: #{inspect(reason)}")
    end

    _ = :gen_tcp.close(socket)
    :ok
  end

  defp handle_send_response(socket, response) do
    case send_response(socket, response) do
      :ok ->
        :ok

      {:error, reason} ->
        Logger.error("Error sending response: #{inspect(reason)}")
        :ok
    end
  end

  defp recv_request(socket) do
    case recv_until(socket, "\r\n\r\n", "", 10_000) do
      {:ok, request_data} ->
        parse_request(request_data)

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp recv_until(socket, delimiter, acc, timeout) do
    case :gen_tcp.recv(socket, 0, timeout) do
      {:ok, data} ->
        new_acc = acc <> data

        if String.contains?(new_acc, delimiter) do
          {:ok, new_acc}
        else
          recv_until(socket, delimiter, new_acc, timeout)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp parse_request(data) do
    [headers_part, body_part] = String.split(data, "\r\n\r\n", parts: 2)
    lines = String.split(headers_part, "\r\n")

    case lines do
      [request_line | header_lines] ->
        {:ok, method, path} = parse_request_line(request_line)
        headers = parse_headers(header_lines)

        # Check if there's more body to read based on Content-Length
        body =
          case Map.get(headers, "content-length") do
            nil ->
              body_part

            content_length_str ->
              case Integer.parse(content_length_str) do
                {length, ""} when length > byte_size(body_part) ->
                  # We need to read more
                  body_part

                _ ->
                  body_part
              end
          end

        {:ok,
         %{
           method: method,
           path: path,
           headers: headers,
           body: body
         }}

      _ ->
        {:error, :invalid_request}
    end
  end

  defp parse_request_line(line) do
    case String.split(line, " ", parts: 3) do
      [method, path, _version] ->
        {:ok, String.downcase(method), path}

      _ ->
        {:error, :invalid_request_line}
    end
  end

  defp parse_headers(lines) do
    lines
    |> Enum.filter(fn line -> line != "" end)
    |> Enum.map(fn line ->
      case String.split(line, ":", parts: 2) do
        [name, value] -> {String.downcase(String.trim(name)), String.trim(value)}
        _ -> nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Map.new()
  end

  defp send_response(socket, response) do
    status_line = "HTTP/1.1 #{response.status} #{status_text(response.status)}\r\n"

    # Ensure Content-Length is set
    body = response.body || ""
    content_length = byte_size(body)

    headers =
      response.headers
      |> Map.put_new("Content-Length", to_string(content_length))
      |> Map.put_new("Connection", "close")

    headers_string =
      Enum.map_join(headers, "", fn {name, value} -> "#{name}: #{value}\r\n" end)

    response_data = [status_line, headers_string, "\r\n", body]

    :gen_tcp.send(socket, response_data)
  end

  defp status_text(200), do: "OK"
  defp status_text(201), do: "Created"
  defp status_text(204), do: "No Content"
  defp status_text(400), do: "Bad Request"
  defp status_text(404), do: "Not Found"
  defp status_text(500), do: "Internal Server Error"
  defp status_text(_), do: "Unknown"
end
