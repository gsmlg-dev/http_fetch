defmodule HTTP.UnixSocket do
  @moduledoc """
  Unix Domain Socket support for HTTP requests.

  `HTTP.fetch/2` uses the same socket owner and HTTP/1.1 parser for Unix sockets
  as it uses for TCP and TLS requests. This module remains as an internal
  compatibility entry point for callers that already have an `HTTP.Request`.

  ## Usage

      HTTP.fetch("http://localhost/version", unix_socket: "/var/run/docker.sock")
  """

  alias HTTP.Request
  alias HTTP.Response

  @doc """
  Executes an HTTP request over a Unix Domain Socket.
  """
  @spec request(String.t(), Request.t(), integer()) :: {:ok, Response.t()} | {:error, term()}
  def request(socket_path, %Request{} = request, timeout \\ 30_000) do
    request = %{request | http_options: Keyword.put(request.http_options, :timeout, timeout)}

    case HTTP.SocketClient.request(request, nil, socket_path) do
      %Response{} = response -> {:ok, response}
      {:error, reason} -> {:error, reason}
    end
  end
end
