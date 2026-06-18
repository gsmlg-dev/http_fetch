defmodule HTTP.Request do
  @moduledoc """
  HTTP request configuration struct.

  This module provides a structured way to build HTTP requests with proper
  conversion to the internal HTTP/1.1 wire format. It handles method normalization,
  header processing, body encoding, and FormData support.

  ## Supported Methods

  - `:get` - GET requests (no body)
  - `:head` - HEAD requests (no body)
  - `:post` - POST requests (with body)
  - `:put` - PUT requests (with body)
  - `:delete` - DELETE requests (no body)
  - `:patch` - PATCH requests (with body)

  ## Usage

      # Basic request
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("https://api.example.com/data"),
        headers: HTTP.Headers.new([{"Accept", "application/json"}])
      }

      # POST with JSON body
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://api.example.com/posts"),
        headers: HTTP.Headers.new([{"Authorization", "Bearer token"}]),
        content_type: "application/json",
        body: JSON.encode!(%{title: "Hello"}),
        http_options: [timeout: 10_000]
      }

      # FormData upload
      form = HTTP.FormData.new()
             |> HTTP.FormData.append_field("name", "John")
             |> HTTP.FormData.append_file("photo", "photo.jpg", file_stream)

      request = %HTTP.Request{
        method: :post,
        url: URI.parse("https://api.example.com/upload"),
        body: form
      }

  ## Default Headers

  The library automatically adds a `User-Agent` header if not provided,
  containing information about the runtime environment (OS, architecture,
  OTP version, Elixir version, and library version).
  """

  defstruct method: :get,
            url: nil,
            headers: %HTTP.Headers{},
            # Separate field for Content-Type header
            content_type: nil,
            body: nil,
            # Request options (e.g., timeout, connect_timeout, ssl, autoredirect)
            http_options: [],
            options: [sync: false]

  @type method :: :head | :get | :post | :put | :delete | :patch
  @type url :: URI.t()
  @type content_type :: String.t() | charlist() | nil
  @type body_content :: String.t() | charlist() | HTTP.FormData.t() | nil
  @type t :: %__MODULE__{
          method: method,
          url: url,
          headers: HTTP.Headers.t(),
          content_type: content_type,
          body: body_content,
          http_options: Keyword.t(),
          options: Keyword.t()
        }

  @doc """
  Converts an `HTTP.Request` struct into HTTP/1.1 wire iodata.
  """
  @spec to_iodata(t()) :: iolist()
  def to_iodata(%__MODULE__{} = req), do: HTTP.HTTP1.serialize_request(req)

  @doc """
  Converts an `HTTP.Request` struct into legacy `:httpc.request/4` arguments.

  This compatibility helper is preserved for callers that inspect or pass the
  request shape directly, even though `HTTP.fetch/2` no longer uses `:httpc`.
  """
  @spec to_httpc_args(t()) :: [term()]
  def to_httpc_args(%__MODULE__{} = req) do
    method = req.method
    url = req.url |> URI.to_string() |> to_charlist()

    headers =
      req.headers.headers
      |> add_default_user_agent()
      |> Enum.map(fn {name, value} -> {to_charlist(name), to_charlist(value)} end)

    request_tuple =
      case method do
        method when method in [:get, :head, :delete] ->
          {url, headers}

        _ when is_struct(req.body, HTTP.FormData) ->
          form_data_to_httpc_tuple(req, url, headers)

        _ ->
          content_type = to_charlist(req.content_type || "application/octet-stream")
          {url, headers, content_type, to_body(req.body)}
      end

    [method, request_tuple, req.http_options, req.options]
  end

  defp form_data_to_httpc_tuple(req, url, headers) do
    case HTTP.FormData.to_body(req.body) do
      {:url_encoded, body} ->
        {url, headers, ~c"application/x-www-form-urlencoded", to_charlist(body)}

      {:multipart, body, boundary} ->
        content_type = ~c"multipart/form-data; boundary=#{boundary}"
        {url, headers, content_type, iodata_to_charlist(body)}
    end
  end

  defp to_body(nil), do: ~c[]
  defp to_body(body) when is_binary(body), do: String.to_charlist(body)
  defp to_body(body) when is_list(body), do: body
  defp to_body(other), do: String.to_charlist(to_string(other))

  defp iodata_to_charlist(iodata) do
    iodata
    |> IO.iodata_to_binary()
    |> String.to_charlist()
  end

  defp add_default_user_agent(headers) do
    if Enum.any?(headers, fn {name, _value} -> String.downcase(name) == "user-agent" end) do
      headers
    else
      [{"User-Agent", HTTP.Headers.user_agent()} | headers]
    end
  end
end
