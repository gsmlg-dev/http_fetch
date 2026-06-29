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
        transport_options: [timeout: 10_000]
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
            # Socket transport options (e.g., timeout, connect_timeout, ssl, redirect)
            transport_options: []

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
          transport_options: Keyword.t()
        }

  @doc """
  Converts an `HTTP.Request` struct into HTTP/1.1 wire iodata.
  """
  @spec to_iodata(t()) :: iolist()
  def to_iodata(%__MODULE__{} = req), do: HTTP.HTTP1.serialize_request(req)
end
