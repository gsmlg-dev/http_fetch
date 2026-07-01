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

  alias HTTP.Headers

  @allowed_methods ~w(DELETE GET HEAD OPTIONS PATCH POST PUT)

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

  @doc false
  @spec method_token(atom() | String.t()) :: String.t()
  def method_token(method) do
    method = method |> to_string() |> String.upcase()

    if method in @allowed_methods and valid_token?(method) do
      method
    else
      raise ArgumentError, "unsupported HTTP method: #{inspect(method)}"
    end
  end

  @doc false
  @spec origin_form(URI.t()) :: String.t()
  def origin_form(%URI{} = uri) do
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

  @doc false
  @spec authority(URI.t()) :: String.t()
  def authority(%URI{} = uri) do
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

  @doc false
  @spec body_payload(t()) :: nil | {iodata(), content_type()}
  def body_payload(%__MODULE__{body: nil}), do: nil
  def body_payload(%__MODULE__{method: method}) when method in [:get, :head, :delete], do: nil

  def body_payload(%__MODULE__{body: %HTTP.FormData{} = form_data}) do
    case HTTP.FormData.to_body(form_data) do
      {:url_encoded, body} ->
        {body, "application/x-www-form-urlencoded"}

      {:multipart, body, boundary} ->
        body = IO.iodata_to_binary(body)
        {body, "multipart/form-data; boundary=#{boundary}"}
    end
  end

  def body_payload(%__MODULE__{body: body, content_type: content_type}) do
    {to_body(body), content_type || "application/octet-stream"}
  end

  @doc false
  @spec put_body_headers(Headers.t(), t()) :: {Headers.t(), iodata()}
  def put_body_headers(%Headers{} = headers, %__MODULE__{} = request) do
    case body_payload(request) do
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

  @doc false
  @spec reject_unsupported_request_framing!(Headers.t()) :: Headers.t()
  def reject_unsupported_request_framing!(%Headers{} = headers) do
    cond do
      Headers.has?(headers, "Transfer-Encoding") ->
        raise ArgumentError, "Transfer-Encoding request headers are not supported"

      Headers.has?(headers, "Trailer") ->
        raise ArgumentError, "Trailer request headers are not supported"

      true ->
        headers
    end
  end

  @doc false
  @spec default_port(String.t() | nil) :: 80 | 443
  def default_port("https"), do: 443
  def default_port(_), do: 80

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

  defp valid_request_target!(target) do
    if safe_request_target?(target) do
      target
    else
      raise ArgumentError, "request target contains invalid whitespace or control characters"
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

  defp safe_request_target?(target) do
    target
    |> :binary.bin_to_list()
    |> Enum.all?(fn char -> char > 32 and char != 127 end)
  end
end
