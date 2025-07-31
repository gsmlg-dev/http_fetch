defmodule HTTP.Request do
  @moduledoc """
  Represents an HTTP request that can be serialized into :httpc.request arguments.
  """

  # Note: `http_options` are for the 3rd argument of :httpc.request (request-specific options like timeout).
  # `options` are for the 4th argument of :httpc.request (client-specific options like sync/body_format).
  defstruct method: :get,
            url: nil,
            headers: %HTTP.Headers{},
            # Separate field for Content-Type header
            content_type: nil,
            body: nil,
            # HTTPC request options (e.g., timeout)
            http_options: [],
            options: [sync: false]

  @type method :: :head | :get | :post | :put | :delete | :patch
  @type url :: URI.t()
  @type content_type :: String.t() | charlist() | nil
  @type body_content :: String.t() | charlist() | HTTP.FormData.t() | nil
  @type httpc_options :: Keyword.t()
  @type httpc_client_opts :: Keyword.t()

  @type t :: %__MODULE__{
          method: method,
          url: url,
          headers: HTTP.Headers.t(),
          content_type: content_type,
          body: body_content,
          http_options: httpc_options,
          options: httpc_client_opts
        }

  @doc """
  Converts an `HTTP.Request` struct into arguments suitable for `:httpc.request/4`.
  """
  @spec to_httpc_args(t()) :: {atom, tuple, Keyword.t(), Keyword.t()}
  def to_httpc_args(%__MODULE__{} = req) do
    method = req.method
    url = req.url |> URI.to_string() |> to_charlist()
    headers = Enum.map(req.headers.headers, fn {k, v} -> {to_charlist(k), to_charlist(v)} end)

    request_tuple =
      case method do
        :get ->
          {url, headers}

        :head ->
          {url, headers}

        :delete ->
          {url, headers}

        # For methods with HTTP.FormData body
        _ when is_struct(req.body, HTTP.FormData) ->
          case HTTP.FormData.to_body(req.body) do
            {:url_encoded, body} ->
              content_type = to_charlist("application/x-www-form-urlencoded")
              {url, headers, content_type, to_charlist(body)}

            {:multipart, body, boundary} ->
              content_type = to_charlist("multipart/form-data; boundary=#{boundary}")
              # Add boundary header
              updated_headers = headers ++ [{~c"Content-Type", to_charlist(content_type)}]
              {url, updated_headers, to_charlist(body)}
          end

        # For regular string/charlist bodies
        _ ->
          content_type = to_charlist(req.content_type || "application/octet-stream")
          body_content = to_body(req.body)
          {url, headers, content_type, body_content}
      end

    [method, request_tuple, req.http_options, req.options]
  end

  @spec to_body(body_content()) :: charlist()
  defp to_body(nil), do: ~c[]
  defp to_body(body) when is_binary(body), do: String.to_charlist(body)
  defp to_body(body) when is_list(body), do: body
  defp to_body(other), do: String.to_charlist(to_string(other))
end
