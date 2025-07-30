defmodule HTTP.Request do
  @moduledoc """
  Represents an HTTP request that can be serialized into :httpc.request arguments.
  """

  # Note: `options` are for the 3rd argument of :httpc.request (request-specific options like timeout).
  # `opts` are for the 4th argument of :httpc.request (client-specific options like sync/body_format).
  defstruct method: :get,
            url: nil,
            headers: %HTTP.Headers{},
            # Separate field for Content-Type header
            content_type: nil,
            body: nil,
            # HTTPC request options (e.g., timeout)
            options: [],
            opts: [sync: false, body_format: :binary]

  @type method :: :head | :get | :post | :put | :delete | :patch
  @type url :: String.t() | charlist()
  @type content_type :: String.t() | charlist() | nil
  @type body_content :: String.t() | charlist() | nil
  @type httpc_options :: Keyword.t()
  @type httpc_client_opts :: Keyword.t()

  @type t :: %__MODULE__{
          method: method,
          url: url,
          headers: HTTP.Headers.t(),
          content_type: content_type,
          body: body_content,
          options: httpc_options,
          opts: httpc_client_opts
        }

  @doc """
  Converts an `HTTP.Request` struct into arguments suitable for `:httpc.request/4`.
  """
  @spec to_httpc_args(t()) :: {atom, tuple, Keyword.t(), Keyword.t()}
  def to_httpc_args(%__MODULE__{} = req) do
    method = req.method
    url = to_charlist(req.url)
    headers = Enum.map(req.headers.headers, fn {k, v} -> {to_charlist(k), to_charlist(v)} end)

    request_tuple =
      case method do
        :get ->
          {url, headers}

        :head ->
          {url, headers}

        :delete ->
          {url, headers}

        # For methods typically with a body, include content_type and body
        _ ->
          content_type = to_charlist(req.content_type || "application/octet-stream")
          {url, headers, content_type, to_body(req.body)}
      end

    [method, request_tuple, req.options, req.opts]
  end

  @spec to_body(body_content()) :: charlist()
  defp to_body(nil), do: ~c[]
  defp to_body(body) when is_binary(body), do: String.to_charlist(body)
  # Assume already charlist/iodata
  defp to_body(body) when is_list(body), do: body
  # Convert other types to string then charlist
  defp to_body(other), do: String.to_charlist(to_string(other))
end
