defmodule HTTP.Response do
  @moduledoc """
  Represents an HTTP response with status, headers, body, and URL information.
  """

  defstruct status: 0,
            headers: %HTTP.Headers{},
            body: nil,
            url: nil

  @type t :: %__MODULE__{
          status: integer(),
          headers: HTTP.Headers.t(),
          body: String.t(),
          url: String.t()
        }

  @doc """
  Reads the response body as text.
  """
  @spec text(t()) :: String.t()
  def text(%__MODULE__{body: body}), do: body

  @doc """
  Parses the response body as JSON using Elixir's built-in `JSON` module (available in Elixir 1.18+).

  Returns:
    - `{:ok, map | list}` if the body is valid JSON.
    - `{:error, reason}` if the body cannot be parsed as JSON.
  """
  @spec json(t()) :: {:ok, map() | list()} | {:error, term()}
  def json(%__MODULE__{body: body}) do
    case JSON.decode(body) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Gets a response header value by name (case-insensitive).

  ## Examples
      iex> response = %HTTP.Response{headers: HTTP.Headers.new([{"Content-Type", "application/json"}])}
      iex> HTTP.Response.get_header(response, "content-type")
      "application/json"
      
      iex> response = %HTTP.Response{headers: HTTP.Headers.new([{"Content-Type", "application/json"}])}
      iex> HTTP.Response.get_header(response, "missing")
      nil
  """
  @spec get_header(t(), String.t()) :: String.t() | nil
  def get_header(%__MODULE__{headers: headers}, name) do
    HTTP.Headers.get(headers, name)
  end

  @doc """
  Parses the Content-Type header to extract media type and parameters.

  ## Examples
      iex> response = %HTTP.Response{headers: HTTP.Headers.new([{"Content-Type", "application/json; charset=utf-8"}])}
      iex> HTTP.Response.content_type(response)
      {"application/json", %{"charset" => "utf-8"}}
      
      iex> response = %HTTP.Response{headers: HTTP.Headers.new([{"Content-Type", "text/plain"}])}
      iex> HTTP.Response.content_type(response)
      {"text/plain", %{}}
  """
  @spec content_type(t()) :: {String.t(), map()}
  def content_type(%__MODULE__{headers: headers}) do
    case HTTP.Headers.get(headers, "content-type") do
      nil -> {"text/plain", %{}}
      content_type -> HTTP.Headers.parse_content_type(content_type)
    end
  end
end
