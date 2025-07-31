defmodule HTTP.Response do
  @moduledoc """
  Represents an HTTP response with status, headers, body, and URL information.
  """

  defstruct status: 0,
            headers: %HTTP.Headers{},
            body: nil,
            url: nil,
            stream: nil

  @type t :: %__MODULE__{
          status: integer(),
          headers: HTTP.Headers.t(),
          body: String.t() | nil,
          url: URI.t(),
          stream: pid() | nil
        }

  @doc """
  Reads the response body as text.

  For streaming responses, this will read the entire stream into memory.
  """
  @spec text(t()) :: String.t()
  def text(%__MODULE__{body: body, stream: nil}), do: body

  def text(%__MODULE__{body: body, stream: stream}) do
    if is_nil(body) and is_pid(stream) do
      read_all(%__MODULE__{body: body, stream: stream})
    else
      body || ""
    end
  end

  @doc """
  Reads the entire response body as binary.

  For streaming responses, this will consume the entire stream into memory.
  For non-streaming responses, returns the existing body.

  ## Examples
      iex> response = %HTTP.Response{body: "Hello World", stream: nil}
      iex> HTTP.Response.read_all(response)
      "Hello World"
  """
  @spec read_all(t()) :: String.t()
  def read_all(%__MODULE__{body: body, stream: nil}), do: body || ""

  def read_all(%__MODULE__{body: _body, stream: stream}) do
    if is_pid(stream) do
      # Request data from the stream
      send(stream, {:read_chunk, self()})
      collect_stream(stream, "")
    else
      ""
    end
  end

  defp collect_stream(stream, acc) do
    receive do
      {:stream_chunk, ^stream, chunk} ->
        collect_stream(stream, acc <> chunk)

      {:stream_end, ^stream} ->
        acc

      {:stream_error, ^stream, _reason} ->
        acc
    after
      # 60 second timeout
      60_000 -> acc
    end
  end

  @doc """
  Reads the response body and parses it as JSON.

  For streaming responses, this will read the entire stream before parsing.

  Returns:
    - `{:ok, map | list}` if the body is valid JSON.
    - `{:error, reason}` if the body cannot be parsed as JSON.

  ## Examples
      iex> response = %HTTP.Response{body: ~s({"key": "value"})}
      iex> HTTP.Response.read_as_json(response)
      {:ok, %{"key" => "value"}}
  """
  @spec read_as_json(t()) :: {:ok, map() | list()} | {:error, term()}
  def read_as_json(%__MODULE__{} = response) do
    body = read_all(response)

    case JSON.decode(body) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, error} -> {:error, error}
    end
  end

  @doc """
  Parses the response body as JSON using Elixir's built-in `JSON` module (available in Elixir 1.18+).

  Returns:
    - `{:ok, map | list}` if the body is valid JSON.
    - `{:error, reason}` if the body cannot be parsed as JSON.

  Note: This method is deprecated in favor of `read_as_json/1` for streaming responses.
  """
  @spec json(t()) :: {:ok, map() | list()} | {:error, term()}
  def json(%__MODULE__{body: body, stream: nil}) do
    case JSON.decode(body) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, error} -> {:error, error}
    end
  end

  def json(%__MODULE__{} = response), do: read_as_json(response)

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
