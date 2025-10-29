defmodule HTTP.Response do
  @moduledoc """
  HTTP response struct with utilities for parsing and consuming response data.

  This module represents an HTTP response with support for both buffered and
  streaming responses. It provides convenient methods for parsing JSON, reading
  text, and writing responses to files.

  ## Struct Fields

  - `status` - HTTP status code (e.g., 200, 404, 500)
  - `headers` - Response headers as `HTTP.Headers` struct
  - `body` - Response body as binary (nil for streaming responses)
  - `url` - The requested URL as `URI` struct
  - `stream` - Stream process PID for streaming responses (nil for buffered)

  ## Streaming vs Buffered Responses

  Responses are automatically streamed when:

  - Content-Length > 5MB
  - Content-Length header is missing/unknown

  **Buffered responses** have the complete body in the `body` field:

      %HTTP.Response{
        status: 200,
        body: "response data",
        stream: nil
      }

  **Streaming responses** have `body: nil` and a stream PID:

      %HTTP.Response{
        status: 200,
        body: nil,
        stream: #PID<0.123.0>
      }

  ## Usage

      # Simple text response
      {:ok, response} = HTTP.fetch("https://example.com") |> HTTP.Promise.await()
      text = HTTP.Response.text(response)

      # JSON parsing
      {:ok, response} = HTTP.fetch("https://api.example.com/data") |> HTTP.Promise.await()
      {:ok, json} = HTTP.Response.json(response)

      # Write to file (works with both streaming and buffered)
      {:ok, response} = HTTP.fetch("https://example.com/file.zip") |> HTTP.Promise.await()
      :ok = HTTP.Response.write_to(response, "/tmp/file.zip")

      # Get specific header
      content_type = HTTP.Response.get_header(response, "content-type")

      # Parse Content-Type
      {media_type, params} = HTTP.Response.content_type(response)

  ## Streaming Responses

  For streaming responses, use `read_all/1` or `write_to/2` to consume the stream:

      # Read entire stream into memory
      body = HTTP.Response.read_all(response)

      # Write stream directly to file (more memory efficient)
      :ok = HTTP.Response.write_to(response, "/path/to/file")
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

  @doc """
  Writes the response body to a file.

  For streaming responses, this will read the entire stream and write it to the file.
  For non-streaming responses, it will write the existing body directly.

  ## Parameters
    - `response`: The HTTP response to write
    - `file_path`: The path to write the file to

  ## Returns
    - `:ok` on success
    - `{:error, reason}` on failure

  ## Examples
      iex> response = %HTTP.Response{body: "file content", stream: nil}
      iex> HTTP.Response.write_to(response, "/tmp/test.txt")
      :ok
  """
  @spec write_to(t(), String.t()) :: :ok | {:error, term()}
  def write_to(%__MODULE__{} = response, file_path) do
    try do
      # Ensure the directory exists
      file_path
      |> Path.dirname()
      |> File.mkdir_p!()

      case response do
        %{body: body, stream: nil} when is_binary(body) or is_list(body) ->
          # Non-streaming response
          binary_body =
            if is_list(body), do: IO.iodata_to_binary(body), else: body

          File.write!(file_path, binary_body)
          :ok

        %{body: _body, stream: stream} when is_pid(stream) ->
          # Streaming response - collect and write
          write_stream_to_file(response, file_path)

        _ ->
          # Empty or nil body
          File.write!(file_path, "")
          :ok
      end
    rescue
      error -> {:error, error}
    end
  end

  defp write_stream_to_file(response, file_path) do
    File.open!(file_path, [:write, :binary], fn file ->
      case response do
        %{body: _body, stream: stream} when is_pid(stream) ->
          # For streaming responses, use collect_stream to get all data
          body = read_all(response)
          IO.binwrite(file, body)

        _ ->
          :ok
      end
    end)
  end
end
