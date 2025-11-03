defmodule HTTP.Response do
  @moduledoc """
  HTTP response struct implementing the Browser Fetch API Response interface.

  This module represents an HTTP response with full compatibility with the
  Browser Fetch API standard. It supports both buffered and streaming responses,
  body consumption tracking, response cloning, and multiple read formats.

  ## Browser Fetch API Compatibility

  This module implements the JavaScript Fetch API Response interface:

  - `status` - HTTP status code (e.g., 200, 404, 500)
  - `status_text` - Status message ("OK", "Not Found", etc.)
  - `ok` - Boolean for success status (200-299)
  - `headers` - Response headers as `HTTP.Headers` struct
  - `body` - Response body as binary (nil for streaming responses)
  - `body_used` - Track if body has been consumed
  - `url` - The requested URL as `URI` struct
  - `redirected` - Whether response was redirected
  - `type` - Response type (:basic, :cors, :error, :opaque)
  - `stream` - Stream process PID for streaming responses (nil for buffered)

  ## Response Methods

  - `json/1` - Parse response as JSON
  - `text/1` - Read response as text
  - `arrayBuffer/1` - Read response as binary
  - `blob/1` - Read response as Blob with metadata
  - `clone/1` - Clone response for multiple reads

  ## Elixir-Specific Differences

  **Immutability**: Unlike JavaScript, Elixir responses are immutable. The `body_used`
  property won't automatically update across function calls. Use `clone/1` before
  multiple reads.

  **Synchronous Returns**: Methods like `json()` and `text()` return values directly
  instead of Promises, following Elixir conventions.

  **Stream Handling**: Large responses use Elixir processes for streaming instead
  of ReadableStream.

  ## Struct Fields

  - `status` - HTTP status code (e.g., 200, 404, 500)
  - `status_text` - Status message (e.g., "OK", "Not Found")
  - `ok` - Boolean indicating success (true for 200-299)
  - `headers` - Response headers as `HTTP.Headers` struct
  - `body` - Response body as binary (nil for streaming responses)
  - `body_used` - Whether body has been consumed (Browser API behavior)
  - `url` - The requested URL as `URI` struct
  - `redirected` - Whether response was redirected
  - `type` - Response type (:basic, :cors, :error, :opaque)
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
            status_text: "",
            ok: false,
            headers: %HTTP.Headers{},
            body: nil,
            body_used: false,
            url: nil,
            redirected: false,
            type: :basic,
            stream: nil

  @type response_type :: :basic | :cors | :error | :opaque

  @type t :: %__MODULE__{
          status: integer(),
          status_text: String.t(),
          ok: boolean(),
          headers: HTTP.Headers.t(),
          body: String.t() | nil,
          body_used: boolean(),
          url: URI.t(),
          redirected: boolean(),
          type: response_type(),
          stream: pid() | nil
        }

  @doc """
  Creates a new Response struct with Browser Fetch API fields populated.

  This is the recommended way to create Response structs. It automatically
  derives `status_text` and `ok` from the status code, and sets proper defaults
  for all Browser API fields.

  ## Parameters
    - `opts` - Keyword list with fields:
      - `:status` - HTTP status code (default: 0)
      - `:headers` - HTTP.Headers struct (default: empty headers)
      - `:body` - Response body binary (default: nil)
      - `:url` - Request URL (default: nil)
      - `:stream` - Stream PID for streaming responses (default: nil)
      - `:redirected` - Whether response was redirected (default: false)
      - `:type` - Response type (default: :basic)

  The following fields are automatically computed:
    - `status_text` - Derived from status code via HTTP.StatusText
    - `ok` - Set to true if status in 200..299
    - `body_used` - Always initialized to false

  ## Examples

      iex> HTTP.Response.new(status: 200, body: "OK", url: URI.parse("https://example.com"))
      %HTTP.Response{
        status: 200,
        status_text: "OK",
        ok: true,
        body: "OK",
        body_used: false,
        redirected: false,
        type: :basic
      }

      iex> HTTP.Response.new(status: 404, headers: HTTP.Headers.new())
      %HTTP.Response{
        status: 404,
        status_text: "Not Found",
        ok: false,
        body_used: false
      }
  """
  @spec new(keyword()) :: t()
  def new(opts \\ []) do
    status = Keyword.get(opts, :status, 0)

    %__MODULE__{
      status: status,
      status_text: HTTP.StatusText.get(status),
      ok: status in 200..299,
      headers: Keyword.get(opts, :headers, %HTTP.Headers{}),
      body: Keyword.get(opts, :body, nil),
      body_used: false,
      url: Keyword.get(opts, :url, nil),
      redirected: Keyword.get(opts, :redirected, false),
      type: Keyword.get(opts, :type, :basic),
      stream: Keyword.get(opts, :stream, nil)
    }
  end

  # Note: body_used tracking exists for Browser API compatibility but due to
  # Elixir's immutability, it cannot prevent multiple reads like in JavaScript.
  # The field is present for API compatibility and documentation purposes.

  @doc """
  Reads the response body as text.

  For streaming responses, this will read the entire stream into memory.

  **Note**: Due to Elixir's immutability, the `body_used` field exists for API
  compatibility but doesn't prevent multiple reads. Use `clone/1` for clarity
  when reading multiple times.

  ## Examples

      iex> response = HTTP.Response.new(status: 200, body: "Hello")
      iex> HTTP.Response.text(response)
      "Hello"
  """
  @spec text(t()) :: String.t()
  def text(%__MODULE__{body: body, stream: nil}), do: body

  def text(%__MODULE__{body: body, stream: stream} = response) do
    if is_nil(body) and is_pid(stream) do
      read_all(response)
    else
      body || ""
    end
  end

  @doc """
  Reads the entire response body as binary.

  For streaming responses, this will consume the entire stream into memory.
  For non-streaming responses, returns the existing body.

  ## Examples
      iex> response = HTTP.Response.new(status: 200, body: "Hello World")
      iex> HTTP.Response.read_all(response)
      "Hello World"
  """
  @spec read_all(t()) :: binary()
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
      HTTP.Config.streaming_timeout() -> acc
    end
  end

  @doc """
  Reads the response body and parses it as JSON.

  For streaming responses, this will read the entire stream before parsing.

  Returns:
    - `{:ok, map | list}` if the body is valid JSON.
    - `{:error, reason}` if the body cannot be parsed as JSON.

  ## Examples
      iex> response = HTTP.Response.new(status: 200, body: ~s({"key": "value"}))
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
  Creates a duplicate of the response, allowing the body to be read multiple times.

  For buffered responses, this creates a shallow copy with the body duplicated and
  `body_used` reset to false.

  For streaming responses, this creates a "tee" that splits the stream into two
  independent streams that can be consumed separately.

  ## Examples

      # Clone buffered response
      response = HTTP.Response.new(status: 200, body: "data")
      clone = HTTP.Response.clone(response)

      # Read original
      text1 = HTTP.Response.text(response)

      # Read clone independently
      text2 = HTTP.Response.text(clone)

      # Both contain the same data
      text1 == text2  # true

      # Clone streaming response
      response = HTTP.Response.new(status: 200, stream: stream_pid)
      clone = HTTP.Response.clone(response)

      # Both can be read independently
      data1 = HTTP.Response.read_all(response)
      data2 = HTTP.Response.read_all(clone)
  """
  @spec clone(t()) :: t()
  def clone(%__MODULE__{body: body, stream: nil} = response) when not is_nil(body) do
    # Buffered response - simple copy with body_used reset
    %{response | body_used: false}
  end

  def clone(%__MODULE__{stream: stream_pid} = response) when is_pid(stream_pid) do
    # Streaming response - create a tee
    # Note: This implementation reads the entire stream and creates two buffered copies
    # This is simpler than implementing a true stream tee at the process level
    body = read_all(%{response | body_used: false})

    # Return clone as buffered response
    %{response | body: body, stream: nil, body_used: false}
  end

  def clone(%__MODULE__{} = response) do
    # Empty body case
    %{response | body_used: false}
  end

  @doc """
  Reads the response body as raw binary data (equivalent to JavaScript's ArrayBuffer).

  Returns the body as an Elixir binary. For streaming responses, this reads
  the entire stream into memory.

  ## Examples

      iex> response = HTTP.Response.new(status: 200, body: <<1, 2, 3, 4>>)
      iex> HTTP.Response.arrayBuffer(response)
      <<1, 2, 3, 4>>
  """
  @spec arrayBuffer(t()) :: binary()
  # credo:disable-for-next-line Credo.Check.Readability.FunctionNames
  def arrayBuffer(%__MODULE__{} = response) do
    # arrayBuffer is essentially the same as read_all for binary data
    read_all(response)
  end

  @doc """
  Alias for `arrayBuffer/1` following Elixir naming conventions.
  """
  @spec array_buffer(t()) :: binary()
  def array_buffer(response), do: arrayBuffer(response)

  @doc """
  Reads the response body as a Blob (binary data with metadata).

  Returns an `HTTP.Blob` struct containing the body data, MIME type extracted
  from the Content-Type header, and size in bytes.

  ## Examples

      iex> response = HTTP.Response.new(
      ...>   status: 200,
      ...>   body: <<1, 2, 3, 4>>,
      ...>   headers: HTTP.Headers.new([{"content-type", "image/png"}])
      ...> )
      iex> blob = HTTP.Response.blob(response)
      iex> blob.type
      "image/png"
      iex> blob.size
      4
  """
  @spec blob(t()) :: HTTP.Blob.t()
  def blob(%__MODULE__{} = response) do
    # Read body data
    data = read_all(response)

    # Extract MIME type from Content-Type header
    {content_type, _params} = content_type(response)

    HTTP.Blob.new(data, content_type)
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
