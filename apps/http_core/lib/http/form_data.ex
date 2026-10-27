defmodule HTTP.FormData do
  @moduledoc """
  HTTP form data and multipart/form-data encoding for file uploads.

  This module provides a convenient API for building form submissions with support
  for both URL-encoded forms and multipart file uploads. It automatically chooses
  the appropriate encoding based on the presence of file fields.

  ## Encoding Selection

  - **URL-encoded** (`application/x-www-form-urlencoded`): Used when form contains only text fields
  - **Multipart** (`multipart/form-data`): Used when form contains file fields

  ## Features

  - **File stream inputs**: Accepts `File.Stream` values when building multipart bodies
  - **Automatic encoding**: Selects appropriate encoding based on content
  - **Boundary generation**: Automatically generates unique multipart boundaries
  - **Mixed content**: Support for both text fields and files in the same form

  ## Basic Usage

      # Simple form with text fields
      form = HTTP.FormData.new()
             |> HTTP.FormData.append_field("username", "john_doe")
             |> HTTP.FormData.append_field("email", "john@example.com")

      HTTP.fetch("https://api.example.com/signup", method: "POST", body: form)

  ## File Upload

      # Single file upload
      file_stream = File.stream!("document.pdf")
      form = HTTP.FormData.new()
             |> HTTP.FormData.append_field("title", "My Document")
             |> HTTP.FormData.append_file("document", "document.pdf", file_stream, "application/pdf")

      HTTP.fetch("https://api.example.com/upload", method: "POST", body: form)

  ## Multiple Files

      # Upload multiple files
      form = HTTP.FormData.new()
             |> HTTP.FormData.append_field("description", "Photos from vacation")
             |> HTTP.FormData.append_file("photo1", "beach.jpg", File.stream!("beach.jpg"), "image/jpeg")
             |> HTTP.FormData.append_file("photo2", "sunset.jpg", File.stream!("sunset.jpg"), "image/jpeg")

      HTTP.fetch("https://api.example.com/gallery", method: "POST", body: form)

  ## Content Types

  When uploading files, you can specify the MIME type. If not provided, it defaults
  to `"application/octet-stream"`:

      # With explicit content type
      form |> HTTP.FormData.append_file("image", "photo.jpg", stream, "image/jpeg")

      # With default content type
      form |> HTTP.FormData.append_file("data", "data.bin", stream)
  """

  defstruct parts: [],
            boundary: nil

  @type form_part ::
          {:field, String.t(), String.t()}
          | {:file, String.t(), String.t(), String.t(), File.Stream.t()}
          | {:file, String.t(), String.t(), String.t(), String.t()}

  @type t :: %__MODULE__{
          parts: [form_part()],
          boundary: String.t() | nil
        }

  @type stream_envelope :: %{
          body: Enumerable.t(),
          content_length: non_neg_integer(),
          content_type: String.t(),
          boundary: String.t()
        }

  @doc """
  Creates a new empty FormData struct.

  ## Examples

      iex> HTTP.FormData.new()
      %HTTP.FormData{parts: [], boundary: nil}
  """
  @spec new() :: t()
  def new, do: %__MODULE__{parts: [], boundary: nil}

  @doc """
  Adds a form field.

  ## Examples

      iex> HTTP.FormData.new() |> HTTP.FormData.append_field("name", "value")
      %HTTP.FormData{parts: [{:field, "name", "value"}], boundary: nil}
  """
  @spec append_field(t(), String.t(), String.t()) :: t()
  def append_field(%__MODULE__{parts: parts} = form, name, value) do
    %{form | parts: parts ++ [{:field, name, value}]}
  end

  @doc """
  Adds a file field for upload.

  ## Examples

      iex> file_stream = File.stream!("test.txt")
      iex> HTTP.FormData.new() |> HTTP.FormData.append_file("upload", "test.txt", file_stream)
      %HTTP.FormData{parts: [{:file, "upload", "test.txt", "text/plain", %File.Stream{}}], boundary: nil}
  """
  @spec append_file(t(), String.t(), String.t(), File.Stream.t() | String.t(), String.t()) :: t()
  def append_file(
        %__MODULE__{parts: parts} = form,
        name,
        filename,
        content,
        content_type \\ "application/octet-stream"
      ) do
    %{form | parts: parts ++ [{:file, name, filename, content_type, content}]}
  end

  @doc """
  Generates a random boundary for multipart/form-data.
  """
  @spec generate_boundary() :: String.t()
  def generate_boundary do
    "--boundary-#{System.unique_integer([:positive])}"
  end

  @doc """
  Converts FormData to HTTP body content with appropriate encoding.

  Returns {:url_encoded, body} for regular forms or {:multipart, body, boundary} for multipart.
  The multipart body is returned as iodata for memory efficiency with large file uploads.
  """
  @spec to_body(t()) :: {:url_encoded, String.t()} | {:multipart, iodata(), String.t()}
  def to_body(%__MODULE__{parts: parts} = form) do
    has_file? =
      Enum.any?(parts, fn
        {:file, _, _, _, %File.Stream{}} -> true
        {:file, _, _, _, _} -> true
        _ -> false
      end)

    if has_file? do
      encode_multipart(form)
    else
      encode_url_encoded(form)
    end
  end

  @doc """
  Builds a lazy multipart envelope with an exact byte length.

  Returns `{:ok, %{body: enumerable, content_length: bytes, content_type: type,
  boundary: boundary}}`. Construction stats regular file paths but does not open
  or read them. Enumeration opens one file at a time and emits binary chunks of
  at most `:chunk_size` bytes (default 32,768; maximum 65,536). Halting enumeration
  closes the current file. The existing `to_body/1` buffered API is unchanged.

  For Fetch uploads, adapt the enumerable through `HTTP.Stream.from_enumerable/1`
  and provide the matching length and content type:

      {:ok, multipart} = HTTP.FormData.to_stream(form)
      {:ok, upload} = HTTP.Stream.from_enumerable(multipart.body)
      HTTP.fetch(url,
        method: :post,
        body: upload,
        duplex: :half,
        content_type: multipart.content_type,
        headers: [{"Content-Length", Integer.to_string(multipart.content_length)}]
      )

  File inputs must be local regular `File.Stream` paths with byte-preserving
  modes. Default line-mode streams are reopened in binary chunks. Encoded,
  compressed, remote-node and write-mode streams are rejected because their
  output length cannot be obtained from file metadata alone. Field values and
  in-memory file content must be binaries.

  Keep files unchanged until upload completion. Fetch's fixed-length upload
  checks reject underflow or overflow if a file's size changes. Creating the
  envelope starts no producer; Fetch's upload stream owns enumeration and its
  existing cancellation, failed-connection and owner-exit cleanup applies. The
  serializer does not retry uploads.
  """
  @spec to_stream(t(), keyword()) :: {:ok, stream_envelope()} | {:error, term()}
  def to_stream(%__MODULE__{} = form, options \\ []) do
    boundary = form.boundary || generate_boundary()

    with {:ok, chunk_size} <- stream_chunk_size(options),
         {:ok, segments, length} <- stream_segments(form.parts, boundary, chunk_size) do
      closing = "--#{boundary}--\r\n"

      body =
        (segments ++ [{:data, closing}])
        |> Stream.flat_map(fn
          {:data, data} -> binary_chunks(data, chunk_size)
          {:file, stream} -> stream
        end)

      {:ok,
       %{
         body: body,
         content_length: length + byte_size(closing),
         content_type: "multipart/form-data; boundary=#{boundary}",
         boundary: boundary
       }}
    end
  end

  defp stream_chunk_size(options) do
    if Keyword.keyword?(options) and Keyword.keys(options) -- [:chunk_size] == [] do
      case Keyword.get(options, :chunk_size, 32_768) do
        size when is_integer(size) and size > 0 and size <= 65_536 -> {:ok, size}
        _ -> {:error, :invalid_multipart_chunk_size}
      end
    else
      {:error, :invalid_multipart_options}
    end
  end

  defp stream_segments(parts, boundary, chunk_size) do
    Enum.reduce_while(parts, {:ok, [], 0}, fn part, {:ok, segments, length} ->
      case stream_part(part, boundary, chunk_size) do
        {:ok, next, bytes} -> {:cont, {:ok, [next | segments], length + bytes}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, segments, length} -> {:ok, segments |> Enum.reverse() |> List.flatten(), length}
      error -> error
    end
  end

  defp stream_part({:field, name, value}, boundary, _chunk_size)
       when is_binary(name) and is_binary(value) do
    data = IO.iodata_to_binary([encode_multipart_field(boundary, name, value), "\r\n"])
    {:ok, [{:data, data}], byte_size(data)}
  end

  defp stream_part({:file, name, filename, content_type, content}, boundary, chunk_size)
       when is_binary(name) and is_binary(filename) and is_binary(content_type) do
    head =
      IO.iodata_to_binary(
        encode_multipart_file_content(boundary, name, filename, content_type, "")
      )

    with {:ok, segment, length} <- stream_content(content, chunk_size) do
      {:ok, [{:data, head}, segment, {:data, "\r\n"}], byte_size(head) + length + 2}
    end
  end

  defp stream_part(_part, _boundary, _chunk_size), do: {:error, :invalid_multipart_part}

  defp stream_content(content, _chunk_size) when is_binary(content),
    do: {:ok, {:data, content}, byte_size(content)}

  defp stream_content(%File.Stream{} = stream, chunk_size) do
    if stream.node == node() and Enum.all?(stream.modes, &byte_preserving_mode?/1) do
      case File.stat(stream.path) do
        {:ok, %File.Stat{type: :regular, size: size}} ->
          source = file_chunks(stream.path, chunk_size)
          {:ok, {:file, source}, size}

        {:ok, %File.Stat{type: type}} ->
          {:error, {:unsupported_multipart_file_type, stream.path, type}}

        {:error, reason} ->
          {:error, {:multipart_file_stat, stream.path, reason}}
      end
    else
      {:error, :unsupported_multipart_file_stream}
    end
  end

  defp stream_content(_content, _chunk_size), do: {:error, :invalid_multipart_part}

  defp byte_preserving_mode?(mode) when mode in [:raw, :binary, :read, :read_ahead], do: true
  defp byte_preserving_mode?({:read_ahead, size}) when is_integer(size) and size >= 0, do: true
  defp byte_preserving_mode?(_mode), do: false

  defp file_chunks(path, chunk_size) do
    Stream.resource(
      fn -> File.open!(path, [:read, :binary]) end,
      fn file ->
        case IO.binread(file, chunk_size) do
          :eof -> {:halt, file}
          {:error, reason} -> raise File.Error, reason: reason, action: "read file", path: path
          bytes -> {[bytes], file}
        end
      end,
      &File.close/1
    )
  end

  defp binary_chunks(data, chunk_size) do
    Stream.unfold(data, fn
      "" ->
        nil

      data ->
        :erlang.split_binary(data, min(byte_size(data), chunk_size))
    end)
  end

  @doc """
  Gets the appropriate Content-Type header for the form data.
  """
  @spec get_content_type(t()) :: String.t()
  def get_content_type(%__MODULE__{parts: parts}) do
    has_file? =
      Enum.any?(parts, fn
        {:file, _, _, _, %File.Stream{}} -> true
        {:file, _, _, _, _} -> true
        _ -> false
      end)

    if has_file? do
      boundary = generate_boundary()
      "multipart/form-data; boundary=#{boundary}"
    else
      "application/x-www-form-urlencoded"
    end
  end

  defp encode_url_encoded(%__MODULE__{parts: parts}) do
    encoded =
      parts
      |> Enum.filter(fn
        {:field, _, _} -> true
        _ -> false
      end)
      |> Enum.map_join("&", fn {:field, name, value} ->
        URI.encode_www_form(name) <> "=" <> URI.encode_www_form(value)
      end)

    {:url_encoded, encoded}
  end

  defp encode_multipart(%__MODULE__{parts: parts} = form) do
    boundary = form.boundary || generate_boundary()

    body_parts =
      parts
      |> Enum.flat_map(fn
        {:field, name, value} ->
          [encode_multipart_field(boundary, name, value), "\r\n"]

        {:file, name, filename, content_type, %File.Stream{} = stream} ->
          [encode_multipart_file_stream(boundary, name, filename, content_type, stream), "\r\n"]

        {:file, name, filename, content_type, content} ->
          [encode_multipart_file_content(boundary, name, filename, content_type, content), "\r\n"]
      end)

    # Build as iodata list for memory efficiency
    body = [body_parts, "--", boundary, "--\r\n"]

    {:multipart, body, boundary}
  end

  defp encode_multipart_field(boundary, name, value) do
    [
      "--#{boundary}\r\n",
      "Content-Disposition: form-data; name=\"#{name}\"\r\n\r\n",
      value
    ]
  end

  defp encode_multipart_file_content(boundary, name, filename, content_type, content) do
    [
      "--#{boundary}\r\n",
      "Content-Disposition: form-data; name=\"#{name}\"; filename=\"#{filename}\"\r\n",
      "Content-Type: #{content_type}\r\n\r\n",
      content
    ]
  end

  defp encode_multipart_file_stream(
         boundary,
         name,
         filename,
         content_type,
         %File.Stream{} = stream
       ) do
    # Reopen default line-mode File.Streams in byte chunks so arbitrary binary
    # uploads are not interpreted as lines.
    content_chunks =
      stream
      |> binary_file_stream()
      |> Enum.to_list()

    encode_multipart_file_content(boundary, name, filename, content_type, content_chunks)
  end

  defp binary_file_stream(%File.Stream{line_or_bytes: line_or_bytes} = stream)
       when is_integer(line_or_bytes) do
    stream
  end

  defp binary_file_stream(%File.Stream{} = stream) do
    File.stream!(stream.path, 2048, stream.modes)
  end
end
