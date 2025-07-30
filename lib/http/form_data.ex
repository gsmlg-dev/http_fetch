defmodule HTTP.FormData do
  @moduledoc """
  Handles HTTP form data and multipart/form-data encoding for file uploads.
  Supports both regular form data and multipart uploads with streaming file support.
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
  Adds a file field for upload with streaming support.

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
  """
  @spec to_body(t()) :: {:url_encoded, String.t()} | {:multipart, String.t(), String.t()}
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
      |> Enum.map(fn {:field, name, value} ->
        URI.encode_www_form(name) <> "=" <> URI.encode_www_form(value)
      end)
      |> Enum.join("&")

    {:url_encoded, encoded}
  end

  defp encode_multipart(%__MODULE__{parts: parts} = form) do
    boundary = form.boundary || generate_boundary()

    body_parts =
      parts
      |> Enum.map(fn
        {:field, name, value} ->
          encode_multipart_field(boundary, name, value)

        {:file, name, filename, content_type, %File.Stream{} = stream} ->
          encode_multipart_file_stream(boundary, name, filename, content_type, stream)

        {:file, name, filename, content_type, content} ->
          encode_multipart_file_content(boundary, name, filename, content_type, content)
      end)

    body = Enum.join(body_parts, "\r\n") <> "\r\n--" <> boundary <> "--\r\n"

    {:multipart, body, boundary}
  end

  defp encode_multipart_field(boundary, name, value) do
    "--#{boundary}\r\n" <>
      "Content-Disposition: form-data; name=\"#{name}\"\r\n\r\n" <>
      "#{value}"
  end

  defp encode_multipart_file_content(boundary, name, filename, content_type, content) do
    "--#{boundary}\r\n" <>
      "Content-Disposition: form-data; name=\"#{name}\"; filename=\"#{filename}\"\r\n" <>
      "Content-Type: #{content_type}\r\n\r\n" <>
      content
  end

  defp encode_multipart_file_stream(
         boundary,
         name,
         filename,
         content_type,
         %File.Stream{} = stream
       ) do
    content = stream |> Enum.into("")
    encode_multipart_file_content(boundary, name, filename, content_type, content)
  end
end
