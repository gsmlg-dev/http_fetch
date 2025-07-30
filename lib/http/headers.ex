defmodule HTTP.Headers do
  @moduledoc """
  Module for processing HTTP headers with utilities for parsing, normalizing, and manipulating headers.
  """

  defstruct headers: []

  @type header :: {String.t(), String.t()}
  @type headers_list :: list(header)
  @type t :: %__MODULE__{headers: headers_list}

  @doc """
  Creates a new HTTP.Headers struct.

  ## Examples
      iex> HTTP.Headers.new([{"Content-Type", "application/json"}])
      %HTTP.Headers{headers: [{"Content-Type", "application/json"}]}
      
      iex> HTTP.Headers.new()
      %HTTP.Headers{headers: []}
  """
  @spec new(headers_list) :: t()
  def new(headers \\ []) when is_list(headers) do
    %__MODULE__{headers: headers}
  end

  @doc """
  Normalizes header names to title case (e.g., "content-type" becomes "Content-Type").

  ## Examples
      iex> HTTP.Headers.normalize_name("content-type")
      "Content-Type"
      
      iex> HTTP.Headers.normalize_name("AUTHORIZATION")
      "Authorization"
  """
  @spec normalize_name(String.t()) :: String.t()
  def normalize_name(name) when is_binary(name) do
    name
    |> String.downcase()
    |> String.split("-")
    |> Enum.map(&String.capitalize/1)
    |> Enum.join("-")
  end

  @doc """
  Parses a header string into a {name, value} tuple.

  ## Examples
      iex> HTTP.Headers.parse("Content-Type: application/json")
      {"Content-Type", "application/json"}
      
      iex> HTTP.Headers.parse("Authorization: Bearer token123")
      {"Authorization", "Bearer token123"}
  """
  @spec parse(String.t()) :: header
  def parse(header_str) when is_binary(header_str) do
    case String.split(header_str, ":", parts: 2) do
      [name, value] ->
        {normalize_name(String.trim(name)), String.trim(value)}

      [name] ->
        {normalize_name(String.trim(name)), ""}
    end
  end

  @doc """
  Converts a HTTP.Headers struct to a map for easy lookup.

  ## Examples
      iex> headers = HTTP.Headers.new([{"Content-Type", "application/json"}, {"Authorization", "Bearer token"}])
      iex> HTTP.Headers.to_map(headers)
      %{"content-type" => "application/json", "authorization" => "Bearer token"}
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{headers: headers}) do
    Enum.reduce(headers, %{}, fn {name, value}, acc ->
      Map.put(acc, String.downcase(name), value)
    end)
  end

  @doc """
  Converts a map of headers to a HTTP.Headers struct.

  ## Examples
      iex> headers = HTTP.Headers.from_map(%{"content-type" => "application/json", "authorization" => "Bearer token"})
      iex> {"Content-Type", "application/json"} in headers.headers
      true
      iex> {"Authorization", "Bearer token"} in headers.headers
      true
  """
  @spec from_map(map()) :: t()
  def from_map(map) when is_map(map) do
    headers =
      map
      |> Enum.map(fn {name, value} ->
        {normalize_name(to_string(name)), to_string(value)}
      end)

    %__MODULE__{headers: headers}
  end

  @doc """
  Gets a header value by name (case-insensitive).

  ## Examples
      iex> headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      iex> HTTP.Headers.get(headers, "content-type")
      "application/json"
      
      iex> headers = HTTP.Headers.new([{"Authorization", "Bearer token"}])
      iex> HTTP.Headers.get(headers, "missing")
      nil
  """
  @spec get(t(), String.t()) :: String.t() | nil
  def get(%__MODULE__{headers: headers}, name) when is_binary(name) do
    normalized_name = String.downcase(name)

    Enum.find_value(headers, fn {header_name, value} ->
      if String.downcase(header_name) == normalized_name, do: value
    end)
  end

  @doc """
  Sets a header value, replacing any existing header with the same name.

  ## Examples
      iex> headers = HTTP.Headers.new([{"Content-Type", "text/plain"}])
      iex> updated = HTTP.Headers.set(headers, "Content-Type", "application/json")
      iex> HTTP.Headers.get(updated, "Content-Type")
      "application/json"
      
      iex> headers = HTTP.Headers.new()
      iex> updated = HTTP.Headers.set(headers, "Authorization", "Bearer token")
      iex> HTTP.Headers.get(updated, "Authorization")
      "Bearer token"
  """
  @spec set(t(), String.t(), String.t()) :: t()
  def set(%__MODULE__{headers: headers} = headers_struct, name, value)
      when is_binary(name) and is_binary(value) do
    normalized_name = normalize_name(name)

    updated_headers =
      headers
      |> Enum.reject(fn {header_name, _} ->
        String.downcase(header_name) == String.downcase(normalized_name)
      end)
      |> Kernel.++([{normalized_name, value}])

    %{headers_struct | headers: updated_headers}
  end

  @doc """
  Merges two HTTP.Headers structs, with the second taking precedence.

  ## Examples
      iex> headers1 = HTTP.Headers.new([{"Content-Type", "text/plain"}])
      iex> headers2 = HTTP.Headers.new([{"Content-Type", "application/json"}])
      iex> merged = HTTP.Headers.merge(headers1, headers2)
      iex> HTTP.Headers.get(merged, "Content-Type")
      "application/json"
      
      iex> headers1 = HTTP.Headers.new([{"A", "1"}])
      iex> headers2 = HTTP.Headers.new([{"B", "2"}])
      iex> merged = HTTP.Headers.merge(headers1, headers2)
      iex> HTTP.Headers.get(merged, "A")
      "1"
      iex> HTTP.Headers.get(merged, "B")
      "2"
  """
  @spec merge(t(), t()) :: t()
  def merge(%__MODULE__{headers: headers1}, %__MODULE__{headers: headers2}) do
    map1 = to_map(%__MODULE__{headers: headers1})
    map2 = to_map(%__MODULE__{headers: headers2})
    merged = Map.merge(map1, map2)
    from_map(merged)
  end

  @doc """
  Checks if a header exists (case-insensitive).

  ## Examples
      iex> headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      iex> HTTP.Headers.has?(headers, "content-type")
      true
      
      iex> headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      iex> HTTP.Headers.has?(headers, "missing")
      false
  """
  @spec has?(t(), String.t()) :: boolean()
  def has?(%__MODULE__{headers: headers}, name) when is_binary(name) do
    normalized_name = String.downcase(name)

    Enum.any?(headers, fn {header_name, _} ->
      String.downcase(header_name) == normalized_name
    end)
  end

  @doc """
  Removes a header by name (case-insensitive).

  ## Examples
      iex> headers = HTTP.Headers.new([{"Content-Type", "application/json"}, {"Authorization", "Bearer token"}])
      iex> updated = HTTP.Headers.delete(headers, "content-type")
      iex> HTTP.Headers.has?(updated, "content-type")
      false
      iex> HTTP.Headers.has?(updated, "Authorization")
      true
  """
  @spec delete(t(), String.t()) :: t()
  def delete(%__MODULE__{headers: headers} = headers_struct, name) when is_binary(name) do
    normalized_name = String.downcase(name)

    updated_headers =
      Enum.reject(headers, fn {header_name, _} ->
        String.downcase(header_name) == normalized_name
      end)

    %{headers_struct | headers: updated_headers}
  end

  @doc """
  Parses a Content-Type header to extract the media type and parameters.

  ## Examples
      iex> HTTP.Headers.parse_content_type("application/json; charset=utf-8")
      {"application/json", %{"charset" => "utf-8"}}
      
      iex> HTTP.Headers.parse_content_type("text/plain")
      {"text/plain", %{}}
  """
  @spec parse_content_type(String.t()) :: {String.t(), map()}
  def parse_content_type(content_type) when is_binary(content_type) do
    parts = String.split(content_type, ";")
    media_type = parts |> hd() |> String.trim()

    params =
      parts
      |> tl()
      |> Enum.reduce(%{}, fn param, acc ->
        case String.split(param, "=", parts: 2) do
          [key, value] -> Map.put(acc, String.trim(key), String.trim(value))
          _ -> acc
        end
      end)

    {media_type, params}
  end

  @doc """
  Formats headers for display (useful for debugging).

  ## Examples
      iex> headers = HTTP.Headers.new([{"Content-Type", "application/json"}, {"Authorization", "Bearer token"}])
      iex> HTTP.Headers.format(headers)
      "Content-Type: application/json\nAuthorization: Bearer token"
  """
  @spec format(t()) :: String.t()
  def format(%__MODULE__{headers: headers}) do
    headers
    |> Enum.map(fn {name, value} -> "#{name}: #{value}" end)
    |> Enum.join("\n")
  end

  @doc """
  Returns the underlying list of headers.

  ## Examples
      iex> headers = HTTP.Headers.new([{"Content-Type", "application/json"}])
      iex> HTTP.Headers.to_list(headers)
      [{"Content-Type", "application/json"}]
  """
  @spec to_list(t()) :: headers_list
  def to_list(%__MODULE__{headers: headers}) do
    headers
  end
end
