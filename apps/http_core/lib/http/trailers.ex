defmodule HTTP.Trailers do
  @moduledoc false

  alias HTTP.Headers

  @max_fields 128
  @max_bytes 65_536
  @forbidden ~w(content-length transfer-encoding host connection keep-alive trailer te upgrade
                authorization proxy-authorization proxy-authenticate www-authenticate cookie set-cookie
                content-encoding content-type content-range cache-control expect max-forwards pragma range
                if-match if-none-match if-modified-since if-unmodified-since if-range)

  def validate(fields, initial \\ %Headers{})
  def validate(%Headers{headers: fields}, initial), do: validate(fields, initial)

  def validate(fields, initial) when is_list(fields) do
    forbidden = @forbidden ++ connection_names(initial)

    fields
    |> Enum.reduce_while({:ok, 0, 2, []}, fn field, {:ok, count, bytes, acc} ->
      with {:ok, name, value} <- validate_field(field, forbidden),
           true <-
             count < @max_fields and bytes + byte_size(name) + byte_size(value) + 4 <= @max_bytes do
        {:cont,
         {:ok, count + 1, bytes + byte_size(name) + byte_size(value) + 4, [{name, value} | acc]}}
      else
        false -> {:halt, {:error, :trailers_too_large}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, _count, _bytes, fields} -> {:ok, Headers.new(Enum.reverse(fields))}
      error -> error
    end
  end

  def validate(_fields, _initial), do: {:error, :invalid_trailer}

  def parse(block, initial) when byte_size(block) + 4 <= @max_bytes do
    block
    |> :binary.split("\r\n", [:global])
    |> Enum.reduce_while({:ok, []}, fn line, {:ok, fields} ->
      case :binary.split(line, ":") do
        [name, value] -> {:cont, {:ok, [{name, trim_ows(value)} | fields]}}
        _ -> {:halt, {:error, :invalid_trailer}}
      end
    end)
    |> case do
      {:ok, fields} -> validate(Enum.reverse(fields), initial)
      error -> error
    end
  end

  def parse(_block, _initial), do: {:error, :trailers_too_large}

  def declaration(initial) do
    values = Headers.get_all(initial, "trailer")

    if Enum.reduce(values, 0, &(byte_size(&1) + &2)) > @max_bytes do
      {:error, :trailers_too_large}
    else
      validate_declaration(initial, values)
    end
  end

  defp validate_declaration(initial, values) do
    names = field_names(values)
    forbidden = @forbidden ++ connection_names(initial)

    cond do
      length(names) > @max_fields -> {:error, :trailers_too_large}
      Enum.any?(names, &(not valid_name?(&1))) -> {:error, :invalid_trailer_declaration}
      Enum.any?(names, &(&1 in forbidden)) -> {:error, :forbidden_trailer_declaration}
      true -> {:ok, names}
    end
  end

  def upload(fields, initial) do
    with {:ok, headers} <- validate(fields, initial),
         {:ok, names} <- declaration(initial) do
      if Enum.all?(headers.headers, fn {name, _} -> String.downcase(name) in names end),
        do: {:ok, headers},
        else: {:error, :undeclared_trailer}
    end
  end

  def serialize(%Headers{headers: fields}),
    do: Enum.map(fields, fn {name, value} -> [name, ": ", value, "\r\n"] end)

  defp validate_field({name, value}, forbidden) when is_binary(name) and is_binary(value) do
    cond do
      not valid_name?(name) or not valid_value?(value) -> {:error, :invalid_trailer}
      String.downcase(name) in forbidden -> {:error, {:forbidden_trailer, String.downcase(name)}}
      true -> {:ok, name, value}
    end
  end

  defp validate_field(_field, _forbidden), do: {:error, :invalid_trailer}

  defp valid_name?(name) do
    name != "" and
      Enum.all?(:binary.bin_to_list(name), fn char ->
        char in ?0..?9 or char in ?A..?Z or char in ?a..?z or char in ~c"!#$%&'*+-.^_`|~"
      end)
  end

  defp valid_value?(value),
    do: Enum.all?(:binary.bin_to_list(value), &(&1 == 9 or (&1 >= 32 and &1 != 127)))

  defp connection_names(initial), do: field_names(Headers.get_all(initial, "connection"))

  defp field_names(values),
    do:
      Enum.flat_map(values, fn value ->
        Enum.map(:binary.split(value, ",", [:global]), &String.downcase(trim_ows(&1)))
      end)

  defp trim_ows(value), do: Regex.replace(~r/\A[ \t]+|[ \t]+\z/, value, "")
end
