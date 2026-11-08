defmodule HTTP.AltSvc do
  @moduledoc """
  Pure RFC 7838 `Alt-Svc` field-value parser.

  `parse/1` returns `:clear`, a list of alternatives, or `{:error, reason}` for
  a malformed value. Each alternative is a map with the percent-decoded ALPN
  protocol id, the alternative host (`""` when omitted, IPv6 brackets removed),
  port, `max_age` in seconds (default 86,400) and `persist?`. Unknown
  parameters are ignored. Alt-authorities are accepted as quoted strings and,
  leniently, as tokens.
  """

  @default_max_age 86_400

  @type alternative :: %{
          alpn: String.t(),
          host: String.t(),
          port: 1..65_535,
          max_age: non_neg_integer(),
          persist?: boolean()
        }

  @spec default_max_age() :: pos_integer()
  def default_max_age, do: @default_max_age

  @spec parse(String.t()) :: :clear | [alternative()] | {:error, term()}
  def parse(value) when is_binary(value) do
    case String.trim(value) do
      "clear" -> :clear
      trimmed -> parse_list(trimmed)
    end
  end

  def parse(_value), do: {:error, :invalid_alt_svc}

  defp parse_list(value) do
    with {:ok, elements} <- split_unquoted(value, ?,) do
      elements
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
      |> parse_elements([])
    end
  end

  defp parse_elements([], []), do: {:error, :empty_alt_svc}
  defp parse_elements([], acc), do: Enum.reverse(acc)

  defp parse_elements([element | rest], acc) do
    case parse_alternative(element) do
      {:ok, alternative} -> parse_elements(rest, [alternative | acc])
      {:error, _} = error -> error
    end
  end

  defp parse_alternative(element) do
    with {:ok, [alternative | parameters]} <- split_unquoted(element, ?;),
         {:ok, protocol, authority} <- split_pair(alternative),
         {:ok, alpn} <- protocol_id(protocol),
         {:ok, authority} <- authority_value(authority),
         {:ok, host, port} <- alt_authority(authority),
         {:ok, params} <- parameters(parameters, %{}) do
      {:ok,
       %{
         alpn: alpn,
         host: host,
         port: port,
         max_age: Map.get(params, :max_age, @default_max_age),
         persist?: Map.get(params, :persist?, false)
       }}
    end
  end

  defp split_pair(text) do
    case :binary.split(String.trim(text), "=") do
      [name, value] when name != "" and value != "" -> {:ok, name, value}
      _ -> {:error, :invalid_alt_svc_pair}
    end
  end

  defp protocol_id(protocol) do
    if token?(protocol) and percent_encoded?(protocol),
      do: {:ok, URI.decode(protocol)},
      else: {:error, :invalid_protocol_id}
  end

  defp percent_encoded?(<<>>), do: true

  defp percent_encoded?(<<?%, high, low, rest::binary>>),
    do: hex?(high) and hex?(low) and percent_encoded?(rest)

  defp percent_encoded?(<<?%, _rest::binary>>), do: false
  defp percent_encoded?(<<_char, rest::binary>>), do: percent_encoded?(rest)

  defp hex?(char), do: char in ?0..?9 or char in ?a..?f or char in ?A..?F

  defp alt_authority(authority) do
    with [host, port] <- split_host_port(authority),
         true <- digits?(port),
         {port, ""} when port in 1..65_535 <- Integer.parse(port),
         {:ok, host} <- authority_host(host) do
      {:ok, host, port}
    else
      _ -> {:error, :invalid_alt_authority}
    end
  end

  defp split_host_port(authority) do
    case authority |> String.split(":") |> Enum.split(-1) do
      {[_ | _] = host, [port]} -> [Enum.join(host, ":"), port]
      _ -> :error
    end
  end

  defp authority_host(""), do: {:ok, ""}

  defp authority_host("[" <> rest) do
    case String.split(rest, "]") do
      [address, ""] -> ip_host(address)
      _ -> {:error, :invalid_host}
    end
  end

  defp authority_host(host) do
    if String.contains?(host, [":", "[", "]", " ", "\t", "/", "@"]),
      do: {:error, :invalid_host},
      else: {:ok, String.downcase(host)}
  end

  defp ip_host(address) do
    case :inet.parse_ipv6strict_address(String.to_charlist(address)) do
      {:ok, _} -> {:ok, String.downcase(address)}
      {:error, _} -> {:error, :invalid_host}
    end
  end

  defp parameters([], acc), do: {:ok, acc}

  defp parameters([parameter | rest], acc) do
    with {:ok, name, raw} <- split_pair(parameter),
         true <- token?(name) || {:error, :invalid_parameter},
         {:ok, value} <- value(raw),
         {:ok, acc} <- parameter(String.downcase(name), value, acc) do
      parameters(rest, acc)
    end
  end

  defp parameter("ma", value, acc) do
    if digits?(value),
      do: {:ok, Map.put(acc, :max_age, String.to_integer(value))},
      else: {:error, :invalid_max_age}
  end

  defp parameter("persist", value, acc), do: {:ok, Map.put(acc, :persist?, value == "1")}
  defp parameter(_name, _value, acc), do: {:ok, acc}

  defp value("\"" <> _ = quoted), do: unquote_string(quoted)

  defp value(raw) do
    if token?(raw), do: {:ok, raw}, else: {:error, :invalid_value}
  end

  # RFC 7838 requires a quoted alt-authority; a bare authority is accepted leniently.
  defp authority_value("\"" <> _ = quoted), do: unquote_string(quoted)

  defp authority_value(raw) do
    if raw |> :binary.bin_to_list() |> Enum.all?(&(tchar?(&1) or &1 in ~c":[]")),
      do: {:ok, raw},
      else: {:error, :invalid_alt_authority}
  end

  defp unquote_string("\"" <> rest), do: unquote_chars(rest, [])

  defp unquote_chars("\"", acc), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp unquote_chars(<<?\\, char, rest::binary>>, acc) when char >= 0x20 or char == ?\t,
    do: unquote_chars(rest, [char | acc])

  defp unquote_chars(<<char, rest::binary>>, acc)
       when char != ?" and char != ?\\ and (char >= 0x20 or char == ?\t) and char != 0x7F,
       do: unquote_chars(rest, [char | acc])

  defp unquote_chars(_rest, _acc), do: {:error, :invalid_quoted_string}

  # Splits on `separator` outside quoted strings; rejects unterminated quotes.
  defp split_unquoted(value, separator), do: split_unquoted(value, separator, false, [], [])

  defp split_unquoted(<<>>, _separator, true, _current, _parts),
    do: {:error, :invalid_quoted_string}

  defp split_unquoted(<<>>, _separator, false, current, parts),
    do: {:ok, Enum.reverse([part(current) | parts])}

  defp split_unquoted(<<?\\, char, rest::binary>>, separator, true, current, parts),
    do: split_unquoted(rest, separator, true, [char, ?\\ | current], parts)

  defp split_unquoted(<<?", rest::binary>>, separator, quoted?, current, parts),
    do: split_unquoted(rest, separator, not quoted?, [?" | current], parts)

  defp split_unquoted(<<char, rest::binary>>, separator, false, current, parts)
       when char == separator,
       do: split_unquoted(rest, separator, false, [], [part(current) | parts])

  defp split_unquoted(<<char, rest::binary>>, separator, quoted?, current, parts),
    do: split_unquoted(rest, separator, quoted?, [char | current], parts)

  defp part(current), do: current |> Enum.reverse() |> IO.iodata_to_binary()

  defp token?(""), do: false

  defp token?(value) do
    value
    |> :binary.bin_to_list()
    |> Enum.all?(&tchar?/1)
  end

  defp tchar?(char) when char in ?a..?z or char in ?A..?Z or char in ?0..?9, do: true
  defp tchar?(char), do: char in ~c"!#$%&'*+-.^_`|~"

  defp digits?(""), do: false
  defp digits?(value), do: value |> :binary.bin_to_list() |> Enum.all?(&(&1 in ?0..?9))
end
