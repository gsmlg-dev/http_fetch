defmodule SSL.TCPOptions do
  @moduledoc false

  @mutable [:nodelay, :keepalive, :sndbuf, :recbuf]
  @bind [:ip, :port]

  @spec extract(term(), term()) :: {:ok, list(), list()} | {:error, {:options, term()}}
  def extract(host, raw) when is_list(raw) do
    with :ok <- proper_list(raw),
         {:ok, tls, tcp, family} <- split(raw, :connect),
         :ok <- validate_family(host, tcp, family),
         :ok <- validate_upgrade(host, tcp, family) do
      family = family || inferred_family(host, tcp)
      {:ok, tls, tcp ++ if(family, do: [family], else: [])}
    end
  end

  def extract(_, _), do: error(:invalid_options)

  @spec extract_setopts(term()) :: {:ok, list(), list()} | {:error, {:options, term()}}
  def extract_setopts(raw) when is_list(raw) do
    with :ok <- proper_list(raw),
         {:ok, tls, tcp, nil} <- split(raw, :setopts),
         do: {:ok, tls, tcp}
  end

  def extract_setopts(_), do: error(:invalid_options)

  @spec mutable(list()) :: list()
  def mutable(options), do: Enum.filter(options, &match?({key, _} when key in @mutable, &1))

  defp split(raw, phase) do
    Enum.reduce_while(raw, {:ok, [], [], nil, MapSet.new()}, fn option,
                                                                {:ok, tls, tcp, family, seen} ->
      case option do
        atom when atom in [:inet, :inet6] ->
          cond do
            phase == :setopts -> {:halt, error({atom, :unsupported_or_invalid})}
            family != nil -> {:halt, error({atom, :conflicting_family})}
            true -> {:cont, {:ok, tls, tcp, atom, seen}}
          end

        {key, value} when key in @mutable or key in @bind ->
          cond do
            MapSet.member?(seen, key) ->
              {:halt, error({key, :duplicate})}

            phase == :setopts and key in @bind ->
              {:halt, error({key, :unsupported_or_invalid})}

            not valid?(key, value) ->
              {:halt, error({key, :unsupported_or_invalid})}

            true ->
              {:cont, {:ok, tls, [{key, value} | tcp], family, MapSet.put(seen, key)}}
          end

        _ ->
          {:cont, {:ok, [option | tls], tcp, family, seen}}
      end
    end)
    |> case do
      {:ok, tls, tcp, family, _} -> {:ok, Enum.reverse(tls), Enum.reverse(tcp), family}
      error -> error
    end
  end

  defp valid?(key, value) when key in [:nodelay, :keepalive], do: is_boolean(value)

  defp valid?(key, value) when key in [:sndbuf, :recbuf],
    do: is_integer(value) and value in 1..0x7FFFFFFF

  defp valid?(:port, value), do: is_integer(value) and value in 0..65_535
  defp valid?(:ip, value), do: is_tuple(value) and address_family(value) in [:inet, :inet6]

  defp validate_upgrade(:upgrade, tcp, family) do
    cond do
      family != nil -> error({family, :unsupported_for_upgrade})
      Keyword.has_key?(tcp, :ip) -> error({:ip, :unsupported_for_upgrade})
      Keyword.has_key?(tcp, :port) -> error({:port, :unsupported_for_upgrade})
      true -> :ok
    end
  end

  defp validate_upgrade(_, _, _), do: :ok

  defp validate_family(host, tcp, family) do
    host_family = address_family(host)
    local_family = address_family(Keyword.get(tcp, :ip))

    cond do
      family != nil and host_family != nil and family != host_family ->
        error({family, :address_family_mismatch})

      family != nil and local_family != nil and family != local_family ->
        error({:ip, :address_family_mismatch})

      host_family != nil and local_family != nil and host_family != local_family ->
        error({:ip, :address_family_mismatch})

      true ->
        :ok
    end
  end

  defp inferred_family(host, tcp),
    do: address_family(host) || address_family(Keyword.get(tcp, :ip))

  defp address_family(value) when is_tuple(value) and tuple_size(value) == 4 do
    if value |> Tuple.to_list() |> Enum.all?(&valid_octet?/1), do: :inet
  end

  defp address_family(value) when is_tuple(value) and tuple_size(value) == 8 do
    if value |> Tuple.to_list() |> Enum.all?(&valid_hextet?/1), do: :inet6
  end

  defp address_family(value) when is_binary(value) do
    if String.valid?(value), do: address_family(String.to_charlist(value))
  end

  defp address_family(value) when is_list(value) do
    case :inet.parse_address(value) do
      {:ok, address} -> address_family(address)
      {:error, _} -> nil
    end
  rescue
    _ -> nil
  end

  defp address_family(_), do: nil
  defp valid_octet?(value), do: is_integer(value) and value in 0..255
  defp valid_hextet?(value), do: is_integer(value) and value in 0..65_535

  defp proper_list(options) do
    _ = length(options)
    :ok
  rescue
    ArgumentError -> error(:invalid_options)
  end

  defp error(reason), do: {:error, {:options, reason}}
end
