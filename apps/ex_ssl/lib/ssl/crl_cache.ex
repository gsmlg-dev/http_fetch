defmodule SSL.CRLCache do
  @moduledoc """
  Bounded storage for untrusted CRL bytes. Every handshake validates CRL
  signatures, issuer authorization and freshness against its selected path.
  """
  use GenServer
  alias SSL.PKIX.Revocation
  alias SSL.PolicyIO.HTTP

  alias SSL.PolicyIO
  alias SSL.PolicyIO.Bounded
  require Record

  Record.defrecordp(
    :dp,
    :DistributionPoint,
    Record.extract(:DistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  def start_link(_), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  def insert(source), do: insert(:no_distribution_point, source)

  def insert(uri, source) do
    with {:ok, key} <- key(uri),
         {:ok, values} <- source(source),
         {:ok, entries} <- entries(values) do
      GenServer.call(__MODULE__, {:insert, key, entries})
    end
  catch
    _, _ -> {:error, :invalid_crl_source}
  end

  def delete({kind, _} = source) when kind in [:der, :file] do
    with {:ok, values} <- source(source), do: GenServer.call(__MODULE__, {:delete_der, values})
  catch
    _, _ -> {:error, :invalid_crl_source}
  end

  def delete(uri) do
    with {:ok, key} <- key(uri), do: GenServer.call(__MODULE__, {:delete, key})
  catch
    _, _ -> {:error, :invalid_crl_source}
  end

  @doc false
  def lookup_owned(context, point, {:ssl_crl_cache, {_reference, options}}) do
    case dp(point, :distributionPoint) do
      {:fullName, names} -> names(context, bounded(names, 128), options)
      _ -> :not_available
    end
  end

  @doc false
  def select_owned(_context, issuer, _cache) do
    issuers =
      if match?({:rdnSequence, _}, issuer),
        do: [issuer],
        else: for({:directoryName, name} <- bounded(issuer, 128), do: name)

    issuers = Enum.map(issuers, &:public_key.pkix_normalize_name/1)
    GenServer.call(__MODULE__, {:select, issuers})
  end

  defp names(_, [], _), do: :not_available

  defp names(context, [{:uniformResourceIdentifier, uri} | rest], options) do
    case key(uri) do
      {:ok, key} ->
        case GenServer.call(__MODULE__, {:lookup, key}) do
          [] ->
            fetch_name(context, uri, rest, options)

          values ->
            values
        end

      _ ->
        names(context, rest, options)
    end
  end

  defp names(context, [_ | rest], options), do: names(context, rest, options)

  defp fetch_name(context, uri, rest, [{:http, timeout}] = options) do
    case HTTP.get(context, uri, timeout) do
      {:ok, bytes} -> Revocation.pem_or_der(bytes)
      {:error, :policy_capacity} -> PolicyIO.fail!(:policy_capacity)
      _ -> names(context, rest, options)
    end
  end

  defp fetch_name(context, _uri, rest, options), do: names(context, rest, options)

  defp source({:der, der}) when is_binary(der), do: der_source([der])
  defp source({:der, values}), do: der_source(values)

  defp source({:file, path}) do
    owner = self()
    reference = make_ref()
    deadline = PolicyIO.now() + 5_000

    {worker, monitor} =
      spawn_monitor(fn ->
        result = file_source(path, owner, deadline)
        send(owner, {reference, self(), result})
      end)

    receive do
      {^reference, ^worker, result} ->
        receive do
          {:DOWN, ^monitor, :process, ^worker, :normal} -> result
          {:DOWN, ^monitor, :process, ^worker, _} -> {:error, :acceptance_unconfirmed}
        after
          1_000 -> {:error, :acceptance_unconfirmed}
        end

      {:DOWN, ^monitor, :process, ^worker, _} ->
        {:error, :acceptance_unconfirmed}
    after
      6_000 ->
        Process.exit(worker, :kill)

        receive do
          {:DOWN, ^monitor, :process, ^worker, _} -> {:error, :acceptance_unconfirmed}
        after
          1_000 -> {:error, :acceptance_unconfirmed}
        end
    end
  end

  defp source(_), do: {:error, :invalid_crl_source}

  defp der_source(values) do
    with {:ok, values} <- Bounded.list(values, 256) do
      Enum.reduce_while(values, {:ok, 0}, fn der, {:ok, total} ->
        cond do
          not is_binary(der) ->
            {:halt, {:error, :invalid_crl_source}}

          byte_size(der) > 16_777_216 or total + byte_size(der) > 33_554_432 ->
            {:halt, {:error, :policy_capacity}}

          true ->
            {:cont, {:ok, total + byte_size(der)}}
        end
      end)
      |> case do
        {:ok, _} -> {:ok, values}
        error -> error
      end
    end
  end

  defp file_source(path, owner, deadline) do
    with {:ok, context} <- PolicyIO.install(nil, owner, deadline) do
      result =
        try do
          with {:ok, bytes} <- PolicyIO.read_file(context, path),
               do: {:ok, Revocation.pem_or_der(bytes)}
        catch
          _, _ -> {:error, :invalid_crl_source}
        end

      case PolicyIO.finish(context) do
        :ok ->
          result

        error ->
          # Keep any unconfirmed native obligation in the private Guard while
          # it drains; its setup timer must no longer kill this public caller.
          _ = PolicyIO.retire(context)
          error
      end
    end
  end

  defp entries(values) do
    Enum.reduce_while(values, {:ok, [], 0}, fn der, {:ok, entries, bytes} ->
      with true <- is_binary(der) and bytes + byte_size(der) <= 33_554_432,
           {:ok, _} <- Bounded.der(der, :crl) do
        crl = :public_key.der_decode(:CertificateList, der)
        issuer = crl |> :public_key.pkix_crl_issuer() |> :public_key.pkix_normalize_name()
        {:cont, {:ok, [{der, issuer} | entries], bytes + byte_size(der)}}
      else
        _ -> {:halt, {:error, :policy_capacity}}
      end
    end)
    |> case do
      {:ok, entries, _} -> {:ok, entries}
      error -> error
    end
  end

  defp key(:no_distribution_point), do: {:ok, :no_distribution_point}

  defp key(uri) when is_list(uri) do
    with {:ok, bytes} <- uri_bytes(uri, [], 0), do: key(bytes)
  end

  defp key(uri) when is_binary(uri) and byte_size(uri) <= 16_384 do
    case URI.parse(uri) do
      %URI{scheme: "http", host: host, userinfo: nil, fragment: nil} = parsed
      when is_binary(host) ->
        {:ok, {String.downcase(host), parsed.port || 80, parsed.path || "/", parsed.query}}

      _ ->
        {:error, :unsupported_crl_uri}
    end
  end

  defp key(_), do: {:error, :unsupported_crl_uri}
  defp uri_bytes([], acc, _size), do: {:ok, acc |> Enum.reverse() |> IO.iodata_to_binary()}

  defp uri_bytes([point | rest], acc, size)
       when is_integer(point) and point >= 0 and
              point <= 0x10FFFF and point not in 0xD800..0xDFFF do
    encoded = <<point::utf8>>

    if size + byte_size(encoded) <= 16_384,
      do: uri_bytes(rest, [encoded | acc], size + byte_size(encoded)),
      else: {:error, :unsupported_crl_uri}
  end

  defp uri_bytes(_, _, _), do: {:error, :unsupported_crl_uri}

  defp bounded(values, limit) do
    case Bounded.list(values, limit) do
      {:ok, values} -> values
      _ -> PolicyIO.fail!(:policy_capacity)
    end
  end

  @impl true
  def format_status(status),
    do: status |> Map.put(:state, :redacted) |> Map.put(:message, :redacted) |> Map.put(:log, [])

  @impl true
  def init(_) do
    Process.flag(:sensitive, true)
    {:ok, %{}}
  end

  @impl true
  def handle_call({:insert, key, entries}, _from, state) do
    candidate =
      Enum.reduce(entries, state, fn {der, issuer}, acc ->
        Map.put(acc, {key, :crypto.hash(:sha256, der)}, {der, issuer})
      end)

    bytes = Enum.reduce(candidate, 0, fn {_, {der, _}}, count -> count + byte_size(der) end)

    if map_size(candidate) <= 128 and bytes <= 33_554_432,
      do: {:reply, :ok, candidate},
      else: {:reply, {:error, :policy_capacity}, state}
  end

  def handle_call({:delete, key}, _, state),
    do: {:reply, :ok, Map.reject(state, fn {{uri, _}, _} -> uri == key end)}

  def handle_call({:delete_der, values}, _, state),
    do: {:reply, :ok, Map.reject(state, fn {_, {der, _}} -> der in values end)}

  def handle_call({:lookup, key}, _, state),
    do: {:reply, for({{uri, _}, {der, _}} <- state, uri == key, do: der), state}

  def handle_call({:select, issuers}, _, state),
    do:
      {:reply, for({_, {der, issuer}} <- state, issuer in issuers, do: der) |> Enum.uniq(), state}
end
