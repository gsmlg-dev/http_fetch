defmodule HTTP.QUIC.TLSOptions do
  @moduledoc false

  @default_alpn ["ex-quic-phase1"]
  @allowed [
    :alpn,
    :cacerts,
    :cacertfile,
    :cert,
    :certfile,
    :ciphers,
    :customize_hostname_check,
    :depth,
    :groups,
    :key,
    :keyfile,
    :profile,
    :reference_identity,
    :server_name_indication,
    :signature_algorithms,
    :verify
  ]
  @private_key_types [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]
  @max_file_bytes 1_048_576

  @spec normalize(String.t(), keyword()) :: {:ok, keyword()} | {:error, term()}
  def normalize(host, options) do
    with :ok <- valid_options(options),
         :ok <- verify_peer(options),
         {:ok, cacerts} <- trust(options),
         {:ok, reference_identity} <- reference_identity(host, options),
         {:ok, server_name} <- server_name(options),
         {:ok, alpn} <- alpn(options),
         {:ok, identity} <- identity(options),
         :ok <- algorithms(options),
         :ok <- profile(options),
         :ok <- verifier_options(options) do
      {:ok,
       [
         cacerts: cacerts,
         reference_identity: reference_identity,
         alpn: alpn
       ]
       |> maybe_put(:server_name, server_name)
       |> merge_identity(identity)
       |> copy_optional(options, :ciphers)
       |> copy_optional(options, :groups)
       |> copy_optional(options, :signature_algorithms)
       |> copy_optional(options, :profile)
       |> copy_optional(options, :depth)
       |> copy_optional(options, :customize_hostname_check)}
    end
  end

  defp valid_options(options) when is_list(options) do
    cond do
      not Keyword.keyword?(options) ->
        {:error, :invalid_tls_options}

      Keyword.keys(options) != Enum.uniq(Keyword.keys(options)) ->
        {:error, :duplicate_tls_option}

      true ->
        case Enum.find(Keyword.keys(options), &(&1 not in @allowed)) do
          nil -> :ok
          key -> {:error, {:unsupported_tls_option, key}}
        end
    end
  end

  defp valid_options(_options), do: {:error, :invalid_tls_options}

  defp verify_peer(options) do
    case Keyword.get(options, :verify, :verify_peer) do
      :verify_peer -> :ok
      :verify_none -> {:error, :verify_none_not_supported}
      _ -> {:error, :invalid_verify_option}
    end
  end

  defp trust(options) do
    case {Keyword.fetch(options, :cacerts), Keyword.fetch(options, :cacertfile)} do
      {{:ok, _}, {:ok, _}} -> {:error, :conflicting_ca_sources}
      {{:ok, cacerts}, :error} -> normalize_cacerts(cacerts)
      {:error, {:ok, path}} -> path |> read_file(:invalid_ca_file) |> with_cacerts()
      {:error, :error} -> {:error, :ca_trust_required}
    end
  end

  defp with_cacerts({:ok, pem}), do: normalize_cacerts(pem)
  defp with_cacerts({:error, _reason} = error), do: error

  defp normalize_cacerts(pem) when is_binary(pem) do
    with {:ok, entries} <- pem_entries(pem),
         ders when ders != [] <- for({:Certificate, der, :not_encrypted} <- entries, do: der),
         true <- length(ders) == length(entries),
         :ok <- validate_certificates(ders) do
      {:ok, ders}
    else
      _ -> {:error, :invalid_ca_trust}
    end
  end

  defp normalize_cacerts(cacerts) when is_list(cacerts) and cacerts != [] do
    with {:ok, ders} <- trust_ders(cacerts), :ok <- validate_certificates(ders) do
      {:ok, ders}
    end
  end

  defp normalize_cacerts(_cacerts), do: {:error, :invalid_ca_trust}

  defp trust_ders(cacerts) do
    cacerts
    |> Enum.reduce_while({:ok, []}, fn
      {:cert, der, _decoded}, {:ok, acc} when is_binary(der) -> {:cont, {:ok, [der | acc]}}
      der, {:ok, acc} when is_binary(der) -> {:cont, {:ok, [der | acc]}}
      _entry, _acc -> {:halt, {:error, :invalid_ca_trust}}
    end)
    |> case do
      {:ok, ders} -> {:ok, Enum.reverse(ders)}
      error -> error
    end
  end

  defp reference_identity(host, options) do
    case Keyword.fetch(options, :reference_identity) do
      {:ok, identity} -> normalize_reference_identity(identity)
      :error -> host_reference_identity(host)
    end
  end

  defp normalize_reference_identity({:dns_id, name}) when is_binary(name), do: dns_identity(name)

  defp normalize_reference_identity({:ip, ip}) do
    case parse_ip(ip) do
      {:ok, parsed} -> {:ok, {:ip, parsed}}
      :error -> {:error, :invalid_reference_identity}
    end
  end

  defp normalize_reference_identity(_identity), do: {:error, :invalid_reference_identity}

  defp host_reference_identity(host) when is_binary(host) do
    case parse_ip(host) do
      {:ok, ip} -> {:ok, {:ip, ip}}
      :error -> dns_identity(host)
    end
  end

  defp host_reference_identity(_host), do: {:error, :invalid_reference_identity}

  defp dns_identity(name) do
    if String.valid?(name) and byte_size(name) in 1..253 do
      {:ok, {:dns_id, name}}
    else
      {:error, :invalid_reference_identity}
    end
  end

  defp server_name(options) do
    case Keyword.get(options, :server_name_indication) do
      nil ->
        {:ok, nil}

      name when is_binary(name) and byte_size(name) in 1..253 ->
        {:ok, name}

      name when is_list(name) ->
        try do
          name |> List.to_string() |> server_name_value()
        rescue
          _ -> {:error, :invalid_server_name}
        end

      _ ->
        {:error, :invalid_server_name}
    end
  end

  defp server_name_value(name) when byte_size(name) in 1..253, do: {:ok, name}
  defp server_name_value(_name), do: {:error, :invalid_server_name}

  defp alpn(options) do
    case Keyword.get(options, :alpn, @default_alpn) do
      protocols when is_list(protocols) and protocols != [] ->
        if protocols == Enum.uniq(protocols) and
             Enum.all?(protocols, &(is_binary(&1) and byte_size(&1) in 1..255)) and
             Enum.sum(Enum.map(protocols, &(byte_size(&1) + 1))) <= 65_533 and
             Enum.all?(protocols, &(not h3_protocol?(&1))) do
          {:ok, protocols}
        else
          {:error, :invalid_alpn}
        end

      _ ->
        {:error, :invalid_alpn}
    end
  end

  defp identity(options) do
    with {:ok, source} <- identity_source(options),
         :ok <- validate_identity(source) do
      {:ok, source}
    end
  end

  defp identity_source(options) do
    case {Keyword.fetch(options, :cert), Keyword.fetch(options, :certfile),
          Keyword.fetch(options, :key), Keyword.fetch(options, :keyfile)} do
      {:error, :error, :error, :error} -> {:ok, []}
      {{:ok, _cert}, {:ok, _certfile}, _key, _keyfile} -> {:error, :conflicting_identity_sources}
      {_cert, _certfile, {:ok, _key}, {:ok, _keyfile}} -> {:error, :conflicting_identity_sources}
      {{:ok, cert}, :error, {:ok, key}, :error} -> {:ok, [cert: cert, key: key]}
      {:error, {:ok, certfile}, :error, {:ok, keyfile}} -> load_identity_files(certfile, keyfile)
      _ -> {:error, :incomplete_identity}
    end
  end

  defp load_identity_files(certfile, keyfile) do
    with {:ok, cert_pem} <- read_file(certfile, :invalid_certificate_file),
         {:ok, key_pem} <- read_file(keyfile, :invalid_private_key_file),
         {:ok, cert_entries} <- pem_entries(cert_pem),
         certs when certs != [] <-
           for({:Certificate, der, :not_encrypted} <- cert_entries, do: der),
         true <- length(certs) == length(cert_entries),
         :ok <- validate_certificates(certs),
         {:ok, key_entries} <- pem_entries(key_pem),
         [{type, key, :not_encrypted}] when type in @private_key_types <- key_entries do
      {:ok, [cert: certs, key: {type, key}]}
    else
      {:error, _reason} = error -> error
      _ -> {:error, :invalid_identity}
    end
  end

  defp validate_identity([]), do: :ok

  defp validate_identity(identity) do
    case SSL.ClientIdentity.load(identity) do
      {:ok, %SSL.ClientIdentity{}} -> :ok
      _ -> {:error, :invalid_identity}
    end
  end

  defp algorithms(options) do
    with :ok <- validate_algorithm(options, :ciphers, :cipher_suites),
         :ok <- validate_algorithm(options, :groups, :groups) do
      validate_algorithm(options, :signature_algorithms, :signatures)
    end
  end

  defp validate_algorithm(options, option, capability) do
    case Keyword.fetch(options, option) do
      :error ->
        :ok

      {:ok, values} when is_list(values) and values != [] ->
        supported = SSL.QUIC.capabilities() |> Map.fetch!(capability)
        available = for %{available: true, id: id} <- supported, do: id

        cond do
          values != Enum.uniq(values) -> {:error, {:invalid_algorithm_option, option}}
          Enum.all?(values, &(&1 in available)) -> :ok
          true -> {:error, {:unsupported_algorithm, option}}
        end

      {:ok, _values} ->
        {:error, {:invalid_algorithm_option, option}}
    end
  end

  defp profile(options) do
    case Keyword.fetch(options, :profile) do
      :error ->
        :ok

      {:ok,
       %SSL.ClientHello.WireProfile{
         session_id: :empty,
         record: %SSL.ClientHello.RecordPolicy{mode: :none}
       }} ->
        :ok

      {:ok, _profile} ->
        {:error, :invalid_profile}
    end
  end

  defp verifier_options(options) do
    with :ok <- depth(options), do: hostname_check(options)
  end

  defp depth(options) do
    case Keyword.get(options, :depth, 10) do
      depth when is_integer(depth) and depth >= 0 -> :ok
      _ -> {:error, :invalid_depth}
    end
  end

  defp hostname_check(options) do
    case Keyword.get(options, :customize_hostname_check, []) do
      [] -> :ok
      [match_fun: fun] when is_function(fun, 2) -> :ok
      _ -> {:error, :invalid_customize_hostname_check}
    end
  end

  defp read_file(path, error) do
    with {:ok, path} <- path(path, error),
         {:ok, io} <- File.open(path, [:read, :binary]) do
      try do
        case IO.binread(io, @max_file_bytes + 1) do
          bytes when is_binary(bytes) and byte_size(bytes) in 1..@max_file_bytes -> {:ok, bytes}
          _ -> {:error, error}
        end
      after
        File.close(io)
      end
    else
      _ -> {:error, error}
    end
  end

  defp path(path, _error) when is_binary(path) and byte_size(path) > 0, do: {:ok, path}

  defp path(path, error) when is_list(path) do
    case List.to_string(path) do
      "" -> {:error, error}
      value -> {:ok, value}
    end
  rescue
    ArgumentError -> {:error, error}
  end

  defp path(_path, error), do: {:error, error}

  defp pem_entries(pem) do
    case :public_key.pem_decode(pem) do
      [] -> {:error, :invalid_pem}
      entries -> {:ok, entries}
    end
  catch
    :error, _reason -> {:error, :invalid_pem}
  end

  defp validate_certificates(ders) do
    if Enum.all?(ders, &valid_certificate?/1), do: :ok, else: {:error, :invalid_ca_trust}
  end

  defp valid_certificate?(der) when is_binary(der) do
    _certificate = :public_key.pkix_decode_cert(der, :otp)
    true
  catch
    :error, _reason -> false
  end

  defp valid_certificate?(_der), do: false

  defp parse_ip(ip) when is_tuple(ip) do
    case :inet.ntoa(ip) do
      value when is_list(value) -> {:ok, ip}
      _ -> :error
    end
  catch
    _kind, _reason -> :error
  end

  defp parse_ip(ip) when is_binary(ip) and byte_size(ip) > 0 do
    if String.valid?(ip) do
      try do
        case :inet.parse_address(String.to_charlist(ip)) do
          {:ok, address} -> {:ok, address}
          _ -> :error
        end
      rescue
        ArgumentError -> :error
      end
    else
      :error
    end
  end

  defp parse_ip(_ip), do: :error

  defp h3_protocol?(<<"h3", _rest::binary>>), do: true
  defp h3_protocol?(_protocol), do: false

  defp maybe_put(options, _key, nil), do: options
  defp maybe_put(options, key, value), do: Keyword.put(options, key, value)

  defp merge_identity(options, identity), do: Keyword.merge(options, identity)

  defp copy_optional(options, source, key) do
    case Keyword.fetch(source, key) do
      {:ok, value} -> Keyword.put(options, key, value)
      :error -> options
    end
  end
end
