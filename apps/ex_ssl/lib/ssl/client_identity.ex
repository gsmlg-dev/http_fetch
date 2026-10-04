defmodule SSL.ClientIdentity do
  @moduledoc false

  alias SSL.Capabilities
  alias SSL.Crypto.Signature
  alias SSL.PKIX

  @derive {Inspect, only: [:signature_schemes]}
  @enforce_keys [:chain, :private_key, :public_key, :signature_schemes]
  defstruct [:chain, :private_key, :public_key, :signature_schemes]

  @type t :: %__MODULE__{
          chain: [binary()],
          private_key: term(),
          public_key: term(),
          signature_schemes: [non_neg_integer()]
        }

  @max_certificates 16
  @max_certificate_bytes 262_144
  # Leaves room for CertificateVerify, Finished, and record overhead within
  # the current writer's one-MiB aggregate handshake output ceiling.
  @max_chain_bytes 524_288
  @max_pem_bytes 1_048_576
  @max_key_bytes 1_048_576
  @identity_keys [:cert, :certfile, :key, :keyfile]
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @rsa_pss_oid {1, 2, 840, 113_549, 1, 1, 10}
  @ec_oid {1, 2, 840, 10_045, 2, 1}
  @ed25519_oid {1, 3, 101, 112}

  @spec load(keyword()) :: {:ok, nil | t()} | {:error, {:options, atom()}}
  def load(options) when is_list(options) do
    with :ok <- validate_options(options),
         {:ok, sources} <- sources(options) do
      case sources do
        :none -> {:ok, nil}
        {cert_source, key_source} -> load_sources(cert_source, key_source)
      end
    end
  end

  def load(_options), do: error(:invalid_identity_options)

  defp validate_options(options) do
    if Keyword.keyword?(options) and
         Enum.all?(options, fn
           {key, _value} -> key in @identity_keys
           _ -> false
         end) and Enum.uniq(Keyword.keys(options)) == Keyword.keys(options) do
      :ok
    else
      error(:unsupported_identity_option)
    end
  end

  defp sources(options) do
    cert = Keyword.fetch(options, :cert)
    certfile = Keyword.fetch(options, :certfile)
    key = Keyword.fetch(options, :key)
    keyfile = Keyword.fetch(options, :keyfile)

    cond do
      cert != :error and certfile != :error ->
        error(:conflicting_identity_sources)

      key != :error and keyfile != :error ->
        error(:conflicting_identity_sources)

      sources_absent?(cert, certfile) and sources_absent?(key, keyfile) ->
        {:ok, :none}

      certfile != :error and key == :error and keyfile == :error ->
        {:ok, {{:file, elem(certfile, 1)}, {:file, elem(certfile, 1)}}}

      sources_absent?(cert, certfile) or sources_absent?(key, keyfile) ->
        error(:incomplete_identity)

      true ->
        certificate_source =
          if cert != :error, do: {:der, elem(cert, 1)}, else: {:file, elem(certfile, 1)}

        private_key_source =
          if key != :error, do: {:der, elem(key, 1)}, else: {:file, elem(keyfile, 1)}

        {:ok, {certificate_source, private_key_source}}
    end
  end

  defp load_sources(cert_source, key_source) do
    with {:ok, chain} <- certificate_chain(cert_source, key_source),
         :ok <- validate_chain_order(chain),
         {:ok, private_key} <- private_key(key_source),
         {:ok, public_key} <- leaf_public_key(hd(chain)),
         {:ok, schemes} <- matching_schemes(private_key, public_key) do
      {:ok,
       %__MODULE__{
         chain: chain,
         private_key: private_key,
         public_key: public_key,
         signature_schemes: schemes
       }}
    end
  end

  defp certificate_chain({:der, der}, _key_source) when is_binary(der), do: checked_chain([der])
  defp certificate_chain({:der, ders}, _key_source) when is_list(ders), do: checked_chain(ders)
  defp certificate_chain({:der, _}, _key_source), do: error(:invalid_certificate)

  defp certificate_chain({:file, path}, key_source) do
    with {:ok, pem} <- read_bounded(path, @max_pem_bytes),
         {:ok, entries} <- pem_entries(pem),
         certs when certs != [] <- for({:Certificate, der, :not_encrypted} <- entries, do: der),
         true <- valid_certificate_entries?(entries, same_file?(path, key_source)) do
      checked_chain(certs)
    else
      _ -> error(:invalid_certificate_file)
    end
  end

  defp valid_certificate_entries?(entries, same_file?) do
    keys = Enum.reject(entries, fn {type, _, _} -> type == :Certificate end)

    Enum.all?(keys, fn {type, _, _} -> private_key_pem_type?(type) end) and
      if(same_file?, do: length(keys) == 1, else: keys == [])
  end

  defp same_file?(cert_path, {:file, key_path}) do
    case {normalize_path(cert_path), normalize_path(key_path)} do
      {{:ok, left}, {:ok, right}} -> left == right
      _ -> false
    end
  end

  defp same_file?(_, _), do: false

  defp checked_chain(chain) do
    case PKIX.decode_chain(chain,
           max_certificates: @max_certificates,
           max_der_bytes: @max_certificate_bytes,
           max_total_der_bytes: @max_chain_bytes
         ) do
      {:ok, _decoded} -> {:ok, chain}
      _ -> error(:invalid_certificate_chain)
    end
  end

  defp validate_chain_order([_]), do: :ok

  defp validate_chain_order(chain) do
    if Enum.uniq(chain) == chain do
      chain
      |> Enum.chunk_every(2, 1, :discard)
      |> Enum.reduce_while(:ok, fn [child_der, issuer_der], :ok ->
        with {:ok, child} <- decode_certificate(child_der),
             {:ok, issuer} <- decode_certificate(issuer_der),
             true <- :public_key.pkix_is_issuer(child, issuer),
             {:ok, issuer_key} <- certificate_public_key(issuer),
             true <- :public_key.pkix_verify(child_der, issuer_key) do
          {:cont, :ok}
        else
          _ -> {:halt, error(:invalid_chain_order)}
        end
      end)
    else
      error(:invalid_chain_order)
    end
  catch
    _, _ -> error(:invalid_chain_order)
  end

  defp private_key({:der, {type, der}})
       when type in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo] and is_binary(der) and
              byte_size(der) <= @max_key_bytes do
    decode_private_key({type, der, :not_encrypted})
  end

  defp private_key({:der, _}), do: error(:unsupported_private_key)

  defp private_key({:file, path}) do
    with {:ok, pem} <- read_bounded(path, @max_pem_bytes),
         {:ok, entries} <- pem_entries(pem),
         [entry] <- Enum.reject(entries, fn {type, _, _} -> type == :Certificate end),
         true <- elem(entry, 2) == :not_encrypted,
         true <- private_key_pem_type?(elem(entry, 0)) do
      decode_private_key(entry)
    else
      _ -> error(:unsupported_private_key)
    end
  end

  defp private_key_pem_type?(type), do: type in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]

  defp decode_private_key(entry) do
    key = :public_key.pem_entry_decode(entry)

    case key do
      {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} ->
        {:ok, key}

      {:ECPrivateKey, _, _, _, _, _} ->
        {:ok, key}

      {{:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _}, {:"RSASSA-PSS-params", _, _, _, _}} ->
        {:ok, key}

      _ ->
        error(:unsupported_private_key)
    end
  catch
    _, _ -> error(:unsupported_private_key)
  end

  defp matching_schemes(private_key, public_key) do
    digest = :crypto.hash(:sha256, "ex_ssl client identity key match")

    schemes =
      Capabilities.identifiers(:signature_algorithm)
      |> Enum.filter(fn id ->
        is_integer(id) and matches_key?(id, private_key, public_key, digest)
      end)

    if schemes == [], do: error(:key_certificate_mismatch), else: {:ok, schemes}
  end

  defp matches_key?(id, private_key, public_key, digest) do
    case Signature.sign_client(id, private_key, :sha256, digest) do
      {:ok, signature} ->
        Signature.verify_client(id, public_key, :sha256, digest, signature) == :ok

      _ ->
        false
    end
  end

  defp leaf_public_key(der) do
    with {:ok, certificate} <- decode_certificate(der) do
      certificate_public_key_info(certificate)
    end
  end

  defp certificate_public_key(certificate) do
    with {:ok, info} <- certificate_public_key_info(certificate) do
      case info do
        {@rsa_pss_oid, key, _} -> {:ok, key}
        {@ed25519_oid, point, params} -> {:ok, {point, params}}
        key -> {:ok, key}
      end
    end
  end

  defp certificate_public_key_info(certificate) do
    case certificate |> elem(1) |> elem(7) do
      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_encryption_oid, _},
       {:RSAPublicKey, _, _} = key} ->
        {:ok, key}

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_pss_oid, params},
       {:RSAPublicKey, _, _} = key} ->
        {:ok, {@rsa_pss_oid, key, params}}

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @ec_oid, params}, {:ECPoint, _} = key} ->
        {:ok, {key, params}}

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @ed25519_oid, :asn1_NOVALUE},
       {:ECPoint, _} = key} ->
        {:ok, {@ed25519_oid, key, {:namedCurve, @ed25519_oid}}}

      _ ->
        error(:unsupported_certificate_key)
    end
  catch
    _, _ -> error(:unsupported_certificate_key)
  end

  defp decode_certificate(der) do
    {:ok, :public_key.pkix_decode_cert(der, :otp)}
  catch
    _, _ -> error(:invalid_certificate)
  end

  defp read_bounded(path, max_bytes) do
    with {:ok, path} <- normalize_path(path),
         {:ok, io} <- File.open(path, [:read, :binary]) do
      try do
        case IO.binread(io, max_bytes + 1) do
          bytes
          when is_binary(bytes) and byte_size(bytes) >= 1 and byte_size(bytes) <= max_bytes ->
            {:ok, bytes}

          _ ->
            error(:invalid_or_oversized_file)
        end
      after
        File.close(io)
      end
    else
      _ -> error(:invalid_or_oversized_file)
    end
  end

  defp normalize_path(path) when is_binary(path) and byte_size(path) > 0, do: {:ok, path}

  defp normalize_path(path) when is_list(path) do
    try do
      {:ok, List.to_string(path)}
    rescue
      _ -> error(:invalid_file_path)
    end
  end

  defp normalize_path(_), do: error(:invalid_file_path)

  defp pem_entries(pem) do
    case :public_key.pem_decode(pem) do
      [] -> error(:invalid_pem)
      entries when is_list(entries) -> {:ok, entries}
    end
  catch
    _, _ -> error(:invalid_pem)
  end

  defp error(reason), do: {:error, {:options, reason}}

  defp sources_absent?(direct, file), do: direct == :error and file == :error
end
