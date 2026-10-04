defmodule SSL.PKIX do
  @moduledoc """
  Pure, bounded certificate decoding, trust normalization, and peer verification.

  Certificate chains are accepted in TLS leaf-first order. Trust sources are
  supplied in memory as a DER list or PEM bundle; this module performs no file,
  network, or operating-system trust lookup.
  """

  alias SSL.PKIX.Certificate
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.PKIX.VerifiedPeer

  require Record

  Record.defrecordp(
    :otp_certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :otp_tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :certificate_extension,
    :Extension,
    Record.extract(:Extension, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @default_max_certificates 128
  @default_max_trust_anchors 4_096
  @default_max_der_bytes 1_048_576
  @default_max_total_der_bytes 8_388_608
  @default_max_pem_bytes 8_388_608
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @ec_public_key_oid {1, 2, 840, 10_045, 2, 1}
  @rsa_pss_oid {1, 2, 840, 113_549, 1, 1, 10}
  @ed25519_oid {1, 3, 101, 112}
  @subject_alt_name_oid {2, 5, 29, 17}
  @maximum_dns_name_length 253
  @option_keys [
    :max_certificates,
    :max_trust_anchors,
    :max_der_bytes,
    :max_total_der_bytes,
    :max_pem_bytes,
    :depth,
    :customize_hostname_check,
    :certificate_signature_schemes
  ]

  @type identity :: {:dns_id, binary()} | {:ip, binary() | :inet.ip_address()}
  @type option ::
          {:max_certificates, pos_integer()}
          | {:max_trust_anchors, pos_integer()}
          | {:max_der_bytes, pos_integer()}
          | {:max_total_der_bytes, pos_integer()}
          | {:max_pem_bytes, pos_integer()}
          | {:depth, non_neg_integer()}
          | {:customize_hostname_check, keyword()}
          | {:certificate_signature_schemes, [non_neg_integer()] | nil}
  @type error_reason ::
          :empty_certificate_chain
          | :empty_trust_anchors
          | :hostname_mismatch
          | :malformed_pem
          | {:invalid_input, :certificate_chain | :trust_source | :options}
          | {:invalid_identity, term()}
          | {:invalid_certificate, non_neg_integer()}
          | {:certificate_count_limit_exceeded, non_neg_integer(), pos_integer()}
          | {:certificate_der_limit_exceeded, non_neg_integer(), non_neg_integer(), pos_integer()}
          | {:certificate_total_der_limit_exceeded, non_neg_integer(), pos_integer()}
          | {:pem_limit_exceeded, non_neg_integer(), pos_integer()}
          | {:path_validation_failed, term()}
          | {:certificate_signature_scheme_not_allowed, [non_neg_integer()]}

  @spec decode_chain(term(), [option()]) ::
          {:ok, [Certificate.t()]} | {:error, error_reason()}
  def decode_chain(chain, options \\ []) do
    with {:ok, limits} <- limits(options),
         :ok <- nonempty_list(chain, :certificate_chain) do
      decode_der_list(chain, limits)
    end
  end

  @spec normalize_trust(term(), [option()]) ::
          {:ok, [Certificate.t()]} | {:error, error_reason()}
  def normalize_trust(source, options \\ []) do
    with {:ok, limits} <- limits(options) do
      normalize_trust_source(source, %{limits | max_certificates: limits.max_trust_anchors})
    end
  end

  @spec verify(term(), term(), term(), [option()]) ::
          {:ok, VerifiedPeer.t()} | {:error, error_reason()}
  def verify(chain, trust_source, identity, options \\ []) do
    with :ok <- validate_identity(identity),
         {:ok, chain} <- decode_chain(chain, options),
         {:ok, trust_anchors} <- normalize_trust(trust_source, options),
         {:ok, public_key} <-
           validate_path(
             chain,
             trust_anchors,
             Keyword.get(options, :depth, 10),
             Keyword.get(options, :certificate_signature_schemes)
           ),
         [leaf | _] <- chain,
         :ok <-
           verify_identity(
             leaf.decoded,
             identity,
             Keyword.get(options, :customize_hostname_check, [])
           ) do
      {:ok,
       %VerifiedPeer{
         leaf_der: leaf.der,
         leaf: leaf.decoded,
         public_key: public_key,
         chain: Enum.map(chain, & &1.der)
       }}
    end
  end

  defp normalize_trust_source(<<>>, _limits), do: {:error, :empty_trust_anchors}

  defp normalize_trust_source(pem, limits) when is_binary(pem) do
    pem_size = byte_size(pem)

    if pem_size > limits.max_pem_bytes do
      {:error, {:pem_limit_exceeded, pem_size, limits.max_pem_bytes}}
    else
      decode_pem(pem, limits)
    end
  end

  defp normalize_trust_source(source, limits) when is_list(source) do
    with :ok <- nonempty_list(source, :trust_source),
         {:ok, ders} <- trust_der_entries(source) do
      decode_der_list(ders, limits)
    end
  end

  defp normalize_trust_source(_source, _limits),
    do: {:error, {:invalid_input, :trust_source}}

  # OTP returns CA certificates as tagged tuples. The decoded term is deliberately
  # ignored so all trust anchors follow the same bounded DER decoding path.
  defp trust_der_entries(entries) do
    entries
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, []}, fn
      {{:cert, der, _decoded}, _index}, {:ok, ders} when is_binary(der) ->
        {:cont, {:ok, [der | ders]}}

      {der, _index}, {:ok, ders} when is_binary(der) ->
        {:cont, {:ok, [der | ders]}}

      {_entry, index}, _acc ->
        {:halt, {:error, {:invalid_certificate, index}}}
    end)
    |> case do
      {:ok, ders} -> {:ok, Enum.reverse(ders)}
      {:error, _reason} = error -> error
    end
  end

  defp decode_pem(pem, limits) do
    case safe_pem_decode(pem) do
      [] ->
        {:error, :malformed_pem}

      entries when is_list(entries) ->
        entries
        |> Enum.reduce_while({:ok, []}, fn
          {:Certificate, der, :not_encrypted}, {:ok, certificates} ->
            {:cont, {:ok, [der | certificates]}}

          _entry, _accumulator ->
            {:halt, {:error, :malformed_pem}}
        end)
        |> case do
          {:ok, ders} -> decode_der_list(Enum.reverse(ders), limits)
          {:error, _reason} = error -> error
        end

      :error ->
        {:error, :malformed_pem}
    end
  end

  defp safe_pem_decode(pem) do
    :public_key.pem_decode(pem)
  catch
    _kind, _reason -> :error
  end

  defp decode_der_list(ders, limits) do
    count = length(ders)

    if count > limits.max_certificates do
      {:error, {:certificate_count_limit_exceeded, count, limits.max_certificates}}
    else
      decode_der_entries(ders, limits)
    end
  end

  defp decode_der_entries(ders, limits) do
    ders
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, [], 0}, fn {der, index}, {:ok, certificates, total} ->
      case decode_der(der, index, total, limits) do
        {:ok, certificate, new_total} ->
          {:cont, {:ok, [certificate | certificates], new_total}}

        {:error, _reason} = error ->
          {:halt, error}
      end
    end)
    |> case do
      {:ok, certificates, _total} -> {:ok, Enum.reverse(certificates)}
      {:error, _reason} = error -> error
    end
  end

  defp decode_der(der, index, total, limits) when is_binary(der) do
    der_size = byte_size(der)
    new_total = total + der_size

    cond do
      der_size > limits.max_der_bytes ->
        {:error, {:certificate_der_limit_exceeded, index, der_size, limits.max_der_bytes}}

      new_total > limits.max_total_der_bytes ->
        {:error, {:certificate_total_der_limit_exceeded, new_total, limits.max_total_der_bytes}}

      true ->
        case safe_decode_cert(der) do
          {:ok, decoded} -> {:ok, %Certificate{der: der, decoded: decoded}, new_total}
          :error -> {:error, {:invalid_certificate, index}}
        end
    end
  end

  defp decode_der(_der, index, _total, _limits),
    do: {:error, {:invalid_certificate, index}}

  defp safe_decode_cert(der) do
    {:ok, :public_key.pkix_decode_cert(der, :otp)}
  catch
    _kind, _reason -> :error
  end

  defp validate_path(chain, trust_anchors, depth, signature_schemes) do
    Enum.reduce_while(trust_anchors, {:error, {:path_validation_failed, :unknown_ca}}, fn anchor,
                                                                                          previous_error ->
      path = otp_path(chain, anchor)

      case safe_path_validation(anchor.der, path, depth) do
        {:ok, public_key} ->
          if signature_schemes == nil or
               CertificateSignaturePolicy.compatible?(
                 Enum.map(chain, & &1.der),
                 anchor.der,
                 signature_schemes
               ) do
            {:halt, {:ok, public_key}}
          else
            {:cont, {:error, {:certificate_signature_scheme_not_allowed, signature_schemes}}}
          end

        {:error, reason} ->
          case previous_error do
            {:error, {:certificate_signature_scheme_not_allowed, _}} ->
              {:cont, previous_error}

            _ ->
              {:cont, {:error, {:path_validation_failed, reason}}}
          end
      end
    end)
  end

  defp otp_path(chain, anchor) do
    chain
    |> maybe_drop_anchor(anchor.der)
    |> Enum.map(& &1.der)
    |> Enum.reverse()
  end

  defp maybe_drop_anchor(chain, anchor_der) do
    case List.last(chain) do
      %Certificate{der: ^anchor_der} -> Enum.drop(chain, -1)
      _certificate -> chain
    end
  end

  defp safe_path_validation(anchor_der, path, depth) do
    case :public_key.pkix_path_validation(anchor_der, path, max_path_length: depth) do
      {:ok, {public_key_info, _policy_tree}} ->
        {:ok, certificate_verify_key(public_key_info)}

      {:error, reason} ->
        {:error, reason}
    end
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp certificate_verify_key({@ec_public_key_oid, {:ECPoint, _point} = public_key, parameters}),
    do: {public_key, parameters}

  defp certificate_verify_key(
         {@rsa_encryption_oid, {:RSAPublicKey, _modulus, _exponent} = public_key, _parameters}
       ),
       do: public_key

  # Retain the SubjectPublicKeyInfo algorithm and restrictions for TLS
  # CertificateVerify scheme selection. OTP's bare RSA key omits this policy.
  defp certificate_verify_key({@rsa_pss_oid, {:RSAPublicKey, _, _}, _} = public_key_info),
    do: public_key_info

  defp certificate_verify_key({@ed25519_oid, {:ECPoint, _}, _} = public_key_info),
    do: public_key_info

  defp certificate_verify_key(public_key_info), do: public_key_info

  defp verify_identity(certificate, identity, hostname_options) do
    if san_matches_identity?(subject_alt_names(certificate), identity, hostname_options) do
      :ok
    else
      {:error, :hostname_mismatch}
    end
  end

  defp subject_alt_names(certificate) do
    certificate
    |> otp_certificate(:tbsCertificate)
    |> otp_tbs_certificate(:extensions)
    |> find_subject_alt_name()
  end

  defp find_subject_alt_name(:asn1_NOVALUE), do: []

  defp find_subject_alt_name(extensions) when is_list(extensions) do
    Enum.find_value(extensions, [], fn extension ->
      if certificate_extension(extension, :extnID) == @subject_alt_name_oid do
        certificate_extension(extension, :extnValue)
      end
    end)
  end

  defp find_subject_alt_name(_extensions), do: []

  defp san_matches_identity?(names, {:dns_id, reference}, options) do
    Enum.any?(names, fn
      {:dNSName, name} ->
        customized_name_matches?({:dns_id, reference}, {:dNSName, name}, options)

      _name ->
        false
    end)
  end

  defp san_matches_identity?(names, {:ip, reference} = identity, options) do
    case ip_reference_bytes(reference) do
      {:ok, reference_bytes} ->
        Enum.any?(names, fn
          {:iPAddress, bytes} ->
            customized_name_matches?(
              identity,
              {:iPAddress, bytes},
              options,
              bytes == reference_bytes
            )

          _name ->
            false
        end)

      :error ->
        false
    end
  end

  defp customized_name_matches?(
         {:dns_id, reference} = reference_id,
         {:dNSName, name} = presented,
         options
       ) do
    case hostname_match_fun(options, reference_id, presented) do
      true -> true
      false -> false
      :default -> dns_name_matches?(name, reference)
    end
  end

  defp customized_name_matches?(reference, presented, options, default) do
    case hostname_match_fun(options, reference, presented) do
      true -> true
      false -> false
      :default -> default
    end
  end

  defp hostname_match_fun(options, reference, presented) do
    case Keyword.get(options, :match_fun) do
      nil ->
        :default

      fun when is_function(fun, 2) ->
        case fun.(reference, presented) do
          true -> true
          false -> false
          :default -> :default
          _other -> false
        end
    end
  catch
    _kind, _reason -> false
  end

  defp dns_name_matches?(name, reference) when is_list(name),
    do: dns_name_matches?(List.to_string(name), reference)

  defp dns_name_matches?(name, reference) when is_binary(name) and is_binary(reference) do
    with {:ok, presented_labels} <- presented_dns_labels(name),
         {:ok, reference_labels} <- dns_labels(reference) do
      case {presented_labels, reference_labels} do
        {["*" | presented_suffix], [_reference_label | reference_suffix]} ->
          presented_suffix == reference_suffix

        {presented_labels, reference_labels} ->
          presented_labels == reference_labels
      end
    else
      :error -> false
    end
  end

  defp dns_name_matches?(_name, _reference), do: false

  defp presented_dns_labels(name) when byte_size(name) <= @maximum_dns_name_length do
    case :binary.split(name, ".", [:global]) do
      ["*" | suffix] when suffix != [] ->
        normalize_dns_labels(suffix, ["*"])

      labels ->
        normalize_dns_labels(labels, [])
    end
  end

  defp presented_dns_labels(_name), do: :error

  defp dns_labels(name) when byte_size(name) <= @maximum_dns_name_length do
    name
    |> :binary.split(".", [:global])
    |> normalize_dns_labels([])
  end

  defp dns_labels(_name), do: :error

  defp normalize_dns_labels(labels, prefix) do
    if Enum.all?(labels, &valid_dns_label?/1) do
      {:ok, prefix ++ Enum.map(labels, &String.downcase/1)}
    else
      :error
    end
  end

  defp valid_dns_label?(label) when byte_size(label) in 1..63 do
    first = :binary.first(label)
    last = :binary.last(label)

    ascii_alphanumeric?(first) and ascii_alphanumeric?(last) and
      Enum.all?(:binary.bin_to_list(label), &(ascii_alphanumeric?(&1) or &1 == ?-))
  end

  defp valid_dns_label?(_label), do: false

  defp ascii_alphanumeric?(character),
    do: character in ?0..?9 or character in ?A..?Z or character in ?a..?z

  defp ip_reference_bytes(reference) when is_binary(reference) do
    case :inet.parse_address(String.to_charlist(reference)) do
      {:ok, address} -> ip_reference_bytes(address)
      {:error, _reason} -> :error
    end
  end

  defp ip_reference_bytes({a, b, c, d})
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255,
       do: {:ok, <<a, b, c, d>>}

  defp ip_reference_bytes({a, b, c, d, e, f, g, h})
       when a in 0..65_535 and b in 0..65_535 and c in 0..65_535 and d in 0..65_535 and
              e in 0..65_535 and f in 0..65_535 and g in 0..65_535 and h in 0..65_535,
       do: {:ok, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}

  defp ip_reference_bytes(_reference), do: :error

  defp validate_identity({:dns_id, hostname})
       when is_binary(hostname) and byte_size(hostname) > 0 do
    if valid_dns_reference?(hostname) do
      :ok
    else
      {:error, {:invalid_identity, {:dns_id, hostname}}}
    end
  end

  defp validate_identity({:ip, address}) when is_binary(address) and byte_size(address) > 0 do
    if String.valid?(address), do: :ok, else: {:error, {:invalid_identity, {:ip, address}}}
  end

  defp validate_identity({:ip, {a, b, c, d}})
       when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255,
       do: :ok

  defp validate_identity({:ip, {a, b, c, d, e, f, g, h}})
       when a in 0..65_535 and b in 0..65_535 and c in 0..65_535 and d in 0..65_535 and
              e in 0..65_535 and f in 0..65_535 and g in 0..65_535 and h in 0..65_535,
       do: :ok

  defp validate_identity(identity), do: {:error, {:invalid_identity, identity}}

  defp valid_dns_reference?(hostname) do
    match?({:ok, _labels}, dns_labels(hostname))
  end

  defp nonempty_list([], :certificate_chain), do: {:error, :empty_certificate_chain}
  defp nonempty_list([], :trust_source), do: {:error, :empty_trust_anchors}
  defp nonempty_list([_value | rest], field), do: proper_list_tail(rest, field)
  defp nonempty_list(_value, field), do: {:error, {:invalid_input, field}}

  defp proper_list_tail([], _field), do: :ok
  defp proper_list_tail([_value | rest], field), do: proper_list_tail(rest, field)
  defp proper_list_tail(_tail, field), do: {:error, {:invalid_input, field}}

  defp limits(options) when is_list(options) do
    if Keyword.keyword?(options) do
      limit_options = Keyword.drop(options, [:customize_hostname_check])

      if Enum.all?(limit_options, fn {key, value} ->
           key in @option_keys and valid_pkix_option?(key, value)
         end) and
           valid_hostname_options?(Keyword.get(options, :customize_hostname_check, [])) do
        {:ok,
         %{
           max_certificates: Keyword.get(options, :max_certificates, @default_max_certificates),
           max_trust_anchors:
             Keyword.get(options, :max_trust_anchors, @default_max_trust_anchors),
           max_der_bytes: Keyword.get(options, :max_der_bytes, @default_max_der_bytes),
           max_total_der_bytes:
             Keyword.get(options, :max_total_der_bytes, @default_max_total_der_bytes),
           max_pem_bytes: Keyword.get(options, :max_pem_bytes, @default_max_pem_bytes)
         }}
      else
        {:error, {:invalid_input, :options}}
      end
    else
      {:error, {:invalid_input, :options}}
    end
  end

  defp limits(_options), do: {:error, {:invalid_input, :options}}

  defp valid_limit?(value), do: is_integer(value) and value > 0
  defp valid_pkix_option?(:depth, value), do: is_integer(value) and value >= 0
  defp valid_pkix_option?(:certificate_signature_schemes, nil), do: true

  defp valid_pkix_option?(:certificate_signature_schemes, schemes),
    do: valid_scheme_list?(schemes)

  defp valid_pkix_option?(_key, value), do: valid_limit?(value)

  defp valid_scheme_list?([scheme | rest]) when is_integer(scheme) and scheme in 0..0xFFFF,
    do: valid_scheme_list_tail?(rest)

  defp valid_scheme_list?(_), do: false
  defp valid_scheme_list_tail?([]), do: true

  defp valid_scheme_list_tail?([scheme | rest])
       when is_integer(scheme) and scheme in 0..0xFFFF,
       do: valid_scheme_list_tail?(rest)

  defp valid_scheme_list_tail?(_), do: false

  defp valid_hostname_options?([]), do: true
  defp valid_hostname_options?(match_fun: fun) when is_function(fun, 2), do: true
  defp valid_hostname_options?(_options), do: false
end
