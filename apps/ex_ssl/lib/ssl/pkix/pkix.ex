defmodule SSL.PKIX do
  @moduledoc """
  Pure, bounded certificate decoding, trust normalization, and peer verification.

  Certificate chains are accepted in TLS leaf-first order. Trust sources are
  supplied in memory as a DER list or PEM bundle; this module performs no file,
  network, or operating-system trust lookup.

  `peer/5` and `decode_peer/2` retain the legacy `VerifiedPeer` container for
  handshake key material. Under `verify_none` it contains decoded, untrusted
  credentials; the struct name is not proof of trust, identity, or possession.
  The protocol must still verify CertificateVerify/ServerKeyExchange and Finished.
  """

  alias SSL.PKIX.Certificate
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.PKIX.VerifiedPeer
  alias SSL.PKIX.VerifyFun

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
    :verify_fun,
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
          | {:verify_fun, VerifyFun.policy()}
          | {:customize_hostname_check, keyword()}
          | {:certificate_signature_schemes, [non_neg_integer()] | nil}
  @type error_reason ::
          :empty_certificate_chain
          | :empty_trust_anchors
          | :hostname_mismatch
          | :unsupported_certificate_key
          | :invalid_peer_key_usage
          | {:invalid_peer_certificate_version, non_neg_integer()}
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
    if is_list(options) and Keyword.keyword?(options) and
         VerifyFun.enabled?(Keyword.get(options, :verify_fun, :undefined)) do
      verify_callback(chain, trust_source, identity, options)
    else
      verify_default(chain, trust_source, identity, options)
    end
  end

  defp verify_default(chain, trust_source, identity, options) do
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

  @doc false
  @spec peer(term(), term(), term(), :verify_peer | :verify_none, [option()]) ::
          {:ok, VerifiedPeer.t()} | {:error, error_reason()}
  @spec peer(term(), term(), term(), :verify_peer | :verify_none, [option()], :tls12 | :tls13) ::
          {:ok, VerifiedPeer.t()} | {:error, error_reason()}
  def peer(chain, trust_source, identity, mode, options, protocol \\ :tls13)

  def peer(chain, trust_source, identity, mode, options, protocol)
      when mode in [:verify_peer, :verify_none] do
    with {:ok, _limits} <- limits(options),
         :ok <- protocol_chain(chain, protocol, options) do
      result =
        case mode do
          :verify_peer ->
            verify(chain, trust_source, identity, options)

          :verify_none ->
            if VerifyFun.enabled?(Keyword.get(options, :verify_fun, :undefined)),
              do: verify_callback(chain, trust_source, identity, options),
              else: decode_peer(chain, options)
        end

      signing_peer(result)
    end
  end

  defp verify_callback(chain, trust_source, identity, options) do
    with :ok <- callback_identity(identity),
         {:ok, [leaf | _] = certificates} <- decode_chain(chain, options),
         {:ok, anchors} <- callback_trust(trust_source, options),
         {:ok, public_key} <- callback_paths(certificates, anchors, identity, options) do
      {:ok,
       %VerifiedPeer{
         leaf_der: leaf.der,
         leaf: leaf.decoded,
         public_key: public_key,
         chain: Enum.map(certificates, & &1.der)
       }}
    end
  end

  defp callback_identity(nil), do: :ok
  defp callback_identity(identity), do: validate_identity(identity)
  defp callback_trust(source, _options) when source in [nil, []], do: {:ok, []}
  defp callback_trust(source, options), do: normalize_trust(source, options)

  # Each candidate has a decreasing position in the admitted peer list. Skip
  # disjoint cross-sign siblings without expanding a certificate graph. The
  # ordinary no-callback prefix selection below is deliberately independent.
  defp callback_paths(chain, anchors, identity, options) do
    chain
    |> Enum.with_index()
    |> Enum.reverse()
    |> Enum.reject(fn {certificate, _} ->
      Enum.any?(chain, fn issuer ->
        certificate.der != issuer.der and safe_is_issuer(certificate.decoded, issuer.decoded)
      end)
    end)
    |> Enum.flat_map(fn {top, index} ->
      case callback_chain(top, index, chain) do
        nil -> []
        path -> callback_anchors(path, anchors)
      end
    end)
    |> Enum.reduce_while({:error, {:path_validation_failed, :unknown_ca}}, fn {anchor, path}, _ ->
      hostname_match = fn certificate ->
        identity == nil or
          verify_identity(
            certificate,
            identity,
            Keyword.get(options, :customize_hostname_check, [])
          ) == :ok
      end

      callback = VerifyFun.wrap(Keyword.fetch!(options, :verify_fun), hostname_match)

      case callback_path_validation(anchor, path, callback, options) do
        {:ok, _} = success -> {:halt, success}
        {:error, _} = error -> {:cont, error}
      end
    end)
  end

  defp callback_chain(leaf, 0, _chain), do: [leaf]

  defp callback_chain(top, index, chain) do
    chain
    |> Enum.take(index)
    |> Enum.with_index()
    |> Enum.reverse()
    |> Enum.find(fn {child, _} -> safe_is_issuer(child.decoded, top.decoded) end)
    |> case do
      nil ->
        nil

      {child, position} ->
        case callback_chain(child, position, chain) do
          nil -> nil
          path -> path ++ [top]
        end
    end
  end

  defp callback_anchors([leaf] = path, anchors) do
    if :public_key.pkix_is_self_signed(leaf.decoded),
      do: [{:selfsigned_peer, path}],
      else: callback_trusted_anchors(path, anchors)
  end

  defp callback_anchors(path, anchors), do: callback_trusted_anchors(path, anchors)

  defp callback_trusted_anchors(path, anchors) do
    top = List.last(path)

    candidates =
      Enum.flat_map(anchors, fn anchor ->
        cond do
          top.der == anchor.der -> [{anchor, Enum.drop(path, -1)}]
          safe_is_issuer(top.decoded, anchor.decoded) -> [{anchor, path}]
          true -> []
        end
      end)

    if candidates == [], do: [{:unknown_ca, path}], else: candidates
  end

  defp callback_path_validation(anchor, path, callback, options) do
    anchor_der = if is_atom(anchor), do: anchor, else: anchor.der
    ders = path |> Enum.map(& &1.der) |> Enum.reverse()

    case :public_key.pkix_path_validation(anchor_der, ders,
           max_path_length: Keyword.get(options, :depth, 10),
           verify_fun: callback
         ) do
      {:ok, {public_key_info, _}} ->
        schemes = Keyword.get(options, :certificate_signature_schemes)
        policy_anchor = if is_atom(anchor), do: nil, else: anchor.der

        if schemes == nil or
             CertificateSignaturePolicy.compatible?(Enum.reverse(ders), policy_anchor, schemes),
           do: {:ok, certificate_verify_key(public_key_info)},
           else: {:error, {:certificate_signature_scheme_not_allowed, schemes}}

      {:error, reason} ->
        {:error, {:path_validation_failed, reason}}
    end
  catch
    _kind, _reason -> {:error, {:path_validation_failed, {:verify_fun, :invalid_return}}}
  end

  defp protocol_chain(chain, :tls13, options) do
    # RFC9846 4.5.1.2 applies to all certificates supplied, including entries
    # outside the selected trust path. Generic PKIX and TLS12 keep their policy.
    with {:ok, certificates} <- decode_chain(chain, options) do
      case Enum.find_index(certificates, fn certificate ->
             certificate.decoded
             |> otp_certificate(:tbsCertificate)
             |> otp_tbs_certificate(:version) != :v3
           end) do
        nil -> :ok
        index -> {:error, {:invalid_peer_certificate_version, index}}
      end
    end
  end

  defp protocol_chain(_chain, :tls12, _options), do: :ok

  defp signing_peer({:ok, %VerifiedPeer{leaf: certificate} = peer}) do
    usages =
      case certificate |> otp_certificate(:tbsCertificate) |> otp_tbs_certificate(:extensions) do
        :asn1_NOVALUE ->
          []

        extensions when is_list(extensions) ->
          for extension <- extensions,
              certificate_extension(extension, :extnID) == {2, 5, 29, 15},
              do: certificate_extension(extension, :extnValue)

        _ ->
          [:invalid]
      end

    case usages do
      [] ->
        {:ok, peer}

      [usage] when is_list(usage) ->
        if :digitalSignature in usage, do: {:ok, peer}, else: {:error, :invalid_peer_key_usage}

      _ ->
        {:error, :invalid_peer_key_usage}
    end
  end

  defp signing_peer({:error, _} = error), do: error

  # An explicitly selected leaf is a trust anchor, so the path validator has
  # no subordinate certificates and emits no leaf events. Its time is still
  # checked by public_key; enforce TLS identity and purpose without replaying
  # any user verify_fun event or claiming an issuer-validated nonempty path.
  @doc false
  def verify_selected_leaf(%Certificate{decoded: certificate}, identity, options) do
    extensions =
      certificate |> otp_certificate(:tbsCertificate) |> otp_tbs_certificate(:extensions)

    extensions = if extensions == :asn1_NOVALUE, do: [], else: extensions

    usages =
      for extension <- extensions,
          certificate_extension(extension, :extnID) == {2, 5, 29, 37},
          do: certificate_extension(extension, :extnValue)

    constraints =
      for extension <- extensions,
          certificate_extension(extension, :extnID) == {2, 5, 29, 19},
          do: certificate_extension(extension, :extnValue)

    ids = Enum.map(extensions, &certificate_extension(&1, :extnID))
    # Only extensions checked as leaf properties are admitted here. Other
    # critical constraints need a real subordinate path, not OID recognition.
    checked_critical = for id <- [15, 17, 19, 37], do: {2, 5, 29, id}

    cond do
      length(ids) != length(Enum.uniq(ids)) ->
        {:error, {:path_validation_failed, {:bad_cert, :duplicate_extensions}}}

      not valid_leaf_constraints?(constraints) ->
        {:error, {:path_validation_failed, {:bad_cert, :invalid_basic_constraints}}}

      Enum.any?(extensions, fn extension ->
        certificate_extension(extension, :critical) == true and
            certificate_extension(extension, :extnID) not in checked_critical
      end) ->
        {:error, {:path_validation_failed, {:bad_cert, :unknown_critical_extension}}}

      not valid_leaf_usages?(usages) ->
        {:error, {:path_validation_failed, {:bad_cert, :invalid_ext_keyusage}}}

      identity == nil ->
        :ok

      true ->
        verify_identity(
          certificate,
          identity,
          Keyword.get(options, :customize_hostname_check, [])
        )
    end
  end

  defp valid_leaf_constraints?([]), do: true
  defp valid_leaf_constraints?([{:BasicConstraints, false, :asn1_NOVALUE}]), do: true
  defp valid_leaf_constraints?([{:BasicConstraints, true, :asn1_NOVALUE}]), do: true

  defp valid_leaf_constraints?([{:BasicConstraints, true, length}])
       when is_integer(length) and length >= 0,
       do: true

  defp valid_leaf_constraints?(_), do: false

  defp valid_leaf_usages?([]), do: true
  defp valid_leaf_usages?([[_ | _] = usages]), do: {1, 3, 6, 1, 5, 5, 7, 3, 1} in usages
  defp valid_leaf_usages?(_), do: false

  @doc false
  @spec decode_peer(term(), [option()]) :: {:ok, VerifiedPeer.t()} | {:error, error_reason()}
  def decode_peer(chain, options \\ []) do
    with {:ok, [leaf | _] = certificates} <- decode_chain(chain, options),
         {:ok, public_key} <- untrusted_public_key(leaf.decoded) do
      {:ok,
       %VerifiedPeer{
         leaf_der: leaf.der,
         leaf: leaf.decoded,
         public_key: public_key,
         chain: Enum.map(certificates, & &1.der)
       }}
    end
  end

  defp untrusted_public_key(certificate) do
    info =
      certificate
      |> otp_certificate(:tbsCertificate)
      |> otp_tbs_certificate(:subjectPublicKeyInfo)

    case info do
      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_encryption_oid, params},
       {:RSAPublicKey, _, _} = key} ->
        {:ok, certificate_verify_key({@rsa_encryption_oid, key, params})}

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_pss_oid, params},
       {:RSAPublicKey, _, _} = key} ->
        {:ok, certificate_verify_key({@rsa_pss_oid, key, params})}

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @ec_public_key_oid, params},
       {:ECPoint, _} = key} ->
        {:ok, certificate_verify_key({@ec_public_key_oid, key, params})}

      {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @ed25519_oid, :asn1_NOVALUE},
       {:ECPoint, _} = key} ->
        {:ok, certificate_verify_key({@ed25519_oid, key, {:namedCurve, @ed25519_oid}})}

      _ ->
        {:error, :unsupported_certificate_key}
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
      case validate_anchor_paths(chain, anchor, depth, signature_schemes, previous_error) do
        {:ok, _public_key} = result -> {:halt, result}
        {:error, _reason} = error -> {:cont, error}
      end
    end)
  end

  defp validate_anchor_paths(chain, anchor, depth, signature_schemes, previous_error) do
    chain
    |> anchor_paths(anchor)
    |> Enum.reduce_while(previous_error, fn selected_chain, error ->
      path = selected_chain |> Enum.map(& &1.der) |> Enum.reverse()

      case safe_path_validation(anchor.der, path, depth) do
        {:ok, public_key} ->
          if signature_schemes == nil or
               CertificateSignaturePolicy.compatible?(
                 Enum.map(selected_chain, & &1.der),
                 anchor.der,
                 signature_schemes
               ) do
            {:halt, {:ok, public_key}}
          else
            {:cont, {:error, {:certificate_signature_scheme_not_allowed, signature_schemes}}}
          end

        {:error, reason} ->
          case error do
            {:error, {:certificate_signature_scheme_not_allowed, _}} ->
              {:cont, error}

            _ ->
              {:cont, {:error, {:path_validation_failed, reason}}}
          end
      end
    end)
  end

  # A peer may append an alternative cross-sign or certificates above a supplied
  # anchor. Consider only leaf-first prefixes ending at that anchor or its issued
  # certificate. Issuer matching selects candidates; PKIX still verifies each
  # candidate's signatures, constraints, validity and depth.
  defp anchor_paths(chain, anchor) do
    chain
    |> Enum.with_index()
    |> Enum.reverse()
    |> Enum.flat_map(fn {certificate, index} ->
      cond do
        certificate.der == anchor.der ->
          [Enum.take(chain, index)]

        safe_is_issuer(certificate.decoded, anchor.decoded) ->
          [Enum.take(chain, index + 1)]

        true ->
          []
      end
    end)
  end

  defp safe_is_issuer(certificate, anchor) do
    :public_key.pkix_is_issuer(certificate, anchor)
  catch
    _kind, _reason -> false
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
  defp valid_pkix_option?(:verify_fun, value), do: VerifyFun.valid?(value)
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
