defmodule SSL.Protocol.ClientAuthentication do
  @moduledoc false

  alias SSL.ClientIdentity
  alias SSL.ClientIdentity.{Candidates, Chain}
  alias SSL.Crypto.Signature
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.Protocol.{Record, ServerFlight, Transcript}
  alias SSL.Protocol.ServerFlight.CertificateRequest

  @max_record_plaintext 16_384
  @key_usage_filter <<6, 3, 85, 29, 15>>
  @extended_key_usage_filter <<6, 3, 85, 29, 37>>

  @spec emit(CertificateRequest.t() | nil, ClientIdentity.config(), Transcript.t(), term()) ::
          {:ok, Transcript.t(), term(), [binary()]} | {:error, term()}
  def emit(request, identity, transcript, state) do
    with {:ok, transcript, messages} <- messages(request, identity, transcript) do
      Enum.reduce_while(messages, {:ok, transcript, state, []}, fn message,
                                                                   {:ok, transcript, write, out} ->
        case encrypt_message(write, message) do
          {:ok, records, next} -> {:cont, {:ok, transcript, next, out ++ records}}
          error -> {:halt, error}
        end
      end)
    end
  end

  @doc "Generates exact client authentication messages without TLS records."
  @spec messages(CertificateRequest.t() | nil, ClientIdentity.config(), Transcript.t(), keyword()) ::
          {:ok, Transcript.t(), [binary()]} | {:error, term()}
  def messages(request, identity, transcript, constraints \\ [])
  def messages(nil, _identity, transcript, _constraints), do: {:ok, transcript, []}

  def messages(%CertificateRequest{} = request, identity, transcript, constraints) do
    with {:ok, selection} <- select(request, identity, :tls13, constraints),
         {:ok, certificate} <-
           ServerFlight.encode_client_certificate(request.request_context, chain(selection)),
         transcript = Transcript.append(transcript, certificate),
         {:ok, transcript, verify} <- maybe_certificate_verify(selection, transcript) do
      {:ok, transcript, [certificate | verify]}
    end
  end

  def messages(_, _, _, _), do: {:error, :invalid_client_authentication}

  @spec select(CertificateRequest.t(), ClientIdentity.config(), :tls12 | :tls13, keyword()) ::
          {:ok, nil | {ClientIdentity.t(), non_neg_integer()}} | {:error, term()}
  def select(request, identity, version \\ :tls13, constraints \\ [])

  def select(%CertificateRequest{}, nil, version, _) when version in [:tls12, :tls13],
    do: {:ok, nil}

  def select(%CertificateRequest{extensions: extensions}, identity, version, constraints)
      when version in [:tls12, :tls13] and
             (is_struct(identity, ClientIdentity) or is_struct(identity, Candidates)) do
    requested = extension(extensions, :signature_algorithms, [])
    certificate_policy = extension(extensions, :signature_algorithms_cert, requested)
    authorities = extension(extensions, :certificate_authorities, [])
    oid_filters = extension(extensions, :oid_filters, [])

    with :ok <- validate_candidates(identity),
         true <- oid_filters_compatible?(oid_filters),
         {:ok, names} <- Chain.authorities(authorities) do
      pool =
        if authorities == [],
          do: [],
          else: Chain.snapshot(Keyword.get(constraints, :trust_source))

      policy = %{
        version: version,
        requested: requested,
        certificates: certificate_policy,
        names: names,
        pool: pool,
        local: Keyword.get(constraints, :signature_schemes),
        types: Keyword.get(constraints, :certificate_types)
      }

      choose(Candidates.ordered(identity, version), policy, nil, 1_048_576)
    else
      false -> {:ok, nil}
      error -> error
    end
  end

  def select(_, _, _, _), do: {:error, :invalid_client_authentication}

  defp validate_candidates(%Candidates{} = candidates) do
    if Candidates.valid?(candidates), do: :ok, else: {:error, :invalid_client_authentication}
  end

  defp validate_candidates(%ClientIdentity{}), do: :ok

  defp choose([], _policy, fallback, _budget), do: {:ok, fallback}

  defp choose([identity | rest], policy, fallback, budget) do
    case eligible_scheme(identity, policy) do
      nil ->
        choose(rest, policy, fallback, budget)

      scheme ->
        with {:ok, chain, budget} <- complete_chain(identity.chain, policy, budget) do
          selection = {%{identity | chain: chain}, scheme}

          cond do
            not CertificateSignaturePolicy.compatible?(chain, nil, policy.certificates) ->
              choose(rest, policy, fallback, budget)

            MapSet.size(policy.names) == 0 or Chain.matches?(chain, policy.names) ->
              {:ok, selection}

            true ->
              choose(rest, policy, fallback || fallback_candidate(selection, policy), budget)
          end
        end
    end
  end

  defp fallback_candidate({identity, _scheme} = selection, policy) do
    if policy.version == :tls12 or length(identity.chain) == 1, do: selection
  end

  defp complete_chain(chain, policy, budget) do
    if MapSet.size(policy.names) == 0,
      do: {:ok, chain, budget},
      else: Chain.complete(chain, policy.pool, budget)
  end

  defp eligible_scheme(identity, policy) do
    schemes =
      if policy.version == :tls12,
        do: identity.tls12_signature_schemes,
        else: identity.signature_schemes

    if digital_signature_key_usage?(hd(identity.chain)) do
      Enum.find(policy.requested, fn scheme ->
        scheme in schemes and (policy.local == nil or scheme in policy.local) and
          type_allowed?(scheme, policy)
      end)
    end
  end

  defp type_allowed?(_scheme, %{version: :tls13}), do: true
  defp type_allowed?(_scheme, %{types: nil}), do: true

  defp type_allowed?(scheme, policy) do
    type = if SSL.Capabilities.signature(scheme, :tls12).key == :ecdsa, do: 64, else: 1
    type in policy.types
  end

  defp extension(extensions, name, default) do
    case List.keyfind(extensions, name, 0) do
      {^name, value} -> value
      _ -> default
    end
  end

  defp chain(nil), do: []
  defp chain({identity, _scheme}), do: identity.chain

  defp oid_filters_compatible?(filters) do
    Enum.all?(filters, fn
      {oid, _values} when oid in [@key_usage_filter, @extended_key_usage_filter] -> false
      {_oid, _values} -> true
    end)
  end

  defp digital_signature_key_usage?(der) do
    extensions = der |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(10)

    key_usage =
      case extensions do
        :asn1_NOVALUE ->
          nil

        entries when is_list(entries) ->
          Enum.find(entries, fn
            {:Extension, {2, 5, 29, 15}, _, _} -> true
            _ -> false
          end)
      end

    case key_usage do
      nil ->
        true

      {:Extension, {2, 5, 29, 15}, _, usages} when is_list(usages) ->
        :digitalSignature in usages

      _ ->
        false
    end
  catch
    _, _ -> false
  end

  defp maybe_certificate_verify(nil, transcript), do: {:ok, transcript, []}

  defp maybe_certificate_verify({identity, scheme}, transcript) do
    with {:ok, signature} <-
           Signature.sign_client(
             scheme,
             identity.private_key,
             transcript.hash,
             Transcript.digest(transcript)
           ),
         {:ok, encoded} <- ServerFlight.encode_client_certificate_verify(scheme, signature) do
      {:ok, Transcript.append(transcript, encoded), [encoded]}
    end
  end

  defp encrypt_message(state, bytes), do: encrypt_chunks(state, bytes, [])

  defp encrypt_chunks(state, <<>>, records), do: {:ok, Enum.reverse(records), state}

  defp encrypt_chunks(state, bytes, records) do
    size = min(byte_size(bytes), @max_record_plaintext)
    <<chunk::binary-size(^size), rest::binary>> = bytes

    case Record.encrypt(state, :handshake, chunk) do
      {:ok, record, next_state} -> encrypt_chunks(next_state, rest, [record | records])
      {:error, reason} -> {:error, reason}
    end
  end
end
