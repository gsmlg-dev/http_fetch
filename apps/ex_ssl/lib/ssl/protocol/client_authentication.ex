defmodule SSL.Protocol.ClientAuthentication do
  @moduledoc false

  alias SSL.ClientIdentity
  alias SSL.Crypto.Signature
  alias SSL.PKIX.CertificateSignaturePolicy
  alias SSL.Protocol.{Record, ServerFlight, Transcript}
  alias SSL.Protocol.ServerFlight.CertificateRequest

  @max_record_plaintext 16_384
  @key_usage_filter <<6, 3, 85, 29, 15>>
  @extended_key_usage_filter <<6, 3, 85, 29, 37>>

  @spec emit(CertificateRequest.t() | nil, ClientIdentity.t() | nil, Transcript.t(), term()) ::
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
  @spec messages(CertificateRequest.t() | nil, ClientIdentity.t() | nil, Transcript.t()) ::
          {:ok, Transcript.t(), [binary()]} | {:error, term()}
  def messages(nil, _identity, transcript), do: {:ok, transcript, []}

  def messages(%CertificateRequest{} = request, identity, transcript) do
    with {:ok, selection} <- select(request, identity),
         {:ok, certificate} <-
           ServerFlight.encode_client_certificate(request.request_context, chain(selection)),
         transcript = Transcript.append(transcript, certificate),
         {:ok, transcript, verify} <- maybe_certificate_verify(selection, transcript) do
      {:ok, transcript, [certificate | verify]}
    end
  end

  def messages(_, _, _), do: {:error, :invalid_client_authentication}

  @spec select(CertificateRequest.t(), ClientIdentity.t() | nil) ::
          {:ok, nil | {ClientIdentity.t(), non_neg_integer()}} | {:error, term()}
  def select(%CertificateRequest{}, nil), do: {:ok, nil}

  def select(%CertificateRequest{extensions: extensions}, %ClientIdentity{} = identity) do
    requested = extension(extensions, :signature_algorithms, [])
    certificate_policy = extension(extensions, :signature_algorithms_cert, requested)
    authorities = extension(extensions, :certificate_authorities, [])
    oid_filters = extension(extensions, :oid_filters, [])

    cond do
      not oid_filters_compatible?(oid_filters) ->
        # Matching recognized extension values is outside this initial subset.
        {:ok, nil}

      not digital_signature_key_usage?(hd(identity.chain)) ->
        {:ok, nil}

      authorities != [] and not authority_matches?(identity.chain, authorities) ->
        {:ok, nil}

      not CertificateSignaturePolicy.compatible?(identity.chain, nil, certificate_policy) ->
        {:ok, nil}

      true ->
        case Enum.find(requested, &(&1 in identity.signature_schemes)) do
          nil -> {:ok, nil}
          scheme -> {:ok, {identity, scheme}}
        end
    end
  end

  def select(_, _), do: {:error, :invalid_client_authentication}

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

  defp authority_matches?(chain, authorities) do
    normalized =
      Enum.map(authorities, fn der ->
        der |> then(&:public_key.der_decode(:Name, &1)) |> :public_key.pkix_normalize_name()
      end)

    Enum.any?(chain, fn der ->
      issuer = der |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(4)
      :public_key.pkix_normalize_name(issuer) in normalized
    end)
  catch
    _, _ -> false
  end
end
