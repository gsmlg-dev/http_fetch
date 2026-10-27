defmodule SSL.PKIX.OCSP do
  @moduledoc false
  alias SSL.PKIX.PartialChain

  alias SSL.PolicyIO
  require Logger

  def request(nil), do: {:undefined, nil}

  def request(%{ocsp_nonce: enabled}) do
    nonce =
      if enabled,
        do: :public_key.der_encode(:Nonce, :crypto.strong_rand_bytes(32)),
        else: :undefined

    extensions = :public_key.ocsp_extensions(nonce)
    encoded = if extensions == [], do: <<>>, else: :public_key.der_encode(:Extensions, extensions)
    {nonce, <<1, 0::16, byte_size(encoded)::16, encoded::binary>>}
  end

  def check(certificate, der, event, selected, anchors, staples, nonce) do
    case List.keyfind(staples, der, 0) do
      nil when event == :valid_peer ->
        {:bad_cert, :missing_ocsp_staple}

      nil ->
        event

      {^der, response} ->
        with :ok <- PolicyIO.material(response, :ocsp),
             true <- byte_size(response) <= 102_400,
             {:ok, issuer} <- issuer(der, selected) do
          trusted = MapSet.new(anchors, & &1.der)
          predicate = fn {:cert, responder_der, _} -> MapSet.member?(trusted, responder_der) end

          case :public_key.pkix_ocsp_validate(certificate, issuer.decoded, response, nonce,
                 is_trusted_responder_fun: predicate
               ) do
            {:ok, details} ->
              report_missing_nonce(details)
              event

            {:error, {:bad_cert, reason}} ->
              normalize_error(reason)
          end
        else
          {:error, :policy_capacity} -> PolicyIO.fail!(:policy_capacity)
          _ -> {:bad_cert, :revocation_status_undetermined}
        end
    end
  end

  # OTP 28's pkix_ocsp_validate spec omits the RevokedInfo record returned by
  # its implementation. Keep the runtime compatibility boundary independently
  # typed so upstream success typing cannot discard required normalization.
  @doc false
  @spec normalize_error(
          :public_key.bad_cert_reason()
          | {:revoked, {:RevokedInfo, charlist(), atom()}}
        ) :: {:bad_cert, atom() | {:revoked, atom()}}
  def normalize_error({:revoked, reason}), do: {:bad_cert, {:revoked, revoked_reason(reason)}}
  def normalize_error(reason) when is_atom(reason), do: {:bad_cert, reason}
  def normalize_error(_), do: {:bad_cert, :revocation_status_undetermined}

  defp revoked_reason({:RevokedInfo, _time, reason})
       when is_atom(reason) and reason != :asn1_NOVALUE,
       do: reason

  defp revoked_reason(reason) when is_atom(reason), do: reason
  defp revoked_reason(_), do: :unspecified

  defp report_missing_nonce(details) do
    if {:missing, :ocsp_nonce} in details do
      Logger.info(
        "Certificate Status - stapling response provided but with nonce missing",
        reason: [{:missing, :stapling_nonce}]
      )
    end
  end

  defp issuer(der, selected) do
    path = PartialChain.full_path(selected)

    case Enum.find_index(path, &(&1.der == der)) do
      nil ->
        {:error, :unknown_issuer}

      index ->
        case Enum.at(path, index + 1) do
          nil -> {:error, :unknown_issuer}
          issuer -> {:ok, issuer}
        end
    end
  end
end
