defmodule SSL.PolicyValidationBoundaryTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  @fixtures Path.expand("../fixtures/pkix", __DIR__)

  test "untrusted-path callback failures retain their sanitized reason through the policy verifier" do
    [{:Certificate, leaf, _}] =
      @fixtures |> Path.join("leaf.pem") |> File.read!() |> :public_key.pem_decode()

    for {reason, callback} <- [
          rejected: fn _, _, _ -> {:fail, "private callback rejection"} end,
          invalid_return: fn _, _, _ -> %{private: "callback return"} end,
          exception: fn _, _, _ -> raise "private callback exception" end
        ] do
      verify_fun = {callback, nil}
      options = [cacerts: [], stapling: :staple, verify_fun: verify_fun]
      assert {:ok, normalized} = SSL.Options.normalize("example.test", options)

      assert {:ok, context, verify} =
               SSL.PolicyIO.prepare(
                 normalized,
                 nil,
                 self(),
                 System.monotonic_time(:millisecond) + 5_000
               )

      try do
        assert {:error, {:path_validation_failed, {:verify_fun, ^reason}}} =
                 verify.(
                   [leaf],
                   normalized.trust_source,
                   {:dns_id, "example.test"},
                   :verify_peer,
                   [verify_fun: verify_fun],
                   :tls13
                 )
      after
        assert :ok = SSL.PolicyIO.finish(context)
      end
    end
  end
end

defmodule SSL.OCSPErrorBoundaryTest do
  use ExUnit.Case, async: true

  test "OCSP errors normalize both OTP representations without exposing record details" do
    timestamp = ~c"20261027090000Z"

    for reason <- [:keyCompromise, {:RevokedInfo, timestamp, :keyCompromise}] do
      assert {:bad_cert, {:revoked, :keyCompromise}} =
               SSL.PKIX.OCSP.normalize_error({:revoked, reason})
    end

    assert {:bad_cert, {:revoked, :unspecified}} =
             SSL.PKIX.OCSP.normalize_error({:revoked, {:RevokedInfo, timestamp, :asn1_NOVALUE}})

    assert {:bad_cert, :revocation_status_undetermined} =
             SSL.PKIX.OCSP.normalize_error({:revocation_status_undetermined, "private detail"})

    assert {:bad_cert, :cert_expired} = SSL.PKIX.OCSP.normalize_error(:cert_expired)
  end
end
