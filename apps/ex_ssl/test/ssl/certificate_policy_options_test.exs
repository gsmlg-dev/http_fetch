defmodule SSL.CertificatePolicyOptionsTest do
  use ExUnit.Case, async: true

  test "advanced trust and revocation policies reject before network I/O and never call callbacks" do
    parent = self()
    reference = make_ref()

    verify_fun = fn _cert, _event, state ->
      send(parent, {:unsupported_callback, reference})
      {:valid, state}
    end

    partial_chain = fn _chain ->
      send(parent, {:unsupported_callback, reference})
      :unknown_ca
    end

    for {key, value} <- [
          verify_fun: {verify_fun, :private_verification_state},
          partial_chain: partial_chain,
          crl_check: true,
          crl_check: :peer,
          crl_cache: {:ssl_crl_cache, {:internal, [http: 1_000]}},
          stapling: :staple,
          stapling: %{ocsp_nonce: true},
          cert_policy_opts: [explicit_policy: true],
          allow_any_ca_purpose: true
        ] do
      assert {:error, {:options, {^key, :unsupported_or_invalid}}} =
               SSL.connect(~c"127.0.0.1", 1, [{key, value}], 100)
    end

    refute_receive {:unsupported_callback, ^reference}, 0
  end
end
