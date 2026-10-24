defmodule SSL.CertificatePolicyOptionsTest do
  use ExUnit.Case, async: true

  test "unsupported certificate policies reject before network I/O" do
    for {key, value} <- [
          cert_policy_opts: [explicit_policy: true],
          allow_any_ca_purpose: true
        ] do
      assert {:error, {:options, {^key, :unsupported_or_invalid}}} =
               SSL.connect(~c"127.0.0.1", 1, [{key, value}], 100)
    end
  end

  test "supported policies normalize without invoking callbacks or network I/O" do
    parent = self()
    reference = make_ref()

    partial_chain = fn _chain ->
      send(parent, {:unsupported_callback, reference})
      :unknown_ca
    end

    for {key, value} <- [
          partial_chain: partial_chain,
          crl_check: true,
          crl_check: :peer,
          crl_cache: {:ssl_crl_cache, {:internal, [http: 1_000]}},
          stapling: :staple,
          stapling: %{ocsp_nonce: true},
          stapling: %{}
        ] do
      assert {:ok, _options} =
               SSL.Options.normalize(~c"127.0.0.1", [
                 {key, value},
                 {:cacerts, []},
                 {:verify, :verify_none}
               ])
    end

    refute_receive {:unsupported_callback, ^reference}, 0
  end

  test "absent and explicitly disabled policy retains the no-policy route" do
    for options <- [[], [crl_check: false], [stapling: :no_staple]] do
      assert {:ok, %{policy: nil}} =
               SSL.Options.normalize(
                 ~c"127.0.0.1",
                 options ++ [cacerts: [], verify: :verify_none]
               )
    end
  end

  test "malformed policy shapes reject before network I/O" do
    for {key, value} <- [
          partial_chain: :invalid,
          crl_check: :invalid,
          crl_cache: {:ssl_crl_cache, {:internal, [http: 0]}},
          crl_cache: {:ssl_crl_hash_dir, {:internal, [dir: ""]}},
          stapling: %{ocsp_nonce: :invalid},
          stapling: %{ocsp_nonce: false, unknown: true}
        ] do
      assert {:error, {:options, {^key, :unsupported_or_invalid}}} =
               SSL.connect(~c"127.0.0.1", 1, [{key, value}], 100)
    end
  end
end
