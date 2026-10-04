defmodule SSL.ClientIdentityOptionsTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer

  test "normalizes a matching client identity independently of server trust and redacts it" do
    fixture = LocalTLSPeer.certificates()

    options =
      LocalTLSPeer.client_options() ++ [certfile: fixture.certfile, keyfile: fixture.keyfile]

    assert {:ok, normalized} = SSL.Options.normalize(~c"127.0.0.1", options)
    assert %SSL.ClientIdentity{} = normalized.client_identity
    assert normalized.identity == {:dns_id, "exssl.test"}
    assert normalized.trust_source == LocalTLSPeer.certificate_authorities()
    refute inspect(normalized) =~ fixture.keyfile
    refute inspect(normalized) =~ "private_key"
  end

  test "invalid and conflicting identities fail before network I/O without echoing material" do
    fixture = LocalTLSPeer.certificates()

    for identity <- [
          [cert: <<1>>],
          [key: {:ECPrivateKey, <<1>>}],
          [certfile: fixture.certfile, keyfile: fixture.ecdsa_keyfile],
          [certfile: fixture.certfile, cert: <<1>>, keyfile: fixture.keyfile]
        ] do
      assert {:error, {:options, _}} =
               SSL.connect(~c"127.0.0.1", 1, LocalTLSPeer.client_options() ++ identity, 100)
    end
  end

  test "identity selection hardware and encrypted-key controls remain explicitly unsupported" do
    for option <- [certs_keys: [], password: "private-password", key: %{engine: :external}] do
      assert {:error, {:options, reason}} = SSL.Options.normalize(~c"localhost", [option])
      refute inspect(reason) =~ "private-password"
    end
  end
end
