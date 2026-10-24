defmodule SSL.ClientIdentityOptionsTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.LocalTLSPeer

  @tag :integration
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

  @tag :integration
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

  @tag :integration
  test "hardware remains explicitly unsupported" do
    for option <- [key: %{engine: :external}] do
      assert {:error, {:options, _reason}} = SSL.Options.normalize(~c"localhost", [option])
    end
  end
end
