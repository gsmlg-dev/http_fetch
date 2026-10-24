defmodule ExSSL.TestSupport.EncryptedIdentityFixtures do
  @moduledoc false
  alias ExSSL.TestSupport.{ClientAuthFixtures, SignatureFixtures}

  def create(directory) do
    fixtures = ClientAuthFixtures.create(directory)

    encrypted =
      Map.new([:rsa, :ec], fn role ->
        identity = Map.fetch!(fixtures, role)

        {role,
         encrypt(identity, directory, Atom.to_string(role), "encrypted-identity-test-password")}
      end)

    %{fixtures: fixtures, encrypted: encrypted}
  end

  def encrypt(identity, directory, name, password, arguments \\ []) do
    password_file = Path.join(directory, name <> ".password")
    encrypted = Path.join(directory, name <> ".encrypted.key")
    File.write!(password_file, password)
    File.chmod!(password_file, 0o600)

    SignatureFixtures.openssl!(
      [
        "pkcs8",
        "-topk8",
        "-in",
        identity.key,
        "-out",
        encrypted,
        "-v2",
        "aes-256-cbc",
        "-v2prf",
        "hmacWithSHA256",
        "-iter",
        "2048",
        "-passout",
        "file:#{password_file}"
      ] ++ arguments
    )

    Map.merge(identity, %{encrypted_key: encrypted, password: password})
  end

  def legacy(identity, directory, name, cipher, password, kind) do
    password_file = Path.join(directory, name <> ".password")
    encrypted = Path.join(directory, name <> ".encrypted.key")
    File.write!(password_file, password)
    File.chmod!(password_file, 0o600)
    extra = if kind == :rsa, do: ["-traditional"], else: []
    tool = if kind == :rsa, do: "rsa", else: "ec"

    SignatureFixtures.openssl!(
      [
        tool,
        "-in",
        identity.key,
        "-out",
        encrypted,
        "-#{cipher}",
        "-passout",
        "file:#{password_file}"
      ] ++ extra
    )

    Map.merge(identity, %{encrypted_key: encrypted, password: password})
  end

  def rewrite_parameters(fixture, path, fun) do
    [{type, ciphertext, {cipher, params}}] =
      fixture.encrypted_key |> File.read!() |> :public_key.pem_decode()

    File.write!(path, :public_key.pem_encode([{type, ciphertext, {cipher, fun.(params)}}]))
    %{fixture | encrypted_key: path}
  end
end
