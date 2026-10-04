defmodule ExSSL.TestSupport.SignatureFixtures do
  @moduledoc false

  @schemes [
    {0x0503, "ecdsa_secp384r1_sha384", :p384},
    {0x0807, "ed25519", :ed25519},
    {0x0809, "rsa_pss_pss_sha256", {:pss, :sha256, 32}},
    {0x080A, "rsa_pss_pss_sha384", {:pss, :sha384, 48}},
    {0x080B, "rsa_pss_pss_sha512", {:pss, :sha512, 64}}
  ]

  def schemes, do: @schemes

  def create(directory) do
    File.mkdir_p!(directory)

    for {id, name, key_type} <- @schemes, into: %{} do
      key = Path.join(directory, "#{name}.key")
      certificate = Path.join(directory, "#{name}.pem")
      create_key(key, key_type)

      openssl!([
        "req",
        "-new",
        "-x509",
        "-key",
        key,
        "-out",
        certificate,
        "-days",
        "1",
        "-subj",
        "/CN=exssl.test",
        "-addext",
        "subjectAltName=DNS:exssl.test"
      ])

      [{:Certificate, der, :not_encrypted}] =
        certificate |> File.read!() |> :public_key.pem_decode()

      {id, %{key: key, certificate: certificate, der: der}}
    end
  end

  def openssl!(arguments) do
    case System.cmd("openssl", arguments, stderr_to_stdout: true) do
      {output, 0} -> output
      {output, status} -> raise "openssl exited #{status}: #{output}"
    end
  end

  defp create_key(path, :p384),
    do:
      openssl!([
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:secp384r1",
        "-out",
        path
      ])

  defp create_key(path, :ed25519),
    do: openssl!(["genpkey", "-algorithm", "ED25519", "-out", path])

  defp create_key(path, {:pss, hash, salt}) do
    openssl!([
      "genpkey",
      "-algorithm",
      "RSA-PSS",
      "-pkeyopt",
      "rsa_keygen_bits:2048",
      "-pkeyopt",
      "rsa_pss_keygen_md:#{hash}",
      "-pkeyopt",
      "rsa_pss_keygen_mgf1_md:#{hash}",
      "-pkeyopt",
      "rsa_pss_keygen_saltlen:#{salt}",
      "-out",
      path
    ])
  end
end
