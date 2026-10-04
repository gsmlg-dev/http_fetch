defmodule ExSSL.TestSupport.ClientAuthFixtures do
  @moduledoc false
  alias ExSSL.TestSupport.SignatureFixtures

  def create(directory) do
    File.mkdir_p!(directory)
    ca = root(directory, "ca")
    wrong_ca = root(directory, "wrong-ca")
    rsa = leaf(directory, "rsa-client", :rsa, ca, "clientAuth")
    ec = leaf(directory, "ec-client", :ec, ca, "clientAuth")
    server = leaf(directory, "server", :rsa, ca, "serverAuth")
    ec_server = leaf(directory, "ec-server", :ec, ca, "serverAuth")
    wrong = leaf(directory, "wrong-client", :ec, wrong_ca, "clientAuth")
    large = leaf(directory, "large-client", {:key, rsa.key}, ca, "clientAuth", true)
    expired = expired(directory, ca, rsa)

    %{
      ca: ca,
      rsa: rsa,
      ec: ec,
      server: server,
      ec_server: ec_server,
      wrong: wrong,
      large: large,
      expired: expired
    }
  end

  defp root(directory, name) do
    key = Path.join(directory, name <> ".key")
    certificate = Path.join(directory, name <> ".pem")

    openssl!([
      "req",
      "-new",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      key,
      "-out",
      certificate,
      "-days",
      "2",
      "-subj",
      "/CN=#{name}",
      "-addext",
      "basicConstraints=critical,CA:TRUE",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign"
    ])

    %{key: key, certificate: certificate, der: certificate_der(certificate)}
  end

  defp leaf(directory, name, algorithm, ca, usage, large? \\ false) do
    key =
      case algorithm do
        {:key, path} ->
          path

        _ ->
          path = Path.join(directory, name <> ".key")

          arguments =
            case algorithm do
              :rsa -> ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
              :ec -> ["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1"]
            end

          openssl!(arguments ++ ["-out", path])
          path
      end

    request = Path.join(directory, name <> ".csr")
    certificate = Path.join(directory, name <> ".pem")
    extensions = Path.join(directory, name <> ".ext")

    padding =
      if large?,
        do: "1.3.6.1.4.1.55555.1=ASN1:UTF8String:" <> String.duplicate("p", 20_000) <> "\n",
        else: ""

    File.write!(
      extensions,
      "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=#{usage}\nsubjectAltName=DNS:exssl.test,IP:127.0.0.1,IP:::1\n" <>
        padding
    )

    openssl!(["req", "-new", "-key", key, "-out", request, "-subj", "/CN=#{name}"])

    openssl!([
      "x509",
      "-req",
      "-in",
      request,
      "-CA",
      ca.certificate,
      "-CAkey",
      ca.key,
      "-CAcreateserial",
      "-out",
      certificate,
      "-days",
      "2",
      "-extfile",
      extensions
    ])

    %{key: key, certificate: certificate, der: certificate_der(certificate), request: request}
  end

  defp expired(directory, ca, identity) do
    index = Path.join(directory, "index")
    serial = Path.join(directory, "serial")
    config = Path.join(directory, "ca.conf")
    certificate = Path.join(directory, "expired-client.pem")
    File.write!(index, "")
    File.write!(serial, "1000\n")

    File.write!(config, """
    [ca]
    default_ca=issuer
    [issuer]
    database=#{index}
    serial=#{serial}
    new_certs_dir=#{directory}
    certificate=#{ca.certificate}
    private_key=#{ca.key}
    default_md=sha256
    default_days=1
    policy=names
    x509_extensions=client
    [names]
    commonName=supplied
    [client]
    basicConstraints=critical,CA:FALSE
    keyUsage=critical,digitalSignature
    extendedKeyUsage=clientAuth
    """)

    openssl!([
      "ca",
      "-batch",
      "-notext",
      "-config",
      config,
      "-in",
      identity.request,
      "-out",
      certificate,
      "-startdate",
      "20200101000000Z",
      "-enddate",
      "20200102000000Z"
    ])

    %{key: identity.key, certificate: certificate, der: certificate_der(certificate)}
  end

  defp certificate_der(path) do
    [{:Certificate, der, :not_encrypted}] = path |> File.read!() |> :public_key.pem_decode()
    der
  end

  defp openssl!(args), do: SignatureFixtures.openssl!(args)
end
