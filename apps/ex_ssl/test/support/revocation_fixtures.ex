defmodule ExSSL.TestSupport.RevocationFixtures do
  alias ExSSL.TestSupport.IndirectRevocationFixtures
  alias ExSSL.TestSupport.OffpathIntermediateFixtures

  @moduledoc false

  def directory!, do: fixture_directory("R49_POLICY_FIXTURES", "fixtures")
  def ocsp_directory!, do: fixture_directory("R49_OCSP_FIXTURES", "ocsp-fixtures")
  def ocsp_extended!, do: fixture_directory("R49_OCSP_EXTENDED", "ocsp-extended")

  def ocsp_mutated! do
    case System.get_env("R49_OCSP_FIXTURES") do
      nil -> generated!() |> Path.join("ocsp-mutated") |> verify!()
      source -> source |> Path.dirname() |> Path.join("ocsp-mutated") |> verify!()
    end
  end

  def leaf_variants! do
    case System.get_env("R49_POLICY_FIXTURES") do
      nil -> generated!() |> Path.join("leaf-variants") |> verify!()
      source -> source |> Path.dirname() |> Path.join("leaf-variants") |> verify!()
    end
  end

  defp fixture_directory(variable, name) do
    case System.get_env(variable) do
      nil -> generated!() |> Path.join(name) |> verify!()
      directory -> verify!(directory)
    end
  end

  # Integration-only fixtures are fresh for this VM and never stored in source.
  # The lock makes parallel setup_all callers share one bounded generation.
  defp generated! do
    :global.trans({{__MODULE__, :fixtures}, self()}, fn ->
      case :persistent_term.get({__MODULE__, :fixtures}, nil) do
        nil ->
          directory =
            Path.join(System.tmp_dir!(), "exssl-revocation-#{System.unique_integer([:positive])}")

          File.mkdir!(directory)

          try do
            create!(directory)

            ExUnit.after_suite(fn _ ->
              :persistent_term.erase({__MODULE__, :fixtures})
              File.rm_rf!(directory)
            end)

            :persistent_term.put({__MODULE__, :fixtures}, directory)
            directory
          rescue
            exception ->
              File.rm_rf!(directory)
              reraise exception, __STACKTRACE__
          end

        directory ->
          directory
      end
    end)
  end

  defp verify!(directory) do
    manifest = directory |> Path.join("manifest.json") |> File.read!() |> JSON.decode!()

    for %{"path" => path, "sha256" => expected} <- manifest["fixture_public_pins"] do
      actual =
        directory
        |> Path.join(path)
        |> File.read!()
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)

      if actual != expected, do: raise("public revocation fixture pin mismatch")
    end

    directory
  end

  def padded_ocsp!(base, source, target_bytes) do
    filename = if source == :leaf, do: "good.ocsp", else: "wrong-target.ocsp"
    signer = if source == :leaf, do: "intermediate", else: "root"
    response = File.read!(Path.join(ocsp_directory!(), filename))

    {:OCSPResponse, :successful, {:ResponseBytes, oid, bytes}} =
      :public_key.der_decode(:OCSPResponse, response)

    {:BasicOCSPResponse, data, algorithm, _, certs} =
      :public_key.der_decode(:BasicOCSPResponse, bytes)

    [entry] = :public_key.pem_decode(File.read!(Path.join(base, signer <> "-key.pem")))
    key = :public_key.pem_entry_decode(entry)

    result =
      Enum.reduce_while(0..3, 0, fn _, padding ->
        extension = {:Extension, {1, 2, 3, 4, 999}, false, :binary.copy(<<42>>, padding)}
        changed = put_elem(data, 5, [extension])
        signature = :public_key.sign(:public_key.der_encode(:ResponseData, changed), :sha256, key)

        basic =
          :public_key.der_encode(
            :BasicOCSPResponse,
            {:BasicOCSPResponse, changed, algorithm, signature, certs}
          )

        encoded =
          :public_key.der_encode(
            :OCSPResponse,
            {:OCSPResponse, :successful, {:ResponseBytes, oid, basic}}
          )

        if byte_size(encoded) == target_bytes,
          do: {:halt, encoded},
          else: {:cont, padding + target_bytes - byte_size(encoded)}
      end)

    if is_binary(result), do: result, else: raise("bounded OCSP padding did not converge")
  end

  def options(directory, version) do
    [
      mode: :binary,
      active: false,
      verify: :verify_peer,
      cacerts: [File.read!(Path.join(directory, "root.der"))],
      server_name_indication: ~c"r49.example",
      versions: [version]
    ]
  end

  def openssl do
    case System.get_env("R49_OPENSSL_LOADER") do
      nil ->
        {System.find_executable("openssl") || raise("OpenSSL unavailable"), []}

      loader ->
        {loader,
         [
           "--library-path",
           System.fetch_env!("R49_OPENSSL_LIBRARIES"),
           System.fetch_env!("R49_OPENSSL_CLI")
         ]}
    end
  end

  defp create!(directory) do
    base = Path.join(directory, "fixtures")
    File.mkdir!(base)
    create_chain!(base)
    create_crl_variants!(base)
    IndirectRevocationFixtures.create!(base)
    OffpathIntermediateFixtures.create!(base)
    create_ocsp!(directory, base)
    create_leaf_variants!(directory, base)
    create_ocsp_mutations!(directory, base)

    for name <- ["fixtures", "ocsp-fixtures", "ocsp-extended", "leaf-variants", "ocsp-mutated"] do
      public_manifest!(Path.join(directory, name))
    end
  end

  defp create_chain!(base) do
    for authority <- ["root", "intermediate"] do
      File.mkdir!(Path.join(base, authority <> "-newcerts"))
      write!(base, authority <> "-index", "")
      write!(base, authority <> "-serial", "1000\n")
      write!(base, authority <> "-crlnumber", "1000\n")

      write!(base, authority <> "-ca.cnf", """
      [ca]
      default_ca=local
      [local]
      database=#{authority}-index
      new_certs_dir=#{authority}-newcerts
      certificate=#{authority}.pem
      private_key=#{authority}-key.pem
      serial=#{authority}-serial
      crlnumber=#{authority}-crlnumber
      default_md=sha256
      default_days=3
      default_crl_days=2
      policy=policy
      unique_subject=no
      crl_extensions=crl
      [policy]
      commonName=supplied
      [intermediate]
      basicConstraints=critical,CA:TRUE,pathlen:1
      keyUsage=critical,keyCertSign,cRLSign
      subjectKeyIdentifier=hash
      authorityKeyIdentifier=keyid:always
      [leaf]
      basicConstraints=critical,CA:FALSE
      keyUsage=critical,digitalSignature,keyEncipherment
      extendedKeyUsage=serverAuth
      subjectAltName=DNS:r49.example
      subjectKeyIdentifier=hash
      authorityKeyIdentifier=keyid:always
      crlDistributionPoints=URI:http://127.0.0.1:18749/leaf.crl
      [crl]
      authorityKeyIdentifier=keyid:always
      """)
    end

    openssl!(base, [
      "req",
      "-new",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "3",
      "-subj",
      "/CN=ExSSL Revocation Root",
      "-keyout",
      "root-key.pem",
      "-out",
      "root.pem",
      "-addext",
      "basicConstraints=critical,CA:TRUE,pathlen:2",
      "-addext",
      "keyUsage=critical,keyCertSign,cRLSign"
    ])

    for {name, cn, issuer} <- [
          {"intermediate", "ExSSL Revocation Intermediate", "root"},
          {"leaf", "r49.example", "intermediate"}
        ] do
      openssl!(base, [
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=" <> cn,
        "-keyout",
        name <> "-key.pem",
        "-out",
        name <> ".csr"
      ])

      openssl!(base, [
        "ca",
        "-batch",
        "-config",
        issuer <> "-ca.cnf",
        "-extensions",
        name,
        "-in",
        name <> ".csr",
        "-out",
        name <> ".pem",
        "-notext"
      ])
    end

    for {issuer, name} <- [{"root", "root-good"}, {"intermediate", "leaf-good"}] do
      openssl!(base, [
        "ca",
        "-batch",
        "-config",
        issuer <> "-ca.cnf",
        "-gencrl",
        "-out",
        name <> ".crl.pem"
      ])
    end

    for {issuer, certificate, reason, name} <- [
          {"intermediate", "leaf", "keyCompromise", "leaf-revoked"},
          {"root", "intermediate", "cessationOfOperation", "root-revoked"}
        ] do
      openssl!(base, [
        "ca",
        "-batch",
        "-config",
        issuer <> "-ca.cnf",
        "-revoke",
        certificate <> ".pem",
        "-crl_reason",
        reason
      ])

      openssl!(base, [
        "ca",
        "-batch",
        "-config",
        issuer <> "-ca.cnf",
        "-gencrl",
        "-out",
        name <> ".crl.pem"
      ])
    end

    for name <- ["root", "intermediate", "leaf"] do
      openssl!(base, ["x509", "-in", name <> ".pem", "-outform", "DER", "-out", name <> ".der"])
    end

    for name <- ["root-good", "root-revoked", "leaf-good", "leaf-revoked"] do
      openssl!(base, [
        "crl",
        "-in",
        name <> ".crl.pem",
        "-outform",
        "DER",
        "-out",
        name <> ".crl.der"
      ])
    end

    for which <- ["good", "revoked", "intermediate-revoked", "missing"] do
      File.mkdir!(Path.join(base, which))

      if which != "missing" do
        install_hash_issuers(base, which)
      end
    end
  end

  defp create_crl_variants!(base) do
    for {prefix, key_name} <- [{"leaf", "intermediate"}, {"root", "root"}] do
      {:CertificateList, tbs, algorithm, _signature} =
        :public_key.der_decode(
          :CertificateList,
          File.read!(Path.join(base, prefix <> "-good.crl.der"))
        )

      [entry] = :public_key.pem_decode(File.read!(Path.join(base, key_name <> "-key.pem")))
      key = :public_key.pem_entry_decode(entry)
      [other_entry] = :public_key.pem_decode(File.read!(Path.join(base, "leaf-key.pem")))
      other = :public_key.pem_entry_decode(other_entry)
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      time = fn offset ->
        {:utcTime,
         now
         |> DateTime.add(offset, :second)
         |> Calendar.strftime("%y%m%d%H%M%SZ")
         |> String.to_charlist()}
      end

      signed = fn changed, signing_key ->
        signature =
          :public_key.sign(:public_key.der_encode(:TBSCertList, changed), :sha256, signing_key)

        :public_key.der_encode(
          :CertificateList,
          {:CertificateList, changed, algorithm, signature}
        )
      end

      write!(
        base,
        prefix <> "-stale.crl.der",
        signed.(tbs |> put_elem(4, time.(-7_200)) |> put_elem(5, time.(-3_600)), key)
      )

      write!(
        base,
        prefix <> "-future.crl.der",
        signed.(tbs |> put_elem(4, time.(172_800)) |> put_elem(5, time.(259_200)), key)
      )

      write!(base, prefix <> "-forged.crl.der", signed.(tbs, other))

      generalized = fn offset ->
        {:generalTime,
         now
         |> DateTime.add(offset, :second)
         |> Calendar.strftime("%Y%m%d%H%M%SZ")
         |> String.to_charlist()}
      end

      write!(
        base,
        prefix <> "-general-good.crl.der",
        signed.(put_elem(tbs, 4, generalized.(-60)), key)
      )

      write!(
        base,
        prefix <> "-general-future.crl.der",
        signed.(put_elem(tbs, 4, generalized.(172_800)), key)
      )

      write!(
        base,
        prefix <> "-malformed-time.crl.der",
        signed.(put_elem(tbs, 4, {:utcTime, ~c"261332000000Z"}), key)
      )
    end
  end

  defp create_ocsp!(directory, base) do
    target = Path.join(directory, "ocsp-fixtures")
    extended = Path.join(directory, "ocsp-extended")
    File.mkdir!(target)
    File.mkdir!(extended)
    good_index!(base, "intermediate-index", target, "good-index")
    good_index!(base, "root-index", target, "root-good-index")
    write!(target, "empty-index", "")

    for {name, index} <- [
          {"good", Path.join(target, "good-index")},
          {"revoked", Path.join(base, "intermediate-index")},
          {"unknown", Path.join(target, "empty-index")}
        ] do
      ocsp_response!(target, base, name, index, "intermediate", "intermediate", "leaf", [
        "-no_nonce"
      ])
    end

    ocsp_response!(
      target,
      base,
      "wrong-target",
      Path.join(target, "root-good-index"),
      "root",
      "root",
      "intermediate",
      ["-no_nonce"]
    )

    ocsp_response!(
      target,
      base,
      "wrong-signer",
      Path.join(target, "good-index"),
      "root",
      "intermediate",
      "leaf",
      ["-no_nonce"]
    )

    openssl!(target, [
      "ocsp",
      "-issuer",
      Path.join(base, "intermediate.pem"),
      "-cert",
      Path.join(base, "leaf.pem"),
      "-reqout",
      "nonce.req"
    ])

    openssl!(target, [
      "ocsp",
      "-index",
      "good-index",
      "-rsigner",
      Path.join(base, "intermediate.pem"),
      "-rkey",
      Path.join(base, "intermediate-key.pem"),
      "-CA",
      Path.join(base, "intermediate.pem"),
      "-reqin",
      "nonce.req",
      "-respout",
      "nonce.ocsp",
      "-ndays",
      "2"
    ])

    ocsp_response!(
      extended,
      base,
      "cross-intermediate",
      Path.join(target, "root-good-index"),
      "other-root",
      "other-root",
      "intermediate-cross",
      ["-no_nonce"]
    )

    write!(target, "malformed.ocsp", <<0x30, 3, 10, 1, 0>>)

    ocsp_response!(
      extended,
      base,
      "trusted-root",
      Path.join(target, "good-index"),
      "root",
      "intermediate",
      "leaf",
      ["-no_nonce"]
    )

    for {name, eku, authority} <- [
          {"delegated", true, "intermediate"},
          {"no-eku", false, "intermediate"},
          {"unrelated", true, "root"}
        ] do
      openssl!(extended, [
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        name <> "-key.pem",
        "-out",
        name <> ".csr",
        "-subj",
        "/CN=ExSSL " <> name
      ])

      write!(
        extended,
        name <> ".ext",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n" <>
          if(eku, do: "extendedKeyUsage=OCSPSigning\n", else: "")
      )

      openssl!(extended, [
        "x509",
        "-req",
        "-in",
        name <> ".csr",
        "-CA",
        Path.join(base, authority <> ".pem"),
        "-CAkey",
        Path.join(base, authority <> "-key.pem"),
        "-set_serial",
        Integer.to_string(5_000 + byte_size(name)),
        "-days",
        "2",
        "-extfile",
        name <> ".ext",
        "-out",
        name <> ".pem"
      ])

      openssl!(extended, [
        "ocsp",
        "-index",
        Path.join(target, "good-index"),
        "-rsigner",
        name <> ".pem",
        "-rkey",
        name <> "-key.pem",
        "-CA",
        Path.join(base, "intermediate.pem"),
        "-issuer",
        Path.join(base, "intermediate.pem"),
        "-cert",
        Path.join(base, "leaf.pem"),
        "-respout",
        name <> ".ocsp",
        "-ndays",
        "2",
        "-no_nonce"
      ])
    end

    [delegated] = :public_key.pem_decode(File.read!(Path.join(extended, "delegated.pem")))
    {:Certificate, delegated_der, :not_encrypted} = delegated
    {:OTPCertificate, delegated_tbs, _, _} = :public_key.pkix_decode_cert(delegated_der, :otp)
    [issuer_key] = :public_key.pem_decode(File.read!(Path.join(base, "intermediate-key.pem")))

    expired =
      :public_key.pkix_sign(
        put_elem(
          delegated_tbs,
          5,
          {:Validity, {:utcTime, ~c"250101000000Z"}, {:utcTime, ~c"250102000000Z"}}
        ),
        :public_key.pem_entry_decode(issuer_key)
      )

    write!(
      extended,
      "expired-delegated.pem",
      :public_key.pem_encode([{:Certificate, expired, :not_encrypted}])
    )

    write!(extended, "expired-delegated.der", expired)

    openssl!(extended, [
      "ocsp",
      "-index",
      Path.join(target, "good-index"),
      "-rsigner",
      "expired-delegated.pem",
      "-rkey",
      "delegated-key.pem",
      "-CA",
      Path.join(base, "intermediate.pem"),
      "-issuer",
      Path.join(base, "intermediate.pem"),
      "-cert",
      Path.join(base, "leaf.pem"),
      "-respout",
      "expired-delegated.ocsp",
      "-ndays",
      "2",
      "-no_nonce"
    ])
  end

  defp good_index!(base, source, target, name) do
    [_status, expires, _revoked, serial, filename, subject] =
      File.read!(Path.join(base, source)) |> String.trim() |> String.split("\t")

    write!(target, name, Enum.join(["V", expires, "", serial, filename, subject], "\t") <> "\n")
  end

  defp ocsp_response!(directory, base, name, index, signer, issuer, certificate, extra) do
    openssl!(
      directory,
      [
        "ocsp",
        "-index",
        index,
        "-rsigner",
        Path.join(base, signer <> ".pem"),
        "-rkey",
        Path.join(base, signer <> "-key.pem"),
        "-CA",
        Path.join(base, issuer <> ".pem"),
        "-issuer",
        Path.join(base, issuer <> ".pem"),
        "-cert",
        Path.join(base, certificate <> ".pem"),
        "-respout",
        name <> ".ocsp",
        "-ndays",
        "2"
      ] ++ extra
    )
  end

  defp public_manifest!(directory) do
    pins =
      for path <- Path.wildcard(Path.join(directory, "**/*")),
          File.regular?(path),
          not String.ends_with?(path, "-key.pem") do
        bytes = File.read!(path)

        %{
          path: Path.relative_to(path, directory),
          sha256: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
        }
      end

    write!(directory, "manifest.json", JSON.encode!(%{fixture_public_pins: pins}))
  end

  defp write!(directory, name, bytes), do: File.write!(Path.join(directory, name), bytes)

  defp openssl!(directory, arguments) do
    {executable, prefix} = openssl()

    handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        args: prefix ++ arguments,
        cd: directory
      ])

    {:os_pid, pid} = Port.info(handle, :os_pid)
    deadline = System.monotonic_time(:millisecond) + 30_000

    case collect_command(handle, deadline, [], 0) do
      {:ok, output} ->
        output

      {:error, _reason} ->
        if Port.info(handle) do
          _ = System.cmd("kill", ["-KILL", Integer.to_string(pid)], stderr_to_stdout: true)

          receive do
            {^handle, {:exit_status, _}} -> :ok
          after
            1_000 -> raise "revocation fixture command did not stop"
          end
        end

        raise "revocation fixture OpenSSL command failed"
    end
  end

  defp collect_command(handle, deadline, chunks, size) do
    receive do
      {^handle, {:data, bytes}} when size + byte_size(bytes) <= 262_144 ->
        collect_command(handle, deadline, [bytes | chunks], size + byte_size(bytes))

      {^handle, {:data, _}} ->
        {:error, :output_limit}

      {^handle, {:exit_status, 0}} ->
        {:ok, chunks |> Enum.reverse() |> IO.iodata_to_binary()}

      {^handle, {:exit_status, _}} ->
        {:error, :exit}
    after
      max(0, deadline - System.monotonic_time(:millisecond)) -> {:error, :timeout}
    end
  end

  defp create_leaf_variants!(root, base) do
    directory = Path.join(root, "leaf-variants")
    File.mkdir!(directory)
    leaf = :public_key.pkix_decode_cert(File.read!(Path.join(base, "leaf.der")), :otp)
    {:OTPCertificate, tbs, _, _} = leaf
    [key_entry] = :public_key.pem_decode(File.read!(Path.join(base, "intermediate-key.pem")))
    key = :public_key.pem_entry_decode(key_entry)
    extensions = elem(tbs, 10)

    replace = fn id, value ->
      Enum.map(extensions, fn
        {:Extension, ^id, critical, _} -> {:Extension, id, critical, value}
        extension -> extension
      end)
    end

    variants = [
      {"wrong-eku", put_elem(tbs, 10, replace.({2, 5, 29, 37}, [{1, 3, 6, 1, 5, 5, 7, 3, 2}]))},
      {"wrong-key-usage", put_elem(tbs, 10, replace.({2, 5, 29, 15}, [:keyEncipherment]))},
      {"unknown-critical",
       put_elem(
         tbs,
         10,
         extensions ++ [{:Extension, {1, 3, 6, 1, 4, 1, 55_555, 49}, true, <<5, 0>>}]
       )},
      {"expired",
       put_elem(tbs, 5, {:Validity, {:utcTime, ~c"250101000000Z"}, {:utcTime, ~c"250102000000Z"}})},
      {"ip-san",
       put_elem(
         tbs,
         10,
         replace.({2, 5, 29, 17}, dNSName: ~c"r49.example", iPAddress: <<127, 0, 0, 1>>)
       )},
      {"invalid-basic-constraints",
       put_elem(tbs, 10, replace.({2, 5, 29, 19}, {:BasicConstraints, false, 0}))},
      {"duplicate-san",
       put_elem(
         tbs,
         10,
         extensions ++ [{:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"wrong.example"]}]
       )},
      {"critical-policy-constraints",
       put_elem(
         tbs,
         10,
         extensions ++
           [{:Extension, {2, 5, 29, 36}, true, {:PolicyConstraints, 0, :asn1_NOVALUE}}]
       )}
    ]

    for {name, certificate} <- variants do
      bytes = :public_key.pkix_sign(certificate, key)
      path = name <> ".der"
      File.write!(Path.join(directory, path), bytes)

      File.write!(
        Path.join(directory, name <> ".pem"),
        :public_key.pem_encode([{:Certificate, bytes, :not_encrypted}])
      )

      for extension <- [".der", ".pem"] do
        filename = name <> extension
        data = File.read!(Path.join(directory, filename))

        %{
          path: filename,
          bytes: byte_size(data),
          sha256: Base.encode16(:crypto.hash(:sha256, data), case: :lower)
        }
      end
    end
    |> List.flatten()
  end

  defp create_ocsp_mutations!(root, base) do
    directory = Path.join(root, "ocsp-mutated")
    source = Path.join(root, "ocsp-fixtures")
    File.mkdir!(directory)

    {:OCSPResponse, :successful, {:ResponseBytes, oid, bytes}} =
      :public_key.der_decode(:OCSPResponse, File.read!(Path.join(source, "good.ocsp")))

    {:BasicOCSPResponse, data, algorithm, signature, certificates} =
      :public_key.der_decode(:BasicOCSPResponse, bytes)

    {:ResponseData, _, _, _, [single], _} = data
    {:SingleResponse, cert_id, _, _, _, _} = single
    [key_entry] = :public_key.pem_decode(File.read!(Path.join(base, "intermediate-key.pem")))
    key = :public_key.pem_entry_decode(key_entry)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    time = fn seconds ->
      now
      |> DateTime.add(seconds, :second)
      |> Calendar.strftime("%Y%m%d%H%M%SZ")
      |> String.to_charlist()
    end

    signed = fn changed_data, certs ->
      signed_bytes = :public_key.der_encode(:ResponseData, changed_data)
      signature = :public_key.sign(signed_bytes, :sha256, key)

      basic =
        :public_key.der_encode(
          :BasicOCSPResponse,
          {:BasicOCSPResponse, changed_data, algorithm, signature, certs}
        )

      :public_key.der_encode(
        :OCSPResponse,
        {:OCSPResponse, :successful, {:ResponseBytes, oid, basic}}
      )
    end

    with_single = fn changed -> put_elem(data, 4, [changed]) end

    mutations = [
      {"future-produced", signed.(put_elem(data, 3, time.(172_800)), certificates)},
      {"future-this-update",
       signed.(
         with_single.(single |> put_elem(3, time.(172_800)) |> put_elem(4, time.(259_200))),
         certificates
       )},
      {"expired-next-update",
       signed.(
         data
         |> put_elem(3, time.(-7_200))
         |> put_elem(4, [single |> put_elem(3, time.(-7_200)) |> put_elem(4, time.(-3_600))]),
         certificates
       )},
      {"missing-next-update",
       signed.(with_single.(put_elem(single, 4, :asn1_NOVALUE)), certificates)},
      {"wrong-serial",
       signed.(
         with_single.(put_elem(single, 1, put_elem(cert_id, 4, elem(cert_id, 4) + 1))),
         certificates
       )},
      {"wrong-name-hash",
       signed.(
         with_single.(
           put_elem(
             single,
             1,
             put_elem(cert_id, 2, :binary.copy(<<0>>, byte_size(elem(cert_id, 2))))
           )
         ),
         certificates
       )},
      {"wrong-key-hash",
       signed.(
         with_single.(
           put_elem(
             single,
             1,
             put_elem(cert_id, 3, :binary.copy(<<0>>, byte_size(elem(cert_id, 3))))
           )
         ),
         certificates
       )},
      {"bad-signature",
       :public_key.der_encode(
         :OCSPResponse,
         {:OCSPResponse, :successful,
          {:ResponseBytes, oid,
           :public_key.der_encode(
             :BasicOCSPResponse,
             {:BasicOCSPResponse, data, algorithm, :binary.copy(<<0>>, byte_size(signature)),
              certificates}
           )}}
       )},
      {"unsupported-response",
       :public_key.der_encode(
         :OCSPResponse,
         {:OCSPResponse, :successful, {:ResponseBytes, {1, 3, 6, 1, 5, 5, 7, 48, 1, 99}, bytes}}
       )},
      {"unsuccessful-response",
       :public_key.der_encode(:OCSPResponse, {:OCSPResponse, :unauthorized, :asn1_NOVALUE})}
    ]

    Enum.each(mutations, fn {name, bytes} ->
      File.write!(Path.join(directory, name <> ".ocsp"), bytes)
    end)
  end

  defp install_hash_issuers(base, which) do
    for issuer <- ["root", "intermediate"] do
      crl =
        case {issuer, which} do
          {"root", "intermediate-revoked"} -> "root-revoked"
          {"root", _} -> "root-good"
          {_, "revoked"} -> "leaf-revoked"
          _ -> "leaf-good"
        end

      hash =
        openssl!(base, ["x509", "-in", issuer <> ".pem", "-subject_hash", "-noout"])
        |> String.trim()

      File.cp!(Path.join(base, crl <> ".crl.pem"), Path.join([base, which, hash <> ".r0"]))
    end
  end
end

defmodule ExSSL.TestSupport.IndirectRevocationFixtures do
  @moduledoc false
  alias ExSSL.TestSupport.RevocationFixtures
  require Record

  Record.defrecord(
    :otp_cert,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :otp_tbs,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :raw_cert,
    :Certificate,
    Record.extract(:Certificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :raw_tbs,
    :TBSCertificate,
    Record.extract(:TBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :crl,
    :CertificateList,
    Record.extract(:CertificateList, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :crl_tbs,
    :TBSCertList,
    Record.extract(:TBSCertList, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :ext,
    :Extension,
    Record.extract(:Extension, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :dp,
    :DistributionPoint,
    Record.extract(:DistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :idp,
    :IssuingDistributionPoint,
    Record.extract(:IssuingDistributionPoint, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :validity,
    :Validity,
    Record.extract(:Validity, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecord(
    :aki,
    :AuthorityKeyIdentifier,
    Record.extract(:AuthorityKeyIdentifier, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  defp openssl(base, args) do
    {exe, prefix} = RevocationFixtures.openssl()
    {out, code} = System.cmd(exe, prefix ++ args, cd: base, stderr_to_stdout: true)

    IO.puts(
      JSON.encode!(%{
        oracle_argv: args,
        exit: code,
        output: if(hd(args) == "verify", do: out, else: "suppressed fixture generation output")
      })
    )

    {out, code}
  end

  defp command(base, args) do
    {out, 0} = openssl(base, args)
    out
  end

  defp key(base, name) do
    [entry] = :public_key.pem_decode(File.read!(Path.join(base, name <> "-key.pem")))
    :public_key.pem_entry_decode(entry)
  end

  defp cert(base, name),
    do: :public_key.pkix_decode_cert(File.read!(Path.join(base, name <> ".der")), :otp)

  defp public(base, name, type, der) do
    File.write!(Path.join(base, name <> ".der"), der)

    File.write!(
      Path.join(base, name <> ".pem"),
      :public_key.pem_encode([{type, der, :not_encrypted}])
    )
  end

  def create!(base) do
    File.write!(
      Path.join(base, "signer.ext"),
      "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
    )

    command(base, [
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=R49 Indirect CRL Signer",
      "-keyout",
      "signer-key.pem",
      "-out",
      "signer.csr"
    ])

    command(base, [
      "x509",
      "-req",
      "-in",
      "signer.csr",
      "-CA",
      "root.pem",
      "-CAkey",
      "root-key.pem",
      "-set_serial",
      "9301",
      "-days",
      "2",
      "-extfile",
      "signer.ext",
      "-out",
      "signer.pem"
    ])

    command(base, ["x509", "-in", "signer.pem", "-outform", "DER", "-out", "signer.der"])
    signer = cert(base, "signer")
    signer_tbs = otp_cert(signer, :tbsCertificate)
    signer_name = otp_tbs(signer_tbs, :subject)
    leaf_tbs = cert(base, "leaf") |> otp_cert(:tbsCertificate)

    point =
      dp(
        distributionPoint:
          {:fullName, [uniformResourceIdentifier: ~c"http://127.0.0.1/indirect.crl"]},
        cRLIssuer: [directoryName: signer_name]
      )

    extensions =
      Enum.reject(otp_tbs(leaf_tbs, :extensions), &(ext(&1, :extnID) == {2, 5, 29, 31}))

    leaf_tbs =
      otp_tbs(leaf_tbs,
        extensions:
          extensions ++ [ext(extnID: {2, 5, 29, 31}, critical: false, extnValue: [point])]
      )

    public(
      base,
      "indirect-leaf",
      :Certificate,
      :public_key.pkix_sign(leaf_tbs, key(base, "intermediate"))
    )

    {:CertificateList, old_tbs, algorithm, _} =
      :public_key.der_decode(:CertificateList, File.read!(Path.join(base, "leaf-good.crl.der")))

    raw_signer = :public_key.der_decode(:Certificate, File.read!(Path.join(base, "signer.der")))
    raw_subject = raw_signer |> raw_cert(:tbsCertificate) |> raw_tbs(:subject)

    ski =
      Enum.find(otp_tbs(signer_tbs, :extensions), &(ext(&1, :extnID) == {2, 5, 29, 14}))
      |> ext(:extnValue)

    authority = :public_key.der_encode(:AuthorityKeyIdentifier, aki(keyIdentifier: ski))
    idp = :public_key.der_encode(:IssuingDistributionPoint, idp(indirectCRL: true))

    crl_extensions = [
      ext(extnID: {2, 5, 29, 35}, critical: false, extnValue: authority),
      ext(extnID: {2, 5, 29, 28}, critical: true, extnValue: idp)
    ]

    new_tbs = crl_tbs(old_tbs, issuer: raw_subject, crlExtensions: crl_extensions)

    signature =
      :public_key.sign(
        :public_key.der_encode(:TBSCertList, new_tbs),
        :sha256,
        key(base, "signer")
      )

    public(
      base,
      "indirect-crl",
      :CertificateList,
      :public_key.der_encode(
        :CertificateList,
        crl(tbsCertList: new_tbs, signatureAlgorithm: algorithm, signature: signature)
      )
    )

    File.write!(
      Path.join(base, "extra-chain.pem"),
      File.read!(Path.join(base, "intermediate.pem")) <> File.read!(Path.join(base, "signer.pem"))
    )

    # Same key and subject, independently issued serial: revoking S must not
    # revoke this usable alternate certificate merely because it verifies a CRL.
    public(
      base,
      "signer-alternate",
      :Certificate,
      :public_key.pkix_sign(otp_tbs(signer_tbs, serialNumber: 9302), key(base, "root"))
    )

    leaf_key_info =
      cert(base, "leaf") |> otp_cert(:tbsCertificate) |> otp_tbs(:subjectPublicKeyInfo)

    alternate_extensions =
      Enum.reject(otp_tbs(signer_tbs, :extensions), &(ext(&1, :extnID) == {2, 5, 29, 14}))

    alternate_tbs =
      otp_tbs(signer_tbs,
        serialNumber: 9303,
        subjectPublicKeyInfo: leaf_key_info,
        extensions: alternate_extensions
      )

    public(
      base,
      "signer-alternate-key",
      :Certificate,
      :public_key.pkix_sign(alternate_tbs, key(base, "root"))
    )

    alternate_crl_tbs =
      crl_tbs(new_tbs,
        crlExtensions: Enum.reject(crl_extensions, &(ext(&1, :extnID) == {2, 5, 29, 35}))
      )

    alternate_signature =
      :public_key.sign(
        :public_key.der_encode(:TBSCertList, alternate_crl_tbs),
        :sha256,
        key(base, "leaf")
      )

    public(
      base,
      "indirect-crl-alternate",
      :CertificateList,
      :public_key.der_encode(
        :CertificateList,
        crl(
          tbsCertList: alternate_crl_tbs,
          signatureAlgorithm: algorithm,
          signature: alternate_signature
        )
      )
    )

    variants!(base, signer_tbs)
    delta_variants!(base)
    partial_variants!(base)
    base
  end

  defp variants!(base, signer_tbs) do
    extensions = otp_tbs(signer_tbs, :extensions)

    no_usage =
      Enum.map(extensions, fn extension ->
        if ext(extension, :extnID) == {2, 5, 29, 15},
          do: ext(extension, extnValue: [:digitalSignature]),
          else: extension
      end)

    expired =
      validity(notBefore: {:utcTime, ~c"200101000000Z"}, notAfter: {:utcTime, ~c"210101000000Z"})

    for {name, changed, signing_key} <- [
          {"no-crlsign", otp_tbs(signer_tbs, extensions: no_usage), key(base, "root")},
          {"expired", otp_tbs(signer_tbs, validity: expired), key(base, "root")},
          {"critical",
           otp_tbs(signer_tbs,
             extensions:
               extensions ++ [ext(extnID: {1, 2, 3, 4, 999}, critical: true, extnValue: <<5, 0>>)]
           ), key(base, "root")},
          {"bad-signature", signer_tbs, key(base, "leaf")}
        ] do
      public(base, "signer-" <> name, :Certificate, :public_key.pkix_sign(changed, signing_key))
    end

    for {name, subject} <- [
          {"other-root", "/CN=Other CRL Root"},
          {"same-name-root", "/CN=ExSSL Revocation Root"}
        ] do
      command(base, [
        "req",
        "-new",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        subject,
        "-keyout",
        name <> "-key.pem",
        "-out",
        name <> ".pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:3",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign"
      ])

      command(base, ["x509", "-in", name <> ".pem", "-outform", "DER", "-out", name <> ".der"])
      issuer = cert(base, name) |> otp_cert(:tbsCertificate) |> otp_tbs(:subject)
      # Strip old AKI so the alternative is independently cryptographically valid.
      changed =
        otp_tbs(signer_tbs,
          issuer: issuer,
          extensions: Enum.reject(extensions, &(ext(&1, :extnID) == {2, 5, 29, 35}))
        )

      public(
        base,
        "signer-" <> name,
        :Certificate,
        :public_key.pkix_sign(changed, key(base, name))
      )
    end

    # A fully signed off-path branch whose CA A forbids the subordinate CA B.
    command(base, [
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=CRL Branch A",
      "-keyout",
      "branch-a-key.pem",
      "-out",
      "branch-a.csr"
    ])

    command(base, [
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=CRL Branch B",
      "-keyout",
      "branch-b-key.pem",
      "-out",
      "branch-b.csr"
    ])

    File.write!(
      Path.join(base, "branch.ext"),
      "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n"
    )

    for {name, issuer} <- [{"branch-a", "root"}, {"branch-b", "branch-a"}] do
      command(base, [
        "x509",
        "-req",
        "-in",
        name <> ".csr",
        "-CA",
        issuer <> ".pem",
        "-CAkey",
        issuer <> "-key.pem",
        "-set_serial",
        "9401",
        "-days",
        "2",
        "-extfile",
        "branch.ext",
        "-out",
        name <> ".pem"
      ])

      command(base, ["x509", "-in", name <> ".pem", "-outform", "DER", "-out", name <> ".der"])
    end

    issuer = cert(base, "branch-b") |> otp_cert(:tbsCertificate) |> otp_tbs(:subject)

    changed =
      otp_tbs(signer_tbs,
        issuer: issuer,
        extensions: Enum.reject(extensions, &(ext(&1, :extnID) == {2, 5, 29, 35}))
      )

    public(
      base,
      "signer-pathlen",
      :Certificate,
      :public_key.pkix_sign(changed, key(base, "branch-b"))
    )

    for name <- [
          "no-crlsign",
          "expired",
          "critical",
          "bad-signature",
          "other-root",
          "same-name-root",
          "pathlen"
        ] do
      extra = if name == "pathlen", do: ["branch-b", "branch-a"], else: []

      File.write!(
        Path.join(base, "chain-" <> name <> ".pem"),
        IO.iodata_to_binary(
          Enum.map(
            ["intermediate", "signer-" <> name] ++ extra,
            &File.read!(Path.join(base, &1 <> ".pem"))
          )
        )
      )
    end

    # Same signed issuer/IDP, but a different private key signs the CRL.
    {:CertificateList, tbs, algorithm, _} =
      :public_key.der_decode(:CertificateList, File.read!(Path.join(base, "indirect-crl.der")))

    signature =
      :public_key.sign(:public_key.der_encode(:TBSCertList, tbs), :sha256, key(base, "leaf"))

    public(
      base,
      "indirect-crl-wrong-key",
      :CertificateList,
      :public_key.der_encode(
        :CertificateList,
        crl(tbsCertList: tbs, signatureAlgorithm: algorithm, signature: signature)
      )
    )
  end

  defp delta_variants!(base) do
    leaf_tbs = cert(base, "leaf") |> otp_cert(:tbsCertificate)

    extensions =
      Enum.reject(otp_tbs(leaf_tbs, :extensions), &(ext(&1, :extnID) == {2, 5, 29, 31}))

    points =
      for name <- ["second", "first"],
          do:
            dp(
              distributionPoint:
                {:fullName,
                 [uniformResourceIdentifier: String.to_charlist("http://127.0.0.1/" <> name)]}
            )

    for {name, extra} <- [
          {"two-dp-leaf", [ext(extnID: {2, 5, 29, 31}, critical: false, extnValue: points)]},
          {"no-dp-leaf", []}
        ] do
      public(
        base,
        name,
        :Certificate,
        :public_key.pkix_sign(
          otp_tbs(leaf_tbs, extensions: extensions ++ extra),
          key(base, "intermediate")
        )
      )
    end

    {:CertificateList, good, algorithm, _} =
      :public_key.der_decode(:CertificateList, File.read!(Path.join(base, "leaf-good.crl.der")))

    {:CertificateList, revoked, _, _} =
      :public_key.der_decode(
        :CertificateList,
        File.read!(Path.join(base, "leaf-revoked.crl.der"))
      )

    [entry] = crl_tbs(revoked, :revokedCertificates)

    reason_entry = fn reason ->
      put_elem(entry, 3, [
        ext(
          extnID: {2, 5, 29, 21},
          critical: false,
          extnValue: :public_key.der_encode(:CRLReason, reason)
        )
      ])
    end

    hold = reason_entry.(:certificateHold)
    removed = reason_entry.(:removeFromCRL)

    base_extensions =
      Enum.reject(crl_tbs(good, :crlExtensions), &(ext(&1, :extnID) == {2, 5, 29, 20}))

    for {name, entries, number, delta} <- [
          {"base-good", :asn1_NOVALUE, 100, nil},
          {"base-hold", [hold], 100, nil},
          {"delta-good", :asn1_NOVALUE, 101, 100},
          {"delta-revoked", [entry], 101, 100},
          {"delta-remove", [removed], 101, 100},
          {"delta-wrong-base", [removed], 101, 102}
        ] do
      extensions =
        base_extensions ++
          [
            ext(
              extnID: {2, 5, 29, 20},
              critical: false,
              extnValue: :public_key.der_encode(:CRLNumber, number)
            )
          ]

      freshest =
        :public_key.der_encode(:CRLDistributionPoints, [
          dp(
            distributionPoint:
              {:fullName, [uniformResourceIdentifier: ~c"http://127.0.0.1/delta.crl"]}
          )
        ])

      extensions =
        if delta,
          do:
            extensions ++
              [
                ext(
                  extnID: {2, 5, 29, 27},
                  critical: true,
                  extnValue: :public_key.der_encode(:BaseCRLNumber, delta)
                )
              ],
          else: extensions ++ [ext(extnID: {2, 5, 29, 46}, critical: false, extnValue: freshest)]

      tbs = crl_tbs(good, revokedCertificates: entries, crlExtensions: extensions)

      signature =
        :public_key.sign(
          :public_key.der_encode(:TBSCertList, tbs),
          :sha256,
          key(base, "intermediate")
        )

      public(
        base,
        name,
        :CertificateList,
        :public_key.der_encode(
          :CertificateList,
          crl(tbsCertList: tbs, signatureAlgorithm: algorithm, signature: signature)
        )
      )
    end

    all_reasons = [
      :cACompromise,
      :affiliationChanged,
      :superseded,
      :cessationOfOperation,
      :certificateHold,
      :privilegeWithdrawn,
      :aACompromise
    ]

    for {name, additions, remove} <- [
          {"reason-key",
           [
             ext(
               extnID: {2, 5, 29, 28},
               critical: true,
               extnValue:
                 :public_key.der_encode(
                   :IssuingDistributionPoint,
                   idp(onlySomeReasons: [:keyCompromise])
                 )
             )
           ], []},
          {"reason-rest",
           [
             ext(
               extnID: {2, 5, 29, 28},
               critical: true,
               extnValue:
                 :public_key.der_encode(
                   :IssuingDistributionPoint,
                   idp(onlySomeReasons: all_reasons)
                 )
             )
           ], []},
          {"wrong-aki",
           [
             ext(
               extnID: {2, 5, 29, 35},
               critical: false,
               extnValue:
                 :public_key.der_encode(
                   :AuthorityKeyIdentifier,
                   aki(keyIdentifier: :binary.copy(<<0>>, 20))
                 )
             )
           ], [{2, 5, 29, 35}]},
          {"unknown-critical",
           [ext(extnID: {1, 2, 3, 4, 999}, critical: true, extnValue: <<5, 0>>)], []}
        ] do
      extensions =
        Enum.reject(crl_tbs(good, :crlExtensions), &(ext(&1, :extnID) in remove)) ++ additions

      tbs = crl_tbs(good, crlExtensions: extensions)

      signature =
        :public_key.sign(
          :public_key.der_encode(:TBSCertList, tbs),
          :sha256,
          key(base, "intermediate")
        )

      public(
        base,
        name,
        :CertificateList,
        :public_key.der_encode(
          :CertificateList,
          crl(tbsCertList: tbs, signatureAlgorithm: algorithm, signature: signature)
        )
      )
    end

    {:CertificateList, root_crl, root_algorithm, _} =
      :public_key.der_decode(:CertificateList, File.read!(Path.join(base, "root-good.crl.der")))

    serial = cert(base, "signer") |> otp_cert(:tbsCertificate) |> otp_tbs(:serialNumber)
    tbs = crl_tbs(root_crl, revokedCertificates: [put_elem(entry, 1, serial)])

    signature =
      :public_key.sign(:public_key.der_encode(:TBSCertList, tbs), :sha256, key(base, "root"))

    public(
      base,
      "root-signer-revoked",
      :CertificateList,
      :public_key.der_encode(
        :CertificateList,
        crl(tbsCertList: tbs, signatureAlgorithm: root_algorithm, signature: signature)
      )
    )

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    time = fn offset ->
      {:utcTime,
       now
       |> DateTime.add(offset, :second)
       |> Calendar.strftime("%y%m%d%H%M%SZ")
       |> String.to_charlist()}
    end

    for {name, changed, signing_key} <- [
          {"forged", tbs, key(base, "leaf")},
          {"stale", crl_tbs(tbs, thisUpdate: time.(-7_200), nextUpdate: time.(-3_600)),
           key(base, "root")},
          {"future", crl_tbs(tbs, thisUpdate: time.(172_800), nextUpdate: time.(259_200)),
           key(base, "root")},
          {"wrong-issuer", crl_tbs(tbs, issuer: crl_tbs(good, :issuer)), key(base, "root")}
        ] do
      signature =
        :public_key.sign(:public_key.der_encode(:TBSCertList, changed), :sha256, signing_key)

      public(
        base,
        "root-signer-" <> name,
        :CertificateList,
        :public_key.der_encode(
          :CertificateList,
          crl(tbsCertList: changed, signatureAlgorithm: root_algorithm, signature: signature)
        )
      )
    end
  end

  defp partial_variants!(base) do
    intermediate = cert(base, "intermediate") |> otp_cert(:tbsCertificate)

    extensions =
      otp_tbs(intermediate, :extensions) |> Enum.reject(&(ext(&1, :extnID) == {2, 5, 29, 35}))

    issuer = cert(base, "other-root") |> otp_cert(:tbsCertificate) |> otp_tbs(:subject)
    cross = otp_tbs(intermediate, issuer: issuer, extensions: extensions)

    expired =
      validity(notBefore: {:utcTime, ~c"200101000000Z"}, notAfter: {:utcTime, ~c"210101000000Z"})

    public(
      base,
      "intermediate-cross",
      :Certificate,
      :public_key.pkix_sign(cross, key(base, "other-root"))
    )

    public(
      base,
      "intermediate-cross-expired",
      :Certificate,
      :public_key.pkix_sign(otp_tbs(cross, validity: expired), key(base, "other-root"))
    )

    leaf = cert(base, "leaf") |> otp_cert(:tbsCertificate)

    public(
      base,
      "leaf-bad-signature",
      :Certificate,
      :public_key.pkix_sign(leaf, key(base, "root"))
    )

    self_extensions =
      otp_tbs(leaf, :extensions) |> Enum.reject(&(ext(&1, :extnID) == {2, 5, 29, 35}))

    self_leaf = otp_tbs(leaf, issuer: otp_tbs(leaf, :subject), extensions: self_extensions)

    public(
      base,
      "leaf-selfsigned",
      :Certificate,
      :public_key.pkix_sign(self_leaf, key(base, "leaf"))
    )

    a = cert(base, "branch-a") |> otp_cert(:tbsCertificate)

    extensions =
      Enum.map(otp_tbs(a, :extensions), fn e ->
        if ext(e, :extnID) == {2, 5, 29, 19},
          do: ext(e, extnValue: {:BasicConstraints, true, 2}),
          else: e
      end)

    good_a = otp_tbs(a, extensions: extensions)
    public(base, "branch-a-valid", :Certificate, :public_key.pkix_sign(good_a, key(base, "root")))

    constraints =
      {:NameConstraints, [{:GeneralSubtree, {:dNSName, ~c".allowed.example"}, 0, :asn1_NOVALUE}],
       :asn1_NOVALUE}

    for {name, e} <- [
          {"name-constraint",
           ext(extnID: {2, 5, 29, 30}, critical: true, extnValue: constraints)},
          {"critical", ext(extnID: {1, 2, 3, 4, 999}, critical: true, extnValue: <<5, 0>>)}
        ] do
      public(
        base,
        "branch-a-" <> name,
        :Certificate,
        :public_key.pkix_sign(otp_tbs(good_a, extensions: extensions ++ [e]), key(base, "root"))
      )
    end

    issuer = cert(base, "branch-b") |> otp_cert(:tbsCertificate) |> otp_tbs(:subject)
    extensions = otp_tbs(leaf, :extensions) |> Enum.reject(&(ext(&1, :extnID) == {2, 5, 29, 35}))

    public(
      base,
      "leaf-branch",
      :Certificate,
      :public_key.pkix_sign(
        otp_tbs(leaf, issuer: issuer, extensions: extensions),
        key(base, "branch-b")
      )
    )

    b = cert(base, "branch-b") |> otp_cert(:tbsCertificate)
    b_extensions = otp_tbs(b, :extensions)

    for {name, additions} <- [
          {"name-constraint",
           [ext(extnID: {2, 5, 29, 30}, critical: true, extnValue: constraints)]},
          {"critical", [ext(extnID: {1, 2, 3, 4, 999}, critical: true, extnValue: <<5, 0>>)]}
        ] do
      public(
        base,
        "branch-b-" <> name,
        :Certificate,
        :public_key.pkix_sign(
          otp_tbs(b, extensions: b_extensions ++ additions),
          key(base, "branch-a")
        )
      )
    end

    b_deep =
      Enum.map(b_extensions, fn e ->
        if ext(e, :extnID) == {2, 5, 29, 19},
          do: ext(e, extnValue: {:BasicConstraints, true, 1}),
          else: e
      end)

    public(
      base,
      "branch-b-depth1",
      :Certificate,
      :public_key.pkix_sign(otp_tbs(b, extensions: b_deep), key(base, "branch-a"))
    )

    command(base, [
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-subj",
      "/CN=CRL Branch C",
      "-keyout",
      "branch-c-key.pem",
      "-out",
      "branch-c.csr"
    ])

    command(base, [
      "x509",
      "-req",
      "-in",
      "branch-c.csr",
      "-CA",
      "branch-b.pem",
      "-CAkey",
      "branch-b-key.pem",
      "-set_serial",
      "9402",
      "-days",
      "2",
      "-extfile",
      "branch.ext",
      "-out",
      "branch-c.pem"
    ])

    command(base, ["x509", "-in", "branch-c.pem", "-outform", "DER", "-out", "branch-c.der"])
    c_issuer = cert(base, "branch-c") |> otp_cert(:tbsCertificate) |> otp_tbs(:subject)

    public(
      base,
      "leaf-below-c",
      :Certificate,
      :public_key.pkix_sign(
        otp_tbs(leaf, issuer: c_issuer, extensions: extensions),
        key(base, "branch-c")
      )
    )

    for {name, chain} <- [
          {"valid", ["branch-b", "branch-a-valid"]},
          {"name-constraint", ["branch-b-name-constraint", "branch-a-valid"]},
          {"critical", ["branch-b-critical", "branch-a-valid"]},
          {"pathlen", ["branch-c", "branch-b", "branch-a-valid"]},
          {"pathlen-valid", ["branch-c", "branch-b-depth1", "branch-a-valid"]}
        ] do
      File.write!(
        Path.join(base, "below-anchor-" <> name <> ".pem"),
        IO.iodata_to_binary(Enum.map(chain, &File.read!(Path.join(base, &1 <> ".pem"))))
      )
    end

    for {name, chain} <- [
          {"cross-retry", ["intermediate", "intermediate-cross-expired"]},
          {"cross-both", ["intermediate", "intermediate-cross"]},
          {"misordered", ["root", "other-root", "intermediate"]},
          {"duplicated", ["intermediate", "intermediate", "root"]},
          {"branch-valid", ["branch-b", "branch-a-valid"]},
          {"branch-pathlen", ["branch-b", "branch-a"]},
          {"branch-name-constraint", ["branch-b", "branch-a-name-constraint"]},
          {"branch-critical", ["branch-b", "branch-a-critical"]}
        ] do
      File.write!(
        Path.join(base, "partial-" <> name <> ".pem"),
        IO.iodata_to_binary(Enum.map(chain, &File.read!(Path.join(base, &1 <> ".pem"))))
      )
    end
  end
end

defmodule ExSSL.TestSupport.OffpathIntermediateFixtures do
  @moduledoc false
  require Record

  Record.defrecordp(
    :cert,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :tbs,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :crl,
    :CertificateList,
    Record.extract(:CertificateList, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :crl_tbs,
    :TBSCertList,
    Record.extract(:TBSCertList, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :ext,
    :Extension,
    Record.extract(:Extension, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  defp read(base, name), do: File.read!(Path.join(base, name))

  defp key(base, name) do
    [entry] = :public_key.pem_decode(read(base, name <> "-key.pem"))
    :public_key.pem_entry_decode(entry)
  end

  defp public(base, name, type, der) do
    File.write!(Path.join(base, name <> ".der"), der)

    File.write!(
      Path.join(base, name <> ".pem"),
      :public_key.pem_encode([{type, der, :not_encrypted}])
    )
  end

  def create!(base) do
    signer = :public_key.pkix_decode_cert(read(base, "signer.der"), :otp) |> cert(:tbsCertificate)

    branch =
      :public_key.pkix_decode_cert(read(base, "branch-a-valid.der"), :otp)
      |> cert(:tbsCertificate)

    extensions = tbs(signer, :extensions) |> Enum.reject(&(ext(&1, :extnID) == {2, 5, 29, 35}))
    signer = tbs(signer, issuer: tbs(branch, :subject), extensions: extensions)

    public(
      base,
      "signer-via-j",
      :Certificate,
      :public_key.pkix_sign(signer, key(base, "branch-a"))
    )

    {:CertificateList, root_good, algorithm, _} =
      :public_key.der_decode(:CertificateList, read(base, "root-good.crl.der"))

    raw_branch = :public_key.der_decode(:Certificate, read(base, "branch-a-valid.der"))

    j_good =
      crl_tbs(root_good, issuer: elem(elem(raw_branch, 1), 6), crlExtensions: :asn1_NOVALUE)

    sign_crl = fn name, body, signer_name ->
      signature =
        :public_key.sign(
          :public_key.der_encode(:TBSCertList, body),
          :sha256,
          key(base, signer_name)
        )

      public(
        base,
        name,
        :CertificateList,
        :public_key.der_encode(
          :CertificateList,
          crl(tbsCertList: body, signatureAlgorithm: algorithm, signature: signature)
        )
      )
    end

    sign_crl.("j-good", j_good, "branch-a")

    {:CertificateList, revoked, _, _} =
      :public_key.der_decode(:CertificateList, read(base, "root-signer-revoked.der"))

    [entry] = crl_tbs(revoked, :revokedCertificates)

    revoked =
      crl_tbs(revoked, revokedCertificates: [put_elem(entry, 1, tbs(branch, :serialNumber))])

    now = DateTime.utc_now() |> DateTime.truncate(:second)

    time = fn offset ->
      {:utcTime,
       now
       |> DateTime.add(offset, :second)
       |> Calendar.strftime("%y%m%d%H%M%SZ")
       |> String.to_charlist()}
    end

    for {name, body, signer_name} <- [
          {"revoked", revoked, "root"},
          {"good", root_good, "root"},
          {"forged", revoked, "leaf"},
          {"stale", crl_tbs(revoked, thisUpdate: time.(-7200), nextUpdate: time.(-3600)), "root"},
          {"future", crl_tbs(revoked, thisUpdate: time.(172_800), nextUpdate: time.(259_200)),
           "root"},
          {"wrong-issuer", crl_tbs(revoked, issuer: crl_tbs(j_good, :issuer)), "root"}
        ],
        do: sign_crl.("root-j-" <> name, body, signer_name)

    File.write!(
      Path.join(base, "j-chain.pem"),
      read(base, "branch-a-valid.pem") <> read(base, "signer-via-j.pem")
    )

    alternate = tbs(branch, serialNumber: 9441)
    public(base, "j-alternate", :Certificate, :public_key.pkix_sign(alternate, key(base, "root")))
    expired = {:Validity, {:utcTime, ~c"200101000000Z"}, {:utcTime, ~c"210101000000Z"}}

    public(
      base,
      "j-expired",
      :Certificate,
      :public_key.pkix_sign(tbs(alternate, validity: expired), key(base, "root"))
    )

    public(
      base,
      "j-bad-signature",
      :Certificate,
      :public_key.pkix_sign(alternate, key(base, "leaf"))
    )

    base
  end
end
