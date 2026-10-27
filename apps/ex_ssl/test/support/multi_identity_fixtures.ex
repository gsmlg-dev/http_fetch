defmodule ExSSL.TestSupport.MultiIdentityFixtures do
  @moduledoc false
  import ExUnit.Assertions

  @support Path.expand(__DIR__)
  @request "GET /r47 HTTP/1.1\r\nHost: r47.server\r\nConnection: close\r\n\r\n"
  @response "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nr47-peer-ok"
  @broad "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_pss_sha256:rsa_pss_pss_sha384:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ed25519:rsa_pkcs1_sha256:rsa_pkcs1_sha384"

  def create(directory) do
    fixtures = Path.join(directory, "fixtures")

    {_, 0} =
      System.cmd("python3", [Path.join(@support, "multi_identity_fixtures.py"), fixtures],
        stderr_to_stdout: true
      )

    manifest = fixtures |> Path.join("fixtures.json") |> File.read!() |> JSON.decode!()
    executable = Path.join(directory, "peer")

    flags =
      case System.find_executable("pkg-config") do
        nil ->
          ["-lssl", "-lcrypto"]

        pkg ->
          {out, 0} = System.cmd(pkg, ["--cflags", "--libs", "openssl"])
          String.split(out)
      end

    {_, 0} =
      System.cmd(
        "cc",
        [
          "-std=c11",
          "-D_DARWIN_C_SOURCE",
          "-D_GNU_SOURCE",
          "-Wall",
          "-Wextra",
          "-Werror",
          "-Wno-misleading-indentation",
          Path.join(@support, "multi_identity_peer.c"),
          "-o",
          executable
        ] ++ flags,
        stderr_to_stdout: true
      )

    Map.put(manifest, "peer", executable)
  end

  def der(m, name), do: Base.decode64!(m["identities"][name]["der_b64"])
  def root(m, name), do: Base.decode64!(m["roots"][name]["der_b64"])

  def identity(m, name, form \\ :files) do
    entry = m["identities"][name]

    case form do
      :files ->
        %{certfile: entry["cert"], keyfile: entry["key"]}

      :full ->
        %{certfile: entry["full_cert"], keyfile: entry["key"]}

      :partial ->
        %{certfile: entry["partial_cert"], keyfile: entry["key"]}

      :combined ->
        %{certfile: entry["combined"]}

      :der ->
        [{tag, bytes, :not_encrypted}] = entry["key"] |> File.read!() |> :public_key.pem_decode()
        %{cert: der(m, name), key: {tag, bytes}}
    end
  end

  def options(m, names, version \\ "tls13") do
    [
      cacerts: [root(m, "server-root")],
      server_name_indication: ~c"r47.server",
      versions: [if(version == "tls12", do: :"tlsv1.2", else: :"tlsv1.3")],
      certs_keys: Enum.map(names, &identity(m, &1)),
      active: false,
      mode: :binary
    ]
  end

  def name(der),
    do:
      der
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> elem(6)
      |> then(&:public_key.der_encode(:Name, &1))

  def with_peer(m, settings, operation) do
    hint = Keyword.get(settings, :hint)

    args = [
      m["server"]["cert"],
      m["server"]["key"],
      m["client_trust"],
      if(hint, do: m["roots"][hint]["cert"], else: "none"),
      Keyword.get(settings, :version, "tls13"),
      Keyword.get(settings, :auth, "required"),
      Keyword.get(settings, :schemes, @broad),
      Keyword.get(settings, :types, "default"),
      Keyword.get(settings, :groups, "X25519:P-256:P-384"),
      Keyword.get(settings, :application, "http")
    ]

    port =
      Port.open({:spawn_executable, m["peer"]}, [
        :binary,
        :exit_status,
        {:line, 65_536},
        args: args
      ])

    {:os_pid, pid} = Port.info(port, :os_pid)

    try do
      ready =
        receive do
          {^port, {:data, {:eol, line}}} ->
            JSON.decode!(line)

          {^port, {:exit_status, status}} ->
            flunk("independent multi-identity peer exited before ready: #{status}")
        after
          2_000 -> flunk("independent multi-identity peer not ready")
        end

      assert ready["event"] == "ready"
      result = operation.(ready["port"])
      {events, status} = collect(port, [], 500)
      assert status == 0
      assert not alive?(pid)
      {result, events}
    after
      _ =
        if alive?(pid) do
          _ = System.cmd("kill", ["-TERM", Integer.to_string(pid)], stderr_to_stdout: true)
          _ = collect(port, [], 1_000)
        end

      if Port.info(port), do: Port.close(port)
    end
  end

  def exchange(m, options, settings \\ [], mode \\ :host) do
    {result, events} =
      with_peer(m, settings, fn port ->
        connected =
          case mode do
            :host ->
              SSL.connect({127, 0, 0, 1}, port, options, 3_000)

            :prepared ->
              {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 3_000)
              SSL.connect_prepared(tcp, options, 3_000)
          end

        case connected do
          {:ok, socket} ->
            try do
              with :ok <- SSL.send(socket, @request), do: read(socket, <<>>)
            after
              SSL.close(socket)
            end

          error ->
            error
        end
      end)

    {result, events}
  end

  def assert_authenticated(m, events, expected, scheme, version, chain \\ nil) do
    [auth] = Enum.filter(events, &(&1["event"] == "authenticated"))
    [http] = Enum.filter(events, &(&1["event"] == "http"))
    wires = Enum.filter(events, &(&1["event"] == "wire_client_chain"))
    assert auth["verify_result"] == 0
    assert http["request_exact"] and http["response_written"]
    assert auth["version"] == if(version == "tls12", do: "TLSv1.2", else: "TLSv1.3")
    if version == "tls12", do: assert(auth["ems"] == 1 and auth["secure_renegotiation"] == 1)

    if expected do
      [wire] = wires
      assert auth["client_leaf_sha256"] == m["identities"][expected]["sha256"]
      assert wire["sha256"] == (chain || [m["identities"][expected]["sha256"]])
      assert [%{"scheme" => ^scheme}] = Enum.filter(events, &(&1["event"] == "client_cv"))
    else
      assert auth["client_leaf_sha256"] == nil

      assert wires == [%{"event" => "wire_client_chain", "sha256" => []}] or
               not Enum.any?(events, &(&1["event"] == "certificate_request"))

      refute Enum.any?(events, &(&1["event"] == "client_cv"))
    end
  end

  def response, do: @response
  defp read(_, @response), do: {:ok, @response}

  defp read(socket, bytes) do
    case SSL.recv(socket, 0, 3_000) do
      {:ok, part} -> read(socket, bytes <> part)
      error -> error
    end
  end

  defp collect(port, events, timeout) do
    receive do
      {^port, {:data, {:eol, line}}} -> collect(port, events ++ [JSON.decode!(line)], timeout)
      {^port, {:exit_status, status}} -> {events, status}
    after
      timeout -> {events, :timeout}
    end
  end

  defp alive?(pid) do
    {_, status} = System.cmd("kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true)
    status == 0
  end
end
