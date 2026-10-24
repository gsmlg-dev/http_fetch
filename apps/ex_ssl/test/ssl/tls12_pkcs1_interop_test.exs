defmodule SSL.TLS12PKCS1InteropTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.{ClientAuthFixtures, LocalTLSPeer, SignatureFixtures}

  setup_all do
    directory = Path.join(System.tmp_dir!(), "exssl-pkcs1-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, directory: directory, fixtures: ClientAuthFixtures.create(directory)}
  end

  for {scheme, hash} <- [{0x0401, :sha256}, {0x0501, :sha384}, {0x0601, :sha512}],
      mutual? <- [false, true] do
    test "independent TLS12 #{hash} PKCS1 server authentication, mTLS=#{mutual?}", context do
      run_case(context, unquote(scheme), unquote(hash), unquote(mutual?))
    end
  end

  defp run_case(context, scheme, hash, mutual?) do
    server = signed_certificate(context, :server, hash)
    client = signed_certificate(context, :rsa, hash)
    peer = start_peer(context, server, hash, mutual?)

    try do
      options = [
        mode: :binary,
        active: false,
        packet: :raw,
        verify: :verify_peer,
        cacerts: [context.fixtures.ca.der],
        server_name_indication: ~c"exssl.test",
        versions: [:"tlsv1.2"],
        signature_algs: [scheme_name(hash)],
        ciphers: [%{key_exchange: :ecdhe_rsa, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}],
        alpn_advertised_protocols: ["http/1.1"]
      ]

      options =
        if mutual?,
          do: options ++ [certfile: client, keyfile: context.fixtures.rsa.key],
          else: options

      assert {:ok, socket} = SSL.connect({127, 0, 0, 1}, peer.port, options, 5_000)

      try do
        assert {:ok, "http/1.1"} = SSL.negotiated_protocol(socket)
        assert :ok = SSL.send(socket, "GET / HTTP/1.0\r\n\r\n")
        response = receive_response(socket, <<>>)
        assert response =~ "HTTP/1.0 200 ok"
        assert response =~ "ECDHE-RSA-AES128-GCM-SHA256"
        assert response =~ "TLSv1.2"
        assert byte_size(response) > 1_000
      after
        SSL.close(socket)
      end

      assert :ok = await_exit(peer.port_handle, System.monotonic_time(:millisecond) + 5_000)
      trace = File.read!(peer.trace)

      expected =
        "Signature Algorithm: rsa_pkcs1_#{hash} (0x#{scheme |> Integer.to_string(16) |> String.pad_leading(4, "0")})"

      assert Regex.match?(
               ~r/ServerKeyExchange[^\n]*\n(?:(?!\n\n).)*#{Regex.escape(expected)}/s,
               trace
             )

      algorithms =
        Regex.scan(~r/Signature Algorithm: rsa_pkcs1_sha\d+ \(0x[0-9a-f]+\)/, trace)
        |> List.flatten()

      assert algorithms == List.duplicate(expected, if(mutual?, do: 2, else: 1))

      if mutual? do
        assert Regex.match?(~r/CertificateVerify[^\n]*\n\s+#{Regex.escape(expected)}/, trace)
      else
        refute trace =~ "CertificateVerify,"
      end
    after
      LocalTLSPeer.stop_openssl(peer)
    end
  end

  defp scheme_name(:sha256), do: :rsa_pkcs1_sha256
  defp scheme_name(:sha384), do: :rsa_pkcs1_sha384
  defp scheme_name(:sha512), do: :rsa_pkcs1_sha512

  defp signed_certificate(context, role, hash) do
    source = Map.fetch!(context.fixtures, role)
    certificate = Path.join(context.directory, "#{role}-#{hash}.pem")
    extension = Path.rootname(source.request) <> ".ext"

    SignatureFixtures.openssl!([
      "x509",
      "-req",
      "-in",
      source.request,
      "-CA",
      context.fixtures.ca.certificate,
      "-CAkey",
      context.fixtures.ca.key,
      "-CAcreateserial",
      "-#{hash}",
      "-days",
      "2",
      "-extfile",
      extension,
      "-out",
      certificate
    ])

    certificate
  end

  defp start_peer(context, certificate, hash, mutual?) do
    {:ok, reservation} = :gen_tcp.listen(0, [:binary, active: false])
    {:ok, {_address, port}} = :inet.sockname(reservation)
    :ok = :gen_tcp.close(reservation)
    trace = Path.join(context.directory, "#{hash}-#{mutual?}.trace")

    args = [
      "s_server",
      "-accept",
      "127.0.0.1:#{port}",
      "-cert",
      certificate,
      "-key",
      context.fixtures.server.key,
      "-tls1_2",
      "-cipher",
      "ECDHE-RSA-AES128-GCM-SHA256",
      "-sigalgs",
      "rsa_pkcs1_#{hash}",
      "-client_sigalgs",
      "rsa_pkcs1_#{hash}",
      "-alpn",
      "http/1.1",
      "-no_ticket",
      "-www",
      "-naccept",
      "1",
      "-trace",
      "-msgfile",
      trace
    ]

    args =
      if mutual?,
        do:
          args ++
            ["-Verify", "2", "-CAfile", context.fixtures.ca.certificate, "-verify_return_error"],
        else: args

    executable = System.find_executable("openssl") || raise "openssl is required"

    handle =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 524_288},
        args: args
      ])

    peer = %{port: port, port_handle: handle, trace: trace}

    try do
      await_ready(handle, System.monotonic_time(:millisecond) + 5_000)
      peer
    rescue
      error ->
        LocalTLSPeer.stop_openssl(peer)
        reraise error, __STACKTRACE__
    end
  end

  defp await_ready(handle, deadline) do
    receive do
      {^handle, {:data, {:eol, line}}} ->
        if String.starts_with?(line, "ACCEPT"), do: :ok, else: await_ready(handle, deadline)

      {^handle, {:exit_status, status}} ->
        raise "openssl peer exited during startup: #{status}"
    after
      max(0, deadline - System.monotonic_time(:millisecond)) ->
        raise "openssl peer startup timed out"
    end
  end

  defp await_exit(handle, deadline) do
    receive do
      {^handle, {:data, _}} -> await_exit(handle, deadline)
      {^handle, {:exit_status, 0}} -> :ok
      {^handle, {:exit_status, status}} -> {:error, status}
    after
      max(0, deadline - System.monotonic_time(:millisecond)) -> {:error, :peer_exit_timeout}
    end
  end

  defp receive_response(socket, response) when byte_size(response) < 65_536 do
    case SSL.recv(socket, 0, 5_000) do
      {:ok, bytes} -> receive_response(socket, response <> bytes)
      {:error, :closed} -> response
      result -> flunk("unexpected HTTP response: #{inspect(result)}")
    end
  end
end
