# Run with MIX_ENV=test mix run scripts/resumption_benchmark.exs.
for support <- ["signature_fixtures.ex", "client_auth_fixtures.ex", "openssl_peer.ex"] do
  module =
    case support do
      "signature_fixtures.ex" -> ExSSL.TestSupport.SignatureFixtures
      "client_auth_fixtures.ex" -> ExSSL.TestSupport.ClientAuthFixtures
      "openssl_peer.ex" -> ExSSL.TestSupport.OpenSSLPeer
    end

  unless Code.ensure_loaded?(module) do
    Code.require_file(Path.join([__DIR__, "../test/support", support]))
  end
end

defmodule SSL.ResumptionBenchmark do
  alias ExSSL.TestSupport.{ClientAuthFixtures, OpenSSLPeer}

  @host {127, 0, 0, 1}
  @body :binary.copy(<<0x5A>>, 1_048_576)
  @count 6
  @timeout 10_000
  @cipher %{key_exchange: :any, cipher: :aes_128_gcm, mac: :aead, prf: :sha256}

  def run do
    {:ok, _} = Application.ensure_all_started(:ex_ssl)
    :ok = :ssl.start()
    directory = Path.join(System.tmp_dir!(), "exssl-bench-#{System.unique_integer([:positive])}")

    try do
      fixtures = ClientAuthFixtures.create(directory)
      {openssl, 0} = System.cmd("openssl", ["version"])

      IO.puts(
        "environment otp=#{:erlang.system_info(:otp_release)} elixir=#{System.version()} #{String.trim(openssl)}"
      )

      IO.puts(
        "payload_bytes=#{byte_size(@body)} warmup=1 measured=#{@count - 1} cipher=TLS_AES_128_GCM_SHA256 alpn=http/1.1"
      )

      for backend <- [:otp, :ex_ssl], mode <- [:full, :resumed] do
        measure(fixtures, backend, mode)
      end
    after
      File.rm_rf!(directory)
    end
  end

  defp measure(fixtures, backend, mode) do
    {:ok, peer} =
      OpenSSLPeer.start(
        certfile: fixtures.server.certificate,
        keyfile: fixtures.server.key,
        min_version: :tls13,
        max_version: :tls13,
        alpn: ["http/1.1"],
        max_connections: @count
      )

    try do
      samples =
        for index <- 1..@count do
          started = System.monotonic_time(:microsecond)
          socket = connect(backend, peer.port, fixtures, mode)
          connected = System.monotonic_time(:microsecond)
          {:ok, evidence} = OpenSSLPeer.event(peer, "handshake", @timeout)
          expected = mode == :resumed and index > 1
          true = evidence["resumed"] == expected
          true = evidence["version"] == "TLSv1.3"
          true = evidence["cipher"] == "TLS_AES_128_GCM_SHA256"
          true = evidence["alpn"] == "http/1.1"

          sent = System.monotonic_time(:microsecond)
          :ok = send_data(backend, socket, <<byte_size(@body)::32, @body::binary>>)
          expected_len = byte_size(@body)
          <<^expected_len::32>> = receive_exact(backend, socket, 4)
          true = @body == receive_exact(backend, socket, expected_len)
          received = System.monotonic_time(:microsecond)
          {:ok, %{"bytes" => 1_048_576}} = OpenSSLPeer.event(peer, "exchange", @timeout)
          :ok = close(backend, socket)

          {connected - started, received - sent, evidence["resumed"]}
        end

      [_warmup | measured] = samples
      handshakes = Enum.map(measured, &elem(&1, 0))
      transfers = Enum.map(measured, &elem(&1, 1))

      IO.puts(
        "#{backend}/#{mode} handshake_us=#{summary(handshakes)} transfer_us=#{summary(transfers)} resumed=#{inspect(Enum.map(samples, &elem(&1, 2)))}"
      )
    after
      OpenSSLPeer.stop(peer)
    end
  end

  defp connect(:ex_ssl, port, fixtures, mode) do
    {:ok, socket} =
      SSL.connect(@host, port,
        nodelay: true,
        cacerts: [fixtures.ca.der],
        server_name_indication: ~c"exssl.test",
        versions: [:"tlsv1.3"],
        supported_groups: [:x25519],
        signature_algs: [:rsa_pss_rsae_sha256],
        ciphers: ["TLS_AES_128_GCM_SHA256"],
        alpn_advertised_protocols: ["http/1.1"],
        session_tickets: tickets(mode)
      )

    socket
  end

  defp connect(:otp, port, fixtures, mode) do
    {:ok, socket} =
      :ssl.connect(@host, port,
        mode: :binary,
        active: false,
        verify: :verify_peer,
        nodelay: true,
        cacerts: [fixtures.ca.der],
        server_name_indication: ~c"exssl.test",
        versions: [:"tlsv1.3"],
        supported_groups: [:x25519],
        signature_algs: [:rsa_pss_rsae_sha256],
        ciphers: [@cipher],
        alpn_advertised_protocols: ["http/1.1"],
        session_tickets: tickets(mode)
      )

    socket
  end

  defp tickets(:full), do: :disabled
  defp tickets(:resumed), do: :auto

  defp send_data(:otp, socket, data), do: :ssl.send(socket, data)
  defp send_data(:ex_ssl, socket, data), do: SSL.send(socket, data)
  defp close(:otp, socket), do: :ssl.close(socket)
  defp close(:ex_ssl, socket), do: SSL.close(socket)

  defp receive_exact(backend, socket, count), do: receive_exact(backend, socket, count, [])

  defp receive_exact(_backend, _socket, 0, chunks),
    do: chunks |> Enum.reverse() |> IO.iodata_to_binary()

  defp receive_exact(backend, socket, remaining, chunks) do
    size = min(remaining, 65_536)
    {:ok, bytes} = receive_chunk(backend, socket, size)
    true = byte_size(bytes) > 0 and byte_size(bytes) <= remaining
    receive_exact(backend, socket, remaining - byte_size(bytes), [bytes | chunks])
  end

  defp receive_chunk(:otp, socket, size), do: :ssl.recv(socket, size, @timeout)
  defp receive_chunk(:ex_ssl, socket, size), do: SSL.recv(socket, size, @timeout)

  defp summary(values) do
    sorted = Enum.sort(values)
    median = Enum.at(sorted, div(length(sorted), 2))
    "median=#{median} range=#{hd(sorted)}..#{List.last(sorted)}"
  end
end

SSL.ResumptionBenchmark.run()
