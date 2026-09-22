# Run only through scripts/ex_ssl_source_smoke.sh with an explicit source checkout.
Code.require_file(
  Path.join(System.fetch_env!("EX_SSL_SOURCE_DIR"), "test/support/signature_fixtures.ex")
)

defmodule CandidateAlgorithmsTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.SignatureFixtures
  alias HTTP.HTTP2.{Frame, HPACK}
  alias SSL.ClientHello.WireProfile

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "http-algorithms-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: SignatureFixtures.create(directory)}
  end

  for {scheme, name} <- [
        {0x0503, :ecdsa_secp384r1_sha384},
        {0x0807, :eddsa_ed25519},
        {0x0809, :rsa_pss_pss_sha256},
        {0x080A, :rsa_pss_pss_sha384},
        {0x080B, :rsa_pss_pss_sha512}
      ],
      protocol <- ["http/1.1", "h2"] do
    test "verified #{name} HTTP response over #{protocol} with P384", context do
      fixture = Map.fetch!(context.fixtures, unquote(scheme))
      body = "verified-#{unquote(name)}"

      with_peer(
        fixture,
        unquote(name),
        unquote(protocol),
        fn port ->
          response =
            HTTP.fetch("https://127.0.0.1:#{port}/algorithm",
              http_version: if(unquote(protocol) == "h2", do: :http2, else: :http1),
              tls_backend: :ex_ssl,
              ssl: [
                cacerts: [fixture.der],
                server_name_indication: ~c"exssl.test",
                ex_ssl: [profile: profile(unquote(scheme), unquote(protocol))]
              ]
            )
            |> HTTP.Promise.await()

          assert response.status == 200
          assert HTTP.Response.read_all(response) == body
        end,
        body
      )
    end
  end

  test "wrong reference identity still fails for every expanded signature", context do
    for {scheme, name} <- [
          {0x0503, :ecdsa_secp384r1_sha384},
          {0x0807, :eddsa_ed25519},
          {0x0809, :rsa_pss_pss_sha256},
          {0x080A, :rsa_pss_pss_sha384},
          {0x080B, :rsa_pss_pss_sha512}
        ] do
      fixture = Map.fetch!(context.fixtures, scheme)

      with_peer(
        fixture,
        name,
        "http/1.1",
        fn port ->
          assert {:error, _} =
                   HTTP.fetch("https://127.0.0.1:#{port}/algorithm",
                     tls_backend: :ex_ssl,
                     ssl: [
                       cacerts: [fixture.der],
                       server_name_indication: ~c"wrong.test",
                       ex_ssl: [profile: profile(scheme, "http/1.1")]
                     ]
                   )
                   |> HTTP.Promise.await()
        end,
        :reject
      )
    end
  end

  test "default backend remains OTP" do
    assert HTTP.FetchOptions.new([]).tls_backend == :ssl
  end

  defp profile(scheme, protocol) do
    # HTTP/1.1 forces HRR; HTTP/2 sends P384 in the first ClientHello.
    initial = if protocol == "http/1.1", do: 0x001D, else: 0x0018

    %WireProfile{
      name: :candidate_algorithm,
      cipher_suites: [0x1301],
      extensions: [
        {:server_name, :from_connection},
        {:supported_versions, [0x0304]},
        {:supported_groups, [initial, 0x0018] |> Enum.uniq()},
        {:signature_algorithms, [scheme]},
        {:key_share, [initial]},
        {:alpn, [protocol]}
      ]
    }
  end

  defp with_peer(fixture, scheme, protocol, client, body) do
    {:ok, listener} =
      :ssl.listen(0,
        certfile: String.to_charlist(fixture.certificate),
        keyfile: String.to_charlist(fixture.key),
        versions: [:"tlsv1.3"],
        active: false,
        mode: :binary,
        reuseaddr: true,
        signature_algs: [scheme],
        supported_groups: [:secp384r1],
        alpn_preferred_protocols: [protocol]
      )

    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, socket} = :ssl.transport_accept(listener, 5_000)

        case :ssl.handshake(socket, 5_000) do
          {:error, _} when body == :reject ->
            :ok

          {:ok, socket} ->
            try do
              refute body == :reject
              assert {:ok, ^protocol} = :ssl.negotiated_protocol(socket)
              respond(socket, protocol, body)
            after
              :ssl.close(socket)
            end
        end
      end)

    try do
      client.(port)
      assert :ok = Task.await(task, 10_000)
    after
      :ssl.close(listener)
      Task.shutdown(task, :brutal_kill)
    end

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1_000)
  end

  defp respond(socket, "http/1.1", body) do
    request = headers(socket, "")
    assert String.starts_with?(request, "GET /algorithm HTTP/1.1\r\n")

    :ssl.send(socket, [
      "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: #{byte_size(body)}\r\n\r\n",
      body
    ])
  end

  defp respond(socket, "h2", body) do
    preface = HTTP.HTTP2.connection_preface()
    assert {:ok, ^preface} = :ssl.recv(socket, byte_size(preface), 5_000)
    assert %Frame{type: :settings} = frame(socket)
    assert %Frame{type: :headers, stream_id: 1, payload: block} = frame(socket)
    assert {:ok, _, headers} = HPACK.decode(HPACK.new_decoder(), block)
    assert {":path", "/algorithm"} in headers

    :ok =
      :ssl.send(socket, [
        Frame.encode(:settings, 0, 0, ""),
        Frame.encode(
          :headers,
          4,
          1,
          HPACK.encode_headers([
            {":status", "200"},
            {"content-length", Integer.to_string(byte_size(body))}
          ])
        ),
        Frame.encode(:data, 1, 1, body)
      ])

    assert %Frame{type: :settings, flags: 1, stream_id: 0, payload: ""} = frame(socket)
    :ok
  end

  defp frame(socket) do
    assert {:ok, <<size::24, _::binary>> = header} = :ssl.recv(socket, 9, 5_000)
    payload = if size == 0, do: "", else: elem(:ssl.recv(socket, size, 5_000), 1)
    assert {:ok, frame, ""} = Frame.decode(header <> payload)
    frame
  end

  defp headers(socket, buffer) when byte_size(buffer) < 16_384 do
    if String.contains?(buffer, "\r\n\r\n"),
      do: buffer,
      else:
        (
          {:ok, bytes} = :ssl.recv(socket, 0, 5_000)
          headers(socket, buffer <> bytes)
        )
  end
end
