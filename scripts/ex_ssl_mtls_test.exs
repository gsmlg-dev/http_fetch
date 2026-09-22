# Run only through scripts/ex_ssl_source_smoke.sh with an explicit source checkout.
source = System.fetch_env!("EX_SSL_SOURCE_DIR")
Code.require_file(Path.join(source, "test/support/signature_fixtures.ex"))
Code.require_file(Path.join(source, "test/support/client_auth_fixtures.ex"))

defmodule CandidateMTLSTest do
  use ExUnit.Case, async: false
  alias ExSSL.TestSupport.ClientAuthFixtures
  alias HTTP.HTTP2.{Frame, HPACK}

  @body "packaged-mtls"
  @path "/mtls"

  setup_all do
    directory = Path.join(System.tmp_dir!(), "http-mtls-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: ClientAuthFixtures.create(directory)}
  end

  for identity <- [:rsa, :ec, :large], protocol <- ["http/1.1", "h2"] do
    test "required #{identity} identity returns verified #{protocol} HTTP response", context do
      fixture = context.fixtures[unquote(identity)]
      if unquote(identity) == :large, do: assert(byte_size(fixture.der) > 16_384)
      exchange(context.fixtures, fixture, :required, unquote(protocol))
    end
  end

  test "optional client auth without an identity returns an HTTP response", context do
    exchange(context.fixtures, nil, :optional, "http/1.1")
  end

  test "missing, wrong-CA, expired, and wrong-purpose identities cannot fetch", context do
    for identity <- [
          nil,
          context.fixtures.wrong,
          context.fixtures.expired,
          context.fixtures.server
        ] do
      with_peer(
        context.fixtures,
        :required,
        "http/1.1",
        fn port ->
          assert {:error, _} = fetch(port, context.fixtures, identity, "http/1.1")
        end,
        :reject
      )
    end
  end

  test "mismatched client key fails before network I/O", context do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)

    try do
      assert {:error, _} =
               fetch(port, context.fixtures, context.fixtures.rsa, "http/1.1",
                 keyfile: context.fixtures.ec.key
               )

      assert {:error, :timeout} = :gen_tcp.accept(listener, 200)
    after
      :gen_tcp.close(listener)
    end
  end

  test "incompatible requested signature does not authenticate", context do
    with_peer(
      %{context.fixtures | server: context.fixtures.ec_server},
      :required,
      "http/1.1",
      fn port ->
        assert {:error, _} = fetch(port, context.fixtures, context.fixtures.rsa, "http/1.1")
      end,
      :reject,
      signature_algs: [:ecdsa_secp256r1_sha256]
    )
  end

  test "wrong server hostname fails even when client credentials are valid", context do
    with_peer(
      context.fixtures,
      :required,
      "http/1.1",
      fn port ->
        assert {:error, _} =
                 fetch(port, context.fixtures, context.fixtures.rsa, "http/1.1",
                   server_name_indication: ~c"wrong.test"
                 )
      end,
      :reject
    )
  end

  defp exchange(fixtures, identity, mode, protocol) do
    expected = if identity, do: identity.der, else: nil

    response =
      with_peer(
        fixtures,
        mode,
        protocol,
        fn port -> fetch(port, fixtures, identity, protocol) end,
        expected
      )

    assert response.status == 200
    assert HTTP.Response.read_all(response) == @body
  end

  defp fetch(port, fixtures, identity, protocol, overrides \\ []) do
    ssl = [
      cacerts: [fixtures.ca.der],
      server_name_indication: ~c"exssl.test",
      verify: :verify_peer,
      alpn_advertised_protocols: [protocol]
    ]

    credentials =
      if identity, do: [certfile: identity.certificate, keyfile: identity.key], else: []

    ssl = Keyword.merge(ssl ++ credentials, overrides)

    HTTP.fetch("https://127.0.0.1:#{port}#{@path}",
      http_version: if(protocol == "h2", do: :http2, else: :http1),
      tls_backend: :ex_ssl,
      ssl: ssl,
      timeout: 5_000,
      connect_timeout: 5_000
    )
    |> HTTP.Promise.await(10_000)
  end

  defp with_peer(fixtures, mode, protocol, client, expected, extra \\ []) do
    ssl_options =
      [
        certfile: String.to_charlist(fixtures.server.certificate),
        keyfile: String.to_charlist(fixtures.server.key),
        cacerts: [fixtures.ca.der],
        verify: :verify_peer,
        fail_if_no_peer_cert: mode == :required,
        versions: [:"tlsv1.3"],
        active: false,
        mode: :binary,
        reuseaddr: true,
        alpn_preferred_protocols: [protocol]
      ]
      |> Keyword.merge(extra)

    {:ok, listener} = :ssl.listen(0, ssl_options)
    {:ok, {_, port}} = :ssl.sockname(listener)

    task =
      Task.async(fn ->
        {:ok, transport} = :ssl.transport_accept(listener, 5_000)

        case :ssl.handshake(transport, 5_000) do
          {:ok, socket} ->
            try do
              if expected == :reject do
                case :ssl.recv(socket, 0, 5_000) do
                  {:error, _} -> :ok
                  {:ok, bytes} -> flunk("rejected peer sent HTTP bytes: #{byte_size(bytes)}")
                end
              else
                assert {:ok, ^protocol} = :ssl.negotiated_protocol(socket)

                case expected do
                  nil -> assert {:error, :no_peercert} = :ssl.peercert(socket)
                  der -> assert {:ok, ^der} = :ssl.peercert(socket)
                end

                respond(socket, protocol)
              end
            after
              :ssl.close(socket)
            end

          {:error, _} when expected == :reject ->
            :ok
        end
      end)

    result =
      try do
        result = client.(port)
        assert :ok = Task.await(task, 10_000)
        result
      after
        :ssl.close(listener)
        Task.shutdown(task, :brutal_kill)
      end

    assert {:error, :econnrefused} =
             :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false], 1_000)

    result
  end

  defp respond(socket, "http/1.1") do
    request = headers(socket, "")
    assert String.starts_with?(request, "GET #{@path} HTTP/1.1\r\n")

    :ssl.send(socket, [
      "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: #{byte_size(@body)}\r\n\r\n",
      @body
    ])
  end

  defp respond(socket, "h2") do
    preface = HTTP.HTTP2.connection_preface()
    assert {:ok, ^preface} = :ssl.recv(socket, byte_size(preface), 5_000)
    assert %Frame{type: :settings} = frame(socket)
    assert %Frame{type: :headers, stream_id: 1, payload: block} = frame(socket)
    assert {:ok, _, headers} = HPACK.decode(HPACK.new_decoder(), block)
    assert {":path", @path} in headers

    :ok =
      :ssl.send(socket, [
        Frame.encode(:settings, 0, 0, ""),
        Frame.encode(
          :headers,
          4,
          1,
          HPACK.encode_headers([
            {":status", "200"},
            {"content-length", Integer.to_string(byte_size(@body))}
          ])
        ),
        Frame.encode(:data, 1, 1, @body)
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
