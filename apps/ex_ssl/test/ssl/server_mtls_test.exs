defmodule SSL.ServerMTLSTest do
  use ExUnit.Case, async: true

  alias SSL.Capabilities
  alias SSL.Crypto.{Finished, KeyExchange, Signature}
  alias SSL.Protocol.{ServerFlight, ServerHandshake, Transcript}

  setup_all do
    {:ok, _} = Application.ensure_all_started(:ssl)
    ca = root(~c"mtls-ca")
    # Same subject name as the trusted CA but a different key: the OTP client
    # matches certificate_authorities by name and presents its certificate.
    impostor = root(~c"mtls-ca")

    server =
      peer(ca, extensions: [{:Extension, {2, 5, 29, 17}, false, [{:dNSName, ~c"localhost"}]}])

    %{
      ca: ca,
      server: server,
      client: peer(ca),
      untrusted: peer(impostor),
      expired: peer(ca, validity: {{2019, 1, 1}, {2020, 1, 1}}),
      deep: peer(ca, [], 2),
      server_auth_only: peer(ca, extensions: [eku([{1, 3, 6, 1, 5, 5, 7, 3, 1}])])
    }
  end

  test "encode_certificate_request round-trips through decode/2", %{ca: ca} do
    {:Certificate, tbs, _, _} = :public_key.pkix_decode_cert(hd(ca.cacerts), :plain)
    name = :public_key.der_encode(:Name, elem(tbs, 6))
    authorities = <<byte_size(name)::16, name::binary>>

    assert {:ok, encoded} =
             ServerFlight.encode_certificate_request(<<>>, [
               {13, <<4::16, 0x0403::16, 0x0804::16>>},
               {47, <<byte_size(authorities)::16, authorities::binary>>}
             ])

    assert <<13, _::24, _::binary>> = encoded

    assert {:ok, %ServerFlight.CertificateRequest{} = request, <<>>} =
             ServerFlight.decode(encoded, offered_extension_ids: [])

    assert request.request_context == <<>>
    assert request.encoded == encoded
    assert {:signature_algorithms, [0x0403, 0x0804]} in request.extensions
    assert {:certificate_authorities, [name]} in request.extensions

    assert {:error, _} = ServerFlight.encode_certificate_request(<<>>, [{70_000, <<>>}])
    assert {:error, _} = ServerFlight.encode_certificate_request(:binary.copy("a", 256), [])
  end

  test "listen accepts verify_peer and rejects invalid verify values", %{server: server} do
    identity = [cert: server.cert, key: server.key]
    assert SSL.listen(0, identity ++ [verify: :bogus]) == {:error, {:invalid_option, :verify}}

    assert SSL.listen(0, identity ++ [verify: :verify_peer]) ==
             {:error, {:invalid_option, :cacerts}}

    assert {:ok, listen} =
             SSL.listen(0, identity ++ [verify: :verify_peer, cacerts: [server.cert]])

    assert :ok = SSL.close(listen)
  end

  test "a client presenting a valid certificate is authenticated",
       %{ca: ca, client: client} = ctx do
    listen = listen(ctx, ca, fail_if_no_peer_cert: true)
    assert {{:ok, "pong"}, {:ok, s}} = handshake(listen, client_identity(client), "ping")
    assert s.peercert == {:ok, client.cert}
    assert {:ok, info} = s.info
    assert info[:peer_authenticated] == :client
    assert s.peer == {:ok, [peer_authenticated: :client]}
  end

  test "a client without a certificate is certificate_required", %{ca: ca} = ctx do
    listen = listen(ctx, ca, fail_if_no_peer_cert: true)

    assert {_client, {:error, {:tls_alert, {:certificate_required, _}}}} =
             handshake(listen, [], "ping")
  end

  test "an optional client certificate may be omitted", %{ca: ca} = ctx do
    listen = listen(ctx, ca, fail_if_no_peer_cert: false)
    assert {{:ok, "pong"}, {:ok, s}} = handshake(listen, [], "ping")
    assert s.peercert == {:error, :no_peercert}
    assert {:ok, info} = s.info
    assert info[:peer_authenticated] == false
  end

  test "an optional client certificate that is presented is still verified",
       %{ca: ca, untrusted: untrusted} = ctx do
    listen = listen(ctx, ca, fail_if_no_peer_cert: false)

    assert {_client, {:error, {:tls_alert, {:unknown_ca, _}}}} =
             handshake(listen, client_identity(untrusted), "ping")
  end

  test "a client certificate from an untrusted CA is unknown_ca",
       %{ca: ca, untrusted: untrusted} = ctx do
    listen = listen(ctx, ca, fail_if_no_peer_cert: true)

    assert {_client, {:error, {:tls_alert, {:unknown_ca, _}}}} =
             handshake(listen, client_identity(untrusted), "ping")
  end

  test "an expired client certificate is certificate_expired",
       %{ca: ca, expired: expired} = ctx do
    listen = listen(ctx, ca, fail_if_no_peer_cert: true)

    assert {_client, {:error, {:tls_alert, {:certificate_expired, _}}}} =
             handshake(listen, client_identity(expired), "ping")
  end

  test "a client chain longer than depth is unknown_ca", %{ca: ca, deep: deep} = ctx do
    deep_listen = listen(ctx, ca, fail_if_no_peer_cert: true, depth: 1)

    assert {_client, {:error, {:tls_alert, {:unknown_ca, _}}}} =
             handshake(deep_listen, client_identity(deep), "ping")

    listen = listen(ctx, ca, fail_if_no_peer_cert: true, depth: 2)
    assert {{:ok, "pong"}, {:ok, s}} = handshake(listen, client_identity(deep), "ping")
    assert s.peercert == {:ok, deep.cert}
  end

  test "a client certificate restricted to serverAuth is bad_certificate",
       %{ca: ca, server_auth_only: peer} = ctx do
    listen = listen(ctx, ca, fail_if_no_peer_cert: true)

    assert {_client, {:error, {:tls_alert, {:bad_certificate, _}}}} =
             handshake(listen, client_identity(peer), "ping")
  end

  test "without verify_peer no client certificate is requested", %{client: client} = ctx do
    {:ok, listen} =
      SSL.listen(0, ip: {127, 0, 0, 1}, cert: ctx.server.cert, key: ctx.server.key)

    on_exit(fn -> SSL.close(listen) end)
    assert {{:ok, "pong"}, {:ok, s}} = handshake(listen, client_identity(client), "ping")
    assert s.peercert == {:error, :no_peercert}
    assert {:ok, info} = s.info
    assert info[:peer_authenticated] == false
  end

  test "the server flight carries a CertificateRequest only with verify_peer",
       %{ca: ca, server: server} do
    {:ok, base} = SSL.ServerOptions.build(cert: server.cert, key: server.key)

    {:ok, mtls} =
      SSL.ServerOptions.build(
        cert: server.cert,
        key: server.key,
        verify: :verify_peer,
        cacerts: ca.cacerts
      )

    quic = %{mtls | transport_parameters: <<>>}

    assert types(base) == [8, 11, 15, 20]
    assert [8, 13, 11, 15, 20] = types(mtls)
    assert {:ok, _state, _, messages} = flight(quic, quic?: true)
    assert Enum.map(messages, &:binary.first/1) == [8, 11, 15, 20]
  end

  test "peer_authenticated is a server-only connection_information key" do
    machine = %SSL.Protocol.HandshakeMachine{server_hello: %{cipher_suite: 0x1301}}

    assert SSL.Diagnostics.connection_information(machine, [:peer_authenticated]) ==
             {:error, {:options, :unsupported_connection_information_key}}

    assert {:ok, [peer_authenticated: false]} =
             SSL.Diagnostics.connection_information(machine, [:peer_authenticated], %{
               peer_authenticated: false
             })
  end

  describe "client authentication steps" do
    setup %{ca: ca, client: client} do
      {:ok, trust} = SSL.PKIX.normalize_trust(ca.cacerts)
      secret = :crypto.strong_rand_bytes(32)

      state = %ServerHandshake.State{
        phase: :client_certificate,
        transcript: Transcript.new(:sha256),
        secrets: %{hash: :sha256, client_handshake_secret: secret},
        client_auth: %{trust: trust, require: true, depth: 10},
        client_schemes: [0x0403]
      }

      {:ok, certificate} = ServerFlight.encode_client_certificate(<<>>, [client.cert])
      %{state: state, certificate: certificate, secret: secret, key: private_key(client)}
    end

    test "a non-empty Certificate must be followed by CertificateVerify",
         %{state: state, certificate: certificate, secret: secret} do
      assert {:ok, state} = ServerHandshake.accept_client_certificate(state, certificate)
      assert state.phase == :client_certificate_verify
      finished = finished(state.transcript, secret)

      assert {:error, {:unexpected_message, _}} = ServerHandshake.finish(state, finished)

      assert {:error, {:unexpected_message, _}} =
               ServerHandshake.accept_client_certificate_verify(state, finished)
    end

    test "CertificateVerify must use an offered scheme and a valid signature",
         %{state: state, certificate: certificate, key: key, secret: secret} do
      {:ok, state} = ServerHandshake.accept_client_certificate(state, certificate)
      digest = Transcript.digest(state.transcript)

      {:ok, signature} = Signature.sign_client(0x0403, key, :sha256, digest)
      {:ok, offered} = ServerFlight.encode_client_certificate_verify(0x0403, signature)

      {:ok, unoffered} =
        ServerFlight.encode_client_certificate_verify(0x0503, signature)

      assert {:error, {:illegal_parameter, _}} =
               ServerHandshake.accept_client_certificate_verify(state, unoffered)

      {:ok, legacy} = ServerFlight.encode_client_certificate_verify(0x0401, signature)

      assert {:error, {:illegal_parameter, _}} =
               ServerHandshake.accept_client_certificate_verify(state, legacy)

      {:ok, wrong} = Signature.sign_client(0x0403, key, :sha256, :crypto.hash(:sha256, "x"))
      {:ok, forged} = ServerFlight.encode_client_certificate_verify(0x0403, wrong)

      assert {:error, {:decrypt_error, _}} =
               ServerHandshake.accept_client_certificate_verify(state, forged)

      assert {:ok, verified} = ServerHandshake.accept_client_certificate_verify(state, offered)
      assert verified.phase == :finished
      assert verified.peer.leaf_der == state.peer.leaf_der
      assert :ok = ServerHandshake.finish(verified, finished(verified.transcript, secret))
      # The client Finished covers the client Certificate and CertificateVerify.
      assert {:error, {:decrypt_error, _}} =
               ServerHandshake.finish(verified, finished(state.transcript, secret))
    end

    test "an empty Certificate is certificate_required unless optional",
         %{state: state, secret: secret} do
      {:ok, empty} = ServerFlight.encode_empty_certificate(<<>>)

      assert {:error, {:certificate_required, _}} =
               ServerHandshake.accept_client_certificate(state, empty)

      optional = put_in(state.client_auth.require, false)
      assert {:ok, state} = ServerHandshake.accept_client_certificate(optional, empty)
      assert state.phase == :finished
      assert state.peer == nil
      assert :ok = ServerHandshake.finish(state, finished(state.transcript, secret))
    end

    test "Finished in place of Certificate is unexpected", %{state: state, secret: secret} do
      assert {:error, {:unexpected_message, _}} =
               ServerHandshake.accept_client_certificate(
                 state,
                 finished(state.transcript, secret)
               )
    end
  end

  ## Helpers

  defp listen(ctx, ca, extra) do
    options =
      [ip: {127, 0, 0, 1}, cert: ctx.server.cert, key: ctx.server.key] ++
        [verify: :verify_peer, cacerts: ca.cacerts] ++ extra

    {:ok, listen} = SSL.listen(0, options)
    on_exit(fn -> SSL.close(listen) end)
    listen
  end

  # Runs one handshake against an OTP client; returns {client, server} results.
  # The client keeps its socket open until the server has read its peer state.
  defp handshake(listen, identity, ping) do
    {:ok, {_, port}} = SSL.sockname(listen)

    client =
      Task.async(fn ->
        options =
          [
            mode: :binary,
            active: false,
            versions: [:"tlsv1.3"],
            verify: :verify_none,
            log_level: :none
          ] ++ identity

        with {:ok, c} <- :ssl.connect({127, 0, 0, 1}, port, options, 5000),
             :ok <- :ssl.send(c, ping) do
          result = :ssl.recv(c, 0, 5000)
          receive do: (:finish -> :ssl.close(c))
          result
        end
      end)

    {:ok, accepted} = SSL.transport_accept(listen, 5000)

    server =
      with {:ok, s} <- SSL.handshake(accepted, 5000),
           {:ok, ^ping} <- SSL.recv(s, 0, 5000),
           :ok <- SSL.send(s, "pong") do
        state = %{
          peercert: SSL.peercert(s),
          info: SSL.connection_information(s),
          peer: SSL.connection_information(s, [:peer_authenticated])
        }

        SSL.close(s)
        {:ok, state}
      end

    send(client.pid, :finish)
    {Task.await(client), server}
  end

  defp client_identity(peer), do: [cert: peer.cert, key: peer.key, cacerts: peer.cacerts]

  defp types(config) do
    {:ok, _state, _, messages} = flight(config)
    Enum.map(messages, &:binary.first/1)
  end

  # Runs accept_hello/flight on a ClientHello captured from an OTP client.
  defp flight(config, opts \\ []) do
    hello = client_hello(opts)
    {:ok, state} = ServerHandshake.accept_hello(config, hello, nil)
    group = Capabilities.resolve(:group, state.group).name
    {:ok, pair} = KeyExchange.generate(group)
    ServerHandshake.flight(state, config, pair, :crypto.strong_rand_bytes(32))
  end

  defp client_hello(opts) do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, port} = :inet.port(listen)

    quic =
      if opts[:quic?] do
        # A ClientHello acceptable to QUIC rules: ALPN, ext 57, empty session id.
        [middlebox_comp_mode: false]
      else
        []
      end

    connect =
      Task.async(fn ->
        :ssl.connect(
          {127, 0, 0, 1},
          port,
          [versions: [:"tlsv1.3"], verify: :verify_none, log_level: :none] ++ quic,
          2000
        )
      end)

    {:ok, tcp} = :gen_tcp.accept(listen, 2000)
    {:ok, <<22, 3, _, length::16>>} = :gen_tcp.recv(tcp, 5, 2000)
    {:ok, hello} = :gen_tcp.recv(tcp, length, 2000)
    :gen_tcp.close(tcp)
    :gen_tcp.close(listen)
    _ = Task.await(connect)
    if opts[:quic?], do: quic_hello(hello), else: hello
  end

  # Appends an empty QUIC transport_parameters extension (57) to the ClientHello.
  defp quic_hello(
         <<1, _::24, 0x0303::16, random::binary-size(32), sid_len, _sid::binary-size(sid_len),
           rest::binary>>
       ) do
    <<suites_len::16, suites::binary-size(suites_len), comp_len, comp::binary-size(comp_len),
      ext_len::16, exts::binary-size(ext_len)>> = rest

    exts = <<57::16, 0::16, exts::binary>>

    body =
      <<0x0303::16, random::binary, 0, suites_len::16, suites::binary, comp_len, comp::binary,
        byte_size(exts)::16, exts::binary>>

    <<1, byte_size(body)::24, body::binary>>
  end

  defp finished(transcript, secret) do
    {:ok, data} = Finished.client_verify_data(:sha256, secret, Transcript.digest(transcript))
    {:ok, finished} = ServerFlight.encode_finished(data, hash: :sha256)
    finished
  end

  defp private_key(%{key: {:ECPrivateKey, der}}), do: :public_key.der_decode(:ECPrivateKey, der)

  defp root(name) do
    key = :public_key.generate_key({:namedCurve, :secp256r1})

    %{root: :public_key.pkix_test_root_cert(name, key: key, digest: :sha256), cacerts: nil}
    |> then(fn %{root: root} = ca -> %{ca | cacerts: [root.cert]} end)
  end

  defp peer(ca, opts \\ [], intermediates \\ 0) do
    base = [key: {:namedCurve, :secp256r1}, digest: :sha256]

    data =
      :public_key.pkix_test_data(%{
        root: ca.root,
        intermediates: List.duplicate(base, intermediates),
        peer: base ++ opts
      })

    %{cert: data[:cert], key: data[:key], cacerts: data[:cacerts]}
  end

  defp eku(usages), do: {:Extension, {2, 5, 29, 37}, false, usages}
end
