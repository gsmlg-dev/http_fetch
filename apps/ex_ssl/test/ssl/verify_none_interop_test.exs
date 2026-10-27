defmodule SSL.VerifyNoneInteropTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.{LocalTLSPeer, OpenSSLPeer}

  @moduletag :integration

  setup_all do
    :ok = :ssl.start()

    %{cert: cert, key: key} =
      :public_key.pkix_test_root_cert(~c"verify-none-self-signed",
        key: {:rsa, 2048, 65_537},
        digest: :sha256,
        extensions: [
          {:Extension, {2, 5, 29, 15}, true, [:digitalSignature]},
          {:Extension, {2, 5, 29, 19}, true, {:BasicConstraints, false, :asn1_NOVALUE}}
        ]
      )

    {:ok,
     self_signed: [cert: cert, key: {:RSAPrivateKey, :public_key.der_encode(:RSAPrivateKey, key)}],
     self_signed_der: cert}
  end

  test "explicit none accepts a self-signed peer and wrong hostname with real traffic", context do
    for provider <- [SSL, :ssl] do
      with_otp_peer(context.self_signed, fn peer ->
        options = base(verify: :verify_none, server_name_indication: ~c"wrong.example.test")
        assert {:ok, socket} = provider.connect({127, 0, 0, 1}, peer.port, options, 5_000)

        try do
          assert {:ok, der} = provider.peercert(socket)
          assert der == context.self_signed_der
          echo(provider, socket)
        after
          provider.close(socket)
        end
      end)
    end
  end

  test "omitted verification remains peer verification and rejects an untrusted self-signed peer",
       context do
    for provider <- [SSL, :ssl] do
      with_otp_peer(context.self_signed, fn peer ->
        assert {:error, {:tls_alert, _}} =
                 provider.connect(
                   {127, 0, 0, 1},
                   peer.port,
                   base(
                     cacerts: LocalTLSPeer.certificate_authorities(),
                     server_name_indication: ~c"wrong.example.test"
                   ),
                   5_000
                 )
      end)
    end
  end

  test "explicit none skips only trust and hostname checks on a regular CA-issued peer" do
    for provider <- [SSL, :ssl], verify <- [:verify_none, :verify_peer] do
      with_otp_peer([], fn peer ->
        options =
          base(
            verify: verify,
            cacerts: LocalTLSPeer.certificate_authorities(),
            server_name_indication: ~c"wrong.example.test"
          )

        case verify do
          :verify_peer ->
            assert {:error, {:tls_alert, _}} =
                     provider.connect({127, 0, 0, 1}, peer.port, options, 5_000)

          :verify_none ->
            assert {:ok, socket} = provider.connect({127, 0, 0, 1}, peer.port, options, 5_000)

            try do
              echo(provider, socket)
            after
              provider.close(socket)
            end
        end
      end)
    end
  end

  test "none-mode existing TCP upgrade needs neither SNI nor a fabricated reference" do
    for provider <- [SSL, :ssl] do
      with_otp_peer([], fn peer ->
        {:ok, tcp} = :gen_tcp.connect({127, 0, 0, 1}, peer.port, [:binary, active: false], 5_000)
        assert {:ok, socket} = provider.connect(tcp, base(verify: :verify_none), 5_000)

        try do
          echo(provider, socket)
        after
          provider.close(socket)
        end
      end)
    end
  end

  @tag :tmp_dir
  test "none preserves public OTP CA option behavior", %{tmp_dir: dir} do
    text_file = Path.join(dir, "readable-not-ca.pem")
    File.write!(text_file, "not a PEM certificate")
    missing_file = Path.join(dir, "missing.pem")

    for provider <- [SSL, :ssl] do
      with_otp_peer([], fn peer ->
        assert {:error, {:options, _}} =
                 provider.connect(
                   {127, 0, 0, 1},
                   peer.port,
                   base(verify: :verify_none, cacertfile: missing_file),
                   5_000
                 )
      end)

      for ca <- [
            [cacerts: []],
            [cacerts: [<<1, 2, 3>>]],
            [cacertfile: text_file],
            [cacerts: [], cacertfile: missing_file]
          ] do
        with_otp_peer([], fn peer ->
          assert {:ok, socket} =
                   provider.connect(
                     {127, 0, 0, 1},
                     peer.port,
                     base([verify: :verify_none] ++ ca),
                     5_000
                   )

          try do
            echo(provider, socket)
          after
            provider.close(socket)
          end
        end)
      end
    end
  end

  test "OpenSSL TLS12 none still completes an authenticated ECDHE EMS handshake" do
    files = LocalTLSPeer.certificates()

    for provider <- [SSL, :ssl] do
      assert {:ok, peer} = OpenSSLPeer.start(certfile: files.certfile, keyfile: files.keyfile)

      try do
        options = [
          mode: :binary,
          active: false,
          verify: :verify_none,
          versions: [:"tlsv1.2"],
          server_name_indication: ~c"wrong.example.test"
        ]

        assert {:ok, socket} = provider.connect({127, 0, 0, 1}, peer.port, options, 5_000)

        try do
          assert {:ok, %{"version" => "TLSv1.2"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
          assert :ok = provider.send(socket, <<4::32, "ping">>)
          assert {:ok, <<4::32, "ping">>} = provider.recv(socket, 8, 5_000)
          assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        after
          provider.close(socket)
        end
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  @tag :tmp_dir
  test "TLS12 none retains v1 certificate behavior against OTP and OpenSSL", context do
    {:RSAPrivateKey, encoded_key} = Keyword.fetch!(context.self_signed, :key)
    key = :public_key.der_decode(:RSAPrivateKey, encoded_key)
    {:OTPCertificate, tbs, _, _} = :public_key.pkix_decode_cert(context.self_signed_der, :otp)
    # The fixture omits v3 extensions and is freshly signed as a v1 credential.
    legacy = :public_key.pkix_sign(tbs |> put_elem(1, :v1) |> put_elem(10, :asn1_NOVALUE), key)
    certfile = Path.join(context.tmp_dir, "legacy-cert.pem")
    keyfile = Path.join(context.tmp_dir, "legacy-key.pem")
    File.write!(certfile, :public_key.pem_encode([{:Certificate, legacy, :not_encrypted}]))
    File.write!(keyfile, :public_key.pem_encode([{:RSAPrivateKey, encoded_key, :not_encrypted}]))

    for provider <- [SSL, :ssl] do
      assert {:ok, peer} = OpenSSLPeer.start(certfile: certfile, keyfile: keyfile)

      try do
        options = [
          mode: :binary,
          active: false,
          verify: :verify_none,
          versions: [:"tlsv1.2"],
          server_name_indication: ~c"wrong.example.test"
        ]

        assert {:ok, socket} = provider.connect({127, 0, 0, 1}, peer.port, options, 5_000)

        try do
          assert {:ok, ^legacy} = provider.peercert(socket)
          assert {:ok, %{"version" => "TLSv1.2"}} = OpenSSLPeer.event(peer, "handshake", 5_000)
          assert :ok = provider.send(socket, <<4::32, "ping">>)
          assert {:ok, <<4::32, "ping">>} = provider.recv(socket, 8, 5_000)
          assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        after
          provider.close(socket)
        end
      after
        OpenSSLPeer.stop(peer)
      end
    end
  end

  test "none-mode TLS13 rejects auto tickets and ordinary handshakes preserve default peer trust" do
    files = LocalTLSPeer.certificates()

    assert {:ok, peer} =
             OpenSSLPeer.start(
               certfile: files.certfile,
               keyfile: files.keyfile,
               min_version: :tls13,
               max_version: :tls13,
               max_connections: 3
             )

    try do
      options =
        base(
          verify: :verify_none,
          session_tickets: :disabled,
          server_name_indication: ~c"wrong.example.test"
        )

      assert {:error, {:options, {:session_tickets, :verify_peer_required}}} =
               SSL.connect(
                 {127, 0, 0, 1},
                 peer.port,
                 Keyword.put(options, :session_tickets, :auto),
                 5_000
               )

      for _ <- 1..2 do
        assert {:ok, socket} = SSL.connect({127, 0, 0, 1}, peer.port, options, 5_000)

        try do
          assert {:ok, handshake} = OpenSSLPeer.event(peer, "handshake", 5_000)
          assert handshake["resumed"] == false

          assert {:ok, [session_resumption: false]} =
                   SSL.connection_information(socket, [:session_resumption])

          assert :ok = SSL.send(socket, <<4::32, "ping">>)
          assert {:ok, <<4::32, "ping">>} = SSL.recv(socket, 8, 5_000)
          assert {:ok, %{"bytes" => 4}} = OpenSSLPeer.event(peer, "exchange", 5_000)
        after
          SSL.close(socket)
        end
      end

      assert {:error, {:tls_alert, _}} =
               SSL.connect({127, 0, 0, 1}, peer.port, Keyword.delete(options, :verify), 5_000)
    after
      OpenSSLPeer.stop(peer)
    end
  end

  test "none accepts a forced fallback chain while peer enforces its advertised chain policy" do
    files = Path.expand("../fixtures/server_flight", __DIR__)

    [{:Certificate, root, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(files, "root.pem")))

    for provider <- [SSL, :ssl], mode <- [:verify_none, :verify_peer] do
      with_fallback_peer(files, fn peer ->
        options =
          base(
            verify: mode,
            cacerts: [root],
            server_name_indication: ~c"example.test",
            ciphers: [:ssl.str_to_suite(~c"TLS_AES_256_GCM_SHA384")],
            supported_groups: [:x25519],
            signature_algs: [:rsa_pss_rsae_sha256],
            signature_algs_cert: [:rsa_pss_rsae_sha256]
          )

        result = provider.connect({127, 0, 0, 1}, peer.port, options, 5_000)
        reference = peer.reference
        assert_receive {:fallback_offer, ^reference, [0x0804]}

        case {mode, provider} do
          {:verify_none, _} ->
            assert {:ok, socket} = result
            provider.close(socket)

          {:verify_peer, SSL} ->
            assert {:error, {:tls_alert, {:bad_certificate, _}}} = result

          {:verify_peer, :ssl} ->
            assert {:error, {:tls_alert, {:unsupported_certificate, _}}} = result
        end
      end)
    end
  end

  defp base(options),
    do: Keyword.merge([mode: :binary, active: false, versions: [:"tlsv1.3"]], options)

  defp echo(provider, socket) do
    assert :ok = provider.send(socket, "ping")
    assert {:ok, "pong"} = provider.recv(socket, 4, 5_000)
  end

  # This fixture deliberately supplies an RFC-permitted fallback chain. Its KDF,
  # CV, Finished and records use public crypto directly, independently of SSL's
  # authentication implementation. ClientOffer only locates the fresh public share.
  defp with_fallback_peer(files, fun) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    parent = self()
    reference = make_ref()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener)
        {:ok, <<22, 3, _minor, size::16>>} = :gen_tcp.recv(tcp, 5, 5_000)
        {:ok, ch} = :gen_tcp.recv(tcp, size, 5_000)
        {:ok, offer} = SSL.Protocol.ClientOffer.from_client_hello(ch)
        share = Enum.find(offer.key_shares, &(&1.group == 0x001D))
        send(parent, {:fallback_offer, reference, offer.certificate_signature_schemes})
        :ok = :gen_tcp.send(tcp, fallback_server_flight(ch, share.key_exchange, files))
        receive do: (:stop -> :gen_tcp.close(tcp))
      end)

    try do
      fun.(%{port: port, reference: reference})
    after
      Task.shutdown(task, :brutal_kill)
      :gen_tcp.close(listener)
    end
  end

  defp fallback_server_flight(ch, client_public, files) do
    <<1, _::24, _::16, _random::binary-size(32), sid_size, sid::binary-size(sid_size), _::binary>> =
      ch

    {public, private} = :crypto.generate_key(:ecdh, :x25519)
    shared = :crypto.compute_key(:ecdh, client_public, private, :x25519)
    extensions = <<43::16, 2::16, 0x0304::16, 51::16, 36::16, 0x001D::16, 32::16, public::binary>>

    sh =
      fallback_message(
        2,
        <<0x0303::16, :crypto.strong_rand_bytes(32)::binary, sid_size, sid::binary, 0x1302::16, 0,
          byte_size(extensions)::16, extensions::binary>>
      )

    zero = <<0::384>>
    early = fallback_mac(zero, zero)
    handshake = fallback_mac(fallback_label(early, "derived", fallback_hash(<<>>), 48), shared)
    secret = fallback_label(handshake, "s hs traffic", fallback_hash(ch <> sh), 48)
    ee = fallback_message(8, <<0::16>>)

    [{:Certificate, der, :not_encrypted}] =
      :public_key.pem_decode(File.read!(Path.join(files, "leaf-rsa.pem")))

    entry = <<byte_size(der)::24, der::binary, 0::16>>
    cert = fallback_message(11, <<0, byte_size(entry)::24, entry::binary>>)
    [pem] = :public_key.pem_decode(File.read!(Path.join(files, "leaf-rsa-key.pem")))
    key = :public_key.pem_entry_decode(pem)

    signed =
      :binary.copy(<<32>>, 64) <>
        "TLS 1.3, server CertificateVerify" <> <<0>> <> fallback_hash(ch <> sh <> ee <> cert)

    signature =
      :public_key.sign(signed, :sha256, key,
        rsa_padding: :rsa_pkcs1_pss_padding,
        rsa_pss_saltlen: 32,
        rsa_mgf1_md: :sha256
      )

    cv = fallback_message(15, <<0x0804::16, byte_size(signature)::16, signature::binary>>)

    finished =
      fallback_message(
        20,
        fallback_mac(
          fallback_label(secret, "finished", <<>>, 48),
          fallback_hash(ch <> sh <> ee <> cert <> cv)
        )
      )

    plain = ee <> cert <> cv <> finished <> <<22>>
    header = <<23, 3, 3, byte_size(plain) + 16::16>>

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        fallback_label(secret, "key", <<>>, 32),
        fallback_label(secret, "iv", <<>>, 12),
        plain,
        header,
        16,
        true
      )

    <<22, 3, 3, byte_size(sh)::16, sh::binary, 20, 3, 3, 1::16, 1, header::binary,
      ciphertext::binary, tag::binary>>
  end

  # This fixed SHA384 fixture needs one HKDF block (all requested outputs <=48).
  defp fallback_label(secret, text, context, size) do
    label = "tls13 " <> text
    info = <<size::16, byte_size(label), label::binary, byte_size(context), context::binary, 1>>
    binary_part(fallback_mac(secret, info), 0, size)
  end

  defp fallback_message(type, body), do: <<type, byte_size(body)::24, body::binary>>
  defp fallback_hash(data), do: :crypto.hash(:sha384, data)
  defp fallback_mac(key, data), do: :crypto.mac(:hmac, :sha384, key, data)

  defp with_otp_peer(options, fun) do
    {:ok, peer} =
      LocalTLSPeer.start(
        fn socket ->
          case :ssl.recv(socket, 4, 5_000) do
            {:ok, "ping"} ->
              :ok = :ssl.send(socket, "pong")
              :ssl.recv(socket, 0, 5_000)
              :ok

            {:error, _} ->
              :ok
          end
        end,
        ssl_options: options
      )

    try do
      fun.(peer)
    after
      Task.shutdown(peer.task, :brutal_kill)
      :ssl.close(peer.listener)
    end
  end
end
