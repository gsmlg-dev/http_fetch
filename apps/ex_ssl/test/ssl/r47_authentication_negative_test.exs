defmodule SSL.R47AuthenticationNegativeTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.MultiIdentityFixtures, as: F

  @request "GET /r47 HTTP/1.1\r\nHost: r47.server\r\nConnection: close\r\n\r\n"
  @response "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nr47-peer-ok"

  setup_all do
    directory = Path.join(System.tmp_dir!(), "r47-negative-#{System.unique_integer([:positive])}")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, fixtures: F.create(directory)}
  end

  test "M13 valid multiple identities never bypass tampered server CV Finished or AEAD", %{
    fixtures: m
  } do
    for mutation <- [:valid, :certificate_verify, :finished, :aead] do
      with_peer(m, mutation, fn port, peer ->
        options =
          F.options(m, ["p256-a", "rsa2048-a"])
          |> Keyword.put(:ciphers, [:ssl.str_to_suite(~c"TLS_AES_256_GCM_SHA384")])
          |> Keyword.put(:supported_groups, [:x25519])
          |> Keyword.put(:signature_algs, [:rsa_pss_rsae_sha256])
          |> Keyword.put(:signature_algs_cert, [:rsa_pkcs1_sha256])

        result = SSL.connect({127, 0, 0, 1}, port, options, 3_000)

        if mutation == :valid do
          assert {:ok, socket} = result

          try do
            assert :ok = SSL.send(socket, @request)
            assert {:ok, @response} = SSL.recv(socket, byte_size(@response), 3_000)
            assert_receive {:r47_authenticated, ^peer, chain, 0x0804, @request}, 3_000
            assert chain == [F.der(m, "rsa2048-a")]
          after
            SSL.close(socket)
          end
        else
          expected = if mutation == :aead, do: :bad_record_mac, else: :decrypt_error
          assert {:error, {:tls_alert, {^expected, _}}} = result
          assert_receive {:r47_rejected, ^peer, ^mutation, no_http}, 3_000
          assert no_http
          refute_receive {:r47_authenticated, ^peer, _, _, _}, 0
        end
      end)
    end
  end

  test "M13 TLS12 two usable identities retain SKE Finished and AEAD authentication", %{
    fixtures: m
  } do
    alias SSL.Protocol.{TLS12, TLS12Codec, TLS12Record}
    alias SSL.Crypto.TLS12KeySchedule
    {initial, ske} = tls12_exchange(m)
    assert initial.client_identity.count == 2
    assert initial.peer.leaf_der == Base.decode64!(m["server"]["der_b64"])

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_server_key_exchange}} =
             TLS12.feed(initial, plain(flip(ske)))

    assert {:ok, requested, [], []} = TLS12.feed(initial, plain(ske))
    # RSA certificate type and peer schemes force the later configured RSA identity.
    cr = message(13, <<1, 1, 4::16, 0x0804::16, 0x0401::16, 0::16>>)
    assert {:ok, requested, [], []} = TLS12.feed(requested, plain(cr))
    assert {:ok, waiting, [_ | _], []} = TLS12.feed(requested, plain(message(14, <<>>)))

    [client_certificate, _server_certificate] =
      Enum.filter(waiting.transcript.messages, &match?(<<11, _::binary>>, &1))

    assert {:ok, %{chain: selected}} = TLS12Codec.decode(client_certificate)
    assert selected == [F.der(m, "rsa2048-a")]
    [cv] = Enum.filter(waiting.transcript.messages, &match?(<<15, _::binary>>, &1))
    assert <<15, _::24, 0x0804::16, _::binary>> = cv
    assert {:ok, waiting, [], []} = TLS12.feed(waiting, <<20, 3, 3, 1::16, 1>>)
    transcript = waiting.transcript.messages |> Enum.reverse() |> IO.iodata_to_binary()

    assert {:ok, verify} =
             TLS12KeySchedule.finished(0xC02F, waiting.master_secret, :server, transcript)

    assert {:ok, valid, next} =
             TLS12Record.encrypt(waiting.read_state, :handshake, message(20, verify))

    assert {:ok, connected, [], [{:connected, nil}]} = TLS12.feed(waiting, valid)
    assert {:ok, application, _} = TLS12Record.encrypt(next, :application_data, @response)
    assert {:ok, _, [], [{:application_data, @response}]} = TLS12.feed(connected, application)

    assert {:ok, bad_finished, _} =
             TLS12Record.encrypt(waiting.read_state, :handshake, message(20, flip(verify)))

    assert {:error, {:fatal_alert, :decrypt_error, :invalid_finished}} =
             TLS12.feed(waiting, bad_finished)

    assert {:error, {:fatal_alert, :bad_record_mac, _}} =
             TLS12.feed(waiting, flip(valid))
  end

  # Reuses the full TLS12 negative-test construction with real PKIX verification
  # and a real selected multi-identity flight instead of a synthetic Finished state.
  defp tls12_exchange(m) do
    alias SSL.ClientHello.{Materializer, Serializer}
    alias SSL.Protocol.{ClientOffer, TLS12, TLS12Codec}

    assert {:ok, options} =
             SSL.Options.normalize("r47.server", F.options(m, ["p256-a", "rsa2048-a"], "tls12"))

    assert {:ok, materialized} =
             Materializer.materialize(options.profile, SSL.Options.capabilities(), %{
               server_name: "r47.server"
             })

    assert {:ok, hello} = Serializer.encode(materialized.client_hello)
    assert {:ok, offer} = ClientOffer.from_client_hello(hello)

    assert {:ok, initial} =
             TLS12.new(hello, offer, [F.root(m, "server-root")], {:dns_id, "r47.server"},
               client_identity: options.client_identity
             )

    extensions = <<23::16, 0::16, 0xFF01::16, 1::16, 0>>

    sh =
      message(
        2,
        <<3, 3, 0::256, 0, 0xC02F::16, 0, byte_size(extensions)::16, extensions::binary>>
      )

    assert {:ok, initial, [], []} = TLS12.feed(initial, plain(sh))
    assert {:ok, cert} = TLS12Codec.encode_certificate([Base.decode64!(m["server"]["der_b64"])])
    assert {:ok, initial, [], []} = TLS12.feed(initial, plain(cert))
    {public, _private} = :crypto.generate_key(:ecdh, :secp256r1)
    params = <<3, 0x0017::16, byte_size(public), public::binary>>
    [pem] = :public_key.pem_decode(File.read!(m["server"]["key"]))

    signature =
      :public_key.sign(
        initial.client_random <> initial.server_random <> params,
        :sha256,
        :public_key.pem_entry_decode(pem),
        rsa_options()
      )

    {initial,
     message(12, <<params::binary, 0x0804::16, byte_size(signature)::16, signature::binary>>)}
  end

  defp plain(bytes), do: <<22, 3, 3, byte_size(bytes)::16, bytes::binary>>

  # Same public-crypto construction as verify_none_interop's fallback peer, now
  # requesting and independently verifying client authentication and HTTP. Mutated
  # CV/Finished retain valid record AEAD; only the AEAD control changes its tag.
  defp with_peer(m, mutation, operation) do
    {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(listener)
    parent = self()

    task =
      Task.async(fn ->
        {:ok, tcp} = :gen_tcp.accept(listener, 3_000)

        try do
          {:ok, 22, ch} = read_record(tcp)
          {:ok, offer} = SSL.Protocol.ClientOffer.from_client_hello(ch)
          share = Enum.find(offer.key_shares, &(&1.group == 0x001D))
          {wire, secrets} = server_flight(ch, share.key_exchange, m, mutation)
          :ok = :gen_tcp.send(tcp, wire)

          if mutation == :valid do
            authenticate_client(tcp, secrets, m, parent)
          else
            # A rejection can be a plaintext alert or an authenticated handshake alert.
            # Neither can contain a successfully decrypted application request.
            no_http =
              case read_record(tcp) do
                {:ok, 21, _} ->
                  true

                {:ok, 23, encrypted} ->
                  case decrypt(encrypted, secrets.client_handshake, 0) do
                    {21, _} -> true
                    _ -> false
                  end

                {:error, :closed} ->
                  true
              end

            send(parent, {:r47_rejected, self(), mutation, no_http})
            :ok
          end
        after
          :gen_tcp.close(tcp)
        end
      end)

    try do
      operation.(port, task.pid)
      assert :ok = Task.await(task, 3_000)
    after
      if Process.alive?(task.pid), do: Task.shutdown(task, :brutal_kill)
      :gen_tcp.close(listener)
    end
  end

  defp server_flight(ch, client_public, m, mutation) do
    <<1, _::24, _::16, _::binary-size(32), sid_size, sid::binary-size(sid_size), _::binary>> = ch
    {public, private} = :crypto.generate_key(:ecdh, :x25519)
    shared = :crypto.compute_key(:ecdh, client_public, private, :x25519)
    extensions = <<43::16, 2::16, 0x0304::16, 51::16, 36::16, 0x001D::16, 32::16, public::binary>>

    sh =
      message(
        2,
        <<0x0303::16, :crypto.strong_rand_bytes(32)::binary, sid_size, sid::binary, 0x1302::16, 0,
          byte_size(extensions)::16, extensions::binary>>
      )

    zero = <<0::384>>
    early = mac(zero, zero)
    handshake = mac(label(early, "derived", hash(<<>>), 48), shared)
    server_secret = label(handshake, "s hs traffic", hash(ch <> sh), 48)
    client_secret = label(handshake, "c hs traffic", hash(ch <> sh), 48)
    ee = message(8, <<0::16>>)

    cr =
      message(
        13,
        <<0, 16::16, 13::16, 4::16, 2::16, 0x0804::16, 50::16, 4::16, 2::16, 0x0401::16>>
      )

    der = Base.decode64!(m["server"]["der_b64"])
    entry = <<byte_size(der)::24, der::binary, 0::16>>
    cert = message(11, <<0, byte_size(entry)::24, entry::binary>>)
    [pem] = :public_key.pem_decode(File.read!(m["server"]["key"]))

    signed =
      :binary.copy(<<32>>, 64) <>
        "TLS 1.3, server CertificateVerify" <> <<0>> <> hash(ch <> sh <> ee <> cr <> cert)

    signature =
      :public_key.sign(signed, :sha256, :public_key.pem_entry_decode(pem), rsa_options())

    cv = message(15, <<0x0804::16, byte_size(signature)::16, signature::binary>>)
    cv = if mutation == :certificate_verify, do: flip(cv), else: cv
    prefix = ch <> sh <> ee <> cr <> cert <> cv
    finished = message(20, mac(label(server_secret, "finished", <<>>, 48), hash(prefix)))
    finished = if mutation == :finished, do: flip(finished), else: finished
    transcript = prefix <> finished
    encrypted = encrypt(ee <> cr <> cert <> cv <> finished, 22, server_secret, 0)
    encrypted = if mutation == :aead, do: flip(encrypted), else: encrypted
    master = mac(label(handshake, "derived", hash(<<>>), 48), zero)

    secrets = %{
      transcript: transcript,
      client_handshake: client_secret,
      client_application: label(master, "c ap traffic", hash(transcript), 48),
      server_application: label(master, "s ap traffic", hash(transcript), 48)
    }

    {<<22, 3, 3, byte_size(sh)::16, sh::binary, encrypted::binary>>, secrets}
  end

  defp authenticate_client(tcp, secrets, m, parent) do
    {[cert, cv, finished], _} = read_handshakes(tcp, secrets.client_handshake, 0, [], <<>>)
    <<11, _::24, 0, size::24, entries::binary-size(size)>> = cert
    chain = certificates(entries, [])
    assert chain == [F.der(m, "rsa2048-a")]
    <<15, _::24, 0x0804::16, sig_size::16, signature::binary-size(sig_size)>> = cv
    public = chain |> hd() |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(7) |> elem(2)

    signed =
      :binary.copy(<<32>>, 64) <>
        "TLS 1.3, client CertificateVerify" <> <<0>> <> hash(secrets.transcript <> cert)

    assert :public_key.verify(signed, :sha256, signature, public, rsa_options())
    <<20, 48::24, verify::binary-size(48)>> = finished

    assert verify ==
             mac(
               label(secrets.client_handshake, "finished", <<>>, 48),
               hash(secrets.transcript <> cert <> cv)
             )

    {:ok, 23, encrypted} = read_record(tcp)
    assert {23, @request} = decrypt(encrypted, secrets.client_application, 0)
    :ok = :gen_tcp.send(tcp, encrypt(@response, 23, secrets.server_application, 0))
    send(parent, {:r47_authenticated, self(), chain, 0x0804, @request})
    :ok
  end

  defp read_handshakes(_tcp, _secret, sequence, [_, _, _] = messages, <<>>),
    do: {messages, sequence}

  defp read_handshakes(tcp, secret, sequence, messages, pending) do
    {:ok, 23, encrypted} = read_record(tcp)
    {22, plain} = decrypt(encrypted, secret, sequence)
    {decoded, tail} = messages(pending <> plain, [])
    read_handshakes(tcp, secret, sequence + 1, messages ++ decoded, tail)
  end

  defp messages(<<type, size::24, body::binary-size(size), rest::binary>>, out),
    do: messages(rest, out ++ [message(type, body)])

  defp messages(tail, out), do: {out, tail}
  defp certificates(<<>>, out), do: Enum.reverse(out)

  defp certificates(<<size::24, der::binary-size(size), 0::16, rest::binary>>, out),
    do: certificates(rest, [der | out])

  defp read_record(tcp) do
    with {:ok, <<type, 3, _minor, size::16>>} <- :gen_tcp.recv(tcp, 5, 3_000),
         {:ok, bytes} <- :gen_tcp.recv(tcp, size, 3_000) do
      if type == 20 and bytes == <<1>>, do: read_record(tcp), else: {:ok, type, bytes}
    end
  end

  defp encrypt(bytes, type, secret, sequence) do
    inner = bytes <> <<type>>
    header = <<23, 3, 3, byte_size(inner) + 16::16>>

    {cipher, tag} =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        label(secret, "key", <<>>, 32),
        nonce(secret, sequence),
        inner,
        header,
        16,
        true
      )

    header <> cipher <> tag
  end

  defp decrypt(bytes, secret, sequence) do
    size = byte_size(bytes) - 16
    <<cipher::binary-size(^size), tag::binary-size(16)>> = bytes
    header = <<23, 3, 3, byte_size(bytes)::16>>

    plain =
      :crypto.crypto_one_time_aead(
        :aes_256_gcm,
        label(secret, "key", <<>>, 32),
        nonce(secret, sequence),
        cipher,
        header,
        tag,
        false
      )

    assert is_binary(plain)
    size = byte_size(plain) - 1
    <<content::binary-size(^size), type>> = plain
    {type, content}
  end

  defp nonce(secret, sequence),
    do: :crypto.exor(label(secret, "iv", <<>>, 12), <<0::32, sequence::64>>)

  defp label(secret, text, context, size) do
    label = "tls13 " <> text
    info = <<size::16, byte_size(label), label::binary, byte_size(context), context::binary, 1>>
    binary_part(mac(secret, info), 0, size)
  end

  defp message(type, body), do: <<type, byte_size(body)::24, body::binary>>
  defp hash(data), do: :crypto.hash(:sha384, data)
  defp mac(key, data), do: :crypto.mac(:hmac, :sha384, key, data)

  defp rsa_options,
    do: [rsa_padding: :rsa_pkcs1_pss_padding, rsa_pss_saltlen: 32, rsa_mgf1_md: :sha256]

  defp flip(bytes) do
    size = byte_size(bytes) - 1
    <<prefix::binary-size(^size), last>> = bytes
    <<prefix::binary, Bitwise.bxor(last, 1)>>
  end
end
