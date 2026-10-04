defmodule SSL.TestServerFlightBuilder do
  @moduledoc false

  @client_private Base.decode16!(
                    "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A"
                  )
  @server_private Base.decode16!(
                    "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB"
                  )

  def build(options) do
    signature_scheme = Keyword.fetch!(options, :signature_scheme)
    leaf_pem = File.read!(Keyword.fetch!(options, :leaf_pem))
    leaf_key_pem = File.read!(Keyword.fetch!(options, :leaf_key_pem))
    encrypted_extensions = Keyword.get(options, :encrypted_extensions, [])
    certificate_extensions = Keyword.get(options, :certificate_extensions, [])
    additional_certificate_entries = Keyword.get(options, :additional_certificate_entries, [])
    certificate_request_extensions = Keyword.get(options, :certificate_request_extensions)
    client_options = Keyword.get(options, :client_options, [])

    {client_public, @client_private} = :crypto.generate_key(:ecdh, :x25519, @client_private)
    {server_public, @server_private} = :crypto.generate_key(:ecdh, :x25519, @server_private)
    shared_secret = :crypto.compute_key(:ecdh, server_public, @client_private, :x25519)

    client_hello = client_hello(client_public, signature_scheme, client_options)
    server_hello = server_hello(server_public)
    hash = :sha384
    suite = :aes_256_gcm
    hash_length = 48

    early_secret =
      extract(hash, :binary.copy(<<0>>, hash_length), :binary.copy(<<0>>, hash_length))

    derived_early = derive_secret(hash, early_secret, "derived", :crypto.hash(hash, <<>>))
    handshake_secret = extract(hash, derived_early, shared_secret)
    hello_digest = :crypto.hash(hash, client_hello <> server_hello)
    client_handshake_secret = derive_secret(hash, handshake_secret, "c hs traffic", hello_digest)
    server_handshake_secret = derive_secret(hash, handshake_secret, "s hs traffic", hello_digest)
    derived_handshake = derive_secret(hash, handshake_secret, "derived", :crypto.hash(hash, <<>>))
    master_secret = extract(hash, derived_handshake, :binary.copy(<<0>>, hash_length))

    encrypted_extensions_message = handshake(8, extensions_vector(encrypted_extensions))

    certificate_request =
      certificate_request(certificate_request_extensions)

    certificate_entries =
      [{leaf_pem, certificate_extensions} | additional_certificate_entries]
      |> Enum.map(fn {pem, extensions} ->
        der =
          if String.starts_with?(pem, "-----BEGIN"),
            do: pem_der(pem),
            else: pem |> File.read!() |> pem_der()

        <<byte_size(der)::24, der::binary, extensions_vector(extensions)::binary>>
      end)
      |> IO.iodata_to_binary()

    certificate =
      handshake(11, <<0, byte_size(certificate_entries)::24, certificate_entries::binary>>)

    certificate_digest =
      :crypto.hash(
        hash,
        client_hello <>
          server_hello <>
          encrypted_extensions_message <>
          certificate_request <> certificate
      )

    signed_content =
      :binary.copy(<<0x20>>, 64) <>
        "TLS 1.3, server CertificateVerify" <> <<0>> <> certificate_digest

    {signature_hash, signature_options} = signature_parameters(signature_scheme)

    signature =
      :public_key.sign(signed_content, signature_hash, pem_key(leaf_key_pem), signature_options)

    certificate_verify =
      handshake(15, <<signature_scheme::16, byte_size(signature)::16, signature::binary>>)

    finished_digest =
      :crypto.hash(
        hash,
        client_hello <>
          server_hello <>
          encrypted_extensions_message <>
          certificate_request <> certificate <> certificate_verify
      )

    server_finished_key =
      expand_label(hash, server_handshake_secret, "finished", <<>>, hash_length)

    server_verify_data = :crypto.mac(:hmac, hash, server_finished_key, finished_digest)
    finished = handshake(20, server_verify_data)

    server_records =
      encrypt_records(
        hash,
        suite,
        server_handshake_secret,
        [
          encrypted_extensions_message,
          certificate_request <> certificate <> certificate_verify,
          finished
        ]
      )

    server_transcript =
      client_hello <>
        server_hello <>
        encrypted_extensions_message <>
        certificate_request <> certificate <> certificate_verify <> finished

    application_digest = :crypto.hash(hash, server_transcript)
    client_app_secret = derive_secret(hash, master_secret, "c ap traffic", application_digest)
    server_app_secret = derive_secret(hash, master_secret, "s ap traffic", application_digest)

    client_finished_key =
      expand_label(hash, client_handshake_secret, "finished", <<>>, hash_length)

    client_certificate = client_certificate(certificate_request)
    client_transcript = server_transcript <> client_certificate
    client_verify_digest = :crypto.hash(hash, client_transcript)
    client_verify_data = :crypto.mac(:hmac, hash, client_finished_key, client_verify_digest)
    client_finished = handshake(20, client_verify_data)

    client_records =
      encrypt_records(
        hash,
        suite,
        client_handshake_secret,
        if(client_certificate == <<>>,
          do: [client_finished],
          else: [client_certificate, client_finished]
        )
      )

    {client_empty_certificate_record, client_finished_record} =
      case client_records do
        [finished_record] -> {nil, finished_record}
        [certificate_record, finished_record] -> {certificate_record, finished_record}
      end

    %{
      client_private: @client_private,
      client_public: client_public,
      server_public: server_public,
      client_hello: client_hello,
      server_hello: server_hello,
      record_1: Enum.at(server_records, 0),
      record_2: Enum.at(server_records, 1),
      record_3: Enum.at(server_records, 2),
      client_finished_record: client_finished_record,
      transcript_digest: :crypto.hash(hash, client_transcript <> client_finished),
      client_empty_certificate_record: client_empty_certificate_record,
      client_app_key: expand_label(hash, client_app_secret, "key", <<>>, 32),
      client_app_iv: expand_label(hash, client_app_secret, "iv", <<>>, 12),
      server_app_key: expand_label(hash, server_app_secret, "key", <<>>, 32),
      server_app_iv: expand_label(hash, server_app_secret, "iv", <<>>, 12)
    }
  end

  defp client_hello(public_key, signature_scheme, options) do
    alpn_protocols = Keyword.get(options, :alpn_protocols, ["h2", "http/1.1"])

    base_extensions = [
      {43, <<2, 0x0304::16>>},
      {10, <<2::16, 0x001D::16>>},
      {51, <<36::16, 0x001D::16, 32::16, public_key::binary>>},
      {13, <<2::16, signature_scheme::16>>}
    ]

    extensions =
      base_extensions ++
        optional_alpn(alpn_protocols) ++
        optional_extension(options, :status_request, {5, <<1, 0::16, 0::16>>}, true) ++
        optional_extension(options, :signed_certificate_timestamps, {18, <<>>}, true) ++
        optional_extension(options, :early_data, {42, <<>>}, false)

    extension_bytes = encode_extensions(extensions)

    body =
      <<0x0303::16, 0::256, 0, 2::16, 0x1302::16, 1, 0, byte_size(extension_bytes)::16,
        extension_bytes::binary>>

    handshake(1, body)
  end

  defp optional_alpn([]), do: []

  defp optional_alpn(protocols) do
    entries = IO.iodata_to_binary(Enum.map(protocols, &<<byte_size(&1), &1::binary>>))
    [{16, <<byte_size(entries)::16, entries::binary>>}]
  end

  defp optional_extension(options, key, extension, default) do
    if Keyword.get(options, key, default), do: [extension], else: []
  end

  defp server_hello(public_key) do
    extensions = [{43, <<0x0304::16>>}, {51, <<0x001D::16, 32::16, public_key::binary>>}]
    extension_bytes = encode_extensions(extensions)

    body =
      <<0x0303::16, 0xA5::size(32 * 8), 0, 0x1302::16, 0, byte_size(extension_bytes)::16,
        extension_bytes::binary>>

    handshake(2, body)
  end

  defp encrypt_records(hash, cipher, traffic_secret, plaintexts) do
    key = expand_label(hash, traffic_secret, "key", <<>>, 32)
    iv = expand_label(hash, traffic_secret, "iv", <<>>, 12)

    plaintexts
    |> Enum.with_index()
    |> Enum.map(fn {content, sequence} ->
      inner = content <> <<22>>
      header = <<23, 0x0303::16, byte_size(inner) + 16::16>>
      nonce = xor_nonce(iv, sequence)

      {ciphertext, tag} =
        :crypto.crypto_one_time_aead(cipher, key, nonce, inner, header, 16, true)

      header <> ciphertext <> tag
    end)
  end

  defp extract(hash, salt, ikm), do: :crypto.mac(:hmac, hash, salt, ikm)

  defp derive_secret(hash, secret, label, transcript_hash),
    do: expand_label(hash, secret, label, transcript_hash, byte_size(secret))

  defp expand_label(hash, secret, label, context, length) do
    full_label = "tls13 " <> label

    info =
      <<length::16, byte_size(full_label), full_label::binary, byte_size(context),
        context::binary>>

    expand(hash, secret, info, length, 1, <<>>, <<>>)
  end

  defp expand(_hash, _secret, _info, length, _counter, _previous, output)
       when byte_size(output) >= length,
       do: binary_part(output, 0, length)

  defp expand(hash, secret, info, length, counter, previous, output) do
    block = :crypto.mac(:hmac, hash, secret, previous <> info <> <<counter>>)
    expand(hash, secret, info, length, counter + 1, block, output <> block)
  end

  defp xor_nonce(iv, sequence) do
    padded = <<0::32, sequence::64>>
    :crypto.exor(iv, padded)
  end

  defp handshake(type, body), do: <<type, byte_size(body)::24, body::binary>>

  defp certificate_request(nil), do: <<>>

  defp certificate_request(extensions) when is_list(extensions),
    do: handshake(13, <<0, extensions_vector(extensions)::binary>>)

  defp client_certificate(<<>>), do: <<>>
  defp client_certificate(_request), do: handshake(11, <<0, 0::24>>)
  defp extensions_vector(extensions), do: encode_extensions(extensions) |> vector16()

  defp encode_extensions(extensions) do
    IO.iodata_to_binary(
      Enum.map(extensions, fn {id, payload} ->
        <<id::16, byte_size(payload)::16, payload::binary>>
      end)
    )
  end

  defp vector16(bytes), do: <<byte_size(bytes)::16, bytes::binary>>

  defp signature_parameters(0x0403), do: {:sha256, []}

  defp signature_parameters(0x0804) do
    {:sha256,
     [
       {:rsa_padding, :rsa_pkcs1_pss_padding},
       {:rsa_pss_saltlen, 32},
       {:rsa_mgf1_md, :sha256}
     ]}
  end

  defp pem_der(pem) do
    [entry] = :public_key.pem_decode(pem)
    elem(entry, 1)
  end

  defp pem_key(pem) do
    [entry] = :public_key.pem_decode(pem)
    :public_key.pem_entry_decode(entry)
  end
end
