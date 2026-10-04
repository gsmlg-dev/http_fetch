defmodule SSL.Protocol.ServerFlightTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.HandshakeFramer
  alias SSL.Protocol.ServerFlight
  alias SSL.Protocol.ServerFlight.{Certificate, CertificateVerify, EncryptedExtensions, Finished}

  @decode_options [
    offered_extension_ids: [0, 16, 28],
    allowed_signature_schemes: [0x0804],
    hash: :sha256
  ]

  test "recognizing a TLS signature identifier does not make its algorithm implemented" do
    encoded = handshake(15, <<0x0808::16, 1::16, 1>>)
    options = Keyword.put(@decode_options, :allowed_signature_schemes, [0x0808])

    assert {:ok, %CertificateVerify{signature_scheme: 0x0808}, <<>>} =
             ServerFlight.decode(encoded, options)

    refute 0x0808 in SSL.Capabilities.identifiers(:signature_algorithm)

    assert {:error, {:unsupported_signature_scheme, 0x0808}} =
             SSL.Crypto.Signature.verify_server(0x0808, nil, :sha256, <<0::256>>, <<1>>)
  end

  test "decodes ordered EncryptedExtensions and preserves exact bytes and remainder" do
    trailing = <<20, 0, 0>>
    encoded = encrypted_extensions()

    assert {:ok,
            %{
              __struct__: EncryptedExtensions,
              extensions: [
                {:server_name_ack},
                {:alpn, "h2"},
                {:record_size_limit, 16_385}
              ],
              encoded: ^encoded
            }, ^trailing} = ServerFlight.decode(encoded <> trailing, @decode_options)
  end

  test "generic codec recognizes an offered early_data extension" do
    encoded = handshake(8, extensions([extension(42, <<>>)]))
    options = Keyword.put(@decode_options, :offered_extension_ids, [42])

    assert {:ok, %EncryptedExtensions{extensions: [{:early_data}]}, <<>>} =
             ServerFlight.decode(encoded, options)
  end

  test "decodes a bounded Certificate chain and entry extensions" do
    encoded = certificate()

    assert {:ok,
            %{
              __struct__: Certificate,
              request_context: <<>>,
              entries: [
                %{der: <<0x30, 3, 2, 1>>, extensions: [{:status_request, <<0xAA, 0xBB>>}]},
                %{der: <<0x30, 0>>, extensions: []}
              ],
              encoded: ^encoded
            }, <<>>} = ServerFlight.decode(encoded, @decode_options)
  end

  test "decodes CertificateVerify and Finished and preserves exact bytes" do
    certificate_verify = certificate_verify()
    finished = finished()

    assert {:ok,
            %{
              __struct__: CertificateVerify,
              signature_scheme: 0x0804,
              signature: <<1, 2, 3>>,
              encoded: ^certificate_verify
            }, <<>>} = ServerFlight.decode(certificate_verify, @decode_options)

    assert {:ok,
            %{
              __struct__: Finished,
              verify_data: verify_data,
              encoded: ^finished
            }, <<>>} = ServerFlight.decode(finished, @decode_options)

    assert verify_data == :binary.copy(<<0xA5>>, 32)
  end

  test "composes with HandshakeFramer at every split boundary" do
    for message <- [encrypted_extensions(), certificate(), certificate_verify(), finished()],
        split <- 0..byte_size(message) do
      <<first::binary-size(^split), second::binary>> = message
      assert {:ok, first_messages, buffer} = HandshakeFramer.feed(HandshakeFramer.new(), first)
      assert {:ok, second_messages, buffer} = HandshakeFramer.feed(buffer, second)
      assert first_messages ++ second_messages == [message]
      assert HandshakeFramer.buffered_bytes(buffer) == <<>>
      assert {:ok, %{encoded: ^message}, <<>>} = ServerFlight.decode(message, @decode_options)
    end
  end

  test "reports incomplete outer messages and rejects malformed inner lengths" do
    assert {:more, 4} = ServerFlight.decode(<<>>, @decode_options)
    assert {:more, 2} = ServerFlight.decode(<<8, 0>>, @decode_options)
    assert {:more, 1} = ServerFlight.decode(<<8, 0, 0, 3, 0, 1>>, @decode_options)

    assert {:error, {:malformed_extensions, :length}} =
             ServerFlight.decode(handshake(8, <<3::16, 0>>), @decode_options)

    assert {:error, {:malformed_certificate, :certificate_list_length}} =
             ServerFlight.decode(handshake(11, <<0, 3::24, 1, 2>>), @decode_options)

    assert {:error, {:malformed_certificate_verify, :signature_length}} =
             ServerFlight.decode(handshake(15, <<0x0804::16, 2::16, 1>>), @decode_options)
  end

  test "rejects duplicate, forbidden, unoffered, and malformed EncryptedExtensions" do
    duplicate = handshake(8, extensions([extension(0, <<>>), extension(0, <<>>)]))
    forbidden = handshake(8, extensions([extension(43, <<0x0304::16>>)]))
    unsupported = handshake(8, extensions([extension(0xFAFA, <<>>)]))
    unoffered = handshake(8, extensions([extension(16, <<3::16, 2, "h2">>)]))
    malformed_alpn = handshake(8, extensions([extension(16, <<2::16, 0, 0>>)]))

    assert {:error, {:duplicate_extension, :encrypted_extensions, 0}} =
             ServerFlight.decode(duplicate, @decode_options)

    assert {:error, {:forbidden_extension, :encrypted_extensions, 43}} =
             ServerFlight.decode(forbidden, @decode_options)

    assert {:error, {:unsupported_extension, :encrypted_extensions, 0xFAFA}} =
             ServerFlight.decode(unsupported, @decode_options)

    assert {:error, {:extension_not_offered, 16}} =
             ServerFlight.decode(
               unoffered,
               Keyword.put(@decode_options, :offered_extension_ids, [])
             )

    assert {:error, {:malformed_extension, 16, :alpn}} =
             ServerFlight.decode(malformed_alpn, @decode_options)
  end

  test "rejects empty, malformed, and bounded Certificate chains" do
    empty_chain = handshake(11, <<0, 0::24>>)
    nonempty_context = handshake(11, <<1, 1, 0::24>>)
    certificate = certificate()

    assert {:error, :empty_certificate_chain} =
             ServerFlight.decode(empty_chain, @decode_options)

    assert {:error, {:unsupported_certificate_request_context, <<1>>}} =
             ServerFlight.decode(nonempty_context, @decode_options)

    assert {:error, {:certificate_limit_exceeded, :count, 2, 1}} =
             ServerFlight.decode(
               certificate,
               Keyword.put(@decode_options, :max_certificate_count, 1)
             )

    assert {:error, {:certificate_limit_exceeded, :individual_der_bytes, 4, 3}} =
             ServerFlight.decode(
               certificate,
               Keyword.put(@decode_options, :max_certificate_bytes, 3)
             )

    assert {:error, {:certificate_limit_exceeded, :total_der_bytes, 6, 5}} =
             ServerFlight.decode(
               certificate,
               Keyword.put(@decode_options, :max_total_certificate_bytes, 5)
             )

    assert {:error, {:certificate_limit_exceeded, :extension_bytes, 10, 8}} =
             ServerFlight.decode(
               certificate,
               Keyword.put(@decode_options, :max_extension_bytes, 8)
             )
  end

  test "rejects malformed Certificate entry extensions" do
    duplicate =
      handshake(
        11,
        certificate_body([
          certificate_entry(<<1>>, [extension(5, <<1, 1::24, 0>>), extension(5, <<1, 1::24, 0>>)])
        ])
      )

    forbidden =
      handshake(11, certificate_body([certificate_entry(<<1>>, [extension(16, <<>>)])]))

    malformed_status =
      handshake(11, certificate_body([certificate_entry(<<1>>, [extension(5, <<1, 2::24, 0>>)])]))

    assert {:error, {:duplicate_extension, :certificate_entry, 5}} =
             ServerFlight.decode(duplicate, @decode_options)

    assert {:error, {:forbidden_extension, :certificate_entry, 16}} =
             ServerFlight.decode(forbidden, @decode_options)

    assert {:error, {:malformed_extension, 5, :status_request}} =
             ServerFlight.decode(malformed_status, @decode_options)
  end

  test "validates CertificateVerify schemes and signatures" do
    unsupported = handshake(15, <<0x0401::16, 1::16, 0>>)
    empty_signature = handshake(15, <<0x0804::16, 0::16>>)
    trailing = handshake(15, <<0x0804::16, 1::16, 0, 1>>)

    assert {:error, {:unsupported_signature_scheme, 0x0401}} =
             ServerFlight.decode(unsupported, @decode_options)

    assert {:error, :empty_certificate_verify_signature} =
             ServerFlight.decode(empty_signature, @decode_options)

    assert {:error, {:malformed_certificate_verify, :trailing_data}} =
             ServerFlight.decode(trailing, @decode_options)

    assert {:error, {:signature_length_exceeded, 3, 2}} =
             ServerFlight.decode(
               certificate_verify(),
               Keyword.put(@decode_options, :max_signature_bytes, 2)
             )
  end

  test "validates and encodes Finished for SHA-256 and SHA-384" do
    assert {:error, {:invalid_finished_length, 31, 32}} =
             ServerFlight.decode(handshake(20, <<0::248>>), @decode_options)

    assert {:error, {:invalid_finished_length, 32, 48}} =
             ServerFlight.decode(finished(), Keyword.put(@decode_options, :hash, :sha384))

    verify_data = :binary.copy(<<0x5A>>, 48)
    expected = handshake(20, verify_data)
    assert {:ok, ^expected} = ServerFlight.encode_finished(verify_data, hash: :sha384)

    assert {:error, {:invalid_finished_length, 1, 32}} =
             ServerFlight.encode_finished(<<0>>, hash: :sha256)

    assert {:error, {:invalid_input, :verify_data}} = ServerFlight.encode_finished(nil)
  end

  test "parses CertificateRequest extensions that RFC 9846 permits but this client does not use" do
    signature_algorithms = extension(13, <<2::16, 0x0804::16>>)
    server_name = extension(0, <<0, 0>>)
    unknown = extension(0xFAFA, <<1, 2, 3>>)

    request =
      handshake(
        13,
        <<0, byte_size(signature_algorithms <> server_name <> unknown)::16,
          signature_algorithms::binary, server_name::binary, unknown::binary>>
      )

    assert {:ok,
            %ServerFlight.CertificateRequest{
              request_context: <<>>,
              extensions: [
                {:signature_algorithms, [0x0804]},
                {:raw, 0, <<0, 0>>},
                {:raw, 0xFAFA, <<1, 2, 3>>}
              ],
              encoded: ^request
            }, <<>>} = ServerFlight.decode(request, @decode_options)

    assert {:ok, <<11, 4::24, 0, 0::24>>} = ServerFlight.encode_empty_certificate(<<>>)

    assert {:error, {:malformed_certificate_request, :extensions_length}} =
             ServerFlight.decode(handshake(13, <<0, 2::16, 0>>), @decode_options)

    assert {:error, {:unsupported_certificate_request_context, <<1>>}} =
             ServerFlight.decode(handshake(13, <<1, 1, 0::16>>), @decode_options)

    assert {:error, :missing_certificate_request_signature_algorithms} =
             ServerFlight.decode(handshake(13, <<0, 0::16>>), @decode_options)

    malformed = extension(13, <<1, 0x08>>)

    assert {:error, {:malformed_extension, 13, :signature_algorithms}} =
             ServerFlight.decode(
               handshake(13, <<0, byte_size(malformed)::16, malformed::binary>>),
               @decode_options
             )

    forbidden = extension(43, <<0x0304::16>>)

    assert {:error, {:forbidden_extension, :certificate_request, 43}} =
             ServerFlight.decode(
               handshake(
                 13,
                 <<0, byte_size(signature_algorithms <> forbidden)::16,
                   signature_algorithms::binary, forbidden::binary>>
               ),
               @decode_options
             )
  end

  test "validates post-handshake NewSessionTicket and KeyUpdate" do
    early_data = extension(42, <<16_384::32>>)

    ticket =
      handshake(
        4,
        <<60::32, 7::32, 1, 9, 2::16, 1, 2, byte_size(early_data)::16, early_data::binary>>
      )

    assert {:ok, %ServerFlight.NewSessionTicket{ticket: <<1, 2>>}, <<>>} =
             ServerFlight.decode(ticket, @decode_options)

    update = handshake(24, <<1>>)

    assert {:ok, %ServerFlight.KeyUpdate{request_update: true}, <<>>} =
             ServerFlight.decode(update, @decode_options)

    assert {:ok, <<24, 1::24, 0>>} = ServerFlight.encode_key_update(false)

    assert {:error, {:malformed_key_update, 2}} =
             ServerFlight.decode(handshake(24, <<2>>), @decode_options)

    invalid_early_data = extension(42, <<>>)

    assert {:error, {:malformed_extension, 42, :early_data}} =
             ServerFlight.decode(
               handshake(
                 4,
                 <<60::32, 7::32, 0, 1::16, 1, byte_size(invalid_early_data)::16,
                   invalid_early_data::binary>>
               ),
               @decode_options
             )

    assert {:error, {:invalid_new_session_ticket_lifetime, 604_801}} =
             ServerFlight.decode(
               handshake(4, <<604_801::32, 7::32, 0, 1::16, 1, 0::16>>),
               @decode_options
             )

    unknown = extension(0xFAFA, <<1, 2, 3>>)

    unknown_extension_ticket =
      handshake(
        4,
        <<60::32, 7::32, 0, 1::16, 1, byte_size(unknown)::16, unknown::binary>>
      )

    assert {:ok, %ServerFlight.NewSessionTicket{extensions: [{:raw, 0xFAFA, <<1, 2, 3>>}]}, <<>>} =
             ServerFlight.decode(unknown_extension_ticket, @decode_options)

    forbidden = extension(43, <<0x0304::16>>)

    assert {:error, {:forbidden_extension, :new_session_ticket, 43}} =
             ServerFlight.decode(
               handshake(
                 4,
                 <<60::32, 7::32, 0, 1::16, 1, byte_size(forbidden)::16, forbidden::binary>>
               ),
               @decode_options
             )
  end

  test "validates decoder input and configurable limits" do
    assert {:error, {:invalid_input, :not_binary}} = ServerFlight.decode(nil, @decode_options)

    assert {:error, {:malformed_new_session_ticket, :header}} =
             ServerFlight.decode(handshake(4, <<>>), @decode_options)

    for key <- [
          :max_handshake_length,
          :max_certificate_count,
          :max_total_certificate_bytes,
          :max_certificate_bytes,
          :max_extension_bytes,
          :max_signature_bytes
        ] do
      assert {:error, {:invalid_limit, ^key}} =
               ServerFlight.decode(finished(), Keyword.put(@decode_options, key, -1))
    end

    assert {:error, {:invalid_options, :offered_extension_ids}} =
             ServerFlight.decode(
               finished(),
               Keyword.put(@decode_options, :offered_extension_ids, nil)
             )

    assert {:error, {:invalid_options, :allowed_signature_schemes}} =
             ServerFlight.decode(
               finished(),
               Keyword.put(@decode_options, :allowed_signature_schemes, [nil])
             )

    assert {:error, {:invalid_options, :hash}} =
             ServerFlight.decode(finished(), Keyword.put(@decode_options, :hash, :sha512))

    assert {:error, {:handshake_length_exceeded, 32, 31}} =
             ServerFlight.decode(
               finished(),
               Keyword.put(@decode_options, :max_handshake_length, 31)
             )
  end

  property "bounded arbitrary input always returns the documented result shape" do
    check all(input <- binary(max_length: 512), max_runs: 100) do
      case ServerFlight.decode(input, @decode_options) do
        {:ok, %{encoded: encoded}, remainder}
        when is_binary(encoded) and is_binary(remainder) ->
          assert true

        {:more, needed} when is_integer(needed) and needed > 0 ->
          assert true

        {:error, _reason} ->
          assert true

        other ->
          flunk("unexpected decode result: #{inspect(other)}")
      end
    end
  end

  test "rejects improper option lists without raising" do
    assert {:error, {:invalid_options, :structure}} =
             ServerFlight.decode(<<>>, [{:hash, :sha256} | :not_a_list])
  end

  defp handshake(type, body), do: <<type, byte_size(body)::24, body::binary>>

  defp encrypted_extensions do
    handshake(
      8,
      extensions([
        extension(0, <<>>),
        extension(16, <<3::16, 2, "h2">>),
        extension(28, <<16_385::16>>)
      ])
    )
  end

  defp certificate do
    handshake(
      11,
      certificate_body([
        certificate_entry(<<0x30, 3, 2, 1>>, [extension(5, <<1, 2::24, 0xAA, 0xBB>>)]),
        certificate_entry(<<0x30, 0>>, [])
      ])
    )
  end

  defp certificate_verify, do: handshake(15, <<0x0804::16, 3::16, 1, 2, 3>>)
  defp finished, do: handshake(20, :binary.copy(<<0xA5>>, 32))

  defp extensions(items) do
    bytes = IO.iodata_to_binary(items)
    <<byte_size(bytes)::16, bytes::binary>>
  end

  defp extension(type, payload), do: <<type::16, byte_size(payload)::16, payload::binary>>

  defp certificate_body(entries) do
    bytes = IO.iodata_to_binary(entries)
    <<0, byte_size(bytes)::24, bytes::binary>>
  end

  defp certificate_entry(der, entry_extensions) do
    extension_bytes = IO.iodata_to_binary(entry_extensions)

    <<byte_size(der)::24, der::binary, byte_size(extension_bytes)::16, extension_bytes::binary>>
  end
end
