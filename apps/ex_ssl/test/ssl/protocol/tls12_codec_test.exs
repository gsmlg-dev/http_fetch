defmodule SSL.Protocol.TLS12CodecTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.{HandshakeFramer, TLS12Codec}

  @random :binary.copy(<<0x42>>, 32)
  @name <<48, 13, 49, 11, 48, 9, 6, 3, 85, 4, 3, 12, 2, 67, 65>>

  test "decodes exact ServerHello bytes and preserves extension order" do
    body =
      <<3, 3, @random::binary, 2, 0xCA, 0xFE, 0xC0, 0x2F, 0, 10::16, 23::16, 0::16, 16::16, 2::16,
        0x68, 0x32>>

    encoded = frame(2, body)

    assert {:ok,
            %{
              type: :server_hello,
              random: @random,
              session_id: <<0xCA, 0xFE>>,
              cipher_suite: 0xC02F,
              compression: 0,
              extensions: [{23, <<>>}, {16, <<0x68, 0x32>>}],
              encoded: ^encoded
            }} = TLS12Codec.decode(encoded)
  end

  test "decodes a bounded certificate chain and exact signed ECDHE parameters" do
    certificate = frame(11, <<8::24, 2::24, 1, 2, 0::24>>)
    assert {:error, :invalid_certificate_chain} = TLS12Codec.decode(certificate)

    certificate = frame(11, <<5::24, 2::24, 1, 2>>)

    assert {:ok, %{type: :certificate, chain: [<<1, 2>>], encoded: ^certificate}} =
             TLS12Codec.decode(certificate)

    parameters = <<3, 0x0017::16, 3, 4, 5, 6>>
    ske = frame(12, <<parameters::binary, 0x0401::16, 3::16, 7, 8, 9>>)

    assert {:ok,
            %{
              type: :server_key_exchange,
              group: 0x0017,
              public_key: <<4, 5, 6>>,
              parameters: ^parameters,
              scheme: 0x0401,
              signature: <<7, 8, 9>>,
              encoded: ^ske
            }} = TLS12Codec.decode(ske)
  end

  test "decodes CertificateRequest, ServerHelloDone, and twelve-byte Finished" do
    request =
      frame(13, <<2, 1, 64, 4::16, 0x0401::16, 0x0403::16, 17::16, 15::16, @name::binary>>)

    assert {:ok,
            %{
              type: :certificate_request,
              certificate_types: [1, 64],
              signature_schemes: [0x0401, 0x0403],
              authorities: [@name],
              encoded: ^request
            }} = TLS12Codec.decode(request)

    assert {:ok, %{type: :server_hello_done, encoded: <<14, 0, 0, 0>>}} =
             TLS12Codec.decode(<<14, 0, 0, 0>>)

    verify_data = :binary.copy(<<0xA5>>, 12)
    finished = frame(20, verify_data)

    assert {:ok, %{type: :finished, verify_data: ^verify_data, encoded: ^finished}} =
             TLS12Codec.decode(finished)
  end

  test "encodes exact client Certificate, ECDHE key, CertificateVerify, and Finished" do
    assert {:ok, <<11, 0, 0, 3, 0, 0, 0>>} = TLS12Codec.encode_certificate([])

    assert {:ok, <<11, 0, 0, 8, 0, 0, 5, 0, 0, 2, 1, 2>>} =
             TLS12Codec.encode_certificate([<<1, 2>>])

    assert {:ok, <<16, 0, 0, 4, 3, 4, 5, 6>>} =
             TLS12Codec.encode_client_key_exchange(<<4, 5, 6>>)

    assert {:ok, <<15, 0, 0, 7, 0x0401::16, 3::16, 7, 8, 9>>} =
             TLS12Codec.encode_certificate_verify(0x0401, <<7, 8, 9>>)

    finished = :binary.copy(<<0xA5>>, 12)
    assert {:ok, <<20, 0, 0, 12, ^finished::binary>>} = TLS12Codec.encode_finished(finished)
  end

  test "framer reassembles fragmented TLS 1.2 handshakes before codec parsing" do
    message = frame(2, <<3, 3, @random::binary, 0, 0xC02F::16, 0>>)

    for split <- 0..(byte_size(message) - 1) do
      <<first::binary-size(^split), last::binary>> = message
      {:ok, [], buffer} = HandshakeFramer.feed(HandshakeFramer.new(), first)
      {:ok, [^message], buffer} = HandshakeFramer.feed(buffer, last)
      assert HandshakeFramer.buffered_size(buffer) == 0
      assert {:ok, %{type: :server_hello, encoded: ^message}} = TLS12Codec.decode(message)
    end
  end

  test "rejects malformed lengths, trailing bytes, duplicate extensions, and unsupported messages" do
    assert {:error, :invalid_handshake} = TLS12Codec.decode(<<2, 0, 0, 0, 0>>)
    assert {:error, :invalid_handshake} = TLS12Codec.decode(<<2, 0, 0, 2, 3>>)
    assert {:error, :unsupported_handshake_type} = TLS12Codec.decode(frame(99, <<>>))

    assert {:error, :invalid_server_hello} =
             TLS12Codec.decode(frame(2, <<3, 1, @random::binary, 0, 0xC02F::16, 0>>))

    assert {:error, :invalid_server_hello_done} = TLS12Codec.decode(frame(14, <<0>>))
    assert {:error, :invalid_finished} = TLS12Codec.decode(frame(20, :binary.copy(<<0>>, 11)))

    duplicate = <<3, 3, @random::binary, 0, 0xC02F::16, 0, 8::16, 23::16, 0::16, 23::16, 0::16>>
    assert {:error, :duplicate_server_hello_extension} = TLS12Codec.decode(frame(2, duplicate))

    assert {:error, :invalid_server_hello_extensions} =
             TLS12Codec.decode(frame(2, <<3, 3, @random::binary, 0, 0xC02F::16, 0, 1::16, 0>>))
  end

  test "rejects oversized or malformed certificates, ECDHE signatures, and CA names" do
    assert {:error, :invalid_certificate_chain} = TLS12Codec.decode(frame(11, <<0::24>>))
    assert {:error, :invalid_certificate_chain} = TLS12Codec.decode(frame(11, <<3::24, 0::24>>))

    assert {:error, :invalid_certificate_chain} =
             TLS12Codec.encode_certificate([:binary.copy(<<1>>, 262_145)])

    assert {:error, :invalid_server_key_exchange} =
             TLS12Codec.decode(frame(12, <<1, 0x0017::16, 1, 4, 0x0401::16, 1::16, 1>>))

    assert {:error, :invalid_server_key_exchange} =
             TLS12Codec.decode(frame(12, <<3, 0x0017::16, 0, 0x0401::16, 1::16, 1>>))

    assert {:error, :invalid_certificate_request} =
             TLS12Codec.decode(frame(13, <<0, 2::16, 0x0401::16, 0::16>>))

    assert {:error, :invalid_certificate_request} =
             TLS12Codec.decode(frame(13, <<1, 1, 3::16, 1, 2, 3, 0::16>>))

    invalid_name = @name <> <<0>>

    invalid_request =
      frame(
        13,
        <<1, 1, 2::16, 0x0401::16, byte_size(invalid_name) + 2::16, byte_size(invalid_name)::16,
          invalid_name::binary>>
      )

    assert {:error, :invalid_certificate_request} = TLS12Codec.decode(invalid_request)
  end

  test "rejects invalid client encodings" do
    assert {:error, :invalid_certificate_chain} = TLS12Codec.encode_certificate([<<>>])

    assert {:error, :invalid_certificate_chain} =
             TLS12Codec.encode_certificate([<<1>> | :improper])

    assert {:error, :invalid_client_key_exchange} = TLS12Codec.encode_client_key_exchange(<<>>)

    assert {:error, :invalid_client_key_exchange} =
             TLS12Codec.encode_client_key_exchange(:binary.copy(<<1>>, 256))

    assert {:error, :invalid_certificate_verify} =
             TLS12Codec.encode_certificate_verify(0x0401, <<>>)

    assert {:error, :invalid_certificate_verify} = TLS12Codec.encode_certificate_verify(-1, <<1>>)
    assert {:error, :invalid_finished} = TLS12Codec.encode_finished(<<0>>)
  end

  test "enforces certificate, request, signature, and session bounds" do
    seventeen = List.duplicate(<<1>>, 17)
    assert {:error, :invalid_certificate_chain} = TLS12Codec.encode_certificate(seventeen)

    oversized_chain = List.duplicate(:binary.copy(<<1>>, 32_769), 16)
    assert {:error, :invalid_certificate_chain} = TLS12Codec.encode_certificate(oversized_chain)

    assert {:error, :invalid_server_hello} =
             TLS12Codec.decode(
               frame(
                 2,
                 <<3, 3, @random::binary, 33, :binary.copy(<<0>>, 33)::binary, 0xC02F::16, 0>>
               )
             )

    assert {:error, :invalid_certificate_request} =
             TLS12Codec.decode(
               frame(13, <<1, 1, 258::16, :binary.copy(<<4, 1>>, 129)::binary, 0::16>>)
             )

    authorities = :binary.copy(<<byte_size(@name)::16, @name::binary>>, 65)

    request =
      frame(13, <<1, 1, 2::16, 0x0401::16, byte_size(authorities)::16, authorities::binary>>)

    assert {:error, :invalid_certificate_request} = TLS12Codec.decode(request)

    signature = :binary.copy(<<1>>, 16_385)

    assert {:error, :invalid_certificate_verify} =
             TLS12Codec.encode_certificate_verify(0x0401, signature)

    parameters = <<3, 0x0017::16, 1, 4>>

    ske =
      frame(12, <<parameters::binary, 0x0401::16, byte_size(signature)::16, signature::binary>>)

    assert {:error, :invalid_server_key_exchange} = TLS12Codec.decode(ske)
  end

  property "arbitrary bounded handshake bytes return a tagged result" do
    check all(bytes <- binary(max_length: 512), max_runs: 100) do
      assert match?({:ok, _}, TLS12Codec.decode(bytes)) or
               match?({:error, _}, TLS12Codec.decode(bytes))
    end
  end

  defp frame(type, body), do: <<type, byte_size(body)::24, body::binary>>
end
