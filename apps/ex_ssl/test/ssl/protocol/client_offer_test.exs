defmodule SSL.Protocol.ClientOfferTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SSL.Protocol.ClientOffer

  @capture Path.expand("../../fixtures/server_flight/capture.txt", __DIR__)
           |> File.read!()
           |> String.split("\n", trim: true)
           |> Map.new(fn line ->
             [name, value] = String.split(line, "=", parts: 2)
             {String.to_atom(name), Base.decode16!(value)}
           end)
  @missing_signature_algorithms Path.expand(
                                  "../../fixtures/server_flight/malformed_missing_signature_algorithms_client_hello.txt",
                                  __DIR__
                                )
                                |> File.read!()
                                |> String.split("\n", trim: true)
                                |> Enum.reject(&String.starts_with?(&1, "#"))
                                |> List.first()
                                |> Base.decode16!()

  test "extracts negotiation fields from the exact ClientHello bytes" do
    assert {:ok, offer} = ClientOffer.from_client_hello(@capture.client_hello)
    assert offer.encoded == @capture.client_hello
    assert offer.legacy_session_id == <<>>
    assert offer.cipher_suites == [0x1302]
    assert offer.offered_versions == [0x0304]
    assert offer.supported_groups == [0x001D]
    assert [%{group: 0x001D, key_exchange: key_exchange}] = offer.key_shares
    assert key_exchange == @capture.client_public
    assert offer.signature_schemes == [0x0403]
    assert offer.certificate_signature_schemes == nil
    assert offer.alpn_protocols == ["h2", "http/1.1"]
    assert offer.extension_ids == [43, 10, 51, 13, 16, 5, 18]
  end

  test "certificate-signature policy is extracted only from exact extension 50" do
    base = extensions(@capture.client_hello)

    encoded =
      replace_extensions(@capture.client_hello, base ++ [{50, <<4::16, 0x0401::16, 0x0804::16>>}])

    assert {:ok, %{certificate_signature_schemes: [0x0401, 0x0804]}} =
             ClientOffer.from_client_hello(encoded)

    for payload <- [<<0::16>>, <<3::16, 4, 1, 8>>, <<2::16, 4, 1, 0>>] do
      malformed = replace_extensions(@capture.client_hello, base ++ [{50, payload}])
      assert {:error, _} = ClientOffer.from_client_hello(malformed)
    end
  end

  test "does not invent signature schemes for the historical malformed offer" do
    assert {:ok, %{signature_schemes: [], extension_ids: extension_ids}} =
             ClientOffer.from_client_hello(@missing_signature_algorithms)

    refute 13 in extension_ids
  end

  test "preserves unknown extensions and rejects duplicate IDs" do
    extensions = [{65_000, <<1, 2, 3>>} | extensions(@capture.client_hello)]
    encoded = replace_extensions(@capture.client_hello, extensions)

    assert {:ok, %{extensions: [{65_000, <<1, 2, 3>>} | _]}} =
             ClientOffer.from_client_hello(encoded)

    duplicate = replace_extensions(@capture.client_hello, extensions ++ [{65_000, <<>>}])

    assert {:error, {:duplicate_client_hello_extension, 65_000}} =
             ClientOffer.from_client_hello(duplicate)
  end

  test "rejects malformed nested offer vectors and arbitrary terms" do
    [{43, _versions} | rest] = extensions(@capture.client_hello)
    malformed = replace_extensions(@capture.client_hello, [{43, <<4, 3, 4>>} | rest])

    assert {:error, {:malformed_client_hello_extension, 43, :supported_versions}} =
             ClientOffer.from_client_hello(malformed)

    assert {:error, {:invalid_input, :client_hello}} = ClientOffer.from_client_hello(nil)

    assert {:error, {:invalid_input, :client_hello}} =
             ClientOffer.from_client_hello([<<1>> | :bad])
  end

  test "requires exact PSK identity and binder vectors" do
    identities = <<1::16, "i", 0::32>>
    binders = <<1, "b">>

    psk =
      <<byte_size(identities)::16, identities::binary, byte_size(binders)::16, binders::binary>>

    encoded =
      replace_extensions(@capture.client_hello, extensions(@capture.client_hello) ++ [{41, psk}])

    assert {:ok, %{psk_count: 1}} = ClientOffer.from_client_hello(encoded)

    malformed =
      replace_extensions(
        @capture.client_hello,
        extensions(@capture.client_hello) ++ [{41, psk <> <<0>>}]
      )

    assert {:error, {:malformed_client_hello_extension, 41, :pre_shared_key}} =
             ClientOffer.from_client_hello(malformed)
  end

  property "bounded malformed ClientHello encodings return tagged results" do
    check all(bytes <- binary(max_length: 256), max_runs: 100) do
      assert match?({:ok, %ClientOffer{}}, ClientOffer.from_client_hello(bytes)) or
               match?({:error, _reason}, ClientOffer.from_client_hello(bytes))
    end
  end

  defp extensions(client_hello) do
    <<1, _length::24, 0x0303::16, _random::binary-size(32), session_length, rest::binary>> =
      client_hello

    <<_session::binary-size(^session_length), cipher_length::16, rest::binary>> = rest
    <<_ciphers::binary-size(^cipher_length), compression_length, rest::binary>> = rest
    <<_compression::binary-size(^compression_length), extension_length::16, bytes::binary>> = rest
    assert byte_size(bytes) == extension_length
    parse_extensions(bytes, [])
  end

  defp parse_extensions(<<>>, entries), do: Enum.reverse(entries)

  defp parse_extensions(
         <<id::16, length::16, payload::binary-size(length), rest::binary>>,
         entries
       ),
       do: parse_extensions(rest, [{id, payload} | entries])

  defp replace_extensions(client_hello, extensions) do
    <<1, _length::24, prefix::binary-size(34), session_length, rest::binary>> = client_hello
    <<session::binary-size(^session_length), cipher_length::16, rest::binary>> = rest
    <<ciphers::binary-size(^cipher_length), compression_length, rest::binary>> = rest
    <<compression::binary-size(^compression_length), _old_length::16, _old::binary>> = rest

    bytes =
      IO.iodata_to_binary(
        Enum.map(extensions, fn {id, payload} ->
          <<id::16, byte_size(payload)::16, payload::binary>>
        end)
      )

    body =
      <<prefix::binary, session_length, session::binary, cipher_length::16, ciphers::binary,
        compression_length, compression::binary, byte_size(bytes)::16, bytes::binary>>

    <<1, byte_size(body)::24, body::binary>>
  end
end
