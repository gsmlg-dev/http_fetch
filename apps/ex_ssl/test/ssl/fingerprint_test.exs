defmodule SSL.FingerprintTest do
  use ExUnit.Case, async: true

  # FoxIO JA4 technical definition, pinned in docs/FINGERPRINTS.md.
  @ciphers [
    0x1301,
    0x1302,
    0x1303,
    0xC02B,
    0xC02F,
    0xC02C,
    0xC030,
    0xCCA9,
    0xCCA8,
    0xC013,
    0xC014,
    0x009C,
    0x009D,
    0x002F,
    0x0035
  ]
  @ids [27, 0, 51, 16, 17_513, 23, 45, 13, 5, 35, 18, 43, 65_281, 11, 10, 21]
  @sigs [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]

  defp vector16(ids) do
    bytes = for id <- ids, into: <<>>, do: <<id::16>>
    <<byte_size(bytes)::16, bytes::binary>>
  end

  defp hello(ciphers \\ @ciphers, ids \\ @ids, sigs \\ @sigs, alpn \\ "h2") do
    extensions =
      for id <- ids, into: <<>> do
        payload =
          case id do
            13 -> vector16(sigs)
            43 -> <<2, 0x0304::16>>
            10 -> vector16([29])
            11 -> <<1, 0>>
            16 -> <<byte_size(alpn) + 1::16, byte_size(alpn), alpn::binary>>
            _ -> <<>>
          end

        <<id::16, byte_size(payload)::16, payload::binary>>
      end

    body =
      <<0x0303::16, 0::256, 0, vector16(ciphers)::binary, 1, 0, byte_size(extensions)::16,
        extensions::binary>>

    <<1, byte_size(body)::24, body::binary>>
  end

  test "official JA4 example and raw components are computed from wire" do
    assert {:ok, fp} = SSL.Fingerprint.client_hello(hello(), :tcp)
    assert fp.ja4.hash == "t13d1516h2_8daaf6152771_e5627efa2ab1"

    assert fp.ja4.cipher_raw ==
             "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"

    assert String.ends_with?(fp.ja4.extension_raw, "_0403,0804,0401,0503,0805,0501,0806,0601")
    assert fp.observation.cipher_suites == @ciphers
    assert fp.observation.extension_ids == @ids
    assert {:ok, quic} = SSL.Fingerprint.client_hello(hello(), :quic)
    assert quic.ja4.hash == String.replace_prefix(fp.ja4.hash, "t", "q")
    assert quic.ja3 == fp.ja3
    assert quic.transport == :quic
  end

  test "independent Caddy JA3 fixture matches raw and digest" do
    assert {:ok, fp} =
             SSL.Fingerprint.client_hello(
               hello([4865, 4866], [0, 10, 11, 13, 16, 43, 51], [0x0403], "http/1.1"),
               :tcp
             )

    assert fp.ja3.raw == "771,4865-4866,0-10-11-13-16-43-51,29,0"
    assert fp.ja3.hash == "af851f784aed02a8b1e0b6ac13251239"
  end

  test "GREASE is omitted only in analysis; JA4 sorts extensions but not signatures" do
    {:ok, base} = SSL.Fingerprint.client_hello(hello(), :tcp)

    {:ok, grease} =
      SSL.Fingerprint.client_hello(
        hello([0x0A0A | @ciphers], [0x1A1A | @ids], [0x2A2A | @sigs]),
        :tcp
      )

    assert grease.ja4 == base.ja4
    assert grease.ja3 == base.ja3
    assert hd(grease.observation.cipher_suites) == 0x0A0A

    {:ok, reordered} =
      SSL.Fingerprint.client_hello(hello(Enum.reverse(@ciphers), Enum.reverse(@ids)), :tcp)

    assert reordered.ja4 == base.ja4
    refute reordered.ja3 == base.ja3

    {:ok, signatures} =
      SSL.Fingerprint.client_hello(hello(@ciphers, @ids, Enum.reverse(@sigs)), :tcp)

    refute signatures.ja4.hash == base.ja4.hash
  end

  test "unknown IDs are observable, opaque extensions need not be negotiable" do
    {:ok, fp} = SSL.Fingerprint.client_hello(hello([0xFFFF], [0xFFFF]), :quic)
    assert fp.observation.extensions == [{0xFFFF, <<>>}]
    assert fp.ja3.raw == "771,65535,65535,,"

    for {alpn, suffix} <- [{<<0xAB>>, "ab"}, {<<0x30, 0xAB, 0xCD, 0x31>>, "01"}, {"x", "xx"}] do
      {:ok, fp} = SSL.Fingerprint.client_hello(hello(@ciphers, @ids, @sigs, alpn), :tcp)
      assert String.ends_with?(fp.ja4.prefix, suffix)
    end
  end

  test "bounded fragmented observation matches actual emitted ClientHello" do
    [{:Certificate, root, :not_encrypted}] =
      File.read!(Path.expand("../fixtures/server_flight/root.pem", __DIR__))
      |> :public_key.pem_decode()

    {:ok, _, [{:emit, :initial, ch}]} =
      SSL.QUIC.new(:client,
        cacerts: [root],
        reference_identity: {:dns_id, "example.test"},
        alpn: ["test"],
        transport_parameters: <<>>
      )

    {:ok, expected} = SSL.Fingerprint.client_hello(ch, :quic)
    {:ok, observer} = SSL.Fingerprint.new(:quic)

    {_, [actual]} =
      Enum.reduce(:binary.bin_to_list(ch), {observer, []}, fn byte, {state, results} ->
        {:ok, state, out} = SSL.Fingerprint.feed(state, <<byte>>)
        {state, results ++ out}
      end)

    assert actual == expected
    assert {:error, :invalid_transport} = SSL.Fingerprint.client_hello(ch, :udp)
    assert {:error, _} = SSL.Fingerprint.client_hello(<<22, 3, 3, 0>>, :tcp)
    assert {:error, :client_hello_too_large} = SSL.Fingerprint.feed(observer, <<1, 65_536::24>>)

    assert {:error, _} =
             SSL.Fingerprint.client_hello(binary_part(ch, 0, byte_size(ch) - 1), :quic)
  end
end
