defmodule Quic.InspectorTest do
  use ExUnit.Case, async: true

  alias Quic.Inspector
  import Bitwise
  alias Quic.{Codec, Protection}

  @hello Base.decode16!(
           "0100008B03030000000000000000000000000000000000000000000000000000000000000000000002130201000060002B0003020304000A00040002001D003300260024001D00208520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A000D0004000204030010000E000C02683208687474702F312E3100050005010000000000120000",
           case: :mixed
         )

  defp datagram(bytes, at \\ 0),
    do: %{bytes: bytes, remote: {:local, 1}, generation: 1, received_at: at}

  defp generated_client_hello do
    options = [
      cacerts: :public_key.cacerts_get(),
      reference_identity: {:dns_id, "example.test"},
      alpn: ["test"],
      transport_parameters: <<>>
    ]

    assert {:ok, _tls, [{:emit, :initial, hello}]} = SSL.QUIC.new(:client, options)
    dcid = <<0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08>>
    scid = <<1, 2, 3, 4>>
    {hello, dcid, scid}
  end

  defp encrypted_initial(hello_override \\ nil, pn \\ <<0, 0>>) do
    {generated, dcid, scid} = generated_client_hello()
    hello = hello_override || generated
    assert {:ok, plaintext} = Quic.Codec.encode_frames([%{type: :crypto, offset: 0, data: hello}])
    assert {:ok, keys} = Quic.Protection.initial_secrets(dcid, :client)
    {:ok, length} = Quic.Codec.encode_varint(byte_size(pn) + byte_size(plaintext) + 16)

    header =
      <<0xC1, 1::32, byte_size(dcid), dcid::binary, byte_size(scid), scid::binary, 0,
        length::binary>>

    assert {:ok, ciphertext} =
             Quic.Protection.aead_encrypt(
               keys.key,
               keys.iv,
               :binary.decode_unsigned(pn),
               header <> pn,
               plaintext
             )

    packet = header <> pn <> ciphertext
    sample = binary_part(packet, byte_size(header) + 4, 16)
    assert {:ok, mask} = Quic.Protection.header_protection_mask(keys.hp, sample, :aes_128_gcm)

    masked_pn =
      for {byte, index} <- Enum.with_index(:binary.bin_to_list(pn)),
          into: <<>>,
          do: <<bxor(byte, :binary.at(mask, index + 1))>>

    protected_first = bxor(0xC1, :binary.at(mask, 0) &&& 0x0F)

    protected =
      <<protected_first, binary_part(header, 1, byte_size(header) - 1)::binary, masked_pn::binary,
        ciphertext::binary>>

    {protected, hello}
  end

  test "rejects unsupported versions and malformed short input without effects" do
    assert {:ok, inspector} = Inspector.new()

    assert {:error, :unsupported_version, ^inspector} =
             Inspector.ingest(inspector, datagram(<<0xC0, 0, 0, 0, 2>>))

    assert {:error, :truncated_header, ^inspector} = Inspector.ingest(inspector, datagram(<<>>))
  end

  test "initial type is distinguished from another long header" do
    assert {:ok, inspector} = Inspector.new()
    packet = <<0xD0, 0, 0, 0, 1, 0, 0, 0, 0>>
    assert {:error, :not_initial, ^inspector} = Inspector.ingest(inspector, datagram(packet))
  end

  test "limits are explicit and passive" do
    assert {:ok, inspector} = Inspector.new(max_datagram: 4)

    assert {:error, :resource_limited, ^inspector} =
             Inspector.ingest(inspector, datagram(<<1, 2, 3, 4, 5>>))
  end

  test "decrypts an Initial and emits one ClientHello fingerprint observation" do
    {packet, hello} = encrypted_initial()
    assert {:ok, inspector} = Inspector.new()

    assert {:ok, _next,
            [
              %{
                outcome: :complete,
                hello_bytes: ^hello,
                fingerprint: fingerprint,
                provenance: provenance
              }
            ]} =
             Inspector.ingest(inspector, datagram(packet))

    assert fingerprint.transport == :quic
    assert provenance.packet_number == 0
    assert provenance.key_context != nil
  end

  test "decrypts a fixed encrypted Initial and emits one observation" do
    dcid = <<0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08>>
    scid = <<1, 2, 3, 4, 5, 6, 7, 8>>
    {:ok, frame} = Codec.encode_frames([%{type: :crypto, offset: 0, data: @hello}])
    plaintext = frame <> :binary.copy(<<1>>, 32)
    {:ok, keys} = Protection.initial_secrets(dcid, :server)
    pn = <<0, 0, 0, 0>>
    {:ok, token_len} = Codec.encode_varint(0)
    {:ok, length} = Codec.encode_varint(4 + byte_size(plaintext) + 16)

    header =
      <<0xC3, 0, 0, 0, 1, byte_size(dcid), dcid::binary, byte_size(scid), scid::binary,
        token_len::binary, length::binary>>

    {:ok, ciphertext} = Protection.aead_encrypt(keys.key, keys.iv, 0, header <> pn, plaintext)
    raw = header <> pn <> ciphertext

    {:ok, mask} =
      Protection.header_protection_mask(
        keys.hp,
        binary_part(raw, byte_size(header) + 4, 16),
        :aes_128_gcm
      )

    <<first, _rest::binary-size(3), _tail::binary>> = raw
    first = Bitwise.bxor(first, Bitwise.band(:binary.at(mask, 0), 0x0F))

    pn_protected =
      for {b, i} <- Enum.with_index(:binary.bin_to_list(pn)),
          into: <<>>,
          do: <<Bitwise.bxor(b, :binary.at(mask, i + 1))>>

    protected =
      <<first, binary_part(header, 1, byte_size(header) - 1)::binary, pn_protected::binary,
        ciphertext::binary>>

    assert {:ok, inspector} = Inspector.new()

    assert {:ok, _state, [%{outcome: :complete, hello_bytes: @hello} = event]} =
             Inspector.ingest(inspector, datagram(protected))

    assert event.provenance.packet_number == 0
  end

  test "replays an independent aioquic Initial and suppresses retransmission duplicates" do
    hex =
      File.read!(Path.expand("../fixtures/initial/aioquic_1_2_0_initial.hex", __DIR__))
      |> String.trim()

    packet = Base.decode16!(hex, case: :lower)
    assert {:ok, inspector} = Inspector.new()

    assert {:ok, next, [%{outcome: :complete, fingerprint: %{transport: :quic}}]} =
             Inspector.ingest(inspector, datagram(packet))

    assert {:ok, _same, []} = Inspector.ingest(next, datagram(packet))
  end

  test "reports incomplete ClientHello once, then completes after retransmitted bytes" do
    {_full_packet, hello} = encrypted_initial()
    partial = binary_part(hello, 0, 24)
    {partial_packet, _} = encrypted_initial(partial)
    assert {:ok, inspector} = Inspector.new()

    assert {:ok, next, [%{outcome: :incomplete}]} =
             Inspector.ingest(inspector, datagram(partial_packet))

    assert {:ok, same, []} = Inspector.ingest(next, datagram(partial_packet))

    assert {:ok, _done, [%{outcome: :complete, hello_bytes: ^hello}]} =
             Inspector.ingest(same, datagram(encrypted_initial(hello, <<0, 1>>) |> elem(0), 1))
  end

  test "expires old contexts and rejects conflicting CRYPTO overlap" do
    {packet, hello} = encrypted_initial()

    altered =
      :binary.part(hello, 0, 5) <>
        <<Bitwise.bxor(:binary.at(hello, 5), 1)>> <> binary_part(hello, 6, byte_size(hello) - 6)

    {conflict, _} = encrypted_initial(altered, <<0, 1>>)
    assert {:ok, inspector} = Inspector.new(expiry: 1)
    assert {:ok, next, [%{outcome: :complete}]} = Inspector.ingest(inspector, datagram(packet, 0))
    assert {:error, :conflicting_overlap, ^next} = Inspector.ingest(next, datagram(conflict, 0))
    assert {:ok, _fresh, [%{outcome: :complete}]} = Inspector.ingest(next, datagram(packet, 2))
  end

  test "emits separate ordinals for two ClientHello messages in one CRYPTO stream" do
    {_, first} = encrypted_initial()
    {_, second} = encrypted_initial()
    {packet, _} = encrypted_initial(<<first::binary, second::binary>>)
    assert {:ok, inspector} = Inspector.new()
    assert {:ok, _next, events} = Inspector.ingest(inspector, datagram(packet))

    assert [%{outcome: :complete, hello_ordinal: 1}, %{outcome: :complete, hello_ordinal: 2}] =
             events
  end
end
