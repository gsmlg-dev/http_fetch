defmodule HTTP.HTTP2HPACKProductionTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.HPACK

  test "serializes the smallest and final table sizes before the next field" do
    encoder = HPACK.new_encoder()
    encoder = HPACK.set_max_dynamic_size(encoder, 128)
    encoder = HPACK.set_max_dynamic_size(encoder, 256)

    {encoder, block} = HPACK.encode_headers(encoder, [{":method", "GET"}], indexing: :incremental)
    assert block == <<0x3F, 0x61, 0x3F, 0xE1, 0x01, 0x82>>
    assert {:ok, _, [{":method", "GET"}]} = HPACK.decode(HPACK.new_decoder(), block)

    assert {_encoder, <<0x82>>} =
             HPACK.encode_headers(encoder, [{":method", "GET"}], indexing: :incremental)
  end

  test "emits a pending size update even for an empty block" do
    encoder = HPACK.new_encoder() |> HPACK.set_max_dynamic_size(0)
    {_encoder, block} = HPACK.encode_headers(encoder, [])
    assert block == <<0x20>>
  end

  test "does not emit a size update when the advertised maximum is unchanged" do
    encoder = HPACK.new_encoder() |> HPACK.set_max_dynamic_size(4096)

    assert {_encoder, <<0x82>>} =
             HPACK.encode_headers(encoder, [{":method", "GET"}], indexing: :incremental)
  end

  test "rejects table size updates after a field" do
    assert {:error, :invalid_dynamic_table_size_update} =
             HPACK.decode(HPACK.new_decoder(), <<0x82, 0x20>>)
  end

  test "rejects fields without a required shrink update" do
    decoder = HPACK.new_decoder() |> HPACK.set_max_dynamic_size(128)
    assert {:error, :missing_dynamic_table_size_update} = HPACK.decode(decoder, <<0x82>>)
    assert {:ok, _, [{":method", "GET"}]} = HPACK.decode(decoder, <<0x3F, 0x61, 0x82>>)

    decoder = decoder |> HPACK.set_max_dynamic_size(64) |> HPACK.set_max_dynamic_size(256)

    assert {:error, :invalid_dynamic_table_size_update} =
             HPACK.decode(decoder, <<0x3F, 0xE1, 0x01, 0x82>>)

    assert {:ok, _, [{":method", "GET"}]} =
             HPACK.decode(decoder, <<0x3F, 0x21, 0x3F, 0xE1, 0x01, 0x82>>)
  end

  test "accepts an unchanged peer table after an acknowledged limit remains above it" do
    assert {:ok, decoder, [{":method", "GET"}]} =
             HPACK.decode(HPACK.new_decoder(), <<0x3F, 0xE1, 0x03, 0x82>>)

    assert decoder.table_size == 512
    decoder = HPACK.acknowledge_max_dynamic_size(decoder, 1024)

    assert {:ok, decoder, [{":method", "GET"}]} = HPACK.decode(decoder, <<0x82>>)
    assert decoder.table_size == 512
  end

  test "bounds compressed, expanded and counted fields during decode" do
    assert {:error, :hpack_block_too_large} =
             HPACK.decode(HPACK.new_decoder(max_block_bytes: 1), <<0x82, 0x82>>)

    assert {:error, :hpack_field_count_exceeded} =
             HPACK.decode(HPACK.new_decoder(max_fields: 1), <<0x82, 0x82>>)

    assert {:error, :hpack_decoded_bytes_exceeded} =
             HPACK.decode(HPACK.new_decoder(max_decoded_bytes: 9), <<0x82, 0x82>>)

    # RFC 7541 C.4.1 Huffman-coded www.example.com expands from 12 to 15 bytes.
    huffman =
      <<0x00, 0x01, ?x, 0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4,
        0xFF>>

    assert {:error, :hpack_decoded_bytes_exceeded} =
             HPACK.decode(HPACK.new_decoder(max_decoded_bytes: 15), huffman)
  end

  test "rejects overlong integers and truncated Huffman input" do
    assert {:error, :hpack_integer_too_large} =
             HPACK.decode(
               HPACK.new_decoder(),
               <<0xFF, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00>>
             )

    assert {:error, :truncated_hpack_string} =
             HPACK.decode(HPACK.new_decoder(), <<0x00, 0x01, ?x, 0x82, 0xFF>>)
  end
end
