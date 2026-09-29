defmodule QuicHttp3.QpackTest do
  use ExUnit.Case, async: true

  alias QuicHttp3.Qpack

  import Bitwise, only: [<<<: 2]

  test "encodes and decodes prefixed integers with continuation bytes" do
    assert {:ok, <<0x1F, 0xFB, 0x0B>>} = Qpack.encode_integer(1_562, 5, 0)
    assert {:ok, 1_562, <<>>} = Qpack.decode_integer(<<0x1F, 0xFB, 0x0B>>, 5)
    assert :more = Qpack.decode_integer(<<0x1F, 0xFB>>, 5)
  end

  test "handles prefixed integer boundaries and overflow" do
    for value <- [0, 30, 31, 255, 256, (1 <<< 62) - 1] do
      assert {:ok, encoded} = Qpack.encode_integer(value, 5, 0)
      assert {:ok, ^value, <<>>} = Qpack.decode_integer(encoded, 5)
    end

    assert {:error, :integer_overflow} =
             Qpack.decode_integer(
               <<0x1F, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x40>>,
               5
             )

    assert {:error, :invalid_integer_prefix} = Qpack.decode_integer(<<>>, 0)
  end

  test "encodes and decodes raw strings" do
    assert {:ok, <<3, "abc">>} = Qpack.encode_string("abc")
    assert {:ok, "abc", <<>>} = Qpack.decode_string(<<3, "abc">>)
    assert {:error, :huffman_not_supported} = Qpack.decode_string(<<0x83, "abc">>)
  end

  test "round-trips literal-name header fields without a dynamic table" do
    fields = [{":method", "GET"}, {":path", "/"}, {"x-test", "value"}]

    assert {:ok, encoded} = Qpack.encode_header_block(fields)
    assert {:ok, ^fields} = Qpack.decode_header_block(encoded)
  end

  test "supports the never-indexed literal form" do
    fields = [{"authorization", "secret"}]

    assert {:ok, encoded} = Qpack.encode_header_block(fields, never_indexed: true)
    assert {:ok, ^fields} = Qpack.decode_header_block(encoded)
  end

  test "rejects dynamic-table and indexed representations for this slice" do
    assert {:error, :dynamic_table_not_supported} =
             Qpack.decode_header_block(<<1, 0>>)

    assert {:error, :indexed_field_not_supported} =
             Qpack.decode_header_block(<<0, 0, 0x80>>)
  end

  test "returns more for partial header blocks and strings" do
    assert :more = Qpack.decode_header_block(<<0>>)
    assert :more = Qpack.decode_header_block(<<0, 0, 0x21, "a", 3, "ab">>)
    assert :more = Qpack.decode_string(<<3, "ab">>)
  end

  test "rejects unsupported, invalid, and oversized fields deterministically" do
    assert {:error, :huffman_not_supported} = Qpack.decode_header_block(<<0, 0, 0x28>>)
    assert {:error, :invalid_fields} = Qpack.decode_header_block(<<0, 0, 0x21, "A", 0>>)
    assert {:error, :invalid_fields} = Qpack.encode_header_block([{"x y", "value"}])
    assert {:error, :invalid_fields} = Qpack.encode_header_block([{"é", "value"}])
    assert {:error, :invalid_fields} = Qpack.decode_header_block(<<0, 0, 0x20, 0, 0>>)

    assert {:error, :field_limit} =
             Qpack.decode_header_block(<<0, 0, 0x20, 1, "a", 0>>, max_fields: 0)

    assert {:error, :invalid_field_limit} = Qpack.decode_header_block(<<0, 0>>, max_fields: -1)
  end
end
