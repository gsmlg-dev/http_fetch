defmodule QuicHttp3.QpackTest do
  use ExUnit.Case, async: true

  alias QuicHttp3.Qpack

  import Bitwise, only: [<<<: 2]

  test "static-only sections permit a nonzero nonnegative Base" do
    assert {:ok, [{":status", "200"}]} = Qpack.decode_header_block(<<0, 1, 0xD9>>)
    assert {:error, :dynamic_table_not_supported} = Qpack.decode_header_block(<<0, 0x80, 0xD9>>)
  end

  test "mixed literal, indexed and name-reference fields preserve input order" do
    fields = [
      {"x-test", "a"},
      {"content-length", "0"},
      {"x-test", "b"},
      {"content-type", "custom"},
      {"x-test", "c"}
    ]

    assert {:ok, bytes} = Qpack.encode_header_block(fields, indexed: true)
    assert {:ok, ^fields} = Qpack.decode_header_block(bytes)
  end

  test "all static indexes match RFC 9204 Appendix A independent fixtures" do
    rows =
      File.read!(Path.join(__DIR__, "fixtures/qpack-rfc9204-static.tsv"))
      |> String.split("\n", trim: true)
      |> Enum.reject(&String.starts_with?(&1, "#"))

    assert length(rows) == 99

    for row <- rows do
      [index, name, value] = String.split(row, "\t")
      index = String.to_integer(index)
      assert {:ok, {^name, ^value}} = Qpack.static(index)
      {:ok, encoded} = Qpack.encode_integer(index, 6, 0xC0)
      assert {:ok, [{^name, ^value}]} = Qpack.decode_header_block(<<0, 0>> <> encoded)
    end

    assert {:error, :invalid_static_index} = Qpack.static(99)
  end

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

    assert {:ok, <<0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF>>} =
             Qpack.encode_string("www.example.com", huffman: true)

    assert {:ok, "www.example.com", <<>>} =
             Qpack.decode_string(
               <<0x8C, 0xF1, 0xE3, 0xC2, 0xE5, 0xF2, 0x3A, 0x6B, 0xA0, 0xAB, 0x90, 0xF4, 0xFF>>
             )

    assert {:error, :invalid_huffman_padding} = Qpack.decode_string(<<0x81, 0x00>>)
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

  test "never-indexed retains its flag when a static exact match exists" do
    fields = [{":path", "/"}]

    assert {:ok, <<0, 0, 0x71, 1, ?/>> = bytes} =
             Qpack.encode_header_block(fields, indexed: true, never_indexed: true)

    assert {:ok, ^fields} = Qpack.decode_header_block(bytes)
  end

  test "encodes and decodes static indexed and name-reference fields" do
    assert {:ok, indexed} = Qpack.encode_header_block([{":path", "/"}], indexed: true)
    assert indexed == <<0, 0, 0xC1>>
    assert {:ok, [{":path", "/"}]} = Qpack.decode_header_block(indexed)

    assert {:ok, reference} = Qpack.encode_header_block([{":path", "/custom"}], indexed: true)
    assert {:ok, [{":path", "/custom"}]} = Qpack.decode_header_block(reference)
  end

  test "bounds dynamic table entries and evicts oldest values" do
    table = Qpack.new(capacity: 70)
    assert {:ok, table} = Qpack.insert(table, "x", "one")
    assert table.insert_count == 1
    assert {:ok, table} = Qpack.insert(table, "y", "two")
    assert table.size <= 70
    assert {:ok, empty} = Qpack.insert(table, "large", String.duplicate("v", 100))
    assert empty.entries == []
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
    assert {:error, :invalid_fields} = Qpack.decode_header_block(<<0, 0, 0x28>>)
    assert {:error, :invalid_fields} = Qpack.decode_header_block(<<0, 0, 0x21, "A", 0>>)
    assert {:error, :invalid_fields} = Qpack.encode_header_block([{"x y", "value"}])
    assert {:error, :invalid_fields} = Qpack.encode_header_block([{"é", "value"}])
    assert {:error, :invalid_fields} = Qpack.decode_header_block(<<0, 0, 0x20, 0, 0>>)

    assert {:error, :field_limit} =
             Qpack.decode_header_block(<<0, 0, 0x20, 1, "a", 0>>, max_fields: 0)

    assert {:error, :invalid_field_limit} = Qpack.decode_header_block(<<0, 0>>, max_fields: -1)
  end
end
