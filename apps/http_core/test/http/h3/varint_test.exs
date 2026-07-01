defmodule HTTP.H3.VarintTest do
  use ExUnit.Case, async: true

  alias HTTP.H3.Varint

  test "encodes shortest QUIC variable-length integers" do
    assert {:ok, <<0x00>>} = Varint.encode(0)
    assert {:ok, <<0x3F>>} = Varint.encode(63)
    assert {:ok, <<0x40, 0x40>>} = Varint.encode(64)
    assert {:ok, <<0x7F, 0xFF>>} = Varint.encode(16_383)
    assert {:ok, <<0x80, 0x00, 0x40, 0x00>>} = Varint.encode(16_384)
    assert {:ok, <<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>} = Varint.encode(Varint.max())
  end

  test "encodes with a caller-selected length when the value fits" do
    assert {:ok, <<0x40, 0x25>>} = Varint.encode(37, 2)
    assert {:ok, <<0x80, 0x00, 0x00, 0x25>>} = Varint.encode(37, 4)
    assert {:error, :varint_value_too_large} = Varint.encode(64, 1)
    assert {:error, :invalid_varint_length} = Varint.encode(37, 3)
  end

  test "rejects values outside the QUIC varint range" do
    assert {:error, :invalid_varint} = Varint.encode(-1)
    assert {:error, :invalid_varint} = Varint.encode(Varint.max() + 1)
  end

  test "decodes one value and returns the unread tail" do
    max = Varint.max()

    assert {:ok, 37, "rest"} = Varint.decode(<<0x40, 0x25, "rest">>)

    assert {:ok, ^max, <<>>} =
             Varint.decode(<<0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF>>)
  end

  test "reports incomplete encodings as needing more data" do
    assert :more = Varint.decode(<<>>)
    assert :more = Varint.decode(<<0x40>>)
    assert :more = Varint.decode(<<0x80, 0x00, 0x00>>)
  end
end
