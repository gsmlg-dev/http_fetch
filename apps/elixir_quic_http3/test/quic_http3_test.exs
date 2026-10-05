defmodule QuicHttp3Test do
  use ExUnit.Case, async: true

  alias QuicHttp3.{Frame, Qpack, Settings, Varint}

  test "reports the HTTP/3 beta profile and explicit unsupported extensions" do
    assert %{
             alpn: "h3",
             status: :beta,
             http3: true,
             qpack: true,
             qpack_profile: :static_literal,
             qpack_huffman: true,
             dynamic_qpack: false,
             zero_rtt: false,
             connection_migration: false,
             websocket_over_http3: false,
             webtransport: false
           } = QuicHttp3.capabilities()

    assert "h3" == QuicHttp3.alpn()
    assert Quic.capabilities().http3 == false
  end

  test "reported QPACK profile supports static and Huffman literal fields without dynamic references" do
    fields = [{":status", "200"}, {"x-profile", "static and literal"}]
    assert {:ok, encoded} = Qpack.encode_header_block(fields, indexed: true, huffman: true)
    assert {:ok, ^fields} = Qpack.decode_header_block(encoded)
    assert {:error, :dynamic_table_not_supported} = Qpack.decode_header_block(<<0, 0x80, 0xD9>>)
  end

  test "exposes the existing frame codec through the new application boundary" do
    encoded = Frame.encode!(:data, "body")

    assert {:ok, %HTTP.H3.Frame{type: 0, payload: "body"}, <<>>} = Frame.decode(encoded)
  end

  test "exposes settings and varint codecs without duplicating implementations" do
    assert {:ok, <<51, 1>>} = Settings.encode(h3_datagram: 1)
    assert {:ok, 37, "rest"} = Varint.decode(<<0x40, 0x25, "rest">>)
  end
end
