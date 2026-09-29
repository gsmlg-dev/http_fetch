defmodule QuicHttp3Test do
  use ExUnit.Case, async: true

  alias QuicHttp3.{Frame, Settings, Varint}

  test "publishes HTTP/3 protocol identity without claiming incomplete features" do
    assert %{alpn: "h3", http3: false, qpack: false, webtransport: false} =
             QuicHttp3.capabilities()

    assert "h3" == QuicHttp3.alpn()
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
