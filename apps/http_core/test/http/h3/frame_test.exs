defmodule HTTP.H3.FrameTest do
  use ExUnit.Case, async: true

  alias HTTP.H3.Frame

  test "encodes and decodes DATA frames" do
    assert {:ok, <<0x00, 0x05, "hello">>} = Frame.encode(:data, "hello")

    assert {:ok, %Frame{type: type, payload: "hello"}, "tail"} =
             Frame.decode(<<0x00, 0x05, "hello", "tail">>)

    assert type == Frame.data()
    assert Frame.name(type) == :data
  end

  test "encodes extension frame types with QUIC varints" do
    assert {:ok, <<0x40, 0x41, 0x00>>} = Frame.encode(:wt_stream, "")
    assert {:ok, %Frame{type: type, payload: ""}, <<>>} = Frame.decode(<<0x40, 0x41, 0x00>>)
    assert type == Frame.wt_stream()
  end

  test "reports incomplete frame headers or payloads as needing more data" do
    assert :more = Frame.decode(<<>>)
    assert :more = Frame.decode(<<0x00>>)
    assert :more = Frame.decode(<<0x00, 0x05, "hel">>)
  end

  test "rejects invalid frame inputs" do
    assert {:error, :unknown_frame_type} = Frame.encode(:unknown, "")
    assert {:error, :invalid_frame_payload} = Frame.encode(:data, ["not", "binary"])
  end
end
