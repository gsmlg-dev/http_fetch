defmodule QuicHttp3.StreamTest do
  use ExUnit.Case, async: true

  alias QuicHttp3.Stream

  test "classifies stream id direction and initiator" do
    assert :bidi = Stream.direction(0)
    assert :uni = Stream.direction(2)
    assert :client = Stream.initiator(0)
    assert :server = Stream.initiator(3)
    assert {:ok, :request} = Stream.classify(0, :client)
    assert {:ok, :peer_bidi} = Stream.classify(1, :client)
    assert {:ok, :unidirectional} = Stream.classify(2, :client)
  end

  test "decodes standard HTTP/3 unidirectional stream types incrementally" do
    assert :more = Stream.decode_type(<<0x40>>)
    assert {:ok, :control, "payload"} = Stream.decode_type(<<0x00, "payload">>)
    assert {:ok, {:unknown, 64}, <<>>} = Stream.decode_type(<<0x40, 0x40>>)
  end
end
