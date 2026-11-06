defmodule AbyssDhcpSocket.NativeTest do
  use ExUnit.Case, async: true

  alias AbyssDhcpSocket.Native

  test "NIF is loaded and interface failures retain their error return" do
    assert {:error, message} = Native.open("abyss-no-iface", self())
    assert is_binary(message)
    assert message =~ "abyss-no-iface"
  end

  test "invalid interface names return an error without starting a poll thread" do
    assert {:error, "invalid interface name: " <> _} = Native.open("bad" <> <<0>>, self())
  end

  test "native argument validation preserves badarg semantics" do
    assert_raise ArgumentError, fn -> Native.open(:invalid, self()) end
    assert_raise ArgumentError, fn -> Native.open("abyss-no-iface", :invalid) end

    for call <- [
          fn -> Native.send_broadcast(make_ref(), <<1>>) end,
          fn -> Native.send_unicast(make_ref(), {127, 0, 0, 1}, <<1>>) end,
          fn -> Native.send_arp_probe(make_ref(), {127, 0, 0, 1}) end,
          fn -> Native.close(make_ref()) end
        ] do
      assert_raise ArgumentError, call
    end
  end
end
