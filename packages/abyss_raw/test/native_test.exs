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

  describe "owner messages" do
    setup do
      interface = if match?({:unix, :darwin}, :os.type()), do: "lo0", else: "lo"

      case Native.open(interface, self()) do
        socket when is_reference(socket) ->
          on_exit(fn -> Native.close(socket) end)
          {:ok, socket: socket}

        {:error, reason} ->
          # Port 68 / interface binding needs privileges or platform support
          # (unsupported on FreeBSD); the NIF tests above still run.
          {:ok, skip: reason}
      end
    end

    test "received DHCP datagrams carry the socket returned by open/2", context do
      if socket = context[:socket] do
        {:ok, udp} = :gen_udp.open(0, [:binary])
        :ok = :gen_udp.send(udp, {127, 0, 0, 1}, 68, "dhcp-payload")
        assert_receive {:dhcp_rx, ^socket, "dhcp-payload"}, 2_000
        :gen_udp.close(udp)
      end
    end

    test "the poll thread releases the socket when its owner exits", context do
      if socket = context[:socket] do
        interface = if match?({:unix, :darwin}, :os.type()), do: "lo0", else: "lo"
        Native.close(socket)

        {owner, monitor} = spawn_monitor(fn -> Process.sleep(:infinity) end)
        reopened = Native.open(interface, owner)
        assert is_reference(reopened)
        Process.exit(owner, :kill)
        assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}

        # The thread notices the dead owner within one poll timeout (1 s) and
        # frees port 68; without that the resource would leak until close/1.
        assert eventually(
                 fn ->
                   case Native.open(interface, self()) do
                     socket when is_reference(socket) -> Native.close(socket) == :ok
                     _ -> false
                   end
                 end,
                 4_000
               )

        # The handle stays valid but inert; close/1 on it is still idempotent.
        assert {:error, "socket closed"} = Native.send_broadcast(reopened, <<1>>)
        assert :ok = Native.close(reopened)
      end
    end
  end

  defp eventually(fun, timeout) when timeout > 0 do
    case fun.() do
      true ->
        true

      _ ->
        Process.sleep(100)
        eventually(fun, timeout - 100)
    end
  end

  defp eventually(_fun, _timeout), do: false
end
