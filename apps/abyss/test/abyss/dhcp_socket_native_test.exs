defmodule Abyss.DhcpSocket.NativeTest do
  use ExUnit.Case, async: true

  @moduletag :integration

  @facade Path.expand("../../lib/abyss/dhcp_socket/native.ex", __DIR__)

  test "all operations identify the missing optional package" do
    in_vm("""
    socket = make_ref()

    for {function, arguments} <- [
          {:open, ["abyss-no-iface", self()]},
          {:send_broadcast, [socket, <<1>>]},
          {:send_unicast, [socket, {127, 0, 0, 1}, <<1>>]},
          {:send_arp_probe, [socket, {127, 0, 0, 1}]},
          {:close, [socket]}
        ] do
      assert {:error, {:missing_optional_dependency, :abyss_raw}} ==
               apply(Abyss.DhcpSocket.Native, function, arguments)
    end
    """)
  end

  @tag :tmp_dir
  test "a module that fails on load is distinguished from an absent package", %{tmp_dir: tmp_dir} do
    in_vm("""
    [{module, binary}] = Code.compile_string(~S'''
    defmodule AbyssDhcpSocket.Native do
      @on_load :load
      def load, do: :error
      def open(_interface, _owner), do: :unreachable
    end
    ''')

    beam = Path.join(#{inspect(tmp_dir)}, Atom.to_string(module) <> ".beam")
    File.write!(beam, binary)
    Code.prepend_path(#{inspect(tmp_dir)})

    assert {:error, {:optional_dependency_load_failed, :abyss_raw, :on_load_failure}} ==
             Abyss.DhcpSocket.Native.open("abyss-no-iface", self())
    """)
  end

  test "the compatibility facade preserves arguments, operation returns and exceptions" do
    in_vm("""
    defmodule AbyssDhcpSocket.Native do
      def open(interface, owner) do
        socket = make_ref()
        send(owner, {:opened, interface, socket})
        socket
      end

      def send_broadcast(socket, packet) do
        send(self(), {:broadcast, socket, packet})
        :ok
      end

      def send_unicast(socket, destination, packet) do
        send(self(), {:unicast, socket, destination, packet})
        {:error, "socket closed"}
      end

      def send_arp_probe(socket, target) do
        send(self(), {:arp_probe, socket, target})
        {:error, "ARP socket not available"}
      end

      def close(:invalid), do: raise(ArgumentError, "invalid resource")
      def close(_socket), do: :ok
    end

    alias Abyss.DhcpSocket.Native
    socket = Native.open("fixture0", self())
    assert_receive {:opened, "fixture0", ^socket}
    assert is_reference(socket)
    assert :ok = Native.send_broadcast(socket, <<1, 2>>)
    assert_receive {:broadcast, ^socket, <<1, 2>>}
    assert {:error, "socket closed"} = Native.send_unicast(socket, {10, 0, 0, 1}, <<3>>)
    assert_receive {:unicast, ^socket, {10, 0, 0, 1}, <<3>>}
    assert {:error, "ARP socket not available"} = Native.send_arp_probe(socket, {10, 0, 0, 2})
    assert_receive {:arp_probe, ^socket, {10, 0, 0, 2}}
    assert :ok = Native.close(socket)
    assert :ok = Native.close(socket)
    assert_raise ArgumentError, "invalid resource", fn -> Native.close(:invalid) end
    """)
  end

  defp in_vm(source) do
    script = """
    ExUnit.start(autorun: false)
    import ExUnit.Assertions
    Code.require_file(#{inspect(@facade)})
    #{source}
    """

    {output, status} =
      System.cmd(System.find_executable("elixir"), ["--erl", "+S 2:2", "-e", script],
        stderr_to_stdout: true,
        env: [{"ERL_LIBS", nil}, {"ELIXIR_ERL_OPTIONS", nil}]
      )

    assert status == 0, output
  end
end
