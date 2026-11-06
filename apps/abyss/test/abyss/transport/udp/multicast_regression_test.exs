defmodule Abyss.Transport.UDP.MulticastRegressionTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  if :os.type() != {:unix, :linux} do
    @moduletag skip:
                 "Linux reference socket/interface tests; use the portable client and prepared platform matrix"
  end

  alias Abyss.Transport.UDP.Multicast

  test "canonical IPv4 and IPv6 memberships and nonexistent interfaces" do
    assert {:ok, {{239, 255, 42, 1}, {127, 0, 0, 1}}} =
             Multicast.normalize_membership({{239, 255, 42, 1}, "lo"})

    assert {:ok, {{65_282, 0, 0, 0, 0, 0, 0, 42}, 1}} =
             Multicast.normalize_membership({{65_282, 0, 0, 0, 0, 0, 0, 42}, "lo"})

    assert {:error, :enodev} =
             Multicast.normalize_membership({{239, 255, 42, 1}, "abyss-missing"})

    assert {:error, {:invalid_multicast_group, {127, 0, 0, 1}}} =
             Multicast.normalize_membership({{127, 0, 0, 1}, :any})
  end

  test "family mismatch and IPv6 broadcast are explicit failures" do
    assert {:error, {:invalid_membership_interface, :inet6, {127, 0, 0, 1}}} =
             Multicast.normalize_membership({{65_282, 0, 0, 0, 0, 0, 0, 42}, {127, 0, 0, 1}})

    assert {:error, {:invalid_option, :broadcast, :ipv6}} =
             Multicast.open(0, [:inet6, {:broadcast, true}])
  end

  test "strict filtering is explicitly limited to Linux IPv4 inet backend" do
    assert {:error, {:unsupported_capability, :strict_group_filter, :inet6, :inet}} =
             Multicast.open(0, [:inet6, {:strict_group_filter, true}])

    assert {:error, {:unsupported_capability, :strict_group_filter, :inet, :socket}} =
             Multicast.open(0, [{:inet_backend, :socket}, {:strict_group_filter, true}])
  end

  test "identical canonical startup memberships are idempotent after name resolution" do
    assert {:ok, socket} =
             Multicast.open(0, [
               {:add_membership, {{239, 255, 42, 41}, "lo"}},
               {:add_membership, {{239, 255, 42, 41}, {127, 0, 0, 1}}}
             ])

    Multicast.close(socket)
  end

  test "strict IPv4 filtering isolates two groups on one port and leave/rejoin works" do
    first = {239, 255, 42, 51}
    second = {239, 255, 42, 52}

    {:ok, receiver1} =
      Multicast.open(0,
        strict_group_filter: true,
        add_membership: {first, {127, 0, 0, 1}}
      )

    {:ok, {_, port}} = Multicast.sockname(receiver1)

    {:ok, receiver2} =
      Multicast.open(port,
        strict_group_filter: true,
        add_membership: {second, {127, 0, 0, 1}}
      )

    try do
      assert :ok = Abyss.Client.broadcast(first, port, "first-epoch", source: {127, 0, 0, 1})
      assert {:ok, {_, _, "first-epoch"}} = Multicast.recv(receiver1, 0, 1000)
      assert {:error, :timeout} = Multicast.recv(receiver2, 0, 10)
      assert :ok = Abyss.Client.broadcast(second, port, "second-epoch", source: {127, 0, 0, 1})
      assert {:ok, {_, _, "second-epoch"}} = Multicast.recv(receiver2, 0, 1000)
      assert {:error, :timeout} = Multicast.recv(receiver1, 0, 10)
      assert :ok = Multicast.leave(receiver1, {first, {127, 0, 0, 1}})
      assert :ok = Abyss.Client.broadcast(first, port, "left-epoch", source: {127, 0, 0, 1})
      assert {:error, :timeout} = Multicast.recv(receiver1, 0, 10)
      assert :ok = Multicast.join(receiver1, {first, {127, 0, 0, 1}})
      assert :ok = Abyss.Client.broadcast(first, port, "rejoined-epoch", source: {127, 0, 0, 1})
      assert {:ok, {_, _, "rejoined-epoch"}} = Multicast.recv(receiver1, 0, 1000)
    after
      Multicast.close(receiver1)
      Multicast.close(receiver2)
    end
  end

  test "failed startup closes temporary resources" do
    before =
      Enum.filter(Port.list(), &(:erlang.port_info(&1, :connected) == {:connected, self()}))
      |> Enum.sort()

    assert {:error, _} =
             Multicast.open(0, [
               {:add_membership, {{239, 255, 42, 53}, {127, 0, 0, 1}}},
               {:bind_to_device, "abyss-missing"}
             ])

    after_ports =
      Enum.filter(Port.list(), &(:erlang.port_info(&1, :connected) == {:connected, self()}))
      |> Enum.sort()

    assert before == after_ports
  end

  test "every IPv6 startup group is actually joined despite OTP scalar option merging" do
    first = {0xFF02, 0, 0, 0, 0, 0, 0, 0xAA74}
    second = {0xFF02, 0, 0, 0, 0, 0, 0, 0xAA75}

    {:ok, socket} =
      Multicast.open(0, [
        :inet6,
        {:add_membership, {first, "lo"}},
        {:add_membership, {second, "lo"}}
      ])

    try do
      groups = File.read!("/proc/net/igmp6")
      assert groups =~ "ff02000000000000000000000000aa74"
      assert groups =~ "ff02000000000000000000000000aa75"
      assert :ok = Multicast.leave(socket, {first, "lo"})
      assert :ok = Multicast.leave(socket, {second, "lo"})
    after
      Multicast.close(socket)
    end
  end

  test "IPv6 hop and loop options affect the IPv6 kernel options on both backends" do
    for backend <- [:inet, :socket] do
      {:ok, socket} =
        Multicast.open(0, [
          {:inet_backend, backend},
          :inet6,
          {:multicast_if, 1},
          {:multicast_ttl, 7},
          {:multicast_loop, false}
        ])

      try do
        assert {:ok, raw} = Multicast.getopts(socket, [{:raw, 41, 18, 4}, {:raw, 41, 19, 4}])

        values =
          Enum.map(raw, fn
            {:raw, 41, _, value} -> value
            {{:raw, 41, _, 4}, value} -> value
          end)

        assert values == [<<7::native-32>>, <<0::native-32>>]
        assert {:ok, [multicast_if: 1]} = Multicast.getopts(socket, [:multicast_if])
        assert :ok = Multicast.setopts(socket, multicast_ttl: 3, multicast_loop: true)

        assert {:ok, [multicast_ttl: 3, multicast_loop: true]} =
                 Multicast.getopts(socket, [:multicast_ttl, :multicast_loop])
      after
        Multicast.close(socket)
      end
    end
  end

  test "socket backend startup memberships use the actual IPv4 and IPv6 kernel ABIs" do
    {:ok, receiver} =
      Multicast.open(0, [
        {:inet_backend, :socket},
        {:add_membership, {{239, 255, 42, 71}, {127, 0, 0, 1}}}
      ])

    try do
      {:ok, {_, port}} = Multicast.sockname(receiver)

      assert :ok =
               Abyss.Client.broadcast({239, 255, 42, 71}, port, "socket-membership",
                 source: {127, 0, 0, 1}
               )

      assert {:ok, {_, _, "socket-membership"}} = Multicast.recv(receiver, 0, 1000)
      assert :ok = Multicast.leave(receiver, {{239, 255, 42, 71}, {127, 0, 0, 1}})
    after
      Multicast.close(receiver)
    end

    first = {0xFF02, 0, 0, 0, 0, 0, 0, 0xBB74}
    second = {0xFF02, 0, 0, 0, 0, 0, 0, 0xBB75}

    {:ok, receiver6} =
      Multicast.open(0, [
        {:inet_backend, :socket},
        :inet6,
        {:add_membership, {first, "lo"}},
        {:add_membership, {second, "lo"}}
      ])

    try do
      groups = File.read!("/proc/net/igmp6")
      assert groups =~ "ff02000000000000000000000000bb74"
      assert groups =~ "ff02000000000000000000000000bb75"
      assert :ok = Multicast.leave(receiver6, {first, "lo"})
      assert :ok = Multicast.leave(receiver6, {second, "lo"})
    after
      Multicast.close(receiver6)
    end
  end

  test "Linux socket backend IPv4 multicast controls reach the kernel and retain public getters" do
    {:ok, socket} =
      Multicast.open(0, [
        {:inet_backend, :socket},
        {:multicast_if, {127, 0, 0, 1}},
        {:multicast_ttl, 7},
        {:multicast_loop, false}
      ])

    try do
      assert {:ok, values} =
               Multicast.getopts(socket, [{:raw, 0, 32, 4}, {:raw, 0, 33, 4}, {:raw, 0, 34, 4}])

      assert Enum.map(values, fn {{:raw, 0, _, 4}, value} -> value end) ==
               [<<127, 0, 0, 1>>, <<7::native-32>>, <<0::native-32>>]

      assert {:ok, [multicast_if: {127, 0, 0, 1}, multicast_ttl: 7, multicast_loop: false]} =
               Multicast.getopts(socket, [:multicast_if, :multicast_ttl, :multicast_loop])

      assert :ok = Multicast.setopts(socket, multicast_ttl: 3, multicast_loop: true)

      assert {:ok, [multicast_ttl: 3, multicast_loop: true]} =
               Multicast.getopts(socket, [:multicast_ttl, :multicast_loop])
    after
      Multicast.close(socket)
    end
  end

  test "scoped socket-backend sockaddr sends return a capability error and clients close resources" do
    before_sockets = :socket.which_sockets() |> Enum.sort()
    {:ok, socket} = Multicast.open(0, [{:inet_backend, :socket}, :inet6])

    try do
      destination = %{family: :inet6, addr: {0, 0, 0, 0, 0, 0, 0, 1}, port: 49_000, scope_id: 1}

      assert {:error, {:unsupported_capability, :scoped_sockaddr_send, :socket}} =
               Multicast.send(socket, destination, "scoped")

      assert {:error, {:unsupported_capability, :scoped_sockaddr_send, :socket}} =
               Abyss.Client.multicast_query({0xFF02, 0, 0, 0, 0, 0, 0, 42}, 49_000, "scoped", 0,
                 interface: "lo",
                 inet_backend: :socket
               )
    after
      Multicast.close(socket)
    end

    assert Enum.sort(:socket.which_sockets()) == before_sockets
  end

  test "partial membership startup failure removes actual joined groups and temporary sockets" do
    first = {0xFF02, 0, 0, 0, 0, 0, 0, 0xCC74}
    absent = {0xFF02, 0, 0, 0, 0, 0, 0, 0xCC75}
    refute File.read!("/proc/net/igmp6") =~ "ff02000000000000000000000000cc74"
    before_sockets = :socket.which_sockets() |> Enum.sort()
    before_ports = Enum.sort(Port.list())

    assert {:error, {:membership_failed, {:drop_membership, {^absent, 1}}, :eaddrnotavail}} =
             Multicast.open(0, [
               {:inet_backend, :socket},
               :inet6,
               {:add_membership, {first, "lo"}},
               {:drop_membership, {absent, "lo"}}
             ])

    refute File.read!("/proc/net/igmp6") =~ "ff02000000000000000000000000cc74"
    assert Enum.sort(:socket.which_sockets()) == before_sockets
    assert Enum.sort(Port.list()) == before_ports
  end
end
