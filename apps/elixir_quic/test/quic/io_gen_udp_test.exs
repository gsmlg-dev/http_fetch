defmodule Quic.IO.GenUDPTest do
  use ExUnit.Case, async: true

  alias Quic.IO.GenUDP

  test "loopback reports local completion and requires consumption credit" do
    {:ok, receiver} = GenUDP.open(ip: {127, 0, 0, 1}, role: :server)
    {:ok, sender} = GenUDP.open(ip: {127, 0, 0, 1}, role: :client)

    on_exit(fn ->
      close_if_alive(sender)
      close_if_alive(receiver)
    end)

    receiver_addr = GenUDP.local(receiver)
    before_send = GenUDP.monotonic_time()
    assert {:ok, completed_at} = GenUDP.send(sender, "ping", receiver_addr)
    assert completed_at >= before_send
    assert completed_at <= GenUDP.monotonic_time()

    assert_receive {:quic_udp, generation, credit, {{127, 0, 0, 1}, _}, "ping", timestamp}, 1_000
    assert is_integer(timestamp)
    assert {:ok, _} = GenUDP.send(sender, "second", receiver_addr)
    refute_receive {:quic_udp, _, _, _, "second", _}, 50
    assert {:error, :stale_credit} = GenUDP.consumed(receiver, generation, make_ref())
    refute_receive {:quic_udp, _, _, _, "second", _}, 50
    assert :ok = GenUDP.consumed(receiver, generation, credit)
    assert_receive {:quic_udp, ^generation, next_credit, _, "second", _}, 1_000
    assert next_credit != credit
    assert {:error, :stale_credit} = GenUDP.consumed(receiver, generation, credit)
  end

  test "replacement endpoints reject old credit and have distinct generations" do
    {:ok, receiver} = GenUDP.open()
    {:ok, sender} = GenUDP.open()
    assert {:ok, _} = GenUDP.send(sender, "first", GenUDP.local(receiver))
    assert_receive {:quic_udp, old_generation, old_credit, _, "first", _}, 1_000
    :ok = GenUDP.close(receiver)
    {:ok, replacement} = GenUDP.open()
    assert {:error, :stale_credit} = GenUDP.consumed(replacement, old_generation, old_credit)
    assert {:ok, _} = GenUDP.send(sender, "new", GenUDP.local(replacement))
    assert_receive {:quic_udp, generation, _, _, "new", _}, 1_000
    assert generation != old_generation
    :ok = GenUDP.close(sender)
    :ok = GenUDP.close(replacement)
  end

  test "rejects wildcard binds, invalid roles and malformed remote addresses" do
    for ip <- [{0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}, :invalid] do
      assert {:error, {:invalid_local_address, ^ip}} = GenUDP.open(ip: ip)
    end

    assert {:error, :invalid_role} = GenUDP.open(role: :observer)
    {:ok, socket} = GenUDP.open()
    assert {:error, :invalid_remote} = GenUDP.send(socket, "ping", :invalid)
    assert {:error, :invalid_datagram} = GenUDP.send(socket, :invalid, {{127, 0, 0, 1}, 1234})
    assert {:ok, _} = GenUDP.send(socket, "ok", GenUDP.local(socket))
    :ok = GenUDP.close(socket)
  end

  test "socket is closed when its consumer terminates" do
    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    {:ok, adapter} = GenUDP.open(owner: owner)
    monitor = Process.monitor(adapter)
    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^adapter, :normal}, 1_000
  end

  defp close_if_alive(pid) do
    if Process.alive?(pid), do: GenUDP.close(pid)
  end
end
