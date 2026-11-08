defmodule Abyss.UDPMembershipHostTest do
  use ExUnit.Case, async: false

  @moduletag :integration
  @moduletag skip: Abyss.TestHost.linux_only()
  @group1 {239, 255, 72, 1}
  @group2 {239, 255, 72, 2}

  defmodule Handler do
    use Abyss.Handler
    def handle_data(_, state), do: {:close, state}
  end

  test "membership control is responsive and duplicate joins/leaves are idempotent" do
    server =
      start_supervised!(
        {Abyss,
         [
           handler_module: Handler,
           port: 0,
           transport_module: Abyss.Transport.UDP.Multicast,
           transport_options: [
             add_membership: {@group1, {127, 0, 0, 1}},
             add_membership: {@group2, {127, 0, 0, 1}}
           ]
         ]}
      )

    assert Enum.sort(Abyss.memberships(server)) == [
             {@group1, {127, 0, 0, 1}},
             {@group2, {127, 0, 0, 1}}
           ]

    assert :ok = Abyss.join(server, {@group1, "lo"})
    assert length(Abyss.memberships(server)) == 2
    assert :ok = Abyss.leave(server, {@group1, "lo"})
    assert :ok = Abyss.leave(server, {@group1, "lo"})
    assert [{@group2, {127, 0, 0, 1}}] = Abyss.memberships(server)
    assert :ok = Abyss.suspend(server)
    assert :ok = Abyss.resume(server)
    assert [{@group2, {127, 0, 0, 1}}] = Abyss.memberships(server)

    assert {:error, {:invalid_multicast_group, {127, 0, 0, 1}}} =
             Abyss.join(server, {{127, 0, 0, 1}, "lo"})
  end

  test "desired runtime membership survives a socket-generation restart" do
    server =
      start_supervised!(
        {Abyss,
         [handler_module: Handler, port: 0, transport_module: Abyss.Transport.UDP.Multicast]}
      )

    assert :ok = Abyss.join(server, {@group2, "lo"})
    pool = Abyss.Server.listener_pool_pid(server)
    [old] = Abyss.ListenerPool.listener_pids(pool)
    assert :ok = Supervisor.terminate_child(pool, "listener-1")
    assert {:ok, next} = Supervisor.restart_child(pool, "listener-1")
    refute old == next
    assert [{@group2, {127, 0, 0, 1}}] = Abyss.memberships(server)
  end

  test "startup membership operations retain add/drop order across restart" do
    server =
      start_supervised!(
        {Abyss,
         [
           handler_module: Handler,
           port: 0,
           transport_module: Abyss.Transport.UDP.Multicast,
           transport_options: [
             add_membership: {@group1, "lo"},
             drop_membership: {@group1, {127, 0, 0, 1}},
             add_membership: {@group2, "lo"},
             drop_membership: {@group2, "lo"},
             add_membership: {@group2, {127, 0, 0, 1}}
           ]
         ]}
      )

    assert [{@group2, {127, 0, 0, 1}}] = Abyss.memberships(server)
    pool = Abyss.Server.listener_pool_pid(server)
    assert :ok = Supervisor.terminate_child(pool, "listener-1")
    assert {:ok, _next} = Supervisor.restart_child(pool, "listener-1")
    assert [{@group2, {127, 0, 0, 1}}] = Abyss.memberships(server)
  end

  test "startup drop operands are validated even when no membership remains" do
    config = %Abyss.ServerConfig{
      handler_module: Handler,
      transport_options: [drop_membership: {{127, 0, 0, 1}, "lo"}]
    }

    assert_raise ArgumentError, ~r/invalid_multicast_group/, fn ->
      Abyss.Listener.init({"invalid-drop", self(), config})
    end
  end
end
