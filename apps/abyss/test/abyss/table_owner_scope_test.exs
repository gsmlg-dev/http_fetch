defmodule Abyss.TableOwnerScopeTest do
  use ExUnit.Case, async: false

  test "abrupt server death removes endpoint metrics, socket registrations and desired memberships" do
    server =
      spawn(fn ->
        receive do
          :finish -> :ok
        end
      end)

    socket = make_ref()
    Abyss.Telemetry.register_scope(server, ScopeHandler)
    Abyss.Telemetry.register_socket(server, socket)
    Abyss.Telemetry.track_connection_accepted(server)
    Abyss.TableOwner.ensure_table(:abyss_udp_memberships, [:named_table, :public, :set])
    :ets.insert(:abyss_udp_memberships, {{server, 1}, [{{239, 1, 2, 3}, {127, 0, 0, 1}}]})
    state = :sys.get_state(Abyss.TableOwner)
    assert map_size(state.scopes) >= 1

    owner = self()
    monitor = Process.monitor(server)
    scope_monitor = Map.fetch!(state.scopes, server)
    completed = make_ref()

    :ok =
      :sys.install(
        Abyss.TableOwner,
        {fn observed, event, _name ->
           case {observed, event} do
             {false, {:in, {:DOWN, ^scope_monitor, :process, ^server, :killed}}} ->
               true

             {true, {:noreply, _state}} ->
               send(owner, {:endpoint_cleanup_completed, completed})
               :done

             _ ->
               observed
           end
         end, false}
      )

    Process.exit(server, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^server, :killed}
    assert_receive {:endpoint_cleanup_completed, ^completed}
    wait_for_cleanup(server, socket, 100)
    assert :ets.lookup(:abyss_udp_memberships, {server, 1}) == []
    refute Map.has_key?(:sys.get_state(Abyss.TableOwner).scopes, server)
  end

  defp wait_for_cleanup(_server, _socket, 0), do: flunk("endpoint cleanup did not complete")

  defp wait_for_cleanup(server, socket, retries) do
    :sys.get_state(Abyss.TableOwner)

    if Abyss.Telemetry.socket_scope(socket) != :unscoped do
      wait_for_cleanup(server, socket, retries - 1)
    else
      assert Abyss.Telemetry.get_metrics(server).connections_active == 0
    end
  end
end
