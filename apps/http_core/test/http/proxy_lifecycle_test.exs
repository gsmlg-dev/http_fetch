defmodule HTTP.ProxyLifecycleTest do
  use ExUnit.Case, async: true
  alias HTTP.RequestLifecycle

  test "unknown adoption descriptor cannot release a tracked HTTP actor" do
    parent = self()
    {tracker, latch} = RequestLifecycle.start()

    owner =
      spawn(fn ->
        assert :ok = RequestLifecycle.enter(tracker, :owner)

        assert {:error, :adoption_unconfirmed} =
                 RequestLifecycle.adopt_provider(tracker, :forged, self(), :socket, deadline())

        assert map_size(:sys.get_state(tracker).resources) == 1
        RequestLifecycle.complete(tracker)
        send(parent, :completed)
      end)

    ref = Process.monitor(tracker)
    assert_receive :completed, 1_000
    assert_receive {:DOWN, ^ref, :process, ^tracker, :normal}, 1_000
    refute Process.alive?(owner)
    assert :atomics.get(latch, 1) == 2
  end

  test "expired adoption cannot release registered resources" do
    {tracker, _latch} = RequestLifecycle.start()
    assert :ok = RequestLifecycle.enter(tracker, :owner)

    assert {:error, :request_timeout} =
             RequestLifecycle.adopt_provider(
               tracker,
               {make_ref(), make_ref()},
               self(),
               :socket,
               System.monotonic_time(:millisecond)
             )

    assert map_size(:sys.get_state(tracker).resources) == 1
    GenServer.stop(tracker)
  end

  test "unrecognized attempt correlation keeps uncertainty after the actor completes" do
    parent = self()
    {tracker, latch} = RequestLifecycle.start()
    tracker_down = Process.monitor(tracker)

    spawn(fn ->
      :ok = RequestLifecycle.enter(tracker, :owner)

      assert {:error, :adoption_unconfirmed} =
               RequestLifecycle.adopt_provider(
                 tracker,
                 {make_ref(), make_ref()},
                 self(),
                 :socket,
                 deadline()
               )

      assert :sys.get_state(tracker).uncertain?
      assert map_size(:sys.get_state(tracker).resources) == 1
      RequestLifecycle.complete(tracker)
      send(parent, :uncertain_completed)
    end)

    assert_receive :uncertain_completed, 1_000
    assert_receive {:DOWN, ^tracker_down, :process, ^tracker, :normal}, 1_000
    assert :atomics.get(latch, 1) == 3
  end

  test "lost tracker cannot acknowledge a provider adoption" do
    {tracker, _} = RequestLifecycle.start()
    GenServer.stop(tracker)

    assert {:error, :transport_scope_retired} =
             RequestLifecycle.adopt_provider(
               tracker,
               {make_ref(), make_ref()},
               self(),
               :socket,
               deadline()
             )
  end

  defp deadline, do: System.monotonic_time(:millisecond) + 1_000
end
