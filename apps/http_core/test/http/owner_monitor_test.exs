defmodule HTTP.OwnerMonitorTest do
  use ExUnit.Case, async: true

  test "owner exit interrupts a blocked connection and reaps its monitor" do
    parent = self()

    owner =
      spawn(fn ->
        receive do
          :stop -> :ok
        end
      end)

    connection =
      spawn(fn ->
        guardian = HTTP.OwnerMonitor.start(self(), owner)
        send(parent, {:watching, guardian})

        receive do
          :never_sent -> :ok
        end
      end)

    on_exit(fn ->
      Process.exit(owner, :kill)
      Process.exit(connection, :kill)
    end)

    assert_receive {:watching, guardian}
    connection_ref = Process.monitor(connection)
    guardian_ref = Process.monitor(guardian)
    send(owner, :stop)
    assert_receive {:DOWN, ^connection_ref, :process, ^connection, :shutdown}
    assert_receive {:DOWN, ^guardian_ref, :process, ^guardian, _}
  end

  test "normal connection completion reaps its monitor without stopping the owner" do
    parent = self()

    connection =
      spawn(fn ->
        guardian = HTTP.OwnerMonitor.start(self(), parent)
        send(parent, {:watching, guardian})

        receive do
          :done -> :ok
        end
      end)

    on_exit(fn -> Process.exit(connection, :kill) end)
    assert_receive {:watching, guardian}
    guardian_ref = Process.monitor(guardian)
    send(connection, :done)
    assert_receive {:DOWN, ^guardian_ref, :process, ^guardian, :normal}
    assert Process.alive?(parent)
  end
end
