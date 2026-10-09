defmodule Quic.ClosedReadinessTest do
  use ExUnit.Case, async: true

  alias Quic.Runtime.ConnectionHandle

  for operation <- [:ready, :info] do
    test "normal shutdown during #{operation} returns the terminal closed result" do
      {connection, monitor} = exiting_connection(:normal, unquote(operation))
      assert {:error, :closed} = Quic.unquote(operation)(connection)
      assert_receive {:ready_called, pid}, 1_000
      assert pid == connection.id
      assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    end
  end

  test "readiness retains an abnormal shutdown reason" do
    {connection, monitor} = exiting_connection(:test_failure)
    assert {:error, {:closed, :test_failure}} = Quic.ready(connection)
    assert_receive {:ready_called, pid}, 1_000
    assert pid == connection.id
    assert_receive {:DOWN, ^monitor, :process, ^pid, :test_failure}, 1_000
  end

  test "readiness after process termination returns the same terminal closed result" do
    {pid, monitor} = spawn_monitor(fn -> :ok end)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
    connection = %ConnectionHandle{id: pid, generation: make_ref()}
    assert {:error, :closed} = Quic.ready(connection)
  end

  test "a readiness call without a reply retains its timeout result" do
    parent = self()
    generation = make_ref()

    {pid, monitor} =
      spawn_monitor(fn ->
        receive do
          {:"$gen_call", _from, {:ready, ^generation}} ->
            send(parent, {:ready_called, self()})

            receive do
              :stop -> :ok
            end
        end
      end)

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    connection = %ConnectionHandle{id: pid, generation: generation}
    assert {:error, :timeout} = Quic.ready(connection)
    assert_receive {:ready_called, ^pid}, 1_000
    assert Process.alive?(pid)
    send(pid, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 1_000
  end

  defp exiting_connection(reason, operation \\ :ready) do
    parent = self()
    generation = make_ref()

    {pid, monitor} =
      spawn_monitor(fn ->
        receive do
          {:"$gen_call", _from, {^operation, ^generation}} ->
            send(parent, {:ready_called, self()})
            exit(reason)
        end
      end)

    on_exit(fn -> if Process.alive?(pid), do: Process.exit(pid, :kill) end)
    {%ConnectionHandle{id: pid, generation: generation}, monitor}
  end
end
