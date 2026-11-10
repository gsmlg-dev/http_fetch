defmodule Abyss.HandlerHardeningTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  defmodule Probe do
    use Abyss.Handler

    def handle_data({_ip, _port, {owner, result}}, state) do
      state = Map.merge(state, %{owner: owner, marker: :preserved})
      send(owner, {:processed, self()})

      case result do
        :continue -> {:continue, state, 80}
        :infinite -> {:continue, state, {:persistent, :infinity}}
        :close -> {:close, state}
        {:error, reason} -> {:error, reason, state}
      end
    end

    def handle_timeout(state), do: send(state.owner, {:cleanup, :timeout, state.marker})
    def handle_close(state), do: send(state.owner, {:cleanup, :close, state.marker})
    def handle_error(reason, state), do: send(state.owner, {:cleanup, reason, state.marker})
  end

  test "idle expiry survives repeated memory checks and status requests" do
    pid = start_probe(:continue)
    for _ <- 1..10, do: send(pid, :memory_check)
    :sys.get_state(pid)
    assert_receive {:cleanup, :timeout, :preserved}, 300
    assert_receive {:DOWN, _, :process, ^pid, {:shutdown, :timeout}}, 100
  end

  test "persistent infinity does not enter adaptive arithmetic" do
    assert Abyss.Handler.calculate_adaptive_timeout(:infinity, [100]) == :infinity
    pid = start_probe(:infinite)
    send(pid, {:new_connection, make_ref(), {{127, 0, 0, 1}, 1, {self(), :infinite}}})
    assert_receive {:processed, ^pid}
    assert Process.alive?(pid)
    GenServer.stop(pid)
  end

  test "stale idle timer cannot expire a reset deadline" do
    pid = start_probe(:continue)
    old_state = :sys.get_state(pid)
    send(pid, {:new_connection, make_ref(), {{127, 0, 0, 1}, 1, {self(), :infinite}}})
    assert_receive {:processed, ^pid}
    send(pid, {:abyss_idle_timeout, old_state.idle_token})
    current = :sys.get_state(pid)
    assert current.idle_deadline == :infinity
    assert Process.alive?(pid)
    GenServer.stop(pid)
  end

  test "an early current-token event rearms the unchanged absolute deadline" do
    pid = start_probe(:continue)
    deadline = System.monotonic_time(:millisecond) + 100

    previous =
      :sys.replace_state(pid, fn state ->
        _ = Process.cancel_timer(state.idle_timer)
        %{state | idle_timer: nil, idle_deadline: deadline}
      end)

    send(pid, {:abyss_idle_timeout, previous.idle_token})
    current = :sys.get_state(pid)
    assert is_reference(current.idle_timer)
    assert current.idle_deadline == deadline
    assert current.idle_token == previous.idle_token
    assert Process.alive?(pid)
    assert_receive {:cleanup, :timeout, :preserved}, 300
    assert_receive {:DOWN, _, :process, ^pid, {:shutdown, :timeout}}, 100
    refute_receive {:cleanup, :timeout, _}, 20
  end

  test "sampled process memory is measured in bytes" do
    assert Abyss.Handler.memory_megabytes(1_048_576) == 1.0
  end

  test "broadcast cleanup preserves returned state and reports callback error" do
    pid = start_probe({:error, :bad_payload}, broadcast: true)
    assert_receive {:cleanup, :bad_payload, :preserved}
    assert_receive {:DOWN, _, :process, ^pid, {:shutdown, {:silent_termination, :bad_payload}}}
  end

  test "handler termination does not count as a send" do
    Abyss.Telemetry.reset_metrics()
    pid = start_probe(:close)
    assert_receive {:DOWN, _, :process, ^pid, _}
    assert Abyss.Telemetry.get_metrics().responses_total == 0
  end

  defp start_probe(result, options \\ []) do
    config =
      Abyss.ServerConfig.new(
        Keyword.merge(
          [
            handler_module: Probe,
            port: 0,
            read_timeout: 80,
            handler_memory_check_interval: 5,
            silent_terminate_on_error: true
          ],
          options
        )
      )

    span =
      Abyss.Telemetry.start_span(:connection, %{}, %{accept_start_time: System.monotonic_time()})

    {:ok, pid} = Probe.start_link({span, config, self(), make_ref()})
    Process.unlink(pid)
    Process.monitor(pid)
    send(pid, {:new_connection, make_ref(), {{127, 0, 0, 1}, 1, {self(), result}}})
    assert_receive {:processed, ^pid}
    on_exit(fn -> Abyss.TestStop.quietly(pid) end)
    pid
  end
end
