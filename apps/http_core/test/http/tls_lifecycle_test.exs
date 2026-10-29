defmodule HTTP.TLSLifecycleTest do
  use ExUnit.Case, async: true

  alias HTTP.RequestLifecycle

  test "unsupported TLS evidence poisons request and bound scope and refuses handoff" do
    {tracker, _latch, _owner} = lifecycle()
    scope = start_supervised!({__MODULE__.ScopeRecorder, self()})
    deadline = System.monotonic_time(:millisecond) + 5_000
    assert :ok = RequestLifecycle.bind_scope(tracker, scope, deadline)
    socket = {:sslsocket, :unknown}
    assert :ok = RequestLifecycle.track_tls([], socket)

    assert {:error, :unsupported_tls_socket_representation} =
             RequestLifecycle.track_tls([request_lifecycle: tracker], socket)

    assert :sys.get_state(tracker).uncertain?
    assert_receive :scope_unconfirmed, 1_000

    assert {:error, :unsupported_tls_socket_representation} =
             RequestLifecycle.handoff_socket(tracker, socket)

    assert_receive :scope_unconfirmed, 1_000
  end

  test "ordinary request uncertainty does not poison the managed scope" do
    {tracker, _latch, _owner} = lifecycle()
    scope = start_supervised!({__MODULE__.ScopeRecorder, self()})

    assert :ok =
             RequestLifecycle.bind_scope(
               tracker,
               scope,
               System.monotonic_time(:millisecond) + 5_000
             )

    RequestLifecycle.unconfirmed(tracker)
    assert :sys.get_state(tracker).uncertain?
    assert :ok = GenServer.call(scope, :barrier)
    refute_receive :scope_unconfirmed, 0
  end

  defmodule ScopeRecorder do
    use GenServer
    def start_link(parent), do: GenServer.start_link(__MODULE__, parent)
    @impl true
    def init(parent), do: {:ok, parent}
    @impl true
    def handle_call({:track, pid, kind, token}, _from, parent) do
      send(parent, {:scope_tracked, pid, kind, token})
      {:reply, :ok, parent}
    end

    def handle_call(:barrier, _from, parent), do: {:reply, :ok, parent}
    @impl true
    def handle_cast(:unconfirmed, parent) do
      send(parent, :scope_unconfirmed)
      {:noreply, parent}
    end
  end

  defp lifecycle do
    {tracker, latch} = RequestLifecycle.start()

    owner =
      spawn(fn ->
        receive do
          {:finish, tracker} -> RequestLifecycle.complete(tracker)
        end
      end)

    RequestLifecycle.register(tracker, owner, :owner)

    on_exit(fn ->
      if Process.alive?(owner), do: Process.exit(owner, :kill)
      await_tracker(tracker)
    end)

    {tracker, latch, owner}
  end

  defp await_tracker(tracker) do
    monitor = Process.monitor(tracker)
    assert_receive {:DOWN, ^monitor, :process, ^tracker, _}, 5_000
  end
end
