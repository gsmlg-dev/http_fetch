defmodule HTTP.HTTP2FailedOpenCleanupTest do
  use ExUnit.Case, async: false

  alias HTTP.HTTP2.{ConnectionOwner, Pool}
  alias HTTP.Test.HTTP2ScriptedPeer, as: Peer

  def handle_event([:http_fetch, :http2, :body_bridge], measurements, metadata, parent),
    do: send(parent, {:bridge_finished, measurements, metadata})

  def handle_event([:http_fetch, :http2, :connection], measurements, %{event: :released}, parent),
    do: send(parent, {:owner_released, self(), measurements})

  def handle_event(_, _, _, _), do: :ok

  def handle_stream_creation(_, _, _, parent) do
    send(parent, {:stream_creation, self()})

    receive do
      :continue_stream_creation -> :ok
    end
  end

  test "warm POST admission failure releases its unstarted bridge, source, producer and reservation" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {first, true} = Peer.request(socket)
        :ok = Peer.response(socket, first, "first")
        {third, true} = Peer.request(socket)
        :ok = Peer.response(socket, third, "third")
      end)

    handler = "failed-open-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach_many(
        handler,
        [[:http_fetch, :http2, :body_bridge], [:http_fetch, :http2, :connection]],
        &__MODULE__.handle_event/4,
        self()
      )

    on_exit(fn ->
      :telemetry.detach(handler)
      send(peer, :close)
    end)

    opts = [http_version: :h2c, timeout: 2_000]
    assert "first" == url |> HTTP.fetch(opts) |> HTTP.Promise.await() |> HTTP.Response.read_all()

    {pool, key, owner} = pooled_owner(URI.parse(url).port)
    assert_receive {:owner_released, ^owner, %{active_streams: 0, protocol_streams: 0}}, 5_000

    assert %{lifecycle: :ready, active_streams: 0, protocol_streams: 0} =
             ConnectionOwner.status(owner)

    :sys.replace_state(owner, fn state -> %{state | max_streams: 0} end)
    :ok = :sys.suspend(owner)
    children_before = MapSet.new(Task.Supervisor.children(:http_fetch_task_supervisor))
    failed = HTTP.fetch(url, opts ++ [method: :post, body: "payload"])
    await_open_call(owner)

    new_children =
      Task.Supervisor.children(:http_fetch_task_supervisor)
      |> MapSet.new()
      |> MapSet.difference(children_before)
      |> MapSet.to_list()

    producer =
      Enum.find(new_children, fn pid ->
        Process.info(pid, :current_function) == {:current_function, {HTTP.Stream, :chunk, 3}}
      end)

    assert is_pid(producer)

    {:monitors, monitors} = Process.info(producer, :monitors)
    {:process, source} = Enum.find(monitors, fn {kind, _} -> kind == :process end)

    {:monitored_by, watchers} = Process.info(source, :monitored_by)

    bridge =
      Enum.find(watchers, fn watcher ->
        watcher != producer and match?(%{stream: ^source, owner: ^owner}, :sys.get_state(watcher))
      end)

    assert is_pid(bridge)
    bridge_ref = Process.monitor(bridge)
    source_ref = Process.monitor(source)
    producer_ref = Process.monitor(producer)

    :ok = :sys.resume(owner)
    assert {:error, :capacity} = HTTP.Promise.await(failed)
    assert_receive {:DOWN, ^bridge_ref, :process, ^bridge, :normal}
    assert_receive {:DOWN, ^source_ref, :process, ^source, :shutdown}
    assert_receive {:DOWN, ^producer_ref, :process, ^producer, :normal}
    assert_receive {:bridge_finished, %{bytes: 0}, %{outcome: :cancelled}}
    assert %{streams: 0, pending: 0} = Pool.stats(pool)[key]

    :sys.replace_state(owner, fn state -> %{state | max_streams: 100} end)
    assert "third" == url |> HTTP.fetch(opts) |> HTTP.Promise.await() |> HTTP.Response.read_all()
    assert_receive {:owner_released, ^owner, %{active_streams: 0, protocol_streams: 0}}, 5_000

    assert %{lifecycle: :ready, active_streams: 0, protocol_streams: 0} =
             ConnectionOwner.status(owner)
  end

  test "cold POST admission failure preserves the newly pooled owner for a sibling request" do
    {url, peer} =
      Peer.start(self(), fn socket ->
        {next, true} = Peer.request(socket)
        :ok = Peer.response(socket, next, "sibling")
      end)

    barrier = "cold-stream-barrier-#{System.unique_integer([:positive])}"
    bridge_handler = "cold-bridge-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach(
        barrier,
        [:http_fetch, :streaming, :start],
        &__MODULE__.handle_stream_creation/4,
        self()
      )

    :ok =
      :telemetry.attach_many(
        bridge_handler,
        [[:http_fetch, :http2, :body_bridge], [:http_fetch, :http2, :connection]],
        &__MODULE__.handle_event/4,
        self()
      )

    on_exit(fn ->
      :telemetry.detach(barrier)
      :telemetry.detach(bridge_handler)
      send(peer, :close)
    end)

    opts = [http_version: :h2c, timeout: 2_000]
    children_before = MapSet.new(Task.Supervisor.children(:http_fetch_task_supervisor))
    failed = HTTP.fetch(url, opts ++ [method: :post, body: "payload"])
    assert_receive {:stream_creation, worker}
    {pool, key, owner} = pooled_owner(URI.parse(url).port)
    assert %{streams: 1} = Pool.stats(pool)[key]
    :sys.replace_state(owner, fn state -> %{state | max_streams: 0} end)
    send(worker, :continue_stream_creation)

    assert {:error, :capacity} = HTTP.Promise.await(failed)
    assert_receive {:bridge_finished, %{bytes: 0}, %{outcome: :cancelled}}
    assert %{streams: 0, pending: 0, connections: 1} = Pool.stats(pool)[key]

    assert %{lifecycle: :ready, active_streams: 0, protocol_streams: 0} =
             ConnectionOwner.status(owner)

    assert MapSet.equal?(
             MapSet.new(Task.Supervisor.children(:http_fetch_task_supervisor)),
             children_before
           )

    :ok = :telemetry.detach(barrier)
    :sys.replace_state(owner, fn state -> %{state | max_streams: 100} end)
    :ok = Pool.update_capacity(pool, key, owner, 100)

    assert "sibling" ==
             url |> HTTP.fetch(opts) |> HTTP.Promise.await() |> HTTP.Response.read_all()

    assert_receive {:owner_released, ^owner, %{active_streams: 0, protocol_streams: 0}}, 5_000

    assert %{lifecycle: :ready, active_streams: 0, protocol_streams: 0} =
             ConnectionOwner.status(owner)
  end

  defp pooled_owner(port) do
    pool = Process.whereis(:http_fetch_http2_pool)
    state = :sys.get_state(pool)

    {key, entry} =
      Enum.find(state.entries, fn {key, _entry} -> key.port == port end)

    {pool, key, entry.connections |> Map.keys() |> hd()}
  end

  defp await_open_call(owner) do
    deadline = System.monotonic_time(:millisecond) + 2_000
    await_open_call(owner, deadline)
  end

  defp await_open_call(owner, deadline) do
    {:messages, messages} = Process.info(owner, :messages)

    if Enum.any?(messages, &match?({:"$gen_call", _, {:open_stream, _, _}}, &1)) do
      :ok
    else
      if System.monotonic_time(:millisecond) >= deadline, do: flunk("open_stream was not called")
      :erlang.yield()
      await_open_call(owner, deadline)
    end
  end
end
