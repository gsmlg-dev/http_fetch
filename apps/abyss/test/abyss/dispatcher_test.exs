defmodule Abyss.DispatcherTestTransport do
  def send(_socket, _ip, _port, _bytes), do: :ok
end

defmodule Abyss.DispatcherFailingTransport do
  def send(_socket, _ip, _port, _bytes), do: {:error, :closed}
end

defmodule Abyss.DispatcherBlockingTransport do
  def send(owner, _ip, _port, bytes) do
    send(owner, {:writer_send_entered, self(), bytes})

    receive do
      :release_writer_send -> :ok
    end
  end
end

defmodule Abyss.DispatcherTestCallback do
  @behaviour Abyss.DatagramDispatcher

  @impl true
  def init(context, _opts), do: {:ok, %{started: 0, send_fun: context.send_fun}}

  @impl true
  def handle_datagram(_remote, <<key, _rest::binary>>, _at, %{routes: routes, state: state}) do
    case Map.get(routes, key) do
      %{pid: pid} ->
        {:route, [key], pid, %{state | started: state.started}}

      nil ->
        pid = spawn(fn -> Process.sleep(:infinity) end)
        {:new, [key], pid, %{state | started: state.started + 1}}
    end
  end

  def handle_datagram(_remote, _bytes, _at, %{state: state}),
    do: {:drop, :malformed, state}
end

defmodule Abyss.DispatcherInitFailureCallback do
  @behaviour Abyss.DatagramDispatcher

  @impl true
  def init(context, opts) do
    if opts[:send_before_failure] do
      {:ok, _ref} =
        Abyss.Dispatcher.send(context.send, {{127, 0, 0, 1}, 1000}, <<1>>, 100)
    end

    if owner = opts[:owner],
      do: send(owner, {:callback_children, context.send.writer, context.send.admission})

    if opts[:send_before_failure] do
      send(opts[:owner], {:callback_ready_to_fail, self()})

      receive do
        :fail_init -> :ok
      end
    end

    {:error, :attachment_failed}
  end

  @impl true
  def handle_datagram(_remote, _bytes, _at, _context), do: raise("not started")
end

defmodule Abyss.DispatcherReplacingCallback do
  @behaviour Abyss.DatagramDispatcher

  @impl true
  def init(_context, _opts), do: {:ok, nil}

  @impl true
  def handle_datagram(_remote, <<key, encoded_pid::binary>>, _at, %{state: state}) do
    {:route, [key], :erlang.binary_to_term(encoded_pid), state}
  end
end

defmodule Abyss.DispatcherTest do
  use ExUnit.Case, async: true

  alias Abyss.Dispatcher

  test "serializes repeated route keys and cleans routes when connection exits" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: :socket,
        transport: Abyss.DispatcherTestTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 32
      )

    assert :ok = Dispatcher.dispatch(dispatcher, {{127, 0, 0, 1}, 1000}, <<7, 1>>, 1)
    assert %{7 => %{pid: pid}} = Dispatcher.routes(dispatcher)
    assert Process.alive?(pid)

    assert :ok = Dispatcher.dispatch(dispatcher, {{127, 0, 0, 1}, 1000}, <<7, 2>>, 2)
    assert %{7 => %{pid: ^pid}} = Dispatcher.routes(dispatcher)

    Process.exit(pid, :kill)
    assert_eventually(fn -> Dispatcher.routes(dispatcher) == %{} end)
  end

  test "route replacement removes obsolete monitors and preserves the new route" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherReplacingCallback,
        module_options: [],
        socket: :socket,
        transport: Abyss.DispatcherTestTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 32
      )

    first = spawn(fn -> Process.sleep(:infinity) end)
    second = spawn(fn -> Process.sleep(:infinity) end)

    assert :ok = route_to(dispatcher, 7, first)
    assert :ok = route_to(dispatcher, 8, first)
    assert %{monitors: first_monitors} = :sys.get_state(dispatcher)
    assert map_size(first_monitors) == 1

    assert :ok = route_to(dispatcher, 7, second)
    assert %{monitors: replacement_monitors} = :sys.get_state(dispatcher)
    assert map_size(replacement_monitors) == 2

    assert :ok = route_to(dispatcher, 8, second)
    assert %{monitors: final_monitors} = :sys.get_state(dispatcher)
    assert map_size(final_monitors) == 1

    Process.exit(first, :kill)
    assert %{7 => %{pid: ^second}, 8 => %{pid: ^second}} = Dispatcher.routes(dispatcher)

    Process.exit(second, :kill)
    assert_eventually(fn -> Dispatcher.routes(dispatcher) == %{} end)
  end

  test "writer returns bounded admission and actual send completion" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: self(),
        transport: Abyss.DispatcherBlockingTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 2
      )

    state = :sys.get_state(dispatcher)
    assert {:ok, ref} = Dispatcher.send(state.send, {{127, 0, 0, 1}, 1000}, <<1>>)
    assert_receive {:writer_send_entered, writer, <<1>>}

    assert {:error, :queue_bytes_limit} =
             Dispatcher.send(state.send, {{127, 0, 0, 1}, 1000}, <<2, 3>>)

    send(writer, :release_writer_send)
    assert {:ok, at} = Dispatcher.Writer.await(writer, state.send, ref)
    assert is_integer(at)
  end

  test "callback receives a socket-independent send function" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: :socket,
        transport: Abyss.DispatcherTestTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 32
      )

    state = :sys.get_state(dispatcher)
    assert is_function(state.callback_state.send_fun, 2)
    assert {:ok, _ref} = state.callback_state.send_fun.({{127, 0, 0, 1}, 1000}, <<1>>)
  end

  test "send receipt waits for writer completion and preserves failure" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: :socket,
        transport: Abyss.DispatcherFailingTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 32
      )

    state = :sys.get_state(dispatcher)

    assert {:error, :closed} =
             Dispatcher.send_receipt(state.send, {{127, 0, 0, 1}, 1000}, <<1>>)
  end

  test "writer admits before a blocked socket send and retains in-flight credit" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: self(),
        transport: Abyss.DispatcherBlockingTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 2
      )

    state = :sys.get_state(dispatcher)

    assert {:ok, _ref} =
             Dispatcher.send(state.send, {{127, 0, 0, 1}, 1000}, <<1>>, 20)

    assert_receive {:writer_send_entered, writer, <<1>>}

    producer =
      Task.async(fn ->
        Dispatcher.send(state.send, {{127, 0, 0, 1}, 1000}, <<2>>, 20)
      end)

    assert {:ok, _ref} = Task.await(producer)

    assert {:error, :queue_bytes_limit} =
             Dispatcher.send(state.send, {{127, 0, 0, 1}, 1000}, <<3>>, 20)

    send(writer, :release_writer_send)
    assert_receive {:writer_send_entered, ^writer, <<2>>}
    send(writer, :release_writer_send)
  end

  test "rejects an unknown send receipt explicitly" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: :socket,
        transport: Abyss.DispatcherTestTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 32
      )

    state = :sys.get_state(dispatcher)
    assert {:error, :unknown_send} = Dispatcher.Writer.await(state.writer, state.send, make_ref())
  end

  test "capabilities without admission metadata use the persistent writer gate" do
    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: :socket,
        transport: Abyss.DispatcherTestTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 32
      )

    state = :sys.get_state(dispatcher)
    capability = %Dispatcher.SendCapability{writer: state.writer, generation: state.generation}

    assert {:ok, ref} = Dispatcher.send(capability, {{127, 0, 0, 1}, 1000}, <<1>>)
    assert {:ok, _completed_at} = Dispatcher.Writer.await(state.writer, capability, ref)
  end

  test "empty datagrams consume writer item capacity and complete normally" do
    {:ok, dispatcher} = start_dispatcher(max_queue: 1, max_bytes: 1)
    state = :sys.get_state(dispatcher)
    assert {:ok, ref} = Dispatcher.send(state.send, {{127, 0, 0, 1}, 1000}, <<>>)
    assert {:ok, _} = Dispatcher.Writer.await(state.writer, state.send, ref)
  end

  @tag :capture_log
  test "writer death invalidates dispatcher capability instead of retaining success" do
    previous = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous) end)

    {:ok, dispatcher} =
      Dispatcher.start_link(
        module: Abyss.DispatcherTestCallback,
        module_options: [],
        socket: :socket,
        transport: Abyss.DispatcherTestTransport,
        local_info: {{127, 0, 0, 1}, 4433},
        max_queue: 2,
        max_bytes: 32
      )

    state = :sys.get_state(dispatcher)
    Process.exit(state.writer, :kill)

    assert_receive {:EXIT, ^dispatcher, {:writer_exit, :killed}}
    assert {:error, :writer_down} = Dispatcher.send(state.send, {{127, 0, 0, 1}, 1000}, <<1>>)
  end

  test "a timed out reservation is cancelled and releases its credit" do
    {:ok, dispatcher} = start_dispatcher(max_queue: 1, max_bytes: 1)
    %{admission: admission, send: capability} = :sys.get_state(dispatcher)
    :ok = :sys.suspend(admission)

    assert {:error, :writer_timeout} =
             Dispatcher.send(capability, {{127, 0, 0, 1}, 1000}, <<1>>, 1)

    :ok = :sys.resume(admission)
    assert %{entries: %{}, reserved_bytes: 0} = :sys.get_state(admission)

    assert {:ok, _ref} =
             Dispatcher.send(capability, {{127, 0, 0, 1}, 1000}, <<2>>, 100)
  end

  test "await timeout and caller death remove waiter state" do
    {:ok, dispatcher} =
      start_dispatcher(
        socket: self(),
        transport: Abyss.DispatcherBlockingTransport,
        max_queue: 2,
        max_bytes: 2
      )

    %{admission: admission, send: capability} = :sys.get_state(dispatcher)
    assert {:ok, ref} = Dispatcher.send(capability, {{127, 0, 0, 1}, 1000}, <<1>>)
    assert_receive {:writer_send_entered, writer, <<1>>}

    timeout_waiter =
      spawn(fn ->
        Dispatcher.Writer.await(writer, capability, ref, 10)
      end)

    timeout_monitor = Process.monitor(timeout_waiter)
    assert_receive {:DOWN, ^timeout_monitor, :process, ^timeout_waiter, :normal}
    assert %{waiters: %{}} = :sys.get_state(admission)

    dead_waiter =
      spawn(fn ->
        Dispatcher.Writer.await(writer, capability, ref, 5_000)
      end)

    assert_eventually(fn -> map_size(:sys.get_state(admission).waiters) == 1 end)
    Process.exit(dead_waiter, :kill)
    assert_eventually(fn -> :sys.get_state(admission).waiters == %{} end)

    send(writer, :release_writer_send)
  end

  test "late waiter expiry cannot remove a replacement waiter" do
    generation = make_ref()

    {:ok, admission} =
      Dispatcher.Admission.start_link(generation: generation, max_queue: 1, max_bytes: 1)

    :ok = Dispatcher.Admission.bind(admission, self())

    capability = %Dispatcher.SendCapability{
      writer: self(),
      admission: admission,
      generation: generation
    }

    {:ok, ref} = Dispatcher.Admission.reserve(self(), capability, 1, 100)
    first = Task.async(fn -> Dispatcher.Writer.await(self(), capability, ref, 5000) end)
    assert_eventually(fn -> map_size(:sys.get_state(admission).waiters) == 1 end)
    first_monitor = :sys.get_state(admission).waiters[ref].monitor
    send(admission, {:await_expired, ref, first_monitor})
    assert {:unknown, ^ref} = Task.await(first)
    second = Task.async(fn -> Dispatcher.Writer.await(self(), capability, ref, 5000) end)
    assert_eventually(fn -> map_size(:sys.get_state(admission).waiters) == 1 end)
    second_monitor = :sys.get_state(admission).waiters[ref].monitor
    send(admission, {:await_expired, ref, first_monitor})
    assert %{monitor: ^second_monitor} = :sys.get_state(admission).waiters[ref]
    Dispatcher.Admission.complete(admission, generation, ref, {:ok, 123})
    assert {:ok, 123} = Task.await(second)
    GenServer.stop(admission)
  end

  test "completed results expire while admission is idle" do
    generation = make_ref()

    {:ok, admission} =
      Dispatcher.Admission.start_link(
        generation: generation,
        max_queue: 1,
        max_bytes: 1,
        result_ttl: 10
      )

    on_exit(fn -> if Process.alive?(admission), do: GenServer.stop(admission) end)
    :ok = Dispatcher.Admission.bind(admission, self())

    capability = %Dispatcher.SendCapability{
      writer: self(),
      generation: generation,
      admission: admission
    }

    assert {:ok, ref} = Dispatcher.Admission.reserve(self(), capability, 1, 100)
    Dispatcher.Admission.complete(admission, generation, ref, {:ok, 1})
    assert_eventually(fn -> is_map_key(:sys.get_state(admission).results, ref) end)
    assert_eventually(fn -> :sys.get_state(admission).results == %{} end, 100)
  end

  test "writer kill erases the legacy persistent admission lookup" do
    previous = Process.flag(:trap_exit, true)
    on_exit(fn -> Process.flag(:trap_exit, previous) end)

    {:ok, writer} = start_writer(owner: self())
    admission = :sys.get_state(writer).admission
    admission_monitor = Process.monitor(admission)
    assert ^admission = :persistent_term.get({Dispatcher.Writer, writer})

    Process.exit(writer, :kill)
    assert_receive {:EXIT, ^writer, :killed}

    assert_eventually(fn ->
      :persistent_term.get({Dispatcher.Writer, writer}, nil) == nil
    end)

    assert_receive {:DOWN, ^admission_monitor, :process, ^admission, :normal}
  end

  test "a blocked directly started writer stops when its owner dies normally" do
    parent = self()

    owner =
      spawn(fn ->
        {:ok, writer} =
          start_writer(
            owner: self(),
            socket: parent,
            transport: Abyss.DispatcherBlockingTransport
          )

        send(parent, {:direct_writer, writer, :sys.get_state(writer).admission})
        state = :sys.get_state(writer)

        {:ok, _ref} =
          Dispatcher.send(state_capability(state, writer), {{127, 0, 0, 1}, 1000}, <<1>>)

        receive do
          :stop -> :ok
        end
      end)

    assert_receive {:direct_writer, writer, admission}
    assert_receive {:writer_send_entered, ^writer, <<1>>}
    writer_monitor = Process.monitor(writer)
    admission_monitor = Process.monitor(admission)

    send(owner, :stop)
    assert_receive {:DOWN, ^writer_monitor, :process, ^writer, _reason}
    assert_receive {:DOWN, ^admission_monitor, :process, ^admission, _reason}
  end

  test "payload mismatch rejects explicitly without crashing admission" do
    generation = make_ref()

    {:ok, admission} =
      Dispatcher.Admission.start_link(generation: generation, max_queue: 1, max_bytes: 2)

    on_exit(fn -> if Process.alive?(admission), do: GenServer.stop(admission) end)
    :ok = Dispatcher.Admission.bind(admission, self())

    capability = %Dispatcher.SendCapability{
      writer: self(),
      generation: generation,
      admission: admission
    }

    assert {:ok, ref} = Dispatcher.Admission.reserve(self(), capability, 1, 100)

    assert {:error, :invalid_send} =
             Dispatcher.Admission.submit(
               capability,
               ref,
               {{127, 0, 0, 1}, 1000},
               <<1, 2>>,
               100
             )

    assert Process.alive?(admission)

    assert %{reserved_bytes: 1, entries: %{^ref => %{status: :reserved}}} =
             :sys.get_state(admission)
  end

  test "callback initialization failure stops dispatcher startup" do
    assert {:error, :attachment_failed} =
             Dispatcher.start_link(
               module: Abyss.DispatcherInitFailureCallback,
               module_options: [owner: self()],
               socket: :socket,
               transport: Abyss.DispatcherTestTransport,
               local_info: {{127, 0, 0, 1}, 4433},
               max_queue: 2,
               max_bytes: 32
             )

    assert_receive {:callback_children, writer, admission}
    assert_eventually(fn -> not Process.alive?(writer) and not Process.alive?(admission) end)
  end

  test "callback initialization failure bounds cleanup when its writer is blocked" do
    parent = self()

    spawn(fn ->
      result =
        Dispatcher.start_link(
          module: Abyss.DispatcherInitFailureCallback,
          module_options: [owner: parent, send_before_failure: true],
          socket: parent,
          transport: Abyss.DispatcherBlockingTransport,
          local_info: {{127, 0, 0, 1}, 4433},
          max_queue: 2,
          max_bytes: 32
        )

      send(parent, {:blocked_init_result, result})
    end)

    assert_receive {:writer_send_entered, _writer, <<1>>}
    assert_receive {:callback_children, writer, admission}
    assert_receive {:callback_ready_to_fail, callback}
    send(callback, :fail_init)
    assert_receive {:blocked_init_result, {:error, :attachment_failed}}, 1_500
    assert_eventually(fn -> not Process.alive?(writer) and not Process.alive?(admission) end)
  end

  defp start_dispatcher(opts) do
    Dispatcher.start_link(
      module: Abyss.DispatcherTestCallback,
      module_options: [],
      socket: Keyword.get(opts, :socket, :socket),
      transport: Keyword.get(opts, :transport, Abyss.DispatcherTestTransport),
      local_info: {{127, 0, 0, 1}, 4433},
      max_queue: Keyword.get(opts, :max_queue, 2),
      max_bytes: Keyword.get(opts, :max_bytes, 32)
    )
  end

  defp start_writer(opts) do
    Dispatcher.Writer.start_link(
      socket: Keyword.get(opts, :socket, :socket),
      transport: Keyword.get(opts, :transport, Abyss.DispatcherTestTransport),
      owner: Keyword.fetch!(opts, :owner),
      generation: make_ref(),
      max_queue: 2,
      max_bytes: 32
    )
  end

  defp route_to(dispatcher, key, pid) do
    Dispatcher.dispatch(
      dispatcher,
      {{127, 0, 0, 1}, 1000},
      <<key, :erlang.term_to_binary(pid)::binary>>,
      1
    )
  end

  defp state_capability(state, writer) do
    %Dispatcher.SendCapability{
      writer: writer,
      generation: state.generation,
      admission: state.admission
    }
  end

  defp assert_eventually(fun, attempts \\ 20)
  defp assert_eventually(_fun, 0), do: flunk("condition did not become true")

  defp assert_eventually(fun, attempts) do
    if fun.(),
      do: :ok,
      else:
        (
          Process.sleep(5)
          assert_eventually(fun, attempts - 1)
        )
  end
end
