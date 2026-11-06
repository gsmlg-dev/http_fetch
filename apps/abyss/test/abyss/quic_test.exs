defmodule Abyss.QUICServiceTest do
  use ExUnit.Case, async: false

  @moduletag :integration

  defmodule Handler do
    @behaviour Abyss.QUIC.Handler

    def init(connection, %{init: :slow} = metadata, owner) do
      send(owner, {:init_started, connection, self()})

      receive do
        {:release_init, ^connection} -> bind(connection, metadata, owner)
      end
    end

    def init(_connection, %{init: :fail}, _owner), do: {:error, :init_failed}
    def init(_connection, %{init: :crash}, _owner), do: raise("init crashed")
    def init(connection, metadata, owner), do: bind(connection, metadata, owner)

    def handle_event(:block, owner) do
      send(owner, {:event_started, self()})

      receive do
        :release_event -> {:ok, owner}
      end
    end

    def handle_event(:tick, owner), do: {:ok, owner}
    def handle_event(event, owner), do: send(owner, {:event, event}) && {:ok, owner}

    defp bind(connection, metadata, owner) do
      send(owner, {:bound, connection, metadata, self()})
      {:ok, owner}
    end
  end

  defmodule Backend.Endpoint do
    def receive_datagram(_endpoint, _remote, _bytes, _at), do: :ok
  end

  defmodule Backend do
    def listen(opts) do
      {:ok, endpoint} =
        Agent.start_link(fn -> %{acceptor: opts[:acceptor], queue: [], options: opts} end)

      if observer = opts[:tls][:observer], do: send(observer, {:endpoint, endpoint})
      {:ok, endpoint}
    end

    def options(endpoint), do: Agent.get(endpoint, & &1.options)

    def connection(metadata \\ %{alpn: "test"}) do
      {:ok, pid} = Agent.start_link(fn -> %{metadata: metadata, events: []} end)
      %{id: pid, generation: make_ref()}
    end

    def with_generation(connection, generation), do: %{connection | generation: generation}

    def push_event(%{id: id}, event), do: Agent.update(id, &%{&1 | events: &1.events ++ [event]})

    def push(endpoint, connection) do
      acceptor =
        Agent.get_and_update(endpoint, fn state ->
          {state.acceptor, %{state | queue: state.queue ++ [connection]}}
        end)

      send(acceptor, {:quic_accept, endpoint})
    end

    def accept(endpoint, _opts \\ []) do
      Agent.get_and_update(endpoint, fn
        %{queue: [connection | rest]} = state -> {{:ok, connection}, %{state | queue: rest}}
        state -> {{:error, :would_block}, state}
      end)
    end

    def info(%{id: id}), do: {:ok, Agent.get(id, & &1.metadata)}

    def attach(%{id: id} = connection, worker, _opts \\ []) do
      metadata = Agent.get(id, & &1.metadata)

      if observer = metadata[:observer] do
        spawn(fn ->
          ref = Process.monitor(worker)

          receive do
            {:DOWN, ^ref, :process, ^worker, reason} ->
              send(observer, {:consumer_down, connection, worker, reason})
          end
        end)
      end

      case metadata[:attach] do
        {:error, reason} -> {:error, reason}
        _ -> :ok
      end
    end

    def events(%{id: id}, max, _opts \\ []) do
      Agent.get_and_update(id, fn state ->
        {events, rest} = Enum.split(state.events, max)
        {{:ok, events}, %{state | events: rest}}
      end)
    end

    def close(%{id: id} = connection, code, reason, _opts) do
      if Process.alive?(id) do
        metadata = Agent.get(id, & &1.metadata)
        if observer = metadata[:observer], do: send(observer, {:closed, connection, code, reason})
      end

      :ok
    end
  end

  defp start_listener(opts \\ []) do
    defaults = [
      handler: {Handler, self()},
      alpn: ["test"],
      tls: [cert: [], key: :test, observer: self()],
      _backend: Backend,
      shutdown_timeout: 50
    ]

    Abyss.QUIC.start_link(Keyword.merge(defaults, opts))
  end

  defp endpoint! do
    assert_receive {:endpoint, endpoint}, 1_000
    endpoint
  end

  test "rejects a missing QUIC backend explicitly" do
    Process.flag(:trap_exit, true)

    assert {:error, :quic_backend_unavailable} =
             Abyss.QUIC.start_link(
               handler: Handler,
               alpn: ["test"],
               tls: [cert: [], key: :test],
               _backend: MissingBackend
             )
  end

  test "rejects invalid handler, ALPN, and wildcard bind before socket startup" do
    Process.flag(:trap_exit, true)

    assert {:error, :invalid_handler} =
             Abyss.QUIC.start_link(
               handler: MissingHandler,
               alpn: ["test"],
               tls: [cert: [], key: :test],
               _backend: Backend
             )

    assert {:error, :invalid_alpn} =
             Abyss.QUIC.start_link(
               handler: Handler,
               alpn: [<<>>],
               tls: [cert: [], key: :test],
               _backend: Backend
             )

    assert {:error, :wildcard_bind_unsupported} =
             Abyss.QUIC.start_link(
               handler: Handler,
               alpn: ["test"],
               tls: [cert: [], key: :test],
               ip: {0, 0, 0, 0},
               _backend: Backend
             )
  end

  test "rejects malformed handler tuples and credentials before opening a socket" do
    Process.flag(:trap_exit, true)

    assert {:error, :invalid_handler} =
             Abyss.QUIC.start_link(
               handler: {Handler, [], :extra},
               alpn: ["test"],
               tls: [cert: [], key: :test],
               _backend: Backend
             )

    assert {:error, :missing_server_credentials} =
             Abyss.QUIC.start_link(handler: Handler, alpn: ["test"], tls: [], _backend: Backend)
  end

  test "binds a handler only after an accepted connection and stops cleanly" do
    {:ok, listener} =
      Abyss.QUIC.start_link(
        handler: {Handler, self()},
        alpn: ["test"],
        tls: [cert: [], key: :test, observer: self()],
        _backend: Backend
      )

    assert_receive {:endpoint, endpoint}
    connection = Backend.connection()
    Backend.push(endpoint, connection)
    assert_receive {:bound, ^connection, %{alpn: "test"}, _worker}, 1_000
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "does not bind a negotiated ALPN the listener did not declare" do
    {:ok, listener} =
      Abyss.QUIC.start_link(
        handler: {Handler, self()},
        alpn: ["test"],
        tls: [cert: [], key: :test, observer: self()],
        _backend: Backend
      )

    assert_receive {:endpoint, endpoint}
    connection = Backend.connection(%{alpn: "other"})
    Backend.push(endpoint, connection)
    refute_receive {:bound, ^connection, _, _}, 100
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "slow consumer initialization does not block another accept or listener calls" do
    {:ok, listener} = start_listener()
    endpoint = endpoint!()
    slow = Backend.connection(%{alpn: "test", init: :slow, observer: self()})
    fast = Backend.connection(%{alpn: "test", observer: self()})

    Backend.push(endpoint, slow)
    assert_receive {:init_started, ^slow, slow_worker}, 1_000
    assert {:ok, {{127, 0, 0, 1}, _port}} = Abyss.QUIC.local(listener)

    Backend.push(endpoint, fast)
    assert_receive {:bound, ^fast, _, fast_worker}, 1_000
    assert Process.alive?(slow_worker)
    assert Process.alive?(fast_worker)

    send(slow_worker, {:release_init, slow})
    assert_receive {:bound, ^slow, _, ^slow_worker}, 1_000
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "consumer initialization failure is cleaned up and remains connection-local" do
    Process.flag(:trap_exit, true)
    {:ok, listener} = start_listener()
    endpoint = endpoint!()
    failed = Backend.connection(%{alpn: "test", init: :fail, observer: self()})
    Backend.push(endpoint, failed)
    assert_receive {:closed, ^failed, 0, <<>>}, 1_000
    assert Process.alive?(listener)

    healthy = Backend.connection(%{alpn: "test", observer: self()})
    Backend.push(endpoint, healthy)
    assert_receive {:bound, ^healthy, _, _}, 1_000
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "consumer initialization crash is observed by the engine and remains connection-local" do
    Process.flag(:trap_exit, true)
    {:ok, listener} = start_listener()
    endpoint = endpoint!()
    crashed = Backend.connection(%{alpn: "test", init: :crash, observer: self()})
    Backend.push(endpoint, crashed)
    assert_receive {:consumer_down, ^crashed, _worker, {%RuntimeError{}, _stack}}, 1_000
    assert Process.alive?(listener)

    healthy = Backend.connection(%{alpn: "test", observer: self()})
    Backend.push(endpoint, healthy)
    assert_receive {:bound, ^healthy, _, _}, 1_000
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "failed engine attachment is cleaned up without affecting other connections" do
    {:ok, listener} = start_listener()
    endpoint = endpoint!()
    failed = Backend.connection(%{alpn: "test", attach: {:error, :refused}, observer: self()})

    Backend.push(endpoint, failed)
    assert_receive {:closed, ^failed, 0, <<>>}, 1_000
    assert Process.alive?(listener)

    healthy = Backend.connection(%{alpn: "test", observer: self()})
    Backend.push(endpoint, healthy)
    assert_receive {:bound, ^healthy, _, _}, 1_000
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "callback timeout kills only the stalled consumer and engine observes cleanup" do
    {:ok, listener} = start_listener(callback_timeout: 30, poll_interval: 5)
    endpoint = endpoint!()
    stalled = Backend.connection(%{alpn: "test", observer: self()})
    healthy = Backend.connection(%{alpn: "test", observer: self()})

    Backend.push(endpoint, stalled)
    assert_receive {:bound, ^stalled, _, stalled_worker}, 1_000
    Backend.push_event(stalled, :block)
    assert_receive {:event_started, ^stalled_worker}, 1_000
    assert_receive {:consumer_down, ^stalled, ^stalled_worker, :killed}, 1_000
    refute Process.alive?(stalled_worker)
    assert Process.alive?(listener)

    Backend.push(endpoint, healthy)
    assert_receive {:bound, ^healthy, _, _}, 1_000
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "host component death fails the listener and its connection workers" do
    Process.flag(:trap_exit, true)

    for component <- [:writer, :endpoint, :receiver] do
      {:ok, listener} = start_listener()
      endpoint = endpoint!()
      connection = Backend.connection(%{alpn: "test", observer: self()})
      Backend.push(endpoint, connection)
      assert_receive {:bound, ^connection, _, worker}, 1_000

      listener_ref = Process.monitor(listener)
      component_pid = Map.fetch!(:sys.get_state(listener), component)
      Process.exit(component_pid, :kill)

      assert_receive {:DOWN, ^listener_ref, :process, ^listener, {:host_component_down, :killed}},
                     1_000

      refute Process.alive?(worker)
    end
  end

  test "killing the listener owner cannot leak connection workers" do
    Process.flag(:trap_exit, true)
    {:ok, listener} = start_listener()
    endpoint = endpoint!()
    connection = Backend.connection(%{alpn: "test", observer: self()})
    Backend.push(endpoint, connection)
    assert_receive {:bound, ^connection, _, worker}, 1_000
    worker_ref = Process.monitor(worker)

    Process.exit(listener, :kill)

    assert_receive {:DOWN, ^worker_ref, :process, ^worker, _}, 1_000
  end

  test "a normally stopped transient supervised listener stays stopped" do
    child =
      {Abyss.QUIC,
       handler: {Handler, self()},
       alpn: ["test"],
       tls: [cert: [], key: :test, observer: self()],
       _backend: Backend,
       shutdown_timeout: 50}

    {:ok, supervisor} = Supervisor.start_link([child], strategy: :one_for_one)
    [{_, listener, :worker, _}] = Supervisor.which_children(supervisor)
    endpoint!()

    assert :ok = Abyss.QUIC.stop(listener)
    assert [{_, :undefined, :worker, [Abyss.QUIC]}] = Supervisor.which_children(supervisor)
    refute_receive {:endpoint, _}, 50
    assert :ok = Supervisor.stop(supervisor)
  end

  test "an abnormal supervised restart replaces the listener generation and old workers" do
    engine_options = [idle_timeout: :infinity, handshake_timeout: 2000]

    child =
      {Abyss.QUIC,
       handler: {Handler, self()},
       alpn: ["test"],
       tls: [cert: [], key: :test, observer: self()],
       _backend: Backend,
       quic_options: engine_options,
       shutdown_timeout: 50}

    {:ok, supervisor} = Supervisor.start_link([child], strategy: :one_for_one)
    [{_, listener, :worker, _}] = Supervisor.which_children(supervisor)
    endpoint = endpoint!()

    assert Keyword.take(Backend.options(endpoint), [:idle_timeout, :handshake_timeout]) ==
             engine_options

    state = :sys.get_state(listener)
    connection = Backend.connection(%{alpn: "test", observer: self()})
    Backend.push(endpoint, connection)
    assert_receive {:bound, ^connection, _, worker}, 1_000
    listener_ref = Process.monitor(listener)
    worker_ref = Process.monitor(worker)

    Process.exit(state.writer, :kill)

    assert_receive {:DOWN, ^listener_ref, :process, ^listener, {:host_component_down, :killed}},
                   1_000

    assert_receive {:DOWN, ^worker_ref, :process, ^worker, _}, 1_000
    replacement_endpoint = endpoint!()

    assert Keyword.take(Backend.options(replacement_endpoint), [:idle_timeout, :handshake_timeout]) ==
             engine_options

    [{_, replacement, :worker, _}] = Supervisor.which_children(supervisor)
    refute replacement == listener
    refute :sys.get_state(replacement).generation == state.generation
    assert :ok = Supervisor.stop(supervisor)
  end

  test "late terminal events for another generation are ignored and close is delivered once" do
    {:ok, listener} = start_listener()
    endpoint = endpoint!()
    connection = Backend.connection(%{alpn: "test", observer: self()})
    Backend.push(endpoint, connection)
    assert_receive {:bound, ^connection, _, worker}, 1_000

    stale = Backend.with_generation(connection, make_ref())
    send(worker, {:quic_closed, stale, :stale})
    refute_receive {:event, {:closed, :stale}}, 50
    assert Process.alive?(worker)

    send(worker, {:quic_closed, connection, :peer_closed})
    send(worker, {:quic_closed, connection, :duplicate})
    assert_receive {:event, {:closed, :peer_closed}}, 1_000
    refute_receive {:event, {:closed, :duplicate}}, 50
    refute Process.alive?(worker)
    assert Process.alive?(listener)
    assert :ok = Abyss.QUIC.stop(listener)
  end

  test "rejects invalid timeouts, limits, unknown options, and non-keyword configuration" do
    Process.flag(:trap_exit, true)

    for option <- [
          {:init_timeout, 0},
          {:callback_timeout, -1},
          {:shutdown_timeout, :infinity},
          {:event_batch, 0},
          {:event_batch, 129},
          {:writer_max_bytes, 0}
        ] do
      assert {:error, :invalid_limit} = start_listener([option])
    end

    assert {:error, :unknown_option} = start_listener(unknown: true)
    assert {:error, :invalid_configuration} = Abyss.QUIC.start_link(:invalid)
  end

  test "rejects malformed engine limits before listener startup" do
    Process.flag(:trap_exit, true)

    for engine <- [
          [streams: [max_data: -1]],
          [streams: [max_buffer: 0]],
          [streams: [max_data: :infinity]],
          [streams: [unknown: 1]],
          [handshake_timeout: -1],
          [retry: :yes],
          [unknown: 1]
        ] do
      assert {:error, :invalid_quic_options} =
               Abyss.QUIC.start_link(
                 handler: Handler,
                 alpn: ["test"],
                 _backend: Backend,
                 tls: [cert: [], key: :test],
                 quic_options: engine
               )
    end
  end

  test "forwards finite and disabled local idle policy with independent operation bounds" do
    for idle_timeout <- [1000, :infinity] do
      engine_options = [
        idle_timeout: idle_timeout,
        handshake_timeout: 2000,
        closing_timeout: 3000,
        draining_timeout: 4000
      ]

      assert {:ok, listener} = start_listener(quic_options: engine_options)
      endpoint = endpoint!()

      assert Keyword.take(Backend.options(endpoint), Keyword.keys(engine_options)) ==
               engine_options

      assert :ok = Abyss.QUIC.stop(listener)
    end
  end

  test "rejects invalid idle policies and keeps other engine timers finite" do
    for value <- [0, -1, nil, false, "infinity", 1.5] do
      assert {:error, :invalid_quic_options} =
               start_listener(quic_options: [idle_timeout: value])
    end

    for key <- [:handshake_timeout, :closing_timeout, :draining_timeout],
        value <- [:infinity, 0, -1] do
      assert {:error, :invalid_quic_options} =
               start_listener(quic_options: [{:idle_timeout, :infinity}, {key, value}])
    end

    assert {:error, :invalid_quic_options} =
             start_listener(quic_options: [idle_timeout: :infinity, idle_timeout: 1000])
  end

  test "invalid startup returns an error without an asynchronous caller exit" do
    owner = self()

    {pid, ref} =
      spawn_monitor(fn ->
        result = Abyss.QUIC.start_link(handler: Handler, alpn: ["test"], _backend: MissingBackend)
        send(owner, {:startup_result, result})

        receive do
          :finish -> :ok
        end
      end)

    assert_receive {:startup_result, {:error, :quic_backend_unavailable}}
    send(pid, :finish)
    assert_receive {:DOWN, ^ref, :process, ^pid, :normal}
  end

  test "shutdown stops new ingress before waiting for consumer drain" do
    {:ok, listener} = start_listener(shutdown_timeout: 500)
    endpoint = endpoint!()
    connection = Backend.connection(%{alpn: "test", init: :slow})
    Backend.push(endpoint, connection)
    assert_receive {:init_started, ^connection, worker}
    receiver = :sys.get_state(listener).receiver
    monitor = Process.monitor(receiver)
    stopping = Task.async(fn -> Abyss.QUIC.stop(listener) end)
    assert_receive {:DOWN, ^monitor, :process, ^receiver, _}, 100
    assert Process.alive?(worker)
    send(worker, {:release_init, connection})
    assert :ok = Task.await(stopping)
  end
end
