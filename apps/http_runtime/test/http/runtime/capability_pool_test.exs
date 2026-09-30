defmodule HTTP.Runtime.CapabilityPoolTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.Pool

  defmodule Owner do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(_), do: {:ok, nil}
    def handle_info(_, state), do: {:noreply, state}
  end

  setup do
    {:ok, pool} =
      start_supervised({Pool, max_connections: 1, max_total_connections: 1, idle_timeout: 0})

    {:ok, owner} = start_supervised({Owner, nil})
    %{pool: pool, owner: owner}
  end

  test "unknown capability waits without a slot while ordinary clients progress", context do
    %{pool: pool, owner: owner} = context
    :ok = Pool.register(pool, :key, owner, max_streams: 1)
    {required, token} = waiter(pool, required_capability: :extended_connect)
    assert Pool.stats(pool).key.streams == 0
    assert {:ok, ^owner, ordinary} = Pool.reserve(pool, :key)
    :ok = Pool.update_capabilities(pool, :key, owner, %{extended_connect: true})
    assert :sys.get_state(pool).callers[token] != nil
    assert Pool.stats(pool).key.streams == 1
    :ok = Pool.release(pool, :key, ordinary)
    assert_receive {:result, ^required, {:ok, ^owner, ^token}}
    :ok = Pool.release(pool, :key, token)
    assert_clean(pool)
  end

  test "initial refusal settles all required waiters without stream reservations", context do
    %{pool: pool, owner: owner} = context
    :ok = Pool.register(pool, :key, owner)
    {first, _} = waiter(pool, required_capability: :extended_connect)
    {second, _} = waiter(pool, required_capability: :extended_connect)
    GenServer.cast(pool, {:owner_capabilities, :key, owner, %{extended_connect: false}})
    assert_receive {:result, ^first, {:error, :extended_connect_not_supported}}
    assert_receive {:result, ^second, {:error, :extended_connect_not_supported}}
    assert Pool.stats(pool).key.streams == 0
    assert_clean(pool)

    assert {:error, :extended_connect_not_supported} =
             Pool.reserve(pool, :key, required_capability: :extended_connect)
  end

  test "later capability enablement permits a new attempt on the same owner", context do
    %{pool: pool, owner: owner} = context
    :ok = Pool.register(pool, :key, owner)
    :ok = Pool.update_capabilities(pool, :key, owner, %{extended_connect: false})

    assert {:error, :extended_connect_not_supported} =
             Pool.reserve(pool, :key, required_capability: :extended_connect)

    :ok = Pool.update_capabilities(pool, :key, owner, %{extended_connect: true})

    assert {:ok, ^owner, token} =
             Pool.reserve(pool, :key, required_capability: :extended_connect)

    :ok = Pool.release(pool, :key, token)
    assert_clean(pool)
  end

  test "unknown head does not block eligible ordinary waiters and retains required FIFO",
       context do
    %{pool: pool, owner: owner} = context
    :ok = Pool.register(pool, :key, owner, max_streams: 0)
    {first, first_token} = waiter(pool, required_capability: :extended_connect)
    {ordinary, ordinary_token} = waiter(pool)
    {last, last_token} = waiter(pool, required_capability: :extended_connect)
    :ok = Pool.update_capacity(pool, :key, owner, 1)
    assert_receive {:result, ^ordinary, {:ok, ^owner, ^ordinary_token}}
    :ok = Pool.update_capabilities(pool, :key, owner, %{extended_connect: true})
    :ok = Pool.release(pool, :key, ordinary_token)
    assert_receive {:result, ^first, {:ok, ^owner, ^first_token}}
    assert :sys.get_state(pool).callers[last_token] != nil
    :ok = Pool.release(pool, :key, first_token)
    assert_receive {:result, ^last, {:ok, ^owner, ^last_token}}
    :ok = Pool.release(pool, :key, last_token)
    assert_clean(pool)
  end

  test "unknown required reservation cancellation and caller death remove monitors", context do
    %{pool: pool, owner: owner} = context
    :ok = Pool.register(pool, :key, owner)
    {cancelled, token} = waiter(pool, required_capability: :extended_connect)
    assert :ok = Pool.cancel(pool, token)
    send(cancelled, :stop)
    {dead, dead_token} = waiter(pool, required_capability: :extended_connect)
    Process.exit(dead, :kill)
    monitor = Process.monitor(dead)
    assert_receive {:DOWN, ^monitor, :process, ^dead, _}
    :ok = Pool.update_capabilities(pool, :key, owner, %{extended_connect: true})
    assert :sys.get_state(pool).callers[dead_token] == nil
    assert_clean(pool)
  end

  test "unknown required reservation retains its real admission deadline", context do
    %{pool: pool, owner: owner} = context
    :ok = Pool.register(pool, :key, owner)

    {caller, _} =
      waiter(pool,
        required_capability: :extended_connect,
        deadline_at: System.monotonic_time(:millisecond) + 100
      )

    assert_receive {:result, ^caller, {:error, :deadline_exceeded}}, 2_000
    assert_clean(pool)
  end

  test "invalid requirement is rejected before key or caller mutation", %{pool: pool} do
    for requirement <- [:unknown, true, nil] do
      assert {:error, :invalid_required_capability} =
               Pool.reserve(pool, :key, required_capability: requirement)
    end

    assert Pool.stats(pool) == %{}
    assert_clean(pool)
  end

  test "capability updates reject malformed values and unknown owners", context do
    %{pool: pool, owner: owner} = context

    assert {:error, :unknown_owner} =
             Pool.update_capabilities(pool, :key, owner, %{extended_connect: true})

    :ok = Pool.register(pool, :key, owner)

    assert {:error, :invalid_capabilities} =
             Pool.update_capabilities(pool, :key, owner, %{extended_connect: :unknown})

    assert {:error, :invalid_capabilities} = Pool.update_capabilities(pool, :key, owner, %{})
    assert :sys.get_state(pool).entries.key.connections[owner].extended_connect == :unknown
  end

  test "promoted connector retains token cleanup when its initial SETTINGS refuses CONNECT",
       context do
    %{pool: pool, owner: owner} = context
    test_pid = self()
    promotion = make_ref()
    admission = make_ref()
    handler = attach_queue(pool)

    caller =
      spawn(fn ->
        result =
          Pool.reserve(pool, :key,
            connect?: true,
            token: promotion,
            required_capability: :extended_connect
          )

        send(test_pid, {:promoted, self(), result})
        receive do: (:register -> :ok)
        :ok = Pool.register(pool, :key, owner, connecting?: true)

        result =
          Pool.reserve(pool, :key,
            token: admission,
            registered_owner: owner,
            required_capability: :extended_connect
          )

        send(test_pid, {:admitted, result})
        receive do: (:stop -> :ok)
      end)

    on_exit(fn -> Process.exit(caller, :kill) end)
    assert_receive :queued
    assert_receive {:promoted, ^caller, {:connect, ^promotion}}
    send(caller, :register)
    assert_receive :queued
    :telemetry.detach(handler)
    assert Pool.stats(pool).key.connecting == 0
    assert Pool.stats(pool).key.streams == 0
    :ok = Pool.update_capabilities(pool, :key, owner, %{extended_connect: false})
    assert_receive {:admitted, {:error, :extended_connect_not_supported}}
    assert {:ok, ^owner, ordinary} = Pool.reserve(pool, :key)
    :ok = Pool.release(pool, :key, ordinary)
    assert_clean(pool)
    send(caller, :stop)
  end

  test "required admission waits for its supported owner without using an unsupported sibling",
       %{owner: supported} do
    {:ok, pool} = start_supervised({Pool, max_connections: 2, idle_timeout: 0}, id: :two_pool)
    {:ok, unsupported} = start_supervised({Owner, nil}, id: :unsupported)
    :ok = Pool.register(pool, :key, supported, max_streams: 1)
    :ok = Pool.update_capabilities(pool, :key, supported, %{extended_connect: true})
    assert {:ok, ^supported, active} = Pool.reserve(pool, :key)
    :ok = Pool.register(pool, :key, unsupported, max_streams: 1)
    :ok = Pool.update_capabilities(pool, :key, unsupported, %{extended_connect: false})
    {caller, token} = waiter(pool, required_capability: :extended_connect)
    assert :sys.get_state(pool).entries.key.connections[unsupported].streams == 0
    assert {:ok, ^unsupported, ordinary} = Pool.reserve(pool, :key)
    :ok = Pool.release(pool, :key, active)
    assert_receive {:result, ^caller, {:ok, ^supported, ^token}}
    :ok = Pool.release(pool, :key, ordinary)
    :ok = Pool.release(pool, :key, token)
    assert_clean(pool)
  end

  test "unknown capability does not promote another connector before initial SETTINGS",
       %{owner: owner} do
    {:ok, pool} = start_supervised({Pool, max_connections: 2, idle_timeout: 0}, id: :two_pool)
    :ok = Pool.register(pool, :key, owner)
    {caller, _} = waiter(pool, required_capability: :extended_connect, connect?: true)
    assert Pool.stats(pool).key.connecting == 0
    :ok = Pool.update_capabilities(pool, :key, owner, %{extended_connect: false})
    assert_receive {:result, ^caller, {:error, :extended_connect_not_supported}}
    assert_clean(pool)
  end

  test "capability is per owner and replacement on the same key starts unknown", %{owner: first} do
    {:ok, pool} = start_supervised({Pool, max_connections: 1, idle_timeout: 0}, id: :replace_pool)
    :ok = Pool.register(pool, :key, first)
    :ok = Pool.update_capabilities(pool, :key, first, %{extended_connect: false})
    :ok = Pool.mark_draining(pool, :key, first)
    {:ok, replacement} = start_supervised({Owner, nil}, id: :replacement)
    :ok = Pool.register(pool, :key, replacement)
    {caller, token} = waiter(pool, required_capability: :extended_connect)
    assert Pool.stats(pool).key.streams == 0
    :ok = Pool.update_capabilities(pool, :key, replacement, %{extended_connect: true})
    assert_receive {:result, ^caller, {:ok, ^replacement, ^token}}
    :ok = Pool.release(pool, :key, token)
    assert_clean(pool)
  end

  test "one SETTINGS observation enables CONNECT with zero capacity without granting a slot",
       %{pool: pool, owner: owner} do
    :ok = Pool.register(pool, :key, owner, max_streams: 1)
    {caller, token} = waiter(pool, required_capability: :extended_connect)
    GenServer.cast(pool, {:owner_settings, :key, owner, %{extended_connect: true}, 0})
    assert %{streams: 0, pending: 1} = Pool.stats(pool).key
    state = :sys.get_state(pool)
    assert state.entries.key.connections[owner].extended_connect == true
    assert state.entries.key.connections[owner].max_streams == 0
    assert state.callers[token] != nil
    refute_receive {:result, ^caller, _}, 0
    GenServer.cast(pool, {:owner_settings, :key, owner, %{extended_connect: true}, 1})
    assert_receive {:result, ^caller, {:ok, ^owner, ^token}}
    :ok = Pool.release(pool, :key, token)
    assert_clean(pool)
  end

  test "one SETTINGS refusal with zero capacity settles required waiters without slots",
       %{pool: pool, owner: owner} do
    :ok = Pool.register(pool, :key, owner, max_streams: 1)
    {caller, _} = waiter(pool, required_capability: :extended_connect)
    GenServer.cast(pool, {:owner_settings, :key, owner, %{extended_connect: false}, 0})
    assert_receive {:result, ^caller, {:error, :extended_connect_not_supported}}
    assert %{streams: 0, pending: 0} = Pool.stats(pool).key
    assert :none = Pool.try_reserve(pool, :key)
    assert_clean(pool)
  end

  test "malformed SETTINGS observations cannot partially enable capabilities", context do
    %{pool: pool, owner: owner} = context
    :ok = Pool.register(pool, :key, owner, max_streams: 1)

    for {capabilities, capacity} <- [
          {%{extended_connect: true}, -1},
          {%{extended_connect: true}, :invalid},
          {%{extended_connect: :unknown}, 0},
          {%{}, 0}
        ] do
      GenServer.cast(pool, {:owner_settings, :key, owner, capabilities, capacity})
      connection = :sys.get_state(pool).entries.key.connections[owner]
      assert connection.extended_connect == :unknown
      assert connection.max_streams == 1
    end
  end

  defp waiter(pool, opts \\ []) do
    parent = self()
    token = make_ref()
    handler = attach_queue(pool)

    caller =
      spawn(fn ->
        result = Pool.reserve(pool, :key, Keyword.merge([token: token], opts))
        send(parent, {:result, self(), result})
        receive do: (:stop -> :ok)
      end)

    on_exit(fn -> Process.exit(caller, :kill) end)
    assert_receive :queued
    :telemetry.detach(handler)
    assert :sys.get_state(pool).callers[token] != nil
    {caller, token}
  end

  defp attach_queue(pool) do
    parent = self()
    handler = make_ref()

    :ok =
      :telemetry.attach(
        handler,
        [:http_fetch, :http2, :pool],
        fn _, _, metadata, _ ->
          if self() == pool and metadata.event == :queued, do: send(parent, :queued)
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler) end)
    handler
  end

  defp assert_clean(pool) do
    state = :sys.get_state(pool)
    assert state.callers == %{}
    assert state.reservations == %{}
    assert state.promotions == %{}
    assert state.deadlines == %{}
    assert state.connectors == %{}
  end
end
