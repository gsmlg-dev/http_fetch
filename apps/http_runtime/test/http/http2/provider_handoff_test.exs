defmodule HTTP.HTTP2.ProviderHandoffTest do
  use ExUnit.Case, async: true

  alias HTTP.HTTP2.{ConnectionOwner, Pool}
  alias HTTP.{Request, RequestLifecycle}
  alias HTTP.Runtime.Stream

  test "expired queued preparation neither reserves capacity nor activates an owner" do
    pool = start_supervised!({Pool, max_total_connections: 1})
    owner = inert_owner()
    :sys.suspend(pool)
    deadline = now() + 20

    queued =
      Task.async(fn -> GenServer.call(pool, {:prepare_provider, :key, owner, [], deadline}) end)

    witness = :erlang.start_timer(30, self(), :expired)
    assert_receive {:timeout, ^witness, :expired}
    :sys.resume(pool)

    assert {:error, :handoff_expired} = Task.await(queued)
    assert Pool.stats(pool) == %{}
    assert %{wrote_preface?: false} = ConnectionOwner.status(owner)
    refute_receive {:wire, _}, 0
  end

  test "a lost offer retains bounded unpublished capacity without activating or redialing" do
    pool = start_supervised!({Pool, max_connections: 1, max_total_connections: 1})
    owner = inert_owner()
    tracker = tracker({:error, :handoff_unconfirmed})

    assert {:error, :handoff_unconfirmed, :registered} =
             Pool.register(pool, :key, owner,
               provider_handoff: true,
               request_lifecycle: tracker,
               socket: :opaque_socket,
               deadline_at: now() + 1_000
             )

    assert %{connections: 0, provider_pending: 1} = Pool.stats(pool).key
    assert :none = Pool.try_reserve(pool, :key)
    assert :wait = Pool.claim_connect(pool, :key)
    refute_receive {:wire, _}, 0
    monitor = Process.monitor(owner)
    assert_receive {:DOWN, ^monitor, :process, ^owner, _}, 1_000
    refute_receive :transport_closed, 0
  end

  test "rejected opaque acceptance retains unconfirmed evidence and never publishes" do
    pool = start_supervised!({Pool, max_connections: 1, max_total_connections: 1})
    owner = inert_owner()
    carrier = %{handle: :missing, transfer: :missing, epoch: 0, nonce: make_ref()}
    tracker = tracker({:ok, carrier})

    assert {:error, :invalid_transfer, :registered} =
             Pool.register(pool, :key, owner,
               provider_handoff: true,
               request_lifecycle: tracker,
               socket: :opaque_socket,
               deadline_at: now() + 1_000
             )

    assert :unconfirmed =
             RequestLifecycle.provider_cleanup(SSL.Lifecycle.await(:missing, {:abs_ms, now()}))

    assert %{connections: 0, provider_pending: 1} = Pool.stats(pool).key
    assert %{wrote_preface?: false} = ConnectionOwner.status(owner)
    refute_receive {:wire, _}, 0
  end

  test "unactivated owner death cannot manufacture provider cleanup or free pending capacity" do
    pool = start_supervised!({Pool, max_connections: 1, max_total_connections: 1})
    owner = inert_owner()
    deadline = now() + 1_000
    assert :ok = GenServer.call(pool, {:prepare_provider, :key, owner, [], deadline})
    GenServer.stop(owner)
    assert %{connections: 0, provider_pending: 1} = Pool.stats(pool).key
    assert :wait = Pool.claim_connect(pool, :key)
  end

  for opening_timeout <- [0, 30, :infinity] do
    @tag :p3_ex_ssl_h2
    test "Runtime lifecycle admission consumes original #{opening_timeout} opening budget" do
      pool = start_supervised!({Pool, max_total_connections: 0})
      {tracker, latch} = RequestLifecycle.start()
      :sys.suspend(tracker)

      request = %Request{
        url: URI.parse("https://localhost:1/never"),
        transport_options: [
          tls_backend: :ex_ssl,
          http_version: :http2,
          request_lifecycle: tracker,
          http2_pool: pool
        ]
      }

      assert {:ok, stream, generation} =
               Stream.start(request, self(), opening_timeout: unquote(opening_timeout))

      down = Process.monitor(stream)

      try do
        wait = if unquote(opening_timeout) == :infinity, do: 1_200, else: 200
        assert_receive {:http_runtime, ^generation, ^stream, {:error, :opening_timeout}}, wait

        if unquote(opening_timeout) == 0 do
          assert_receive {:DOWN, ^down, :process, ^stream, reason}, 200
          assert reason in [:normal, :noproc]
        else
          assert_receive {:DOWN, ^down, :process, ^stream, :normal}, 200
        end
      after
        if Process.alive?(stream), do: Process.exit(stream, :kill)
        :sys.resume(tracker)
      end

      tracker_down = Process.monitor(tracker)
      assert_receive {:DOWN, ^tracker_down, :process, ^tracker, _}, 1_000
      assert :atomics.get(latch, 1) == 2
      assert Pool.stats(pool) == %{}
    end
  end

  @tag :p3_ex_ssl_h2
  test "Runtime completion does not wait behind a suspended tracker" do
    pool = start_supervised!({Pool, max_total_connections: 0})
    {tracker, latch} = RequestLifecycle.start()

    request = %Request{
      url: URI.parse("https://localhost:1/never"),
      transport_options: [
        tls_backend: :ex_ssl,
        http_version: :http2,
        request_lifecycle: tracker,
        http2_pool: pool
      ]
    }

    assert {:ok, stream, generation} = Stream.start(request, self(), opening_timeout: 1_000)
    down = Process.monitor(stream)
    wait_pending(pool, System.monotonic_time(:millisecond) + 200)
    :sys.suspend(tracker)

    try do
      Stream.close(stream)
      assert_receive {:http_runtime, ^generation, ^stream, {:error, :aborted}}, 200
      assert_receive {:DOWN, ^down, :process, ^stream, :normal}, 200
      assert :atomics.get(latch, 1) == 1
    after
      if Process.alive?(stream), do: Process.exit(stream, :kill)
      :sys.resume(tracker)
    end

    tracker_down = Process.monitor(tracker)
    assert_receive {:DOWN, ^tracker_down, :process, ^tracker, _}, 1_000
    assert :atomics.get(latch, 1) == 2
    assert Pool.stats(pool) == %{}
  end

  @tag :p3_ex_ssl_h2
  test "H2 owner enrollment is bounded and a late ACK cannot activate the transport" do
    parent = self()
    {tracker, latch} = RequestLifecycle.start()
    owner = inert_owner()
    owner_down = Process.monitor(owner)

    worker =
      spawn(fn ->
        receive do
          :enroll ->
            deadline = now() + 30
            result = RequestLifecycle.register(tracker, owner, :connection, deadline)
            send(parent, {:enrollment_result, result})
            send(owner, :http2_shutdown_exclusive)
            RequestLifecycle.complete(tracker, deadline)
        end
      end)

    down = Process.monitor(worker)
    assert :ok = RequestLifecycle.register(tracker, worker, :task)
    :sys.suspend(tracker)

    try do
      send(worker, :enroll)
      assert_receive {:enrollment_result, {:error, :request_timeout}}, 200
      assert_receive {:DOWN, ^down, :process, ^worker, :normal}, 200
      assert_receive {:DOWN, ^owner_down, :process, ^owner, _}, 200
      refute_receive {:wire, _}, 0
      refute_receive :transport_closed, 0
    after
      if Process.alive?(worker), do: Process.exit(worker, :kill)
      :sys.resume(tracker)
    end

    tracker_down = Process.monitor(tracker)
    assert_receive {:DOWN, ^tracker_down, :process, ^tracker, _}, 1_000
    assert :atomics.get(latch, 1) == 2
  end

  defp wait_pending(pool, deadline) do
    unless Enum.any?(Pool.stats(pool), fn {_, entry} -> entry.pending == 1 end) do
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        1 -> wait_pending(pool, deadline)
      end
    end
  end

  defp inert_owner do
    caller = self()

    transport = %{
      send: fn _, bytes ->
        send(caller, {:wire, bytes})
        :ok
      end,
      setopts: fn _, _ -> :ok end,
      close: fn _ ->
        send(caller, :transport_closed)
        :ok
      end,
      normalize_message: fn _, _ -> :unknown end
    }

    start_supervised!(
      Supervisor.child_spec(
        {ConnectionOwner, transport: transport, socket: :socket, activate?: false},
        restart: :temporary
      )
    )
  end

  defp tracker(response) do
    pid = spawn(fn -> tracker_loop(response) end)
    on_exit(fn -> send(pid, :stop) end)
    pid
  end

  defp tracker_loop(response) do
    receive do
      {:"$gen_call", from, {:offer_provider, _, _, _}} ->
        GenServer.reply(from, response)
        tracker_loop(response)

      {:"$gen_cast", :provider_failed} ->
        tracker_loop(response)

      :stop ->
        :ok
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
