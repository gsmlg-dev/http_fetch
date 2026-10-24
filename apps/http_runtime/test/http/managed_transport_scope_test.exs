defmodule HTTP.ManagedTransport.ScopeTest do
  use ExUnit.Case, async: false

  alias ExSSL.TestSupport.ManagedLifecycleProbe, as: Probe
  alias HTTP.ManagedTransport
  alias HTTP.ManagedTransport.Scope

  test "preconstructor birth fence rejects forged retention and survives tracker loss" do
    {scope, request} = ex_ssl_scope()
    {tracker, request, token} = connector(request)

    assert {:ok, %{connections: 1, provider_resources: nil}} =
             ManagedTransport.snapshot(scope, 100)

    {:ok, handle, lease} = SSL.Lifecycle.new(controller: self(), deadline: :infinity)

    assert {:error, :invalid_provider_registration} =
             GenServer.call(scope.coordinator, {:track_provider, token, handle, now() + 1_000})

    assert {:error, :invalid_provider_registration} =
             GenServer.call(
               scope.coordinator,
               {:track_provider, make_ref(), :invalid, now() + 1_000}
             )

    assert :ok = SSL.Lifecycle.cancel(lease, {:abs_ms, now() + 1_000})
    assert {:ok, _} = SSL.Lifecycle.await(handle, {:abs_ms, now() + 1_000})
    GenServer.stop(tracker, :normal)
    assert :ok = ManagedTransport.connect_done(request, token)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 0)
    Process.delete(HTTP.RequestLifecycle)
  end

  test "Handle retention ACK precedes descriptor publication and any native allocation" do
    {scope, request} = ex_ssl_scope()
    {tracker, request, token} = connector(request)

    assert {:ok, {handle, _lease}} =
             HTTP.RequestLifecycle.begin_provider(tracker, :ex_ssl, now() + 1_000)

    assert [^handle] = Probe.handles(scope)

    assert {:pending, %{roles: 0, allocations: 0, setup: :not_started}} =
             SSL.Lifecycle.status(handle)

    assert {:ok,
            %{
              connections: 1,
              provider_resources: %{
                processes: 1,
                observers: 1,
                tcp_sockets: 0,
                data_resources: 0,
                generations: 1
              }
            }} =
             ManagedTransport.snapshot(scope, 100)

    assert :ok = ManagedTransport.connect_done(request, token)
    HTTP.RequestLifecycle.provider_failed(tracker)
    assert {:ok, %{cleanup: :confirmed}} = SSL.Lifecycle.await(handle, {:abs_ms, now() + 1_000})
    GenServer.stop(tracker, :normal)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    Process.delete(HTTP.RequestLifecycle)
  end

  test "late Handle ACK cannot authorize data allocation after the original deadline" do
    {scope, request} = ex_ssl_scope()
    {tracker, request, token} = connector(request)
    :sys.suspend(scope.coordinator)
    deadline = now() + 80

    caller =
      Task.async(fn -> HTTP.RequestLifecycle.begin_provider(tracker, :ex_ssl, deadline) end)

    handle =
      try do
        wait_until(fn ->
          {:messages, messages} = Process.info(scope.coordinator, :messages)

          Enum.any?(
            messages,
            &match?({:"$gen_call", {^tracker, _}, {:track_provider, ^token, _, ^deadline}}, &1)
          )
        end)

        {:messages, messages} = Process.info(scope.coordinator, :messages)

        {_, _, {:track_provider, ^token, handle, ^deadline}} =
          Enum.find(
            messages,
            &match?({:"$gen_call", {^tracker, _}, {:track_provider, ^token, _, ^deadline}}, &1)
          )

        assert Task.await(caller, 500) in [
                 {:error, :request_timeout},
                 {:error, :cleanup_unconfirmed}
               ]

        handle
      after
        :sys.resume(scope.coordinator)
      end

    assert {:ok, %{roles: 0, cleanup: :confirmed}} =
             SSL.Lifecycle.await(handle, {:abs_ms, now() + 1_000})

    assert :ok = ManagedTransport.connect_done(request, token)
    GenServer.stop(tracker, :normal)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    Process.delete(HTTP.RequestLifecycle)
  end

  test "100 retained Handles share one finite numerical observation deadline" do
    {scope, request} = ex_ssl_scope(128, 100)

    connectors =
      for _ <- 1..100 do
        {tracker, prepared, token} = connector(request)

        assert {:ok, {handle, _lease}} =
                 HTTP.RequestLifecycle.begin_provider(tracker, :ex_ssl, now() + 1_000)

        assert :ok = ManagedTransport.connect_done(prepared, token)
        {tracker, handle}
      end

    assert {:ok,
            %{
              provider_resources: %{
                processes: 100,
                observers: 100,
                tcp_sockets: 0,
                data_resources: 0,
                generations: 1
              }
            }} =
             ManagedTransport.snapshot(scope, 1_000)

    control = Probe.observer_control(scope)
    Probe.suspend(control, :observer)
    entered = now()

    try do
      case ManagedTransport.snapshot(scope, 50) do
        {:error, :cleanup_pending} -> :ok
        {:ok, %{provider_resources: nil}} -> :ok
        other -> flunk("suspended Observer returned fabricated counts: #{inspect(other)}")
      end

      assert %{coordinator: coordinator} = GenServer.call(scope.coordinator, :handle, 100)
      assert coordinator == scope.coordinator
      assert Probe.alive?(control, :observer)
    after
      Probe.resume(control, :observer)
    end

    assert now() - entered < 250

    assert {:ok, %{provider_resources: %{observers: 100}}} =
             ManagedTransport.snapshot(scope, 1_000)

    for {tracker, handle} <- connectors do
      HTTP.RequestLifecycle.provider_failed(tracker)
      assert {:ok, _} = SSL.Lifecycle.await(handle, {:abs_ms, now() + 1_000})
      GenServer.stop(tracker, :normal)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    Process.delete(HTTP.RequestLifecycle)
  end

  test "authenticated no-constructor completion discharges only its own birth fence" do
    {scope, request} = ex_ssl_scope()
    parent = self()

    worker =
      spawn(fn ->
        {tracker, prepared, token} = connector(request)
        :ok = HTTP.RequestLifecycle.enter(tracker, :owner)
        send(parent, {:reserved_birth, self(), tracker, token})
        receive do: (:finish -> :ok)
        :ok = ManagedTransport.connect_done(prepared, token)
        :ok = HTTP.RequestLifecycle.complete(tracker)
      end)

    assert_receive {:reserved_birth, ^worker, tracker, token}, 1_000
    monitor = Process.monitor(tracker)

    assert {:error, :invalid_provider_registration} =
             GenServer.call(scope.coordinator, {:provider_not_started, token})

    assert {:ok, %{connections: 1, provider_resources: nil}} =
             ManagedTransport.snapshot(scope, 100)

    send(worker, :finish)
    assert_receive {:DOWN, ^monitor, :process, ^tracker, :normal}, 1_000
    wait_for(scope, :connections, 0)

    assert {:ok,
            %{
              provider_resources: %{
                processes: 0,
                observers: 0,
                tcp_sockets: 0,
                data_resources: 0,
                generations: 1
              }
            }} = ManagedTransport.snapshot(scope, 100)

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
  end

  for outcome <- [:complete, :lost] do
    @tag :p3_scope_order
    test "queued reconcile respects ordered no-constructor evidence when tracker is #{outcome}" do
      ordered_birth_completion(unquote(outcome))
    end
  end

  test "no-constructor discharge rejects wrong caller, token and repeated evidence" do
    {scope, request} = ex_ssl_scope()
    {tracker, prepared, token} = connector(request)
    invalid = {:error, :invalid_provider_registration}
    assert ^invalid = GenServer.call(scope.coordinator, {:provider_not_started, token})

    # Execute authenticated calls in the original tracker without constructing
    # any provider. Its exact state is retained by the fault instrumentation.
    :sys.replace_state(tracker, fn state ->
      assert ^invalid = GenServer.call(scope.coordinator, {:provider_not_started, make_ref()})
      assert :ok = GenServer.call(scope.coordinator, {:provider_not_started, token})
      assert ^invalid = GenServer.call(scope.coordinator, {:provider_not_started, token})
      state
    end)

    assert :ok = ManagedTransport.connect_done(prepared, token)
    GenServer.stop(tracker, :normal)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    Process.delete(HTTP.RequestLifecycle)
  end

  defp ordered_birth_completion(outcome) do
    {scope, request} = ex_ssl_scope()
    parent = self()

    worker =
      spawn(fn ->
        {tracker, prepared, token} = connector(request)
        :ok = HTTP.RequestLifecycle.enter(tracker, :owner)
        send(parent, {:reserved_birth, self(), tracker, token})
        receive do: (:finish -> :ok)
        :ok = ManagedTransport.connect_done(prepared, token)

        case outcome do
          :complete -> :ok = HTTP.RequestLifecycle.complete(tracker)
          :lost -> Process.exit(tracker, :kill)
        end
      end)

    assert_receive {:reserved_birth, ^worker, tracker, token}, 1_000
    before = :sys.get_state(scope.coordinator)
    assert before.slots[token].provider == :birth
    assert tracker in Map.values(before.requests)
    monitor = Process.monitor(tracker)
    :ok = :sys.suspend(scope.coordinator)

    try do
      send(scope.coordinator, {:timeout, before.reconcile_timer, :reconcile})
      send(worker, :finish)
      assert_receive {:DOWN, ^monitor, :process, ^tracker, _}, 1_000
      refute Process.alive?(tracker)
      {:messages, messages} = Process.info(scope.coordinator, :messages)

      timer_index =
        Enum.find_index(messages, &match?({:timeout, _, :reconcile}, &1))

      discharge_index =
        Enum.find_index(
          messages,
          &match?({:"$gen_call", {^tracker, _}, {:provider_not_started, ^token}}, &1)
        )

      down_index = Enum.find_index(messages, &match?({:DOWN, _, :process, ^tracker, _}, &1))
      assert is_integer(timer_index) and is_integer(down_index)
      assert timer_index < down_index

      if outcome == :complete do
        assert is_integer(discharge_index)
        assert timer_index < discharge_index and discharge_index < down_index
      else
        assert discharge_index == nil
      end
    after
      :sys.resume(scope.coordinator)
    end

    assert_birth_outcome(scope, outcome)
  end

  defp assert_birth_outcome(scope, :complete) do
    assert {:ok,
            %{
              lifecycle: :open,
              connections: 0,
              provider_resources: %{
                processes: 0,
                observers: 0,
                tcp_sockets: 0,
                data_resources: 0,
                generations: 1
              }
            }} = ManagedTransport.snapshot(scope, 1_000)

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
  end

  defp assert_birth_outcome(scope, :lost) do
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :transport_scope_retired} = ManagedTransport.snapshot(scope, 100)
  end

  test "lost Observer remains unknown and cannot erase constructor evidence with no-birth message" do
    {scope, request} = ex_ssl_scope()
    {tracker, prepared, token} = connector(request)

    assert {:ok, {handle, _}} =
             HTTP.RequestLifecycle.begin_provider(tracker, :ex_ssl, now() + 1_000)

    control = Probe.observer_control(scope)
    Probe.kill_observer(control)
    wait_until(fn -> not Probe.alive?(control, :observer) end)

    assert {:unconfirmed, :observer_unsealed} =
             SSL.Lifecycle.status(handle, {:abs_ms, now() + 100})

    assert {:error, :invalid_provider_registration} =
             GenServer.call(scope.coordinator, {:provider_not_started, token})

    assert {:ok, %{provider_resources: nil}} = ManagedTransport.snapshot(scope, 100)
    assert :ok = ManagedTransport.connect_done(prepared, token)
    GenServer.stop(tracker, :normal)
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 0)
    Process.delete(HTTP.RequestLifecycle)
  end

  test "tracker death after constructor entry retains queued Handle and joins cancellation before retirement" do
    {scope, request} = ex_ssl_scope()
    {tracker, prepared, token} = connector(request)
    :sys.suspend(scope.coordinator)

    caller =
      Task.async(fn -> HTTP.RequestLifecycle.begin_provider(tracker, :ex_ssl, now() + 1_000) end)

    handle =
      try do
        wait_until(fn ->
          {:messages, messages} = Process.info(scope.coordinator, :messages)

          Enum.any?(
            messages,
            &match?({:"$gen_call", {^tracker, _}, {:track_provider, ^token, _, _}}, &1)
          )
        end)

        {:messages, messages} = Process.info(scope.coordinator, :messages)

        {_, _, {:track_provider, ^token, handle, _}} =
          Enum.find(
            messages,
            &match?({:"$gen_call", {^tracker, _}, {:track_provider, ^token, _, _}}, &1)
          )

        Process.exit(tracker, :kill)
        assert {:error, :cleanup_unconfirmed} = Task.await(caller, 1_000)
        handle
      after
        :sys.resume(scope.coordinator)
      end

    assert :ok = ManagedTransport.connect_done(prepared, token)

    assert {:ok, %{roles: 0, cleanup: :confirmed}} =
             SSL.Lifecycle.await(handle, {:abs_ms, now() + 1_000})

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
    Process.delete(HTTP.RequestLifecycle)
  end

  test "stale reconciliation messages cannot create maintenance chains" do
    state = %{reconcile_timer: make_ref()}

    for _ <- 1..500 do
      assert {:noreply, ^state} =
               Scope.handle_info({:timeout, make_ref(), :reconcile}, state)

      assert {:noreply, ^state} = Scope.handle_info(:reconcile, state)
    end
  end

  for kind <- [:connection, :tls] do
    @tag :integration
    test "closed raw socket retains capacity until its #{kind} process terminates" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}])
      {:ok, {_, port}} = :inet.sockname(listener)
      origin = "http://127.0.0.1:#{port}"

      {:ok, scope} =
        ManagedTransport.open(
          origin: origin,
          connect_address: {127, 0, 0, 1},
          http_version: :http1,
          max_requests: 1,
          max_connections: 1
        )

      {tracker, _} = HTTP.RequestLifecycle.start()

      request = %HTTP.Request{
        url: URI.parse(origin),
        transport_options: [
          transport_scope: scope,
          redirect: :manual,
          decode_body: false,
          stream_response: true
        ]
      }

      assert {:ok, request} = ManagedTransport.prepare(request, [])
      assert :ok = ManagedTransport.associate(request, tracker)
      assert :ok = ManagedTransport.admit(request, tracker)
      Process.put(HTTP.RequestLifecycle, tracker)
      assert {:ok, token} = ManagedTransport.connect_start(request)
      {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 100)
      owner = spawn(fn -> receive do: (:fixture_stop -> :ok) end)
      owner_monitor = Process.monitor(owner)

      on_exit(fn ->
        :gen_tcp.close(listener)
        :gen_tcp.close(socket)
        send(owner, :fixture_stop)
      end)

      assert :ok = GenServer.call(scope.coordinator, {:track, socket, :socket, token})
      assert :ok = GenServer.call(scope.coordinator, {:track, owner, unquote(kind), token})
      assert :ok = ManagedTransport.connect_done(request, token)
      :gen_tcp.close(socket)
      wait_for(scope, :resources, 1)

      assert {:ok, %{connections: 1}} = ManagedTransport.snapshot(scope, 100)

      assert {:error, {:transport_scope_capacity, :connections}} =
               ManagedTransport.connect_start(request)

      send(owner, :fixture_stop)
      assert_receive {:DOWN, ^owner_monitor, _, ^owner, :normal}
      wait_for(scope, :connections, 0)
      assert {:ok, replacement} = ManagedTransport.connect_start(request)
      assert :ok = ManagedTransport.connect_done(request, replacement)
      GenServer.stop(tracker, :normal)
      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert :ok = ManagedTransport.await_retired(receipt, 1_000)
      Process.delete(HTTP.RequestLifecycle)
    end
  end

  @tag :integration
  test "unknown TLS inventory retires admission and preserves unconfirmed generation evidence" do
    {:ok, scope} =
      ManagedTransport.open(
        origin: "https://localhost:443",
        ssl: [
          cacertfile:
            Path.expand("../../../http_fetch/test/support/fixtures/localhost-ca.pem", __DIR__)
        ],
        connect_address: {127, 0, 0, 1},
        http_version: :http1,
        max_requests: 1,
        max_connections: 1
      )

    {tracker, latch} = HTTP.RequestLifecycle.start()

    request = %HTTP.Request{
      url: URI.parse("https://localhost/"),
      transport_options: [
        transport_scope: scope,
        redirect: :manual,
        decode_body: false,
        stream_response: true
      ]
    }

    assert {:ok, request} = ManagedTransport.prepare(request, [])
    assert :ok = ManagedTransport.associate(request, tracker)
    assert :ok = ManagedTransport.admit(request, tracker)

    parent = self()

    owner =
      spawn(fn ->
        HTTP.RequestLifecycle.enter(tracker, :owner)
        send(parent, :registered)

        receive do
          :finish -> HTTP.RequestLifecycle.complete(tracker)
        end
      end)

    assert_receive :registered

    assert {:error, :unsupported_tls_socket_representation} =
             HTTP.RequestLifecycle.track_tls([request_lifecycle: tracker], {:sslsocket, :opaque})

    assert :sys.get_state(tracker).uncertain?
    wait_for(scope, :lifecycle, :draining)
    assert Process.alive?(owner)
    assert {:messages, []} = Process.info(owner, :messages)
    Process.put(HTTP.RequestLifecycle, tracker)
    assert {:error, :transport_scope_retired} = ManagedTransport.connect_start(request)
    Process.delete(HTTP.RequestLifecycle)
    monitor = Process.monitor(tracker)
    send(owner, :finish)
    assert_receive {:DOWN, ^monitor, :process, ^tracker, :normal}, 1_000
    assert :atomics.get(latch, 1) == 3
    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 0)

    assert {:error, :transport_scope_retired} = ManagedTransport.prepare(request, [])
  end

  defp wait_for(scope, key, expected, remaining \\ 100)
  defp wait_for(_, _, _, 0), do: flunk("scope resources did not settle")

  defp wait_for(scope, key, expected, remaining) do
    assert {:ok, snapshot} = ManagedTransport.snapshot(scope, 100)

    if snapshot[key] != expected do
      receive do
      after
        5 -> wait_for(scope, key, expected, remaining - 1)
      end
    end
  end

  defp ex_ssl_scope(requests \\ 8, connections \\ 1) do
    assert {:ok, scope} =
             ManagedTransport.open(
               origin: "https://localhost",
               connect_address: {127, 0, 0, 1},
               http_version: :http1,
               tls_backend: :ex_ssl,
               ssl: [cacerts: []],
               max_requests: requests,
               max_connections: connections
             )

    on_exit(fn ->
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      ManagedTransport.await_retired(receipt, 1_000)
    end)

    {scope,
     %HTTP.Request{
       url: URI.parse("https://localhost/"),
       transport_options: [
         transport_scope: scope,
         redirect: :manual,
         decode_body: false,
         stream_response: true
       ]
     }}
  end

  defp connector(request) do
    {tracker, _latch} = HTTP.RequestLifecycle.start()
    assert {:ok, prepared} = ManagedTransport.prepare(request, [])
    assert :ok = ManagedTransport.associate(prepared, tracker)
    assert :ok = ManagedTransport.admit(prepared, tracker)
    Process.put(HTTP.RequestLifecycle, tracker)
    assert {:ok, token} = ManagedTransport.connect_start(prepared)
    {tracker, prepared, token}
  end

  defp now, do: System.monotonic_time(:millisecond)

  defp wait_until(fun, deadline \\ nil) do
    deadline = deadline || now() + 1_000

    unless fun.() do
      assert now() < deadline

      receive do
      after
        1 -> wait_until(fun, deadline)
      end
    end
  end
end
