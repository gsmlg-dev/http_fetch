defmodule HTTP.ManagedTransportAdmissionTest do
  use ExUnit.Case, async: false

  alias HTTP.ManagedTransport
  alias HTTP.Request
  alias HTTP.RequestCompletion
  alias HTTP.RequestLifecycle

  test "original bind_scope/3 retains its reply and original deadline" do
    {scope, _request} = scope()
    {tracker, _latch} = RequestLifecycle.start()
    deadline = System.monotonic_time(:millisecond) + 1_000

    try do
      assert :ok = RequestLifecycle.bind_scope(tracker, scope.coordinator, deadline)
      assert %{scope: coordinator, deadline: ^deadline} = :sys.get_state(tracker)
      assert coordinator == scope.coordinator
      expired = System.monotonic_time(:millisecond) - 1

      assert {:error, :request_timeout} =
               RequestLifecycle.bind_scope(tracker, coordinator, expired)
    after
      GenServer.stop(tracker)
    end
  end

  test "confirmed completion releases request capacity before Scope processes tracker DOWN" do
    {scope, request} = scope()
    {owner, tracker, completion, prepared} = admitted(request)
    {id, old_token} = prepared.transport_options[:managed_admission_lease]
    :ok = :sys.suspend(scope.coordinator)

    try do
      finish(owner, completion)
      assert [{^id, ^old_token, _, :active, ^tracker}] = :ets.lookup(scope.ingress, id)
      assert {:messages, messages} = Process.info(scope.coordinator, :messages)
      assert Enum.any?(messages, &match?({:DOWN, _, :process, ^tracker, :normal}, &1))

      assert {:ok, replacement} = ManagedTransport.prepare(request, [])
      assert {^id, new_token} = replacement.transport_options[:managed_admission_lease]
      refute new_token == old_token
    after
      :sys.resume(scope.coordinator)
    end
  end

  test "concurrent claims have one winner and queued old DOWN preserves its new token" do
    {scope, request} = scope()
    {owner, _tracker, completion, prepared} = admitted(request)
    {id, old_token} = prepared.transport_options[:managed_admission_lease]
    :ok = :sys.suspend(scope.coordinator)
    parent = self()
    tag = make_ref()

    try do
      finish(owner, completion)

      contenders =
        for _ <- 1..32 do
          Task.async(fn ->
            send(parent, {tag, self(), ManagedTransport.prepare(request, [])})
            receive do: (:finish -> :ok)
          end)
        end

      try do
        results =
          for _ <- contenders do
            assert_receive {^tag, pid, result}, 1_000
            {pid, result}
          end

        winners = for {pid, {:ok, replacement}} <- results, do: {pid, replacement}
        assert [{winner, replacement}] = winners

        assert Enum.count(
                 results,
                 &match?({_, {:error, {:transport_scope_capacity, :requests}}}, &1)
               ) ==
                 31

        assert {^id, new_token} = replacement.transport_options[:managed_admission_lease]
        refute new_token == old_token
        :ok = :sys.resume(scope.coordinator)

        assert {:ok, %{active_requests: 0, preparing_requests: 1}} =
                 ManagedTransport.snapshot(scope, 1_000)

        assert [{^id, ^new_token, ^winner, :preparing, nil}] = :ets.lookup(scope.ingress, id)

        assert {:error, {:transport_scope_capacity, :requests}} =
                 ManagedTransport.prepare(request, [])
      after
        for contender <- contenders do
          send(contender.pid, :finish)
          assert :ok = Task.await(contender, 1_000)
        end
      end
    after
      resume(scope)
    end
  end

  test "a live active tracker retains capacity while Scope is suspended" do
    {scope, request} = scope()
    {owner, tracker, completion, _prepared} = admitted(request)
    :ok = :sys.suspend(scope.coordinator)

    try do
      assert Process.alive?(tracker)
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)

      assert {:error, {:transport_scope_capacity, :requests}} =
               ManagedTransport.prepare(request, [])
    after
      :sys.resume(scope.coordinator)
      finish(owner, completion)
    end
  end

  test "a live tracker cannot be reclaimed even with a terminal latch" do
    {scope, request} = scope()
    {owner, tracker, completion, _prepared} = admitted(request)
    :ok = :sys.suspend(scope.coordinator)

    try do
      # HTTP-owned fault control isolates the independent live-tracker guard.
      :atomics.put(completion.latch, 1, 2)
      assert Process.alive?(tracker)

      assert {:error, {:transport_scope_capacity, :requests}} =
               ManagedTransport.prepare(request, [])
    after
      :atomics.put(completion.latch, 1, 1)
      :sys.resume(scope.coordinator)
      finish(owner, completion)
    end
  end

  test "legacy active rows without an explicit completion proof are not reclaimed" do
    {scope, request} = scope()
    {owner, _tracker, completion, prepared} = admitted(request)
    {id, _token} = prepared.transport_options[:managed_admission_lease]
    :ok = :sys.suspend(scope.coordinator)

    try do
      finish(owner, completion)
      [entry] = :ets.lookup(scope.ingress, id)
      true = :ets.insert(scope.ingress, put_elem(entry, 2, owner.pid))

      assert {:error, {:transport_scope_capacity, :requests}} =
               ManagedTransport.prepare(request, [])
    after
      :sys.resume(scope.coordinator)
    end
  end

  test "confirmed cancellation releases capacity without awaiting Scope DOWN handling" do
    {scope, request} = scope()
    {owner, tracker, completion, _prepared} = admitted(request)
    :ok = :sys.suspend(scope.coordinator)

    try do
      RequestLifecycle.abort(tracker)
      assert :ok = Task.await(owner, 1_000)
      assert :ok = RequestCompletion.await(completion, 1_000)
      refute Process.alive?(tracker)
      assert {:ok, _replacement} = ManagedTransport.prepare(request, [])
    after
      :sys.resume(scope.coordinator)
    end
  end

  test "successive generations retain distinct proofs and reject stale associations" do
    {scope, request} = scope()

    {owner, _tracker, completion, _prepared} =
      Enum.reduce(1..3, admitted(request), fn _, {owner, _tracker, completion, prepared} ->
        :ok = :sys.suspend(scope.coordinator)

        replacement =
          try do
            finish(owner, completion)
            assert {:ok, replacement} = ManagedTransport.prepare(request, [])

            assert {:error, :transport_scope_retired} =
                     ManagedTransport.associate(prepared, self())

            replacement
          after
            :sys.resume(scope.coordinator)
          end

        assert {:ok, %{active_requests: 0, preparing_requests: 1}} =
                 ManagedTransport.snapshot(scope, 1_000)

        next = admitted(replacement, prepared: true)
        refute elem(next, 2).latch == completion.latch
        next
      end)

    finish(owner, completion)
  end

  for phase <- [:preparing, :reserved, :awaiting, :canceled, :canceling] do
    test "a completed tracker cannot reclaim an entry in phase #{phase}" do
      {scope, request} = scope()
      {owner, _tracker, completion, prepared} = admitted(request)
      {id, _token} = prepared.transport_options[:managed_admission_lease]
      :ok = :sys.suspend(scope.coordinator)

      try do
        finish(owner, completion)
        [entry] = :ets.lookup(scope.ingress, id)
        true = :ets.insert(scope.ingress, put_elem(entry, 3, unquote(phase)))

        assert {:error, {:transport_scope_capacity, :requests}} =
                 ManagedTransport.prepare(request, [])
      after
        :sys.resume(scope.coordinator)
      end
    end
  end

  test "closed admission gate rejects a completed request's slot" do
    {scope, request} = scope()
    {owner, _tracker, completion, _prepared} = admitted(request)
    assert {:ok, receipt} = ManagedTransport.retire(scope)
    finish(owner, completion)
    assert {:error, :transport_scope_retired} = ManagedTransport.prepare(request, [])
    assert :ok = ManagedTransport.await_retired(receipt, 1_000)
  end

  test "killed tracker cannot release admission while its constructor proof is missing" do
    {scope, request} = scope()
    {owner, tracker, completion, _prepared} = admitted(request, connector: true)

    assert {:ok, %{connections: 1, provider_resources: nil}} =
             ManagedTransport.snapshot(scope, 1_000)

    :ok = :sys.suspend(scope.coordinator)

    try do
      monitor = Process.monitor(tracker)
      Process.exit(tracker, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^tracker, :killed}, 1_000
      assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(completion, 1_000)

      assert {:error, {:transport_scope_capacity, :requests}} =
               ManagedTransport.prepare(request, [])

      send(owner.pid, :finish)
      assert :ok = Task.await(owner, 1_000)
    after
      :sys.resume(scope.coordinator)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :transport_scope_retired} = ManagedTransport.prepare(request, [])
  end

  test "unconfirmed TLS cleanup cannot be reclaimed before queued scope retirement" do
    {scope, request} = scope()
    {owner, tracker, completion, _prepared} = admitted(request)
    :ok = :sys.suspend(scope.coordinator)

    try do
      assert {:error, :unsupported_tls_socket_representation} =
               RequestLifecycle.track_tls([request_lifecycle: tracker], {:sslsocket, :opaque})

      assert :sys.get_state(tracker).uncertain?
      send(owner.pid, :finish)
      assert :ok = Task.await(owner, 1_000)
      assert {:error, :cleanup_unconfirmed} = RequestCompletion.await(completion, 1_000)
      refute Process.alive?(tracker)

      assert {:error, {:transport_scope_capacity, :requests}} =
               ManagedTransport.prepare(request, [])
    after
      :sys.resume(scope.coordinator)
    end

    assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    assert {:error, :cleanup_unconfirmed} = ManagedTransport.await_retired(receipt, 1_000)
    assert {:error, :transport_scope_retired} = ManagedTransport.prepare(request, [])
  end

  defp scope do
    assert {:ok, scope} =
             ManagedTransport.open(
               origin: "https://localhost",
               connect_address: {127, 0, 0, 1},
               http_version: :http1,
               tls_backend: :ex_ssl,
               ssl: [cacerts: []],
               max_requests: 1,
               max_connections: 1
             )

    on_exit(fn ->
      resume(scope)
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      ManagedTransport.await_retired(receipt, 1_000)
    end)

    request = %Request{
      url: URI.parse("https://localhost/"),
      transport_options: [
        transport_scope: scope,
        redirect: :manual,
        decode_body: false,
        stream_response: true,
        timeout: 1_000
      ]
    }

    {scope, request}
  end

  defp admitted(request, opts \\ []) do
    parent = self()
    tag = make_ref()

    owner =
      Task.async(fn ->
        {tracker, latch} = RequestLifecycle.start()

        assert {:ok, prepared} =
                 if(opts[:prepared],
                   do: {:ok, request},
                   else: ManagedTransport.prepare(request, [])
                 )

        assert :ok = ManagedTransport.associate(prepared, tracker)
        assert :ok = ManagedTransport.admit(prepared, tracker)
        assert :ok = RequestLifecycle.enter(tracker, :owner)
        if opts[:connector], do: assert({:ok, _} = ManagedTransport.connect_start(prepared))
        send(parent, {tag, tracker, latch, prepared})

        receive do
          :finish -> :ok
          :abort -> :ok
        end

        if Process.alive?(tracker), do: RequestLifecycle.complete(tracker)
        :ok
      end)

    assert_receive {^tag, tracker, latch, prepared}, 1_000
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    {owner, tracker, completion, prepared}
  end

  defp finish(owner, completion) do
    send(owner.pid, :finish)
    assert :ok = Task.await(owner, 1_000)
    assert :ok = RequestCompletion.await(completion, 1_000)
    refute Process.alive?(completion.tracker)
  end

  defp resume(scope) do
    if Process.alive?(scope.coordinator), do: :sys.resume(scope.coordinator, 1_000)
    :ok
  catch
    :exit, _ -> :ok
  end
end
