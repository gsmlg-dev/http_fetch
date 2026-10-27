defmodule HTTP.EventSource.ExSSLCompletionIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.ManagedLifecycleProbe, as: Probe
  alias HTTP.{ClientCompletion, EventSource}
  alias HTTP.EventSource.Event.{Error, Message, Open}

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{version} fatal opening result retains completion before client exit kills its worker" do
      version = unquote(version)
      {peer, port} = peer(:sse, version, ["--completion-delay-handshake"])

      client =
        source(port, version,
          ssl: Keyword.put(tls(version), :server_name_indication, ~c"wrong.invalid")
        )

      receipt = EventSource.completion(client)
      client_monitor = Process.monitor(client.pid)
      assert %{"index" => 1} = event(peer, &(&1["kind"] == "setup_wait"))
      :ok = :sys.suspend(client.pid)
      Port.command(peer, "go\n")

      eventually(fn ->
        {:messages, messages} = Process.info(client.pid, :messages)
        Enum.any?(messages, &match?({:http1_connected, _, _, {:error, _}}, &1))
      end)

      {:messages, messages} = Process.info(client.pid, :messages)

      {:http1_connected, _, worker, {:error, _}} =
        Enum.find(messages, &match?({:http1_connected, _, _, {:error, _}}, &1))

      worker_monitor = Process.monitor(worker)
      true = :erlang.suspend_process(worker)

      try do
        :ok = :sys.resume(client.pid)
        assert_receive {EventSource, ^client, %Error{}}, 2_000
        assert_receive {:DOWN, ^client_monitor, :process, _, :normal}, 2_000
        assert_receive {:DOWN, ^worker_monitor, :process, ^worker, :shutdown}, 1_000
        assert :ok = ClientCompletion.await(receipt, 2_000)
      after
        if Process.alive?(worker), do: :erlang.resume_process(worker)
        if Process.alive?(client.pid), do: :sys.resume(client.pid)
      end
    end

    test "#{version} late successful H1 opening queued behind close retains cleanup" do
      version = unquote(version)
      {peer, port} = peer(:sse, version, ["--completion-hold", "--completion-delay-handshake"])
      client = source(port, version)
      assert %{"index" => 1} = event(peer, &(&1["kind"] == "setup_wait"))
      :ok = :sys.suspend(client.pid)
      parent = self()

      {closer, monitor} =
        spawn_monitor(fn -> send(parent, {:closed_late, EventSource.close(client)}) end)

      try do
        eventually(fn ->
          {:messages, messages} = Process.info(client.pid, :messages)
          Enum.any?(messages, &match?({:"$gen_call", {^closer, _}, :close}, &1))
        end)

        Port.command(peer, "go\n")

        eventually(fn ->
          {:messages, messages} = Process.info(client.pid, :messages)
          Enum.any?(messages, &match?({:http1_connected, _, _, {:ok, _, _}}, &1))
        end)

        assert {:error, :cleanup_pending} =
                 ClientCompletion.await(EventSource.completion(client), 0)

        assert %{"version" => actual, "alpn" => "http/1.1"} =
                 event(peer, &(&1["kind"] == "handshake"))

        assert actual == wire(version)
        assert %{"request_exact" => true} = event(peer, &(&1["kind"] == "request"))
      after
        if Process.alive?(client.pid), do: :sys.resume(client.pid)
      end

      assert_receive {:closed_late, :ok}, 2_000
      assert_receive {:DOWN, ^monitor, :process, ^closer, :normal}, 2_000
      assert :ok = ClientCompletion.await(EventSource.completion(client), 2_000)
      refute Process.alive?(client.pid)
      refute_receive {EventSource, ^client, %Open{}}, 30
      Port.command(peer, "stop\n")
    end

    test "#{version} queued dead subscriber opens no late stream on the retained owner" do
      version = unquote(version)
      {peer, port} = peer(:h2, version)
      scope = "dead-subscriber-#{System.unique_integer([:positive])}"
      sibling = h2_source(port, version, scope)
      assert_receive {EventSource, ^sibling, %Message{data: "sibling-1"}}, 5_000
      %{stream_handle: %{owner: owner}} = EventSource.status(sibling)
      :ok = :sys.suspend(owner)
      pending = h2_source(port, version, scope)
      %{stream: worker, generation: generation} = :sys.get_state(pending.pid)

      try do
        eventually(fn ->
          {:messages, messages} = Process.info(owner, :messages)
          Enum.any?(messages, &match?({:"$gen_call", {^worker, _}, {:open_stream, _, _}}, &1))
        end)

        assert :ok = EventSource.close(pending)
        eventually(fn -> not Process.alive?(worker) end)
      after
        :sys.resume(owner)
      end

      assert :ok = ClientCompletion.await(EventSource.completion(pending), 2_000)
      refute Map.has_key?(:sys.get_state(owner).refs, generation)
      later = h2_source(port, version, scope)
      assert_receive {EventSource, ^later, %Message{data: "sibling-1"}}, 5_000
      assert %{stream_handle: %{owner: ^owner, id: 3}} = EventSource.status(later)

      assert %{"connection" => 1, "stream" => 3} =
               event(peer, &(&1["kind"] == "sse" and &1["stream"] == 3))

      for client <- [sibling, later] do
        assert :ok = EventSource.close(client)
        assert :ok = ClientCompletion.await(EventSource.completion(client), 2_000)
      end
    end

    for authority <- [:retained, :lost] do
      test "#{version} queued pool admission with #{authority} authority preserves truthful receipt" do
        version = unquote(version)
        {peer, port} = peer(:h2, version)
        scope = "queued-pool-#{System.unique_integer([:positive])}"
        pool = Process.whereis(:http_fetch_http2_pool)
        :ok = :sys.suspend(pool)
        client = h2_source(port, version, scope)
        %{stream: worker, attempt_tracker: tracker} = :sys.get_state(client.pid)

        try do
          eventually(fn ->
            {:messages, messages} = Process.info(pool, :messages)
            Enum.any?(messages, &match?({:"$gen_call", {^worker, _}, {:reserve, _, _}}, &1))
          end)

          assert {:error, :cleanup_pending} =
                   ClientCompletion.await(EventSource.completion(client), 0)

          if unquote(authority) == :lost, do: Process.exit(tracker, :kill)
          assert :ok = EventSource.close(client)
          eventually(fn -> not Process.alive?(worker) end)
        after
          :sys.resume(pool)
        end

        expected =
          if unquote(authority) == :retained, do: :ok, else: {:error, :cleanup_unconfirmed}

        assert ^expected = ClientCompletion.await(EventSource.completion(client), 2_000)
        refute Enum.any?(:sys.get_state(pool).callers, fn {_, {pid, _}} -> pid == worker end)
        later = h2_source(port, version, scope)
        assert_receive {EventSource, ^later, %Message{data: "sibling-1"}}, 5_000
        assert %{stream_handle: %{id: 1}} = EventSource.status(later)
        assert %{"connection" => 1, "stream" => 1} = event(peer, &(&1["kind"] == "sse"))
        assert :ok = EventSource.close(later)
        assert :ok = ClientCompletion.await(EventSource.completion(later), 2_000)
      end
    end

    test "#{version} H1 explicit opening abort joins the actual held handshake" do
      version = unquote(version)
      {peer, port} = peer(:sse, version, ["--hold-handshake"])
      client = source(port, version)
      assert %{"kind" => "setup"} = event(peer, &(&1["kind"] == "setup"))
      assert :ok = EventSource.close(client)
      assert :ok = ClientCompletion.await(EventSource.completion(client), 2_000)
      assert %{"kind" => "setup_closed"} = event(peer, &(&1["kind"] == "setup_closed"))
      refute Process.alive?(client.pid)
      refute_receive {EventSource, ^client, %Open{}}, 30
    end

    test "#{version} H2 application backpressure bounds output and closing joins cleanup" do
      version = unquote(version)
      {peer, port} = peer(:h2, version)

      source =
        EventSource.new("https://localhost:#{port}/sse/pressure",
          tls_backend: :ex_ssl,
          ssl: tls(version),
          http_version: :http2,
          http2_scope: "pressure-#{System.unique_integer([:positive])}",
          delivery: :ack,
          max_event_size: 8_192,
          max_queue_bytes: 16_384,
          max_queue_events: 2,
          reconnect_time: 5_000
        )

      on_exit(fn -> EventSource.close(source) end)
      assert_receive {EventSource, ^source, %Message{data: data}, _ref}, 5_000
      assert data == String.duplicate("x", 4_096)

      assert %{"sent" => sent, "remaining" => remaining} =
               event(peer, &(&1["kind"] == "sse_flow_blocked" and &1["sent"] >= 1_000_000))

      assert sent < 4_202_496 and remaining > 0
      await_raw_buffer(source)
      status = EventSource.status(source)
      assert status.queued_events <= 2 and status.queued_bytes <= 16_384
      assert status.raw_bytes > 0
      assert :sys.get_state(source.pid).terminal_reason == nil
      assert :ok = EventSource.close(source)
      assert :ok = ClientCompletion.await(EventSource.completion(source), 2_000)
      assert %{"stream" => 1, "code" => 8} = event(peer, &(&1["kind"] == "client_reset"))
      assert %{"alpn" => "h2", "version" => actual} = event(peer, &(&1["kind"] == "connection"))
      assert actual == wire(version)
    end

    test "#{version} H2 retained owner and pool handoff confirms before queued release" do
      version = unquote(version)
      {peer, port} = peer(:h2, version)
      scope = "retained-#{System.unique_integer([:positive])}"
      first = h2_source(port, version, scope)
      assert_receive {EventSource, ^first, %Message{data: "sibling-1"}}, 5_000
      %{stream: stream, stream_handle: %{owner: owner, id: id}} = :sys.get_state(first.pid)
      pool = Process.whereis(:http_fetch_http2_pool)
      %{pid: ^stream, monitor: monitor} = :sys.get_state(owner).streams[id]
      assert is_reference(monitor)

      {token, {^stream, caller_monitor}} =
        Enum.find(:sys.get_state(pool).callers, fn {_, {pid, _}} -> pid == stream end)

      assert is_reference(caller_monitor)
      assert %{owner: ^owner} = :sys.get_state(pool).reservations[token]
      sibling = h2_source(port, version, scope)
      assert_receive {EventSource, ^sibling, %Message{data: "sibling-1"}}, 5_000
      assert %{stream_handle: %{owner: ^owner}} = EventSource.status(sibling)
      :ok = :sys.suspend(owner)
      :ok = :sys.suspend(pool)

      try do
        assert :ok = EventSource.close(first)
        assert :ok = ClientCompletion.await(EventSource.completion(first), 2_000)
        refute Process.alive?(first.pid)
        assert %{pid: ^stream} = :sys.get_state(owner).streams[id]
        assert Map.has_key?(:sys.get_state(pool).reservations, token)
        assert Process.alive?(owner)
      after
        :sys.resume(pool)
        :sys.resume(owner)
      end

      eventually(fn -> not Map.has_key?(:sys.get_state(owner).streams, id) end)
      eventually(fn -> not Map.has_key?(:sys.get_state(pool).reservations, token) end)
      assert EventSource.ready_state(sibling) == EventSource.open()
      later = h2_source(port, version, scope)
      assert_receive {EventSource, ^later, %Message{data: "sibling-1"}}, 5_000
      assert %{stream_handle: %{owner: ^owner}} = EventSource.status(later)

      assert %{"connection" => 1, "alpn" => "h2", "version" => actual} =
               event(peer, &(&1["kind"] == "connection"))

      assert actual == wire(version)
      assert %{"connection" => 1} = event(peer, &(&1["kind"] == "sse" and &1["stream"] == 5))

      for client <- [sibling, later] do
        assert :ok = EventSource.close(client)
        assert :ok = ClientCompletion.await(EventSource.completion(client), 2_000)
      end
    end

    for failure <- [:wrong_ca, :wrong_name] do
      test "#{version} H2 #{failure} has no application request and durable cleanup" do
        version = unquote(version)
        {peer, port} = peer(:h2, version)

        ssl =
          if unquote(failure) == :wrong_ca,
            do:
              Keyword.put(
                tls(version),
                :cacertfile,
                Path.expand("../../../http_fetch/test/support/fixtures/pinned-ca.pem", __DIR__)
              ),
            else: Keyword.put(tls(version), :server_name_indication, ~c"wrong.invalid")

        client =
          h2_source(port, version, "identity-#{System.unique_integer([:positive])}", ssl: ssl)

        assert_receive {EventSource, ^client, %Error{}}, 5_000
        assert :ok = ClientCompletion.await(EventSource.completion(client), 2_000)
        assert %{"peer_error" => "SSLError"} = event(peer, &Map.has_key?(&1, "peer_error"))
        refute Enum.any?(Process.get({__MODULE__, peer}, []), &(&1["kind"] in ["connect", "sse"]))
      end
    end

    for terminal <- [:timeout, :abort] do
      test "#{version} H2 held SETTINGS #{terminal} preserves original opening budget" do
        version = unquote(version)
        {peer, port} = peer(:h2, version, ["--hold-settings"])

        client =
          h2_source(port, version, "held-#{System.unique_integer([:positive])}",
            connect_timeout: 500
          )

        assert %{"alpn" => "h2", "version" => actual} =
                 event(peer, &(&1["kind"] == "settings_held"))

        assert actual == wire(version)

        if unquote(terminal) == :abort do
          assert :ok = EventSource.close(client)
        else
          assert_receive {EventSource, ^client, %Error{reason: reason}}, 2_000
          assert reason in [:opening_timeout, :deadline_exceeded]
          assert :ok = EventSource.close(client)
        end

        assert :ok = ClientCompletion.await(EventSource.completion(client), 2_000)
        refute Process.alive?(client.pid)
        refute_receive {EventSource, ^client, %Open{}}, 50
        refute Enum.any?(Process.get({__MODULE__, peer}, []), &(&1["kind"] in ["connect", "sse"]))
      end
    end

    test "#{version} H2 owner death preserves caller-surviving receipt" do
      version = unquote(version)
      {_peer, port} = peer(:h2, version)
      parent = self()

      owner =
        spawn(fn ->
          client =
            EventSource.new("https://localhost:#{port}/sse/hold",
              tls_backend: :ex_ssl,
              ssl: tls(version),
              http_version: :http2,
              http2_scope: "owner-#{System.unique_integer([:positive])}",
              reconnect_time: 5_000
            )

          receive do
            {EventSource, ^client, %Open{}} -> send(parent, {:owned_h2, client})
          end

          receive do
            :die -> :ok
          end
        end)

      assert_receive {:owned_h2, client}, 5_000
      send(owner, :die)
      assert :ok = ClientCompletion.await(EventSource.completion(client), 2_000)
      refute Process.alive?(client.pid)
    end

    test "#{version} H2 exclusive cleanup joins writer and observer independently" do
      version = unquote(version)
      {_peer, port} = peer(:h2, version)
      client = h2_source(port, version, nil, http2_reuse: false)
      assert_receive {EventSource, ^client, %Message{data: "sibling-1"}}, 5_000
      %{stream_handle: %{owner: owner}} = EventSource.status(client)
      receipt = EventSource.completion(client)
      graph = Probe.graph_handle(handle(receipt))
      Probe.suspend(graph, :writer)
      Probe.suspend(graph, :observer)
      Probe.suspend(graph, :connection)

      try do
        assert :ok = EventSource.close(client)
        Probe.close_tcp(graph)
        Probe.kill_connection(graph)
        Probe.await_down(graph, [:connection, :tcp], 1_000)
        send(owner, :http2_shutdown_exclusive)
        eventually(fn -> not Process.alive?(client.pid) end)
        assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 20)
        assert Probe.alive?(graph, :writer)
        Probe.resume(graph, :writer)
        Probe.await_down(graph, [:writer], 1_000)
        assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 20)
      after
        Probe.resume(graph, :writer)
        Probe.resume(graph, :connection)
        Probe.resume(graph, :observer)
      end

      assert :ok = ClientCompletion.await(receipt, 2_000)
      Probe.await_down(graph, [:observer], 1_000)
      Probe.release_monitors(graph)
    end

    test "#{version} H1 reconnect retains fresh provider identity and Last-Event-ID" do
      version = unquote(version)
      {peer, port} = peer(:sse, version)
      source = source(port, version)
      receipt = EventSource.completion(source)
      assert_receive {EventSource, ^source, %Open{target: ^source}}, 5_000
      assert_receive {EventSource, ^source, %Message{data: "first", last_event_id: "41"}}, 5_000
      first = handle(receipt)

      assert %{"version" => expected, "alpn" => "http/1.1"} =
               event(peer, &(&1["kind"] == "handshake" and &1["index"] == 1))

      assert expected == wire(version)
      assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
      Port.command(peer, "go\n")
      assert_receive {EventSource, ^source, %Message{data: "second"}}, 5_000
      refute handle(receipt) == first

      assert %{"last_id_ok" => true} =
               event(peer, &(&1["kind"] == "request" and &1["index"] == 2))

      assert %{"version" => ^expected, "alpn" => "http/1.1"} =
               event(peer, &(&1["kind"] == "handshake" and &1["index"] == 2))

      assert :ok = EventSource.close(source)
      Port.command(peer, "stop\n")
      assert :ok = ClientCompletion.await(receipt, 2_000)
      assert :ok = ClientCompletion.await(EventSource.completion(source), 0)
    end

    test "#{version} H1 close retains suspended writer and independent observer cleanup" do
      version = unquote(version)
      {peer, port} = peer(:sse, version, ["--completion-hold"])
      source = source(port, version)
      assert_receive {EventSource, ^source, %Message{data: "held"}}, 5_000
      receipt = EventSource.completion(source)
      graph = Probe.graph_handle(handle(receipt))
      Probe.suspend(graph, :observer)
      Probe.suspend(graph, :connection)
      Probe.suspend(graph, :writer)
      Probe.close_tcp(graph)
      Probe.kill_connection(graph)
      Probe.await_down(graph, [:connection, :tcp], 1_000)

      try do
        assert :ok = EventSource.close(source)
        assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 20)
        assert Probe.alive?(graph, :writer)
      after
        Probe.resume(graph, :writer)
        Probe.resume(graph, :observer)
      end

      Port.command(peer, "stop\n")
      assert :ok = ClientCompletion.await(receipt, 2_000)
      Probe.await_down(graph, [:writer, :observer], 2_000)
      Probe.release_monitors(graph)
    end

    test "#{version} H1 owner death seals admission and joins actual provider" do
      version = unquote(version)
      {peer, port} = peer(:sse, version, ["--completion-hold"])
      parent = self()

      owner =
        spawn(fn ->
          source =
            EventSource.new("https://localhost:#{port}/events",
              tls_backend: :ex_ssl,
              ssl: tls(version),
              owner: self(),
              reconnect_time: 30,
              connect_timeout: 2_000
            )

          receive do
            {EventSource, ^source, %Open{}} -> send(parent, {:owned, source})
          end

          receive do
            :die -> :ok
          end
        end)

      assert_receive {:owned, source}, 5_000
      receipt = EventSource.completion(source)
      send(owner, :die)
      assert :ok = ClientCompletion.await(receipt, 2_000)
      refute Process.alive?(source.pid)
      Port.command(peer, "stop\n")
    end

    for failure <- [:wrong_ca, :wrong_name] do
      test "#{version} H1 #{failure} submits no request and confirms cleanup" do
        version = unquote(version)
        {peer, port} = peer(:sse, version, ["--completion-hold"])

        ssl =
          if unquote(failure) == :wrong_ca,
            do:
              Keyword.put(
                tls(version),
                :cacertfile,
                Path.expand("../../../http_fetch/test/support/fixtures/pinned-ca.pem", __DIR__)
              ),
            else: Keyword.put(tls(version), :server_name_indication, ~c"wrong.invalid")

        source = source(port, version, ssl: ssl)
        assert_receive {EventSource, ^source, %Error{reason: reason}}, 5_000
        assert reason != nil
        assert :ok = ClientCompletion.await(EventSource.completion(source), 2_000)
        assert %{"kind_name" => "SSLError"} = event(peer, &(&1["kind"] == "failure"))
        refute Enum.any?(Process.get({__MODULE__, peer}, []), &(&1["kind"] == "request"))
      end
    end

    test "#{version} H1 opening timeout and abort retain the admitted attempt" do
      version = unquote(version)
      {peer, port} = peer(:sse, version, ["--hold-handshake"])
      source = source(port, version, connect_timeout: 500)
      assert %{"kind" => "setup"} = event(peer, &(&1["kind"] == "setup"))
      assert_receive {EventSource, ^source, %Error{}}, 2_000
      assert :ok = EventSource.close(source)
      assert :ok = ClientCompletion.await(EventSource.completion(source), 2_000)
      assert %{"kind" => "setup_closed"} = event(peer, &(&1["kind"] == "setup_closed"))
    end
  end

  test "two unresolved real attempts saturate without a third allocation; settling restores cleanup" do
    {peer, port} = peer(:sse, :"tlsv1.3", ["--completion-reconnects", "3"])
    source = source(port, :"tlsv1.3")
    receipt = EventSource.completion(source)
    assert_receive {EventSource, ^source, %Message{data: "first"}}, 5_000
    first = Probe.graph_handle(handle(receipt))
    Probe.suspend(first, :observer)
    Port.command(peer, "go\n")
    assert_receive {EventSource, ^source, %Message{data: "second"}}, 5_000
    state = :sys.get_state(receipt.tracker)
    first_handle = first.handle

    second_handle =
      state.children
      |> Map.values()
      |> Enum.flat_map(fn entry -> :sys.get_state(entry.child).providers |> Map.keys() end)
      |> Enum.find(&(&1 != first_handle))

    second = Probe.graph_handle(second_handle)
    Probe.suspend(second, :observer)

    try do
      Port.command(peer, "stop\n")
      assert_receive {EventSource, ^source, %Error{reason: :cleanup_capacity}}, 5_000
      assert_receive {EventSource, ^source, %Error{reason: :cleanup_capacity}}, 5_000
      assert map_size(:sys.get_state(receipt.tracker).children) == 2
      assert :sys.get_state(source.pid).worker == nil
      Probe.resume(first, :observer)
      assert_receive {EventSource, ^source, %Message{data: "third"}}, 5_000

      assert %{"last_id_ok" => true, "index" => 3} =
               event(peer, &(&1["kind"] == "request" and &1["index"] == 3))

      assert map_size(:sys.get_state(receipt.tracker).children) == 2
      assert handle_for_current(source) != second_handle
      assert :ok = EventSource.close(source)
      Port.command(peer, "stop\n")
      assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 10)
    after
      Probe.resume(first, :observer)
      Probe.resume(second, :observer)
    end

    assert :ok = ClientCompletion.await(receipt, 2_000)
    Probe.await_down(first, [:connection, :writer, :tcp, :observer], 2_000)
    Probe.await_down(second, [:connection, :writer, :tcp, :observer], 2_000)
    Probe.release_monitors(first)
    Probe.release_monitors(second)
  end

  defp h2_source(port, version, scope, extra \\ []) do
    source =
      EventSource.new(
        "https://localhost:#{port}/sse/hold",
        Keyword.merge(
          [
            tls_backend: :ex_ssl,
            ssl: tls(version),
            http_version: :http2,
            http2_scope: scope,
            reconnect_time: 5_000,
            connect_timeout: 2_000
          ],
          extra
        )
      )

    on_exit(fn -> EventSource.close(source) end)
    source
  end

  defp await_raw_buffer(source) do
    reference = make_ref()
    test_pid = self()

    observe = fn
      ref, {:noreply, %{raw_bytes: bytes, terminal_reason: nil}}, _name when bytes > 0 ->
        send(test_pid, {ref, :buffered})
        :done

      ref, {:noreply, %{terminal_reason: reason}}, _name when not is_nil(reason) ->
        send(test_pid, {ref, {:terminal, reason}})
        :done

      ref, _event, _name ->
        ref
    end

    # A peer write does not join the relay or application callback. Observe a
    # completed callback, then sample after installation to avoid a missed event.
    :ok = :sys.install(source.pid, {reference, observe, reference})

    try do
      state = :sys.get_state(source.pid)
      assert state.terminal_reason == nil

      if state.raw_bytes == 0 do
        assert_receive {^reference, outcome}, 5_000
        assert outcome == :buffered
      end
    after
      if Process.alive?(source.pid), do: :sys.remove(source.pid, reference)
    end
  end

  defp source(port, version, extra \\ []) do
    source =
      EventSource.new(
        "https://localhost:#{port}/events",
        Keyword.merge(
          [tls_backend: :ex_ssl, ssl: tls(version), reconnect_time: 30, connect_timeout: 2_000],
          extra
        )
      )

    on_exit(fn -> EventSource.close(source) end)
    source
  end

  defp peer(kind, version, extra \\ []) do
    h2? = kind == :h2
    script = if h2?, do: "http2_websocket_peer.py", else: "ex_ssl_tls12_peer.py"
    base = Path.expand("../../../../scripts/" <> script, __DIR__)

    args =
      if h2? do
        [
          base,
          "--tls",
          "--cert",
          fixture("localhost.pem"),
          "--key",
          fixture("localhost.key"),
          "--tls-version",
          wire(version)
        ]
      else
        [
          base,
          "--certfile",
          fixture("localhost.pem"),
          "--keyfile",
          fixture("localhost.key"),
          "--cafile",
          fixture("localhost-ca.pem"),
          "--mode",
          Atom.to_string(kind),
          "--max-version",
          if(version == :"tlsv1.2", do: "tls12", else: "tls13"),
          "--no-client-auth"
        ]
      end

    port =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        :use_stdio,
        :stderr_to_stdout,
        {:line, 65_536},
        args: args ++ extra
      ])

    {:os_pid, pid} = Port.info(port, :os_pid)
    ready = event(port, &(&1["kind"] == "ready"))
    on_exit(fn -> stop_peer(port, pid) end)
    {port, ready["port"]}
  end

  defp event(port, predicate, timeout \\ 5_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    events = Process.get({__MODULE__, port}, [])

    case Enum.find(events, predicate) do
      nil -> receive_event(port, predicate, deadline)
      found -> found
    end
  end

  defp receive_event(port, predicate, deadline) do
    receive do
      {^port, {:data, {:eol, line}}} ->
        record = JSON.decode!(line)
        IO.puts("CLIENT_COMPLETION_WIRE " <> line)
        Process.put({__MODULE__, port}, Process.get({__MODULE__, port}, []) ++ [record])
        if predicate.(record), do: record, else: receive_event(port, predicate, deadline)

      {^port, {:exit_status, code}} ->
        flunk("peer exited #{code} before required wire event")
    after
      max(deadline - System.monotonic_time(:millisecond), 0) ->
        flunk("missing independent peer event")
    end
  end

  defp stop_peer(port, pid) do
    # ExUnit's test process can close its Port before on_exit runs. The
    # independently owned peer still needs termination and an absence check.
    System.cmd("kill", ["-TERM", Integer.to_string(pid)], stderr_to_stdout: true)

    if Port.info(port) do
      try do
        Port.close(port)
      rescue
        ArgumentError -> :ok
      end
    end

    wait_dead(pid, System.monotonic_time(:millisecond) + 2_000)
  end

  defp wait_dead(pid, deadline) do
    case System.cmd("kill", ["-0", Integer.to_string(pid)], stderr_to_stdout: true) do
      {_, code} when code != 0 ->
        :ok

      _ ->
        if System.monotonic_time(:millisecond) >= deadline, do: flunk("owned peer still alive")
        Process.sleep(5)
        wait_dead(pid, deadline)
    end
  end

  defp fixture(name), do: Path.expand("../support/fixtures/" <> name, __DIR__)
  defp wire(:"tlsv1.2"), do: "TLSv1.2"
  defp wire(:"tlsv1.3"), do: "TLSv1.3"
  defp tls(version), do: [versions: [version], cacertfile: fixture("localhost-ca.pem")]

  defp handle_for_current(source) do
    tracker = :sys.get_state(source.pid).attempt_tracker
    [handle] = Map.keys(:sys.get_state(tracker).providers)
    handle
  end

  defp handle(receipt) do
    state = :sys.get_state(receipt.tracker)
    [entry | _] = state.children |> Map.values() |> Enum.filter(&is_pid(&1.child))
    child = :sys.get_state(entry.child)
    [handle] = Map.keys(child.providers)
    handle
  end

  defp eventually(fun, timeout \\ 2_000) do
    deadline = System.monotonic_time(:millisecond) + timeout
    until(fun, deadline)
  end

  defp until(fun, deadline) do
    if fun.() do
      :ok
    else
      if System.monotonic_time(:millisecond) >= deadline, do: flunk("condition did not settle")
      Process.sleep(2)
      until(fun, deadline)
    end
  end
end
