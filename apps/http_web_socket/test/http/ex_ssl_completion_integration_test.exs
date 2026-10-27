defmodule HTTP.WebSocket.ExSSLCompletionIntegrationTest do
  use ExUnit.Case, async: false
  @moduletag :integration

  alias ExSSL.TestSupport.ManagedLifecycleProbe, as: Probe
  alias HTTP.{ClientCompletion, WebSocket}
  alias HTTP.WebSocket.Event.{Close, Error, Message, Open}

  for version <- [:"tlsv1.2", :"tlsv1.3"] do
    test "#{version} fatal opening result retains completion before client exit kills its worker" do
      version = unquote(version)
      {peer, port} = peer(:wss, version, ["--completion-delay-handshake"])

      client =
        socket(port, version,
          ssl: Keyword.put(tls(version), :server_name_indication, ~c"wrong.invalid")
        )

      receipt = WebSocket.completion(client)
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
        assert_receive {WebSocket, ^client, %Error{}}, 2_000
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
      {peer, port} = peer(:wss, version, ["--completion-hold", "--completion-delay-handshake"])
      client = socket(port, version)
      assert %{"index" => 1} = event(peer, &(&1["kind"] == "setup_wait"))
      :ok = :sys.suspend(client.pid)
      parent = self()

      {closer, monitor} =
        spawn_monitor(fn -> send(parent, {:closed_late, WebSocket.close(client)}) end)

      try do
        eventually(fn ->
          {:messages, messages} = Process.info(client.pid, :messages)
          Enum.any?(messages, &match?({:"$gen_call", {^closer, _}, {:close, _, _, _}}, &1))
        end)

        Port.command(peer, "go\n")

        eventually(fn ->
          {:messages, messages} = Process.info(client.pid, :messages)
          Enum.any?(messages, &match?({:http1_ready, _, _, _, _}, &1))
        end)

        assert {:error, :cleanup_pending} =
                 ClientCompletion.await(WebSocket.completion(client), 0)

        assert %{"version" => actual, "alpn" => "http/1.1"} =
                 event(peer, &(&1["kind"] == "handshake"))

        assert actual == wire(version)
        assert %{"request_exact" => true} = event(peer, &(&1["kind"] == "request"))
      after
        if Process.alive?(client.pid), do: :sys.resume(client.pid)
      end

      assert_receive {:closed_late, :ok}, 2_000
      assert_receive {:DOWN, ^monitor, :process, ^closer, :normal}, 2_000
      assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
      refute Process.alive?(client.pid)
      refute_receive {WebSocket, ^client, %Open{}}, 30
      Port.command(peer, "stop\n")
    end

    test "#{version} guarded auto fallback retains pending first attempt and original deadline" do
      version = unquote(version)

      {peer, port} =
        peer(:h2, version, ["--capability", "0", "--completion-fallback", "--hold-settings"])

      socket = socket(port, version, http_version: :auto)
      assert %{"alpn" => "h2"} = event(peer, &(&1["kind"] == "settings_held"))

      %{attempt_tracker: first, stream: stream, opening_deadline: deadline} =
        :sys.get_state(socket.pid)

      eventually(fn ->
        state = :sys.get_state(first)
        state.constructor_entered? and map_size(state.providers) == 0
      end)

      :ok = :sys.suspend(socket.pid)
      :ok = :sys.suspend(first)

      try do
        Port.command(peer, "go\n")
        eventually(fn -> not Process.alive?(stream) end)
        :ok = :sys.resume(socket.pid)
        assert_receive {WebSocket, ^socket, %Open{}}, 2_000
        assert_receive {WebSocket, ^socket, %Message{data: "hello"}}, 2_000
        assert %{fallback?: true, http_version: :http1} = WebSocket.status(socket)
        assert :sys.get_state(socket.pid).opening_deadline == deadline
        assert System.monotonic_time(:millisecond) < deadline
        receipt = WebSocket.completion(socket)
        children = :sys.get_state(receipt.tracker).children
        assert map_size(children) == 2
        assert Enum.any?(children, fn {_, child} -> child.child == first end)
        second = :sys.get_state(socket.pid).attempt_tracker
        refute second == first
        assert [_] = Map.keys(:sys.get_state(second).providers)
        assert :ok = WebSocket.send(socket, "tls12-echo")
        assert_receive {WebSocket, ^socket, %Message{data: "echo:tls12-echo"}}, 2_000
        assert :ok = WebSocket.close(socket, 1000)
        assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 2_000
        assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 20)

        assert %{"connection" => 2} = event(peer, &(&1["kind"] == "fallback_tls_closed"))

        assert %{"connection" => 2, "alpn" => "http/1.1", "version" => actual} =
                 event(peer, &(&1["kind"] == "fallback_connection"))

        assert actual == wire(version)
        assert %{"frames" => 1, "bytes" => 10} = event(peer, &(&1["kind"] == "exchange"))
      after
        if Process.alive?(first), do: :sys.resume(first)
        if Process.alive?(socket.pid), do: :sys.resume(socket.pid)
      end

      assert :ok = ClientCompletion.await(WebSocket.completion(socket), 2_000)
      refute Enum.any?(Process.get({__MODULE__, peer}, []), &(&1["connection"] == 3))
    end

    test "#{version} rejected CONNECT does not authorize auto fallback or replay" do
      version = unquote(version)
      {peer, port} = peer(:h2, version, ["--completion-fallback"])

      client =
        WebSocket.new("wss://localhost:#{port}/ws/reject?case=reject", [],
          tls_backend: :ex_ssl,
          ssl: tls(version),
          http_version: :auto,
          opening_timeout: 2_000
        )

      assert_receive {WebSocket, ^client, %Error{reason: {:unexpected_status, 403}}}, 5_000
      assert_receive {WebSocket, ^client, %Close{code: 1006}}, 2_000
      assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
      assert %{"connection" => 1, "case" => "reject"} = event(peer, &(&1["kind"] == "connect"))
      assert %{"alpn" => "h2", "version" => actual} = event(peer, &(&1["kind"] == "connection"))
      assert actual == wire(version)

      refute Enum.any?(
               Process.get({__MODULE__, peer}, []),
               &(&1["kind"] == "fallback_connection")
             )
    end

    for guard <- [:explicit_http2, :custom_profile] do
      test "#{version} #{guard} forbids capability fallback" do
        version = unquote(version)
        {peer, port} = peer(:h2, version, ["--capability", "0", "--completion-fallback"])

        extra =
          if unquote(guard) == :explicit_http2,
            do: [http_version: :http2],
            else: [http_version: :auto, http2_profile: :native_v1]

        socket = socket(port, version, extra)

        assert_receive {WebSocket, ^socket, %Error{reason: :extended_connect_not_supported}},
                       5_000

        assert_receive {WebSocket, ^socket, %Close{code: 1006}}, 2_000
        assert :ok = ClientCompletion.await(WebSocket.completion(socket), 2_000)

        assert %{"connection" => 1, "alpn" => "h2", "version" => actual} =
                 event(peer, &(&1["kind"] == "connection"))

        assert actual == wire(version)

        refute Enum.any?(
                 Process.get({__MODULE__, peer}, []),
                 &(&1["kind"] in ["connect", "fallback_connection"])
               )
      end
    end

    test "#{version} queued dead subscriber opens no late stream on the retained owner" do
      version = unquote(version)
      {peer, port} = peer(:h2, version)
      scope = "dead-subscriber-#{System.unique_integer([:positive])}"
      sibling = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^sibling, %Open{}}, 5_000
      %{stream_handle: %{owner: owner}} = WebSocket.status(sibling)
      :ok = :sys.suspend(owner)
      pending = h2_socket(port, version, scope)
      %{stream: worker, generation: generation} = :sys.get_state(pending.pid)

      try do
        eventually(fn ->
          {:messages, messages} = Process.info(owner, :messages)

          Enum.any?(messages, fn message ->
            match?({:"$gen_call", {^worker, _}, {:open_stream, _, _}}, message) or
              match?({:http2_await_capability, ^worker, ^generation}, message)
          end)
        end)

        assert :ok = WebSocket.close(pending)
        eventually(fn -> not Process.alive?(worker) end)
      after
        :sys.resume(owner)
      end

      assert :ok = ClientCompletion.await(WebSocket.completion(pending), 2_000)
      refute Map.has_key?(:sys.get_state(owner).refs, generation)
      later = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^later, %Open{}}, 5_000
      assert %{stream_handle: %{owner: ^owner, id: 3}} = WebSocket.status(later)

      assert %{"connection" => 1, "stream" => 3} =
               event(peer, &(&1["kind"] == "connect" and &1["stream"] == 3))

      for client <- [sibling, later] do
        assert :ok = WebSocket.close(client)
        assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
      end
    end

    for authority <- [:retained, :lost] do
      test "#{version} queued pool admission with #{authority} authority preserves truthful receipt" do
        version = unquote(version)
        {peer, port} = peer(:h2, version)
        scope = "queued-pool-#{System.unique_integer([:positive])}"
        pool = Process.whereis(:http_fetch_http2_pool)
        :ok = :sys.suspend(pool)
        client = h2_socket(port, version, scope)
        %{stream: worker, attempt_tracker: tracker} = :sys.get_state(client.pid)

        try do
          eventually(fn ->
            {:messages, messages} = Process.info(pool, :messages)
            Enum.any?(messages, &match?({:"$gen_call", {^worker, _}, {:reserve, _, _}}, &1))
          end)

          assert {:error, :cleanup_pending} =
                   ClientCompletion.await(WebSocket.completion(client), 0)

          if unquote(authority) == :lost, do: Process.exit(tracker, :kill)
          assert :ok = WebSocket.close(client)
          eventually(fn -> not Process.alive?(worker) end)
        after
          :sys.resume(pool)
        end

        expected =
          if unquote(authority) == :retained, do: :ok, else: {:error, :cleanup_unconfirmed}

        assert ^expected = ClientCompletion.await(WebSocket.completion(client), 2_000)
        refute Enum.any?(:sys.get_state(pool).callers, fn {_, {pid, _}} -> pid == worker end)
        later = h2_socket(port, version, scope)
        assert_receive {WebSocket, ^later, %Open{}}, 5_000
        assert %{stream_handle: %{id: 1}} = WebSocket.status(later)
        assert %{"connection" => 1, "stream" => 1} = event(peer, &(&1["kind"] == "connect"))
        assert :ok = WebSocket.close(later)
        assert :ok = ClientCompletion.await(WebSocket.completion(later), 2_000)
      end
    end

    test "#{version} H1 explicit opening abort joins the actual held handshake" do
      version = unquote(version)
      {peer, port} = peer(:wss, version, ["--hold-handshake"])
      client = socket(port, version)
      assert %{"kind" => "setup"} = event(peer, &(&1["kind"] == "setup"))
      assert :ok = WebSocket.close(client)
      assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
      assert %{"kind" => "setup_closed"} = event(peer, &(&1["kind"] == "setup_closed"))
      refute Process.alive?(client.pid)
      refute_receive {WebSocket, ^client, %Open{}}, 30
    end

    test "#{version} H2 blocked output is cancelled once with retained cleanup" do
      version = unquote(version)
      {peer, port} = peer(:h2, version)

      socket =
        WebSocket.new("wss://localhost:#{port}/ws/blocked?count=1&case=blocked", [],
          tls_backend: :ex_ssl,
          ssl: tls(version),
          http_version: :http2,
          http2_scope: "blocked-#{System.unique_integer([:positive])}",
          opening_timeout: 2_000,
          close_timeout: 100,
          write_timeout: 1_000
        )

      on_exit(fn -> WebSocket.close(socket) end)
      assert_receive {WebSocket, ^socket, %Open{}}, 5_000
      assert {:ok, ref} = WebSocket.send_ack(socket, String.duplicate("Z", 131_072))

      assert %{"bytes" => 65_535, "connection" => 1, "stream" => 1} =
               event(peer, &(&1["kind"] == "flow_blocked"))

      refute_receive {WebSocket, ^socket, {:send_result, ^ref, :ok}}, 30
      assert :ok = WebSocket.close(socket)
      assert_receive {WebSocket, ^socket, {:send_result, ^ref, {:error, _}}}, 2_000
      assert_receive {WebSocket, ^socket, %Close{was_clean: false}}, 2_000
      assert :ok = ClientCompletion.await(WebSocket.completion(socket), 2_000)

      assert %{"stream" => 1, "code" => 8, "messages" => 0} =
               event(peer, &(&1["kind"] == "client_reset"))

      assert %{"alpn" => "h2", "version" => actual} = event(peer, &(&1["kind"] == "connection"))
      assert actual == wire(version)
    end

    test "#{version} H2 retained owner and pool handoff confirms before queued release" do
      version = unquote(version)
      {peer, port} = peer(:h2, version)
      scope = "retained-#{System.unique_integer([:positive])}"
      first = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^first, %Open{}}, 5_000
      %{stream: stream, stream_handle: %{owner: owner, id: id}} = :sys.get_state(first.pid)
      pool = Process.whereis(:http_fetch_http2_pool)
      %{pid: ^stream, monitor: monitor} = :sys.get_state(owner).streams[id]
      assert is_reference(monitor)

      {token, {^stream, caller_monitor}} =
        Enum.find(:sys.get_state(pool).callers, fn {_, {pid, _}} -> pid == stream end)

      assert is_reference(caller_monitor)
      assert %{owner: ^owner} = :sys.get_state(pool).reservations[token]
      sibling = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^sibling, %Open{}}, 5_000
      assert %{stream_handle: %{owner: ^owner}} = WebSocket.status(sibling)
      :ok = :sys.suspend(owner)
      :ok = :sys.suspend(pool)

      try do
        assert :ok = WebSocket.close(first)
        assert :ok = ClientCompletion.await(WebSocket.completion(first), 2_000)
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
      assert :ok = WebSocket.send(sibling, "retained-sibling")
      assert_receive {WebSocket, ^sibling, %Message{data: "retained-sibling"}}, 5_000
      later = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^later, %Open{}}, 5_000
      assert %{stream_handle: %{owner: ^owner}} = WebSocket.status(later)

      assert %{"connection" => 1, "alpn" => "h2", "version" => actual} =
               event(peer, &(&1["kind"] == "connection"))

      assert actual == wire(version)
      assert %{"connection" => 1} = event(peer, &(&1["kind"] == "connect" and &1["stream"] == 5))

      for client <- [sibling, later] do
        assert :ok = WebSocket.close(client)
        assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
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
          h2_socket(port, version, "identity-#{System.unique_integer([:positive])}", ssl: ssl)

        assert_receive {WebSocket, ^client, %Error{}}, 5_000
        assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
        assert %{"peer_error" => "SSLError"} = event(peer, &Map.has_key?(&1, "peer_error"))
        refute Enum.any?(Process.get({__MODULE__, peer}, []), &(&1["kind"] in ["connect", "sse"]))
      end
    end

    for terminal <- [:timeout, :abort] do
      test "#{version} H2 held SETTINGS #{terminal} preserves original opening budget" do
        version = unquote(version)
        {peer, port} = peer(:h2, version, ["--hold-settings"])

        client =
          h2_socket(port, version, "held-#{System.unique_integer([:positive])}",
            opening_timeout: 500
          )

        assert %{"alpn" => "h2", "version" => actual} =
                 event(peer, &(&1["kind"] == "settings_held"))

        assert actual == wire(version)

        if unquote(terminal) == :abort do
          assert :ok = WebSocket.close(client)
        else
          assert_receive {WebSocket, ^client, %Error{reason: reason}}, 2_000
          assert reason in [:opening_timeout, :deadline_exceeded]
          :ok
        end

        assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
        refute Process.alive?(client.pid)
        refute_receive {WebSocket, ^client, %Open{}}, 50
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
            WebSocket.new("wss://localhost:#{port}/ws/echo?count=1", [],
              tls_backend: :ex_ssl,
              ssl: tls(version),
              http_version: :http2,
              http2_scope: "owner-#{System.unique_integer([:positive])}"
            )

          receive do
            {WebSocket, ^client, %Open{}} -> send(parent, {:owned_h2, client})
          end

          receive do
            :die -> :ok
          end
        end)

      assert_receive {:owned_h2, client}, 5_000
      send(owner, :die)
      assert :ok = ClientCompletion.await(WebSocket.completion(client), 2_000)
      refute Process.alive?(client.pid)
    end

    test "#{version} H2 exclusive cleanup joins writer and observer independently" do
      version = unquote(version)
      {_peer, port} = peer(:h2, version)
      client = h2_socket(port, version, nil, http2_reuse: false)
      assert_receive {WebSocket, ^client, %Open{}}, 5_000
      %{stream_handle: %{owner: owner}} = WebSocket.status(client)
      receipt = WebSocket.completion(client)
      graph = Probe.graph_handle(handle(receipt))
      Probe.suspend(graph, :writer)
      Probe.suspend(graph, :observer)
      Probe.suspend(graph, :connection)

      try do
        assert :ok = WebSocket.close(client)
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

    test "#{version} H1 exact Upgrade, echoed payload and clean close join public completion" do
      version = unquote(version)
      {peer, port} = peer(:wss, version)
      socket = socket(port, version)
      receipt = WebSocket.completion(socket)
      assert_receive {WebSocket, ^socket, %Open{target: ^socket}}, 5_000
      assert_receive {WebSocket, ^socket, %Message{data: "hello"}}, 5_000

      assert %{"version" => expected, "alpn" => "http/1.1"} =
               event(peer, &(&1["kind"] == "handshake"))

      assert expected == wire(version)
      assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 0)
      assert :ok = WebSocket.send(socket, "tls12-echo")
      assert_receive {WebSocket, ^socket, %Message{data: "echo:tls12-echo"}}, 5_000
      assert :ok = WebSocket.close(socket, 1000)
      assert_receive {WebSocket, ^socket, %Close{code: 1000, was_clean: true}}, 5_000
      assert :ok = ClientCompletion.await(receipt, 2_000)
      assert :ok = ClientCompletion.await(WebSocket.completion(socket), 0)
      assert %{"frames" => 1, "bytes" => 10} = event(peer, &(&1["kind"] == "exchange"))
    end

    test "#{version} H1 retained blocked write outlives logical close until writer and observer join" do
      version = unquote(version)
      {peer, port} = peer(:wss, version, ["--completion-hold"])
      socket = socket(port, version)
      assert_receive {WebSocket, ^socket, %Message{data: "held"}}, 5_000
      receipt = WebSocket.completion(socket)
      graph = Probe.graph_handle(handle(receipt))
      Probe.suspend(graph, :writer)

      try do
        assert :ok = WebSocket.send(socket, String.duplicate("Z", 65_536))
        eventually(fn -> :sys.get_state(socket.pid).write != nil end)
        %{write: %{worker: worker}, attempt_tracker: tracker} = :sys.get_state(socket.pid)

        assert Enum.any?(:sys.get_state(tracker).resources, fn {_, {pid, kind}} ->
                 pid == worker and kind == :client_write
               end)

        assert :ok = WebSocket.close(socket)
        Probe.suspend(graph, :observer)
        Probe.suspend(graph, :connection)
        Probe.close_tcp(graph)
        Probe.kill_connection(graph)
        Probe.await_down(graph, [:connection, :tcp], 1_000)
        eventually(fn -> not Process.alive?(socket.pid) end)
        assert Probe.alive?(graph, :writer)
        assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 20)
        Probe.resume(graph, :writer)
        Probe.await_down(graph, [:writer], 1_000)
        assert {:error, :cleanup_pending} = ClientCompletion.await(receipt, 20)
      after
        Probe.resume(graph, :writer)
        Probe.resume(graph, :connection)
        Probe.resume(graph, :observer)
      end

      Port.command(peer, "stop\n")
      assert :ok = ClientCompletion.await(receipt, 2_000)
      Probe.await_down(graph, [:observer], 1_000)
      Probe.release_monitors(graph)
    end

    test "#{version} H1 owner death preserves durable cleanup" do
      version = unquote(version)
      {peer, port} = peer(:wss, version, ["--completion-hold"])
      parent = self()

      owner =
        spawn(fn ->
          socket =
            WebSocket.new("wss://localhost:#{port}/socket", [],
              tls_backend: :ex_ssl,
              ssl: tls(version)
            )

          receive do
            {WebSocket, ^socket, %Open{}} -> send(parent, {:owned, socket})
          end

          receive do
            :die -> :ok
          end
        end)

      assert_receive {:owned, socket}, 5_000
      send(owner, :die)
      assert :ok = ClientCompletion.await(WebSocket.completion(socket), 2_000)
      refute Process.alive?(socket.pid)
      Port.command(peer, "stop\n")
    end

    for failure <- [:wrong_ca, :wrong_name] do
      test "#{version} H1 #{failure} emits no Upgrade request and confirms cleanup" do
        version = unquote(version)
        {peer, port} = peer(:wss, version, ["--completion-hold"])

        ssl =
          if unquote(failure) == :wrong_ca,
            do:
              Keyword.put(
                tls(version),
                :cacertfile,
                Path.expand("../../../http_fetch/test/support/fixtures/pinned-ca.pem", __DIR__)
              ),
            else: Keyword.put(tls(version), :server_name_indication, ~c"wrong.invalid")

        socket = socket(port, version, ssl: ssl)
        assert_receive {WebSocket, ^socket, %Error{reason: reason}}, 5_000
        assert reason != nil
        assert_receive {WebSocket, ^socket, %Close{code: 1006, was_clean: false}}, 5_000
        assert :ok = ClientCompletion.await(WebSocket.completion(socket), 2_000)
        assert %{"kind_name" => "SSLError"} = event(peer, &(&1["kind"] == "failure"))
        refute Enum.any?(Process.get({__MODULE__, peer}, []), &(&1["kind"] == "request"))
      end
    end

    test "#{version} H1 early 80ms timeout leaves no late opening work" do
      version = unquote(version)
      {_peer, port} = peer(:wss, version, ["--hold-handshake"])
      socket = socket(port, version, opening_timeout: 80)
      assert_receive {WebSocket, ^socket, %Error{}}, 2_000
      assert_receive {WebSocket, ^socket, %Close{code: 1006}}, 2_000
      assert :ok = ClientCompletion.await(WebSocket.completion(socket), 2_000)
      refute Process.alive?(socket.pid)
      refute_receive {WebSocket, ^socket, %Open{}}, 100
      assert :ok = ClientCompletion.await(WebSocket.completion(socket), 0)
    end

    test "#{version} H1 opening timeout closes the exact admitted attempt" do
      version = unquote(version)
      {peer, port} = peer(:wss, version, ["--hold-handshake"])
      socket = socket(port, version, opening_timeout: 500)
      assert %{"kind" => "setup"} = event(peer, &(&1["kind"] == "setup"))
      assert_receive {WebSocket, ^socket, %Error{}}, 2_000
      assert_receive {WebSocket, ^socket, %Close{code: 1006}}, 2_000
      assert :ok = ClientCompletion.await(WebSocket.completion(socket), 2_000)
      assert %{"kind" => "setup_closed"} = event(peer, &(&1["kind"] == "setup_closed"))
    end

    test "#{version} H2 shared sibling and later socket reuse exact physical connection" do
      version = unquote(version)
      {peer, port} = peer(:h2, version)
      scope = "completion-#{System.unique_integer([:positive])}"
      first = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^first, %Open{}}, 5_000
      %{stream_handle: %{owner: owner}} = WebSocket.status(first)
      sibling = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^sibling, %Open{}}, 5_000
      assert %{stream_handle: %{owner: ^owner}} = WebSocket.status(sibling)
      assert :ok = WebSocket.close(first)
      assert_receive {WebSocket, ^first, %Close{was_clean: true}}, 5_000
      assert :ok = ClientCompletion.await(WebSocket.completion(first), 2_000)
      assert Process.alive?(owner)
      assert :ok = WebSocket.send(sibling, "sibling-proof")
      assert_receive {WebSocket, ^sibling, %Message{data: "sibling-proof"}}, 5_000
      later = h2_socket(port, version, scope)
      assert_receive {WebSocket, ^later, %Open{}}, 5_000
      assert %{stream_handle: %{owner: ^owner}} = WebSocket.status(later)
      assert :ok = WebSocket.send(later, "later-proof")
      assert_receive {WebSocket, ^later, %Message{data: "later-proof"}}, 5_000

      assert %{"connection" => 1, "alpn" => "h2", "version" => expected} =
               event(peer, &(&1["kind"] == "connection"))

      assert expected == wire(version)

      assert %{"connection" => 1, "wire_oracle" => "PASS"} =
               event(peer, &(&1["kind"] == "connect" and &1["stream"] == 5))

      for current <- [sibling, later] do
        assert :ok = WebSocket.close(current)
        assert_receive {WebSocket, ^current, %Close{was_clean: true}}, 5_000
        assert :ok = ClientCompletion.await(WebSocket.completion(current), 2_000)
      end

      refute Enum.any?(
               Process.get({__MODULE__, peer}, []),
               &(&1["kind"] == "connection" and &1["connection"] != 1)
             )
    end
  end

  defp socket(port, version, extra \\ []) do
    socket =
      WebSocket.new(
        "wss://localhost:#{port}/socket",
        [],
        Keyword.merge(
          [
            tls_backend: :ex_ssl,
            ssl: tls(version),
            opening_timeout: 2_000,
            close_timeout: 100,
            write_timeout: 1_000
          ],
          extra
        )
      )

    on_exit(fn -> WebSocket.close(socket) end)
    socket
  end

  defp h2_socket(port, version, scope, extra \\ []) do
    socket =
      WebSocket.new(
        "wss://localhost:#{port}/ws/echo?count=1",
        [],
        Keyword.merge(
          [
            tls_backend: :ex_ssl,
            ssl: tls(version),
            http_version: :http2,
            http2_scope: scope,
            opening_timeout: 2_000,
            close_timeout: 500
          ],
          extra
        )
      )

    on_exit(fn -> WebSocket.close(socket) end)
    socket
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
