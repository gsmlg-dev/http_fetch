defmodule HTTP.ManagedExSSLTLSLifecycleTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :p3_managed_ex_ssl

  alias ExSSL.TestSupport.ClientAuthFixtures
  alias ExSSL.TestSupport.ManagedLifecycleProbe, as: Probe
  alias ExSSL.TestSupport.OpenSSLPeer
  alias HTTP.{ManagedTransport, Promise, RequestCompletion, Response}
  @fixtures Path.expand("../support/fixtures", __DIR__)
  @peer Path.expand("../../../../scripts/tls_migration_performance_peer.py", __DIR__)

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}],
      {protocol, alpn} <- [{:http1, "http/1.1"}, {:http2, "h2"}] do
    test "#{version} #{protocol} managed completion retains one provider through exact connection reuse" do
      version = unquote(version)
      protocol = unquote(protocol)
      {peer, origin} = peer(unquote(wire), unquote(alpn))
      scope = open(origin, protocol, version)

      try do
        first = fetch(origin, scope, "m-first")
        assert %Response{status: 200} = response = Promise.await(first, 5_000)
        assert Response.read_all(response) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
        stats = wait_stats(peer, &(&1["active_connections"] == 1))

        assert [%{"connection" => 1, "tls" => unquote(wire), "alpn" => unquote(alpn)}] =
                 stats["handshakes"]

        assert stats["accepted_connections"] == 1
        assert stats["closed_connections"] == 0
        assert stats["errors"] == []

        assert {:ok, %{connections: 1, provider_resources: counts}} =
                 ManagedTransport.snapshot(scope, 1_000)

        assert counts == %{
                 processes: 3,
                 tcp_sockets: 1,
                 observers: 1,
                 data_resources: 3,
                 generations: 1
               }

        later = fetch(origin, scope, "m-later")
        assert %Response{status: 200} = response = Promise.await(later, 5_000)
        assert Response.read_all(response) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(later), 1_000)
        assert :ok = RequestCompletion.abort_and_await(Promise.completion(first), 0)
        stats = wait_stats(peer, &(length(&1["requests"]) == 2))
        assert stats["accepted_connections"] == 1
        assert Enum.all?(stats["requests"], &(&1["connection"] == 1 and &1["completed"]))
        assert stats["errors"] == []
        assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
        assert :ok = ManagedTransport.await_retired(receipt, 3_000)
        assert :ok = ManagedTransport.await_retired(receipt, 0)
        stats = wait_stats(peer, &(&1["active_connections"] == 0))
        assert stats["closed_connections"] == 1
        assert stats["errors"] == []
      after
        {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
        ManagedTransport.await_retired(receipt, 3_000)
        stop_peer(peer)
      end
    end
  end

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}],
      {protocol, alpn} <- [{:http1, "http/1.1"}, {:http2, "h2"}] do
    test "#{version} #{protocol} TCP and Connection death retain capacity until Writer and Observer proof" do
      {peer, origin} = peer(unquote(wire), unquote(alpn))
      scope = open(origin, unquote(protocol), unquote(version))
      first = fetch(origin, scope, "m-original")
      assert Response.read_all(Promise.await(first, 5_000)) == "ok"
      assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
      stats = wait_stats(peer, &(&1["active_connections"] == 1))
      assert [%{"tls" => unquote(wire), "alpn" => unquote(alpn)}] = stats["handshakes"]
      graph = Probe.graph(scope)
      Probe.suspend(graph, :observer)
      Probe.suspend(graph, :writer)
      Probe.suspend(graph, :connection)

      try do
        assert :ok = Probe.close_tcp(graph)
        Probe.kill_connection(graph)
        Probe.await_down(graph, [:connection, :tcp], 1_000)
        assert Probe.alive?(graph, :writer)
        state = :sys.get_state(scope.coordinator, 100)

        for {_, {owner, :connection, _}} <- state.resources do
          monitor = Process.monitor(owner)
          send(owner, :http2_shutdown_exclusive)
          assert_receive {:DOWN, ^monitor, :process, ^owner, _}, 1_000
        end

        wait_until(fn -> map_size(:sys.get_state(scope.coordinator, 100).resources) == 0 end)
        assert_unknown_counts(scope)
        rejected = fetch(origin, scope, "m-rejected")

        expected =
          if unquote(protocol) == :http1,
            do: :handoff_unconfirmed,
            else: {:transport_scope_capacity, :connections}

        assert {:error, ^expected} = Promise.await(rejected, 1_000)
        assert_scope_connection_capacity(scope, origin)
        assert :ok = RequestCompletion.await(Promise.completion(rejected), 1_000)
        stats = wait_stats(peer, &(&1["closed_connections"] == 1))
        assert stats["accepted_connections"] == 1
        assert Enum.map(stats["requests"], & &1["id"]) == ["m-original"]
        Probe.resume(graph, :writer)
        Probe.await_down(graph, [:writer], 1_000)
        assert_unknown_counts(scope)
        Probe.resume(graph, :observer)

        assert {:ok, %{cleanup: :confirmed}} =
                 SSL.Lifecycle.await(graph.handle, {:abs_ms, now() + 2_000})

        Probe.await_down(graph, [:observer], 1_000)

        wait_until(fn ->
          match?({:ok, %{connections: 0}}, ManagedTransport.snapshot(scope, 100))
        end)

        if unquote(protocol) == :http1 do
          wait_until(fn -> map_size(:sys.get_state(state.h1, 100).entries) == 0 end)
        end

        replacement = fetch(origin, scope, "m-replacement")
        assert Response.read_all(Promise.await(replacement, 5_000)) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(replacement), 1_000)
        stats = wait_stats(peer, &(&1["accepted_connections"] == 2))

        assert Enum.map(stats["requests"], &{&1["id"], &1["connection"]}) == [
                 {"m-original", 1},
                 {"m-replacement", 2}
               ]

        assert stats["errors"] == []
        assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
        assert :ok = ManagedTransport.await_retired(receipt, 3_000)
      after
        Probe.resume(graph, :connection)
        Probe.resume(graph, :writer)
        Probe.resume(graph, :observer)
        Probe.release_monitors(graph)
        {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
        ManagedTransport.await_retired(receipt, 3_000)
        stop_peer(peer)
      end
    end
  end

  @tag timeout: 60_000
  test "100 authenticated live connections in one generation have exact counts and one observation budget" do
    {peer, origin} = peer("TLSv1.3", "http/1.1")
    scope = open(origin, :http1, :"tlsv1.3", max_connections: 100)

    requests =
      for id <- 1..100 do
        promise =
          HTTP.fetch(origin <> "/perf/m-many-#{id}/download",
            transport_scope: scope,
            stream_response: true,
            decode_body: false,
            redirect: :manual,
            timeout: 30_000
          )

        assert %Response{status: 200} = response = Promise.await(promise, 5_000)
        {promise, response}
      end

    try do
      stats = wait_stats(peer, &(&1["active_connections"] == 100))
      assert stats["accepted_connections"] == 100
      assert stats["errors"] == []
      assert length(stats["handshakes"]) == 100

      assert Enum.all?(
               stats["handshakes"],
               &(&1["tls"] == "TLSv1.3" and &1["alpn"] == "http/1.1")
             )

      assert {:ok, %{connections: 100, provider_resources: counts}} =
               ManagedTransport.snapshot(scope, 2_000)

      assert counts == %{
               processes: 300,
               tcp_sockets: 100,
               observers: 100,
               data_resources: 300,
               generations: 1
             }

      control = Probe.observer_control(scope)
      Probe.suspend(control, :observer)
      entered = now()

      try do
        case ManagedTransport.snapshot(scope, 50) do
          {:ok, %{provider_resources: nil}} -> :ok
          {:error, :cleanup_pending} -> :ok
          other -> flunk("incomplete100-connection census returned #{inspect(other)}")
        end

        assert now() - entered < 300
        assert %{coordinator: coordinator} = GenServer.call(scope.coordinator, :handle, 100)
        assert coordinator == scope.coordinator
        assert Probe.alive?(control, :observer)
      after
        Probe.resume(control, :observer)
      end

      assert {:ok, %{provider_resources: ^counts}} = ManagedTransport.snapshot(scope, 2_000)

      for {promise, response} <- requests do
        assert byte_size(Response.read_all(response)) == 1_048_576
        assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
      end

      assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      assert :ok = ManagedTransport.await_retired(receipt, 5_000)
      stats = wait_stats(peer, &(&1["active_connections"] == 0))
      assert stats["closed_connections"] == 100
      assert stats["accepted_connections"] == 100
      assert stats["errors"] == []
    after
      {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
      ManagedTransport.await_retired(receipt, 5_000)
      stop_peer(peer)
    end
  end

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}] do
    test "#{version} H2 cancellation preserves a live sibling and later exact connection reuse" do
      {peer, origin} = peer(unquote(wire), "h2")
      scope = open(origin, :http2, unquote(version))

      try do
        first = fetch(origin, scope, "m-prime")
        assert Response.read_all(Promise.await(first, 5_000)) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)

        blocked =
          HTTP.fetch(origin <> "/perf/m-blocked/cancel",
            transport_scope: scope,
            stream_response: true,
            decode_body: false,
            redirect: :manual,
            timeout: 5_000,
            method: :post,
            body: String.duplicate("Z", 1_048_576)
          )

        wait_stats(peer, &Enum.any?(&1["requests"], fn r -> r["id"] == "m-blocked" end))
        sibling = fetch(origin, scope, "m-surviving")
        assert %Response{} = response = Promise.await(sibling, 5_000)
        assert :ok = RequestCompletion.abort_and_await(Promise.completion(blocked), 1_000)
        assert {:error, :aborted} = Promise.await(blocked, 1_000)
        assert Response.read_all(response) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(sibling), 1_000)
        later = fetch(origin, scope, "m-after-cancel")
        assert Response.read_all(Promise.await(later, 5_000)) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(later), 1_000)

        stats =
          wait_stats(
            peer,
            &Enum.any?(&1["requests"], fn r -> r["id"] == "m-blocked" and r["cancelled"] end)
          )

        assert stats["accepted_connections"] == 1
        assert Enum.all?(stats["requests"], &(&1["connection"] == 1))
        assert stats["errors"] == []
      after
        cleanup_scope(scope)
        stop_peer(peer)
      end
    end
  end

  for {protocol, alpn} <- [{:http1, "http/1.1"}, {:http2, "h2"}] do
    test "#{protocol} unread response retains request capacity and graceful retirement until consumed" do
      {peer, origin} = peer("TLSv1.3", unquote(alpn))
      scope = open(origin, unquote(protocol), :"tlsv1.3", max_requests: 1)

      try do
        first = fetch(origin, scope, "m-unread")
        assert %Response{} = response = Promise.await(first, 5_000)

        assert {:error, {:transport_scope_capacity, :requests}} =
                 Promise.await(fetch(origin, scope, "m-no-capacity"), 1_000)

        assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
        assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 30)

        assert {:error, :transport_scope_retired} =
                 Promise.await(fetch(origin, scope, "m-retired"), 1_000)

        assert Response.read_all(response) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)

        waiters =
          for _ <- 1..8, do: Task.async(fn -> ManagedTransport.await_retired(receipt, 3_000) end)

        assert Enum.all?(waiters, &(Task.await(&1, 4_000) == :ok))
        assert :ok = ManagedTransport.await_retired(receipt, 0)
        stats = wait_stats(peer, &(&1["active_connections"] == 0))
        assert Enum.map(stats["requests"], & &1["id"]) == ["m-unread"]
        assert stats["accepted_connections"] == 1
        assert stats["errors"] == []
      after
        cleanup_scope(scope)
        stop_peer(peer)
      end
    end

    test "#{protocol} old generation retirement leaves new generation independently reusable" do
      {peer, origin} = peer("TLSv1.3", unquote(alpn))
      old = open(origin, unquote(protocol), :"tlsv1.3")
      fresh = open(origin, unquote(protocol), :"tlsv1.3")

      try do
        assert_drain(fetch(origin, old, "m-old"))
        assert_drain(fetch(origin, fresh, "m-new"))
        assert {:ok, %{identity: identity}} = ManagedTransport.snapshot(old, 100)
        assert {:ok, %{identity: ^identity}} = ManagedTransport.snapshot(fresh, 100)
        assert {:ok, receipt} = ManagedTransport.retire(old, mode: :graceful)
        assert :ok = ManagedTransport.await_retired(receipt, 3_000)
        assert_drain(fetch(origin, fresh, "m-survived-generation"))
        stats = wait_stats(peer, &(&1["closed_connections"] == 1))

        assert Enum.map(stats["requests"], &{&1["id"], &1["connection"]}) ==
                 [{"m-old", 1}, {"m-new", 2}, {"m-survived-generation", 2}]

        assert stats["accepted_connections"] == 2
        assert stats["errors"] == []
      after
        cleanup_scope(old)
        cleanup_scope(fresh)
        stop_peer(peer)
      end
    end

    for failure <- [:creator, :tracker, :abandoned] do
      test "#{protocol} #{failure} death settles admitted unread response and durable generation evidence" do
        {peer, origin} = peer("TLSv1.3", unquote(alpn))
        parent = self()

        {creator, creator_monitor} =
          spawn_monitor(fn ->
            scope = open(origin, unquote(protocol), :"tlsv1.3")
            send(parent, {:created_scope, scope})
            receive do: (:stop -> :ok)
          end)

        assert_receive {:created_scope, scope}, 1_000

        try do
          promise = fetch(origin, scope, "m-death")
          assert %Response{stream: stream} = Promise.await(promise, 5_000)
          stream_monitor = Process.monitor(stream)
          graph = Probe.graph(scope)
          assert {:ok, receipt} = ManagedTransport.retire(scope, mode: :graceful)
          assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 0)

          case unquote(failure) do
            :creator -> send(creator, :stop)
            :tracker -> Process.exit(Promise.completion(promise).tracker, :kill)
            :abandoned -> Process.exit(stream, :kill)
          end

          assert :ok = ManagedTransport.await_retired(receipt, 3_000)
          assert :ok = ManagedTransport.await_retired(receipt, 0)

          assert {:ok, %{cleanup: :confirmed}} =
                   SSL.Lifecycle.await(graph.handle, {:abs_ms, now() + 1_000})

          Probe.await_down(graph, [:connection, :writer, :tcp, :observer], 1_000)
          Probe.release_monitors(graph)

          if unquote(failure) == :tracker do
            assert {:error, :cleanup_unconfirmed} =
                     RequestCompletion.await(Promise.completion(promise), 0)
          end

          assert_receive {:DOWN, ^stream_monitor, :process, ^stream, _}, 1_000
          stats = wait_stats(peer, &(&1["active_connections"] == 0))
          assert stats["accepted_connections"] == 1
          assert Enum.map(stats["requests"], & &1["id"]) == ["m-death"]
          assert stats["errors"] == []
        after
          send(creator, :stop)
          cleanup_scope(scope)
          assert_receive {:DOWN, ^creator_monitor, :process, ^creator, _}, 1_000
          stop_peer(peer)
        end
      end
    end
  end

  for {version, wire} <- [{:"tlsv1.2", :tls12}, {:"tlsv1.3", :tls13}] do
    @tag :tmp_dir
    test "#{version} frozen CA certificate and key files authenticate mTLS after source rotation",
         %{tmp_dir: directory} do
      fixtures =
        ClientAuthFixtures.create(directory,
          server_sans: "DNS:localhost,IP:127.0.0.1"
        )

      {:ok, peer} =
        OpenSSLPeer.start(
          certfile: fixtures.server.certificate,
          keyfile: fixtures.server.key,
          cafile: fixtures.ca.certificate,
          verify: :required,
          min_version: unquote(wire),
          max_version: unquote(wire),
          mode: :http1,
          alpn: ["http/1.1"]
        )

      origin = "https://localhost:#{peer.port}"

      ssl = [
        cacertfile: fixtures.ca.certificate,
        certfile: fixtures.rsa.certificate,
        keyfile: fixtures.rsa.key,
        versions: [unquote(version)],
        alpn_advertised_protocols: ["http/1.1"]
      ]

      scope = open(origin, :http1, unquote(version), ssl: ssl)

      try do
        assert {:ok, %{identity: identity}} = ManagedTransport.snapshot(scope, 100)
        File.cp!(fixtures.wrong.certificate, fixtures.rsa.certificate)
        File.cp!(fixtures.wrong.key, fixtures.rsa.key)
        fresh = open(origin, :http1, unquote(version), ssl: ssl)
        assert {:ok, %{identity: rotated}} = ManagedTransport.snapshot(fresh, 100)
        refute identity == rotated
        cleanup_scope(fresh)
        File.rm!(fixtures.ca.certificate)
        File.rm!(fixtures.rsa.certificate)
        File.rm!(fixtures.rsa.key)
        promise = fetch(origin, scope, "m-captured-identity")
        assert %Response{status: 200} = response = Promise.await(promise, 5_000)
        assert Response.read_all(response) == "pong"
        assert :ok = RequestCompletion.await(Promise.completion(promise), 2_000)
        assert {:ok, handshake} = OpenSSLPeer.event(peer, "handshake", 1_000)
        assert Base.decode64!(handshake["client_der_b64"]) == fixtures.rsa.der
        assert handshake["alpn"] == "http/1.1"
        assert {:ok, %{identity: ^identity}} = ManagedTransport.snapshot(scope, 100)
        assert {:ok, _} = OpenSSLPeer.event(peer, "exchange", 1_000)
      after
        cleanup_scope(scope)
        OpenSSLPeer.stop(peer)
      end
    end
  end

  for failure <- [:deadline, :worker] do
    test "queued #{failure} before connector birth cannot dial after Scope resumes" do
      {peer, origin} = peer("TLSv1.3", "h2")
      scope = open(origin, :http2, :"tlsv1.3")
      :sys.suspend(scope.coordinator)

      try do
        promise = fetch(origin, scope, "m-never-dialed", timeout: 80)

        case unquote(failure) do
          :deadline ->
            assert {:error, :request_timeout} = Promise.await(promise, 500)

          :worker ->
            Process.exit(promise.task.pid, :kill)
            assert {:killed, _} = catch_exit(Promise.await(promise, 500))
        end

        assert wait_stats(peer, fn _ -> true end)["accepted_connections"] == 0
      after
        :sys.resume(scope.coordinator)
      end

      try do
        cleanup_scope(scope)
        stats = wait_stats(peer, fn _ -> true end)
        assert stats["accepted_connections"] == 0
        assert stats["requests"] == []
        assert stats["errors"] == []
      after
        stop_peer(peer)
      end
    end
  end

  @tag :tmp_dir
  test "system trust is captured once and later trust-source rotation changes only new scopes", %{
    tmp_dir: directory
  } do
    original = :public_key.cacerts_get()
    restore = Path.join(directory, "restore-ca.pem")

    entries =
      Enum.map(original, fn
        {:cert, der, _} -> {:Certificate, der, :not_encrypted}
        der when is_binary(der) -> {:Certificate, der, :not_encrypted}
      end)

    File.write!(restore, :public_key.pem_encode(entries))
    {peer, origin} = peer("TLSv1.3", "http/1.1")

    try do
      assert :ok = :public_key.cacerts_load(Path.join(@fixtures, "localhost-ca.pem"))
      ssl = [versions: [:"tlsv1.3"], alpn_advertised_protocols: ["http/1.1"]]
      scope = open(origin, :http1, :"tlsv1.3", ssl: ssl)

      try do
        assert {:ok, %{identity: captured}} = ManagedTransport.snapshot(scope, 100)
        assert :ok = :public_key.cacerts_load(Path.join(@fixtures, "pinned-ca.pem"))
        fresh = open(origin, :http1, :"tlsv1.3", ssl: ssl)
        assert {:ok, %{identity: rotated}} = ManagedTransport.snapshot(fresh, 100)
        refute captured == rotated
        cleanup_scope(fresh)
        assert_drain(fetch(origin, scope, "m-trust-captured"))
        assert {:ok, %{identity: ^captured}} = ManagedTransport.snapshot(scope, 100)
      after
        cleanup_scope(scope)
      end

      stats = wait_stats(peer, &(&1["active_connections"] == 0))
      assert stats["accepted_connections"] == 1
      assert stats["errors"] == []
    after
      assert :ok = :public_key.cacerts_load(restore)
      stop_peer(peer)
    end
  end

  for {protocol, alpn} <- [{:http1, "http/1.1"}, {:http2, "h2"}], mode <- [:graceful, :abort] do
    test "#{protocol} #{mode} retirement joins real Writer and Observer after TCP disappearance" do
      {peer, origin} = peer("TLSv1.3", unquote(alpn))
      scope = open(origin, unquote(protocol), :"tlsv1.3")
      assert_drain(fetch(origin, scope, "m-retire-proof"))
      graph = Probe.graph(scope)
      Probe.suspend(graph, :observer)
      Probe.suspend(graph, :writer)
      Probe.suspend(graph, :connection)

      try do
        assert :ok = Probe.close_tcp(graph)
        Probe.kill_connection(graph)
        Probe.await_down(graph, [:connection, :tcp], 1_000)
        assert Probe.alive?(graph, :writer)
        assert {:ok, receipt} = ManagedTransport.retire(scope, mode: unquote(mode))
        assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 30)
        assert Probe.alive?(graph, :writer)
        Probe.resume(graph, :writer)
        Probe.await_down(graph, [:writer], 1_000)
        assert {:error, :cleanup_pending} = ManagedTransport.await_retired(receipt, 30)
        Probe.resume(graph, :observer)

        assert {:ok, %{cleanup: :confirmed}} =
                 SSL.Lifecycle.await(graph.handle, {:abs_ms, now() + 2_000})

        Probe.await_down(graph, [:observer], 1_000)
        assert :ok = ManagedTransport.await_retired(receipt, 2_000)
        assert :ok = ManagedTransport.await_retired(receipt, 0)
        stats = wait_stats(peer, &(&1["active_connections"] == 0))
        assert stats["accepted_connections"] == 1
        assert stats["errors"] == []
      after
        Probe.resume(graph, :connection)
        Probe.resume(graph, :writer)
        Probe.resume(graph, :observer)
        Probe.release_monitors(graph)
        cleanup_scope(scope)
        stop_peer(peer)
      end
    end
  end

  defp assert_drain(promise) do
    assert %Response{} = response = Promise.await(promise, 5_000)
    assert Response.read_all(response) == "ok"
    assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
  end

  defp cleanup_scope(scope) do
    {:ok, receipt} = ManagedTransport.retire(scope, mode: :abort)
    ManagedTransport.await_retired(receipt, 3_000)
  end

  defp assert_scope_connection_capacity(scope, origin) do
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

    try do
      assert {:ok, request} = ManagedTransport.prepare(request, [])
      assert :ok = ManagedTransport.associate(request, tracker)
      assert :ok = ManagedTransport.admit(request, tracker)
      Process.put(HTTP.RequestLifecycle, tracker)

      assert {:error, {:transport_scope_capacity, :connections}} =
               ManagedTransport.connect_start(request)

      state = :sys.get_state(scope.coordinator, 100)
      assert map_size(state.resources) == 0
      assert map_size(state.slots) == 1
    after
      Process.delete(HTTP.RequestLifecycle)
      if Process.alive?(tracker), do: GenServer.stop(tracker, :normal)
    end
  end

  defp assert_unknown_counts(scope) do
    case ManagedTransport.snapshot(scope, 20) do
      {:ok, %{connections: 1, provider_resources: nil}} -> :ok
      {:error, :cleanup_pending} -> :ok
      result -> flunk("suspended provider observation returned #{inspect(result)}")
    end
  end

  defp now, do: System.monotonic_time(:millisecond)

  defp wait_until(fun, deadline \\ nil) do
    deadline = deadline || now() + 2_000

    unless fun.() do
      assert now() < deadline

      receive do
      after
        1 -> wait_until(fun, deadline)
      end
    end
  end

  defp open(origin, protocol, version, extra \\ []) do
    ssl = [cacertfile: Path.join(@fixtures, "localhost-ca.pem"), versions: [version]]
    ssl = if protocol == :http1, do: ssl ++ [alpn_advertised_protocols: ["http/1.1"]], else: ssl

    assert {:ok, scope} =
             ManagedTransport.open(
               Keyword.merge(
                 [
                   origin: origin,
                   connect_address: {127, 0, 0, 1},
                   http_version: protocol,
                   tls_backend: :ex_ssl,
                   max_connections: 1,
                   max_requests: 128,
                   ssl: ssl
                 ],
                 extra
               )
             )

    scope
  end

  defp fetch(origin, scope, id, extra \\ []),
    do:
      HTTP.fetch(
        origin <> "/perf/" <> id <> "/reuse",
        Keyword.merge(
          [
            transport_scope: scope,
            stream_response: true,
            decode_body: false,
            redirect: :manual,
            timeout: 5_000
          ],
          extra
        )
      )

  defp peer(version, protocol) do
    state =
      Path.join(System.tmp_dir!(), "http-fetch-p3-managed-#{System.unique_integer([:positive])}")

    python = System.find_executable("python3") || raise "python3 is required"

    peer =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          @peer,
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key"),
          "--protocol",
          protocol,
          "--tls",
          version,
          "--workload",
          "cancel",
          "--state-dir",
          state,
          "--lifetime",
          "120"
        ]
      ])

    on_exit(fn -> if Port.info(peer), do: Port.close(peer) end)
    ready = event(peer)
    assert ready["event"] == "ready"
    {peer, "https://localhost:#{ready["port"]}"}
  end

  defp event(peer) do
    receive do
      {^peer, {:data, {:eol, line}}} ->
        if System.get_env("P3_MANAGED_PEER_EVIDENCE"), do: IO.puts("P3_MANAGED_PEER " <> line)
        JSON.decode!(line)

      {^peer, {:exit_status, code}} ->
        flunk("independent peer exited #{code}")
    after
      5_000 -> flunk("independent peer event timeout")
    end
  end

  defp wait_stats(peer, predicate),
    do: wait_stats(peer, predicate, System.monotonic_time(:millisecond) + 1_000)

  defp wait_stats(peer, predicate, deadline) do
    assert Port.command(peer, JSON.encode!(%{command: "stats"}) <> "\n")
    stats = event(peer)

    if predicate.(stats) do
      stats
    else
      assert System.monotonic_time(:millisecond) < deadline, "peer condition did not settle"

      receive do
      after
        1 -> wait_stats(peer, predicate, deadline)
      end
    end
  end

  defp stop_peer(peer) do
    assert Port.command(peer, JSON.encode!(%{command: "stop"}) <> "\n")
    assert event(peer)["event"] == "stop"
    assert_receive {^peer, {:exit_status, 0}}, 5_000
  end
end
