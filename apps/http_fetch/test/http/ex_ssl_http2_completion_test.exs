defmodule HTTP.ExSSLHTTP2CompletionTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :p3_ex_ssl_h2

  alias HTTP.HTTP2.Pool
  alias HTTP.{Promise, RequestCompletion, Response}
  alias HTTP.Transport.ExSSL

  @fixtures Path.expand("../support/fixtures", __DIR__)
  @lifecycle_peer Path.expand("../support/ex_ssl_http2_lifecycle_peer.py", __DIR__)
  @peer Path.expand("../../../../scripts/tls_migration_performance_peer.py", __DIR__)

  for {version, wire, tag} <- [
        {:"tlsv1.2", "TLSv1.2", :p3_ex_ssl_h2_tls12},
        {:"tlsv1.3", "TLSv1.3", :p3_ex_ssl_h2_tls13}
      ] do
    @tag :p3_ex_ssl_h2_red
    @tag tag
    test "authenticated #{version} first completion settles with a live sibling" do
      {peer, origin} = peer(unquote(wire))

      try do
        options = options(unquote(version))
        first = HTTP.fetch(origin <> "/perf/m-first/reuse", options)
        assert %Response{status: 200} = response = Promise.await(first, 5_000)
        assert Response.read_all(response) == "ok"

        sibling =
          HTTP.fetch(
            origin <> "/perf/m-sibling/cancel",
            options ++ [method: :post, body: String.duplicate("Z", 1_048_576)]
          )

        stats = wait_stats(peer, &Enum.any?(&1["requests"], fn r -> r["id"] == "m-sibling" end))

        assert [%{"connection" => 1, "tls" => unquote(wire), "alpn" => "h2"}] =
                 stats["handshakes"]

        assert stats["accepted_connections"] == 1
        assert stats["active_connections"] == 1
        assert stats["closed_connections"] == 0
        assert stats["errors"] == []
        assert Enum.all?(stats["requests"], &(&1["connection"] == 1))
        refute Enum.find(stats["requests"], &(&1["id"] == "m-sibling"))["completed"]

        assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
        assert :ok = RequestCompletion.abort_and_await(Promise.completion(sibling), 1_000)
        assert {:error, :aborted} = Promise.await(sibling, 1_000)

        later = HTTP.fetch(origin <> "/perf/m-later/reuse", options)
        assert %Response{status: 200} = response = Promise.await(later, 5_000)
        assert Response.read_all(response) == "ok"
        assert :ok = RequestCompletion.await(Promise.completion(later), 1_000)

        stats =
          wait_stats(
            peer,
            &Enum.any?(&1["requests"], fn r -> r["id"] == "m-sibling" and r["cancelled"] end)
          )

        assert stats["accepted_connections"] == 1
        assert stats["closed_connections"] == 0
        assert stats["active_connections"] == 1
        assert stats["errors"] == []
        assert Enum.all?(stats["requests"], &(&1["connection"] == 1))
      after
        stop_peer(peer)
      end
    end
  end

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}] do
    for mode <- [:exclusive, :callback] do
      test "#{version} #{mode} keeps cleanup exclusive and does not publish" do
        {peer, origin} = peer(unquote(wire))

        try do
          options = options(unquote(version))

          options =
            if unquote(mode) == :exclusive do
              Keyword.put(options, :http2_reuse, false)
            else
              callback = fn _, _, state -> {:valid, state} end
              Keyword.update!(options, :ssl, &Keyword.put(&1, :verify_fun, {callback, nil}))
            end

          promise = HTTP.fetch(origin <> "/perf/m-exclusive/reuse", options)
          assert %Response{status: 200} = response = Promise.await(promise, 5_000)
          assert Response.read_all(response) == "ok"
          assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
          stats = wait_stats(peer, &(&1["closed_connections"] == 1))
          assert stats["accepted_connections"] == 1
          assert stats["active_connections"] == 0
          assert stats["errors"] == []

          refute Enum.any?(Pool.stats(:http_fetch_http2_pool), fn {key, _} ->
                   key.port == URI.parse(origin).port
                 end)
        after
          stop_peer(peer)
        end
      end
    end

    for terminal <- [:abort, :deadline] do
      test "#{version} queued #{terminal} returns without late request bytes" do
        {peer, origin} = peer(unquote(wire))
        pool = Process.whereis(:http_fetch_http2_pool)
        options = options(unquote(version))
        first = HTTP.fetch(origin <> "/perf/m-first/reuse", options)
        assert %Response{status: 200} = Promise.await(first, 5_000)
        assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
        :sys.suspend(pool)

        try do
          timeout = if unquote(terminal) == :deadline, do: 100, else: 3_000

          second =
            HTTP.fetch(
              origin <> "/perf/m-never/cancel",
              Keyword.merge(options, method: :post, body: "never", timeout: timeout)
            )

          wait_until(fn ->
            {:messages, messages} = Process.info(pool, :messages)

            Enum.any?(messages, fn
              {:"$gen_call", _, {:try_reserve, _, _}} -> true
              _ -> false
            end)
          end)

          if unquote(terminal) == :abort,
            do:
              assert(
                RequestCompletion.abort_and_await(Promise.completion(second), 0) ==
                  {:error, :cleanup_pending}
              )

          expected = if unquote(terminal) == :abort, do: :aborted, else: :request_timeout
          assert {:error, ^expected} = Promise.await(second, 1_500)
          assert :ok = RequestCompletion.await(Promise.completion(second), 1_500)
        after
          :sys.resume(pool)
        end

        try do
          later = HTTP.fetch(origin <> "/perf/m-later/reuse", options)
          assert %Response{status: 200} = Promise.await(later, 5_000)
          assert :ok = RequestCompletion.await(Promise.completion(later), 1_000)
          stats = wait_stats(peer, &(length(&1["requests"]) == 2))
          assert Enum.map(stats["requests"], & &1["id"]) |> Enum.sort() == ["m-first", "m-later"]
          assert stats["accepted_connections"] == 1
          assert stats["errors"] == []
        after
          stop_peer(peer)
        end
      end
    end
  end

  for {version, wire, suspended?} <- [
        {:"tlsv1.2", "TLSv1.2", false},
        {:"tlsv1.3", "TLSv1.3", false},
        {:"tlsv1.3", "TLSv1.3", true}
      ] do
    @tag :p3_fetch_owner_enrollment
    test "#{version} Fetch enrollment timeout preserves bounded cleanup with suspended owner #{suspended?}" do
      alias HTTP.HTTP2.{ConnectionOwner, ConnectionSupervisor}
      alias HTTP.RequestLifecycle

      {peer, origin} = peer(unquote(wire))
      {tracker, latch} = RequestLifecycle.start()
      completion = %RequestCompletion{tracker: tracker, latch: latch}
      supervisor = start_supervised!(ConnectionSupervisor)
      test_pid = self()

      gate =
        spawn_link(fn ->
          receive do
            {:"$gen_call", from, message} ->
              {:ok, owner} = result = GenServer.call(supervisor, message)
              :sys.suspend(tracker)
              send(test_pid, {:enrollment_owner, owner, elem(from, 0)})

              receive do
                :release -> GenServer.reply(from, result)
              end
          end
        end)

      request = %HTTP.Request{
        url: URI.parse(origin <> "/perf/m-never/reuse"),
        transport_options:
          Keyword.merge(options(unquote(version)),
            request_lifecycle: tracker,
            http2_connection_supervisor: gate,
            timeout: 1_000
          )
      }

      worker = Task.async(fn -> HTTP.SocketClient.request(request) end)

      try do
        assert_receive {:enrollment_owner, owner, request_owner}, 1_000
        down = Process.monitor(owner)
        request_down = Process.monitor(request_owner)
        assert %{wrote_preface?: false} = ConnectionOwner.status(owner)
        if unquote(suspended?), do: :erlang.suspend_process(owner)

        try do
          send(gate, :release)
          assert_receive {:DOWN, ^request_down, :process, ^request_owner, :normal}, 1_500

          if unquote(suspended?) do
            assert Process.alive?(owner)
            refute_receive {:DOWN, ^down, :process, ^owner, _}, 0
          else
            assert_receive {:DOWN, ^down, :process, ^owner, :normal}, 200
          end

          assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
        after
          send(gate, :release)
          if unquote(suspended?), do: :erlang.resume_process(owner)
          :sys.resume(tracker)
        end

        assert {:error, :request_timeout} = Task.await(worker, 1_000)
        assert :ok = RequestCompletion.await(completion, 1_000)
        stats = wait_stats(peer, &(&1["closed_connections"] == 1))

        assert [%{"connection" => 1, "tls" => unquote(wire), "alpn" => "h2"}] =
                 stats["handshakes"]

        assert stats["accepted_connections"] == 1
        assert stats["requests"] == []
        assert stats["errors"] == []
      after
        stop_peer(peer)
      end
    end
  end

  for boundary <- [:stream_body, :binary_body, :binary_attach, :response_attach, :delivery] do
    @tag :p3_fetch_worker_enrollment
    test "Fetch #{boundary} enrollment cannot block its original request deadline" do
      assert_worker_enrollment(unquote(boundary))
    end
  end

  for consumer <- [:dialer, :adapter] do
    @tag :p3_provider_control
    test "#{consumer} authenticated provider binding consumes the original setup deadline" do
      alias HTTP.RequestLifecycle

      {peer, origin} = peer("TLSv1.3")
      {tracker, latch} = RequestLifecycle.start()
      completion = %RequestCompletion{tracker: tracker, latch: latch}
      release = install_tracker_barrier(tracker, self(), :provider_bind)

      request = %HTTP.Request{
        url: URI.parse(origin <> "/perf/m-never/reuse"),
        transport_options:
          Keyword.merge(options(:"tlsv1.3"), request_lifecycle: tracker, timeout: 500)
      }

      task =
        Task.async(fn ->
          if unquote(consumer == :dialer) do
            HTTP.SocketClient.request(request)
          else
            RequestLifecycle.enter(tracker, :owner)

            opts =
              Keyword.update!(
                request.transport_options,
                :ssl,
                &Keyword.put(&1, :alpn_advertised_protocols, ["h2"])
              )

            result = ExSSL.connect("localhost", URI.parse(origin).port, opts, 500)
            RequestLifecycle.complete(tracker, :infinity)
            result
          end
        end)

      try do
        assert_receive {:control_held, ^tracker, owner, :provider_bind}, 1_000
        down = Process.monitor(owner)
        assert_receive {:DOWN, ^down, :process, ^owner, :normal}, 800
        assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
        release.()
        result = Task.await(task, 1_000)

        if System.get_env("P3_H2_PEER_EVIDENCE") == "1" do
          IO.puts(
            "P3_H2_CONTROL " <>
              JSON.encode!(%{consumer: unquote(consumer), result: inspect(result)})
          )
        end

        if unquote(consumer == :adapter) do
          assert result == {:error, :request_timeout}
        else
          # The connect timer and adapter binding use the same original budget.
          assert result in [{:error, :request_timeout}, {:error, :connect_timeout}]
        end

        assert :ok = RequestCompletion.await(completion, 1_000)
        stats = wait_stats(peer, &(&1["closed_connections"] == 1))
        assert [%{"tls" => "TLSv1.3", "alpn" => "h2"}] = stats["handshakes"]
        assert stats["accepted_connections"] == 1
        assert stats["requests"] == []
        assert stats["errors"] == []
      after
        release.()
        stop_peer(peer)
      end
    end
  end

  @tag :p3_provider_control
  test "Dialer enrollment timeout stops its waiting worker before any connection" do
    alias HTTP.RequestLifecycle
    {peer, origin} = peer("TLSv1.3")
    {tracker, latch} = RequestLifecycle.start()
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    release = install_tracker_barrier(tracker, self(), :dial_enroll)

    task =
      Task.async(fn ->
        HTTP.SocketClient.request(%HTTP.Request{
          url: URI.parse(origin <> "/perf/m-never/reuse"),
          transport_options:
            Keyword.merge(options(:"tlsv1.3"), request_lifecycle: tracker, timeout: 500)
        })
      end)

    try do
      assert_receive {:control_held, ^tracker, owner, worker}, 1_000
      owner_down = Process.monitor(owner)
      worker_down = Process.monitor(worker)
      assert_receive {:DOWN, ^owner_down, :process, ^owner, :normal}, 800
      assert_receive {:DOWN, ^worker_down, :process, ^worker, :normal}, 200
      assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
      release.()
      assert {:error, :request_timeout} = Task.await(task, 1_000)
      assert :ok = RequestCompletion.await(completion, 1_000)
      stats = wait_stats(peer, fn _ -> true end)
      assert stats["accepted_connections"] == 0
      assert stats["requests"] == []
      assert stats["errors"] == []
    after
      release.()
      stop_peer(peer)
    end
  end

  for failure <- [:wrong_ca, :wrong_name, :no_h2] do
    test "#{failure} rejects before any HTTP/2 request and joins provider cleanup" do
      protocol = if unquote(failure) == :no_h2, do: "http/1.1", else: "h2"
      {peer, origin} = peer("TLSv1.3", protocol)

      try do
        options = options(:"tlsv1.3")

        options =
          if unquote(failure) == :wrong_ca,
            do:
              Keyword.update!(
                options,
                :ssl,
                &Keyword.put(&1, :cacertfile, Path.join(@fixtures, "pinned-ca.pem"))
              ),
            else: options

        url =
          if unquote(failure) == :wrong_name,
            do: String.replace(origin, "localhost", "wrong.invalid"),
            else: origin

        promise = HTTP.fetch(url <> "/perf/m-never/reuse", options)
        assert {:error, reason} = Promise.await(promise, 5_000)

        if unquote(failure) == :no_h2 do
          assert reason == {:http2_not_negotiated, nil}
        end

        assert :ok = RequestCompletion.await(Promise.completion(promise), 1_000)
        stats = wait_stats(peer, &(&1["closed_connections"] == 1))
        assert stats["requests"] == []
        assert stats["accepted_connections"] == 1

        if unquote(failure) == :no_h2 do
          assert [%{"tls" => "TLSv1.3", "alpn" => nil}] = stats["handshakes"]
          assert stats["http_bytes"] == 0
          assert stats["errors"] == []
        end
      after
        stop_peer(peer)
      end
    end
  end

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}] do
    for terminal <- [
          :idle,
          :owner_death,
          :pool_death,
          :failed_activation,
          :lost_ack,
          :abort_after_accept
        ] do
      test "#{version} staged #{terminal} retains real provider evidence until confirmed cleanup" do
        {peer, origin} = peer(unquote(wire))
        alias HTTP.HTTP2.ConnectionOwner
        alias HTTP.{RequestLifecycle, Transport.ExSSL}
        pool = start_supervised!({Pool, idle_timeout: 100, max_total_connections: 1})
        {tracker, latch} = RequestLifecycle.start()

        worker =
          spawn(fn ->
            receive do
              :finish -> RequestLifecycle.complete(tracker)
            end
          end)

        on_exit(fn -> if Process.alive?(worker), do: Process.exit(worker, :kill) end)
        assert :ok = RequestLifecycle.register(tracker, worker, :task)
        deadline = System.monotonic_time(:millisecond) + 5_000

        assert {:ok, {handle, lease}} =
                 RequestLifecycle.begin_provider(tracker, :ex_ssl, deadline)

        try do
          assert {:ok, socket} =
                   SSL.connect({127, 0, 0, 1}, URI.parse(origin).port,
                     verify: :verify_peer,
                     cacertfile: Path.join(@fixtures, "localhost-ca.pem"),
                     server_name_indication: ~c"localhost",
                     versions: [unquote(version)],
                     alpn_advertised_protocols: ["h2"],
                     active: false,
                     ex_ssl: [lifecycle: {handle, lease}]
                   )

          assert :ok = RequestLifecycle.bind_provider(tracker, socket)

          transport =
            if unquote(terminal) == :failed_activation do
              %{
                send: fn _, _ -> {:error, :injected_activation_failure} end,
                setopts: &ExSSL.setopts/2,
                close: &ExSSL.close/1,
                normalize_message: &ExSSL.normalize_message/2
              }
            else
              ExSSL
            end

          owner =
            start_supervised!(
              Supervisor.child_spec(
                {ConnectionOwner, transport: transport, socket: socket, activate?: false},
                restart: :temporary
              )
            )

          owner_down = Process.monitor(owner)
          assert :ok = RequestLifecycle.register(tracker, owner, :connection)

          assert :ok =
                   GenServer.call(
                     pool,
                     {:prepare_provider, :staged, owner, [request_lifecycle: tracker], deadline}
                   )

          assert {:ok, carrier} =
                   RequestLifecycle.offer_provider(
                     tracker,
                     socket,
                     %{controller: pool, owner: owner},
                     deadline
                   )

          if unquote(terminal) == :lost_ack do
            reply = :erlang.alias()
            :erlang.unalias(reply)
            reply_tag = [:alias | reply]

            send(
              pool,
              {:"$gen_call", {self(), reply_tag}, {:accept_provider, owner, carrier, deadline}}
            )

            wait_until(fn -> RequestLifecycle.transfer_state(carrier) == :accepted end)
            refute_receive {^reply_tag, _}, 0
            assert %{connections: 0, provider_pending: 1} = Pool.stats(pool).staged
            assert :none = Pool.try_reserve(pool, :staged)
            assert :wait = Pool.claim_connect(pool, :staged)
          end

          assert :ok = GenServer.call(pool, {:accept_provider, owner, carrier, deadline})
          assert {:pending, %{epoch: 1, transfer: :accepted}} = SSL.Lifecycle.status(handle)
          assert RequestLifecycle.transfer_state(%{carrier | nonce: make_ref()}) == :unconfirmed

          if unquote(terminal) != :abort_after_accept,
            do: assert(:ok == RequestLifecycle.release_provider(tracker, carrier, deadline))

          assert :abort = RequestLifecycle.abort(tracker)
          send(worker, :finish)
          wait_until(fn -> :atomics.get(latch, 1) == 2 end)
          assert Process.alive?(owner)
          assert %{wrote_preface?: false} = ConnectionOwner.status(owner)

          if unquote(terminal) == :failed_activation do
            assert {:error, :injected_activation_failure} =
                     ConnectionOwner.activate(owner, deadline)

            GenServer.cast(pool, {:retire_provider, owner})
          else
            assert :ok = ConnectionOwner.activate(owner, deadline)
            assert :ok = GenServer.call(pool, {:publish_provider, owner, deadline})

            case unquote(terminal) do
              :owner_death -> Process.exit(owner, :kill)
              :pool_death -> stop_supervised(Pool)
              :lost_ack -> GenServer.cast(pool, {:retire_provider, owner})
              mode when mode in [:idle, :abort_after_accept] -> :ok
            end
          end

          assert {:ok, %{cleanup: :confirmed}} =
                   SSL.Lifecycle.await(
                     handle,
                     {:abs_ms, System.monotonic_time(:millisecond) + 1_000}
                   )

          assert_receive {:DOWN, ^owner_down, :process, ^owner, _}, 1_000
          if unquote(terminal) != :pool_death, do: wait_until(fn -> Pool.stats(pool) == %{} end)
          stats = wait_stats(peer, &(&1["closed_connections"] == 1))
          assert [%{"tls" => unquote(wire), "alpn" => "h2"}] = stats["handshakes"]
          assert stats["requests"] == []
          assert stats["accepted_connections"] == 1
          assert stats["errors"] == []
        after
          RequestLifecycle.abort(tracker)
          stop_peer(peer)
        end
      end
    end
  end

  defp assert_worker_enrollment(boundary) do
    alias HTTP.RequestLifecycle

    {peer, origin} = peer("TLSv1.3")
    first = HTTP.fetch(origin <> "/perf/m-first/reuse", options(:"tlsv1.3"))
    assert %Response{status: 200} = Promise.await(first, 5_000)
    assert :ok = RequestCompletion.await(Promise.completion(first), 1_000)
    {tracker, latch} = RequestLifecycle.start()
    completion = %RequestCompletion{tracker: tracker, latch: latch}
    parent = self()
    barrier = tracker
    release = install_tracker_barrier(tracker, parent, boundary)
    {:ok, source} = HTTP.Stream.start_link(0)
    body = if boundary == :stream_body, do: source, else: "request"
    upload? = boundary in [:stream_body, :binary_body, :binary_attach]

    request = %HTTP.Request{
      url: URI.parse(origin <> "/perf/m-target/reuse"),
      method: if(upload?, do: :post, else: :get),
      body: if(upload?, do: body),
      duplex: if(boundary == :stream_body, do: :half),
      transport_options:
        Keyword.merge(options(:"tlsv1.3"),
          request_lifecycle: barrier,
          timeout: 500,
          stream_response: not upload?
        )
    }

    task = Task.async(fn -> HTTP.SocketClient.request(request) end)

    try do
      assert_receive {:control_held, ^barrier, owner, resource}, 1_000
      owner_down = Process.monitor(owner)
      resource_down = Process.monitor(resource)

      try do
        assert_receive {:DOWN, ^owner_down, :process, ^owner, :normal}, 800
        assert_receive {:DOWN, ^resource_down, :process, ^resource, _}, 200
        assert {:error, :cleanup_pending} = RequestCompletion.await(completion, 0)
      after
        release.()
      end

      result = Task.await(task, 1_000)
      if boundary != :delivery, do: assert(result == {:error, :request_timeout})
      assert :ok = RequestCompletion.await(completion, 1_000)
      later = HTTP.fetch(origin <> "/perf/m-later/reuse", options(:"tlsv1.3"))
      assert %Response{status: 200} = Promise.await(later, 5_000)
      assert :ok = RequestCompletion.await(Promise.completion(later), 1_000)
      stats = wait_stats(peer, &Enum.any?(&1["requests"], fn r -> r["id"] == "m-later" end))
      assert stats["accepted_connections"] == 1
      assert stats["errors"] == []
      assert Enum.all?(stats["requests"], &(&1["connection"] == 1))
      if upload?, do: refute(Enum.any?(stats["requests"], &(&1["id"] == "m-target")))
    after
      release.()
      Process.unlink(source)
      Process.exit(source, :shutdown)
      stop_peer(peer)
    end
  end

  defp install_tracker_barrier(tracker, parent, boundary) do
    token = make_ref()
    released = :atomics.new(1, [])

    hook = fn blocked?, event, _name ->
      case event do
        {:in, {:"$gen_call", from, {:bind_provider, _socket}}}
        when not blocked? and boundary == :provider_bind ->
          send(parent, {:control_held, tracker, elem(from, 0), :provider_bind})
          receive do: ({:release_control, ^token} -> :ok)
          true

        {:in, {:"$gen_call", from, {:register, resource, kind}}} when not blocked? ->
          if barrier_kind?(boundary, kind) do
            send(parent, {:control_held, tracker, elem(from, 0), resource})
            receive do: ({:release_control, ^token} -> :ok)
            true
          else
            false
          end

        _ ->
          blocked?
      end
    end

    :ok = :sys.install(tracker, {hook, false})

    fn ->
      if :atomics.compare_exchange(released, 1, 0, 1) == :ok,
        do: send(tracker, {:release_control, token})
    end
  end

  defp barrier_kind?(boundary, :body_bridge), do: boundary in [:stream_body, :binary_body]

  defp barrier_kind?(boundary, kind) when kind in [:stream_starting, :managed_stream_starting],
    do: boundary in [:binary_attach, :response_attach]

  defp barrier_kind?(:dial_enroll, :dial), do: true
  defp barrier_kind?(:delivery, :delivery), do: true
  defp barrier_kind?(_, _), do: false

  defp wait_until(fun), do: wait_until(fun, System.monotonic_time(:millisecond) + 1_000)

  defp wait_until(fun, deadline) do
    if fun.() do
      :ok
    else
      assert System.monotonic_time(:millisecond) < deadline

      receive do
      after
        1 -> wait_until(fun, deadline)
      end
    end
  end

  defp options(version) do
    [
      tls_backend: :ex_ssl,
      http_version: :http2,
      redirect: :manual,
      connect_address: {127, 0, 0, 1},
      timeout: 5_000,
      ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem"), versions: [version]]
    ]
  end

  defp peer(version, protocol \\ "h2") do
    state = Path.join(System.tmp_dir!(), "http-fetch-p3-h2-#{System.unique_integer([:positive])}")
    python = System.find_executable("python3") || raise "python3 is required"

    peer =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          if(protocol == "h2", do: @peer, else: @lifecycle_peer),
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
        if System.get_env("P3_H2_PEER_EVIDENCE"), do: IO.puts("P3_H2_PEER " <> line)
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
