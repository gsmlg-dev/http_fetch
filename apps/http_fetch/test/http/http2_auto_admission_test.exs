defmodule HTTP.HTTP2AutoAdmissionTest do
  use ExUnit.Case, async: false

  alias HTTP.HTTP2.Pool
  alias HTTP.Request
  alias HTTP.SocketClient

  @root Path.expand("../../../..", __DIR__)
  @fixtures Path.expand("../support/fixtures", __DIR__)

  setup do
    pool = Process.whereis(:http_fetch_http2_pool)
    original = :sys.get_state(pool)
    :sys.replace_state(pool, &%{&1 | max_connections: 1, max_total_connections: 1})

    on_exit(fn ->
      state = :sys.get_state(pool)
      for {_, {pid, _}} <- state.connectors, do: Process.exit(pid, :kill)
      for {_, {pid, _}} <- state.callers, do: Process.exit(pid, :kill)

      for {_, entry} <- state.entries, {owner, _} <- entry.connections do
        if Process.alive?(owner), do: GenServer.stop(owner, :normal)
      end

      :sys.replace_state(pool, fn state ->
        %{
          state
          | max_connections: original.max_connections,
            max_total_connections: original.max_total_connections,
            max_pending: original.max_pending
        }
      end)
    end)

    {:ok, pool: pool}
  end

  for backend <- [:ssl, :ex_ssl] do
    @tag backend: backend, admission_cold: true
    test "cold auto HTTPS bounds actual TCP accepts for #{backend}", %{
      pool: pool,
      backend: backend
    } do
      {peer, url} = peer!()
      tasks = burst(url, backend, 6)

      counts =
        barrier(peer, pool, fn counts, state ->
          counts["accepted"] == 6 or (counts["accepted"] >= 1 and pending(state) == 5)
        end)

      assert counts["accepted"] == 1
      command(peer, "handshake")
      command(peer, "respond")
      assert_ok(tasks)
      final = snapshot(peer)
      assert final["handshakes"] == 1
      assert final["peak_inflight_handshakes"] == 1
      IO.puts(JSON.encode!(Map.merge(final, %{gate: "auto_admission_wire", backend: backend})))
      assert_idle(pool)
    end

    @tag backend: backend
    test "saturated auto owner queues bursts without dialing for #{backend}", %{
      pool: pool,
      backend: backend
    } do
      {peer, url} = peer!()
      command(peer, "handshake")
      first = burst(url, backend, 1)
      barrier(peer, pool, fn counts, _ -> counts["requests"] == 1 end)
      more = burst(url, backend, 5)

      counts =
        barrier(peer, pool, fn counts, state -> counts["accepted"] > 1 or pending(state) == 5 end)

      assert counts["accepted"] == 1
      command(peer, "respond")
      assert_ok(first ++ more)
      assert snapshot(peer)["accepted"] == 1
      assert_idle(pool)
    end

    for stage <- [:queued, :dialing], action <- [:abort, :deadline, :caller_down] do
      @tag backend: backend, stage: stage, action: action
      test "#{action} settles #{stage} auto admission for #{backend}", context do
        %{pool: pool, backend: backend, stage: stage, action: action} = context
        {peer, url} = peer!()
        blocker_signal = HTTP.AbortController.new()

        blockers =
          if stage == :queued do
            blocker =
              Task.async(fn -> SocketClient.request(request(url, backend), blocker_signal) end)

            barrier(peer, pool, fn counts, _ -> counts["accepted"] == 1 end)
            [blocker]
          else
            []
          end

        signal = HTTP.AbortController.new()
        timeout = if action == :deadline, do: 1_000, else: 10_000

        task =
          Task.async(fn ->
            SocketClient.request(request(url, backend, timeout: timeout), signal)
          end)

        barrier(peer, pool, fn counts, state ->
          if stage == :queued, do: pending(state) == 1, else: counts["accepted"] == 1
        end)

        case action do
          :abort ->
            HTTP.AbortController.abort(signal)
            assert {:error, :aborted} = Task.await(task, 3_000)

          :deadline ->
            assert {:error, reason} = Task.await(task, 3_000)
            # A dialing TLS handshake can time out before the outer deadline wins.
            assert reason in [:request_timeout, :deadline_exceeded, :connect_timeout] or
                     (stage == :dialing and reason == :timeout)

          :caller_down ->
            Task.shutdown(task, :brutal_kill)
        end

        barrier(peer, pool, fn _, state ->
          pending(state) == 0 and
            Enum.sum(for {_, e} <- state, do: e.connecting) == length(blockers)
        end)

        if blockers != [] do
          HTTP.AbortController.abort(blocker_signal)
          assert [{:error, :aborted}] = Task.await_many(blockers, 3_000)
        end

        assert_idle(pool)
      end
    end

    @tag backend: backend
    test "caller death while awaiting initial stream capacity releases registration for #{backend}",
         %{pool: pool, backend: backend} do
      {peer, url} = peer!("h2", 0)
      [task] = burst(url, backend, 1)
      barrier(peer, pool, fn counts, _ -> counts["accepted"] == 1 end)

      # Hold registration until the peer observes its zero limit acknowledged.
      # An initial request before receiving SETTINGS is otherwise permitted.
      :ok = :sys.suspend(pool)

      try do
        command(peer, "handshake")
        barrier(peer, nil, fn counts, _ -> counts["settings_acks"] == 1 end)
      after
        :ok = :sys.resume(pool)
      end

      barrier(peer, pool, fn counts, state ->
        counts["handshakes"] == 1 and pending(state) == 1
      end)

      assert snapshot(peer)["requests"] == 0
      Task.shutdown(task, :brutal_kill)
      barrier(peer, pool, fn _, state -> pending(state) == 0 end)
      assert_idle(pool)
    end

    @tag backend: backend
    test "auto queue overload rejects before TLS work for #{backend}", %{
      pool: pool,
      backend: backend
    } do
      :sys.replace_state(pool, &%{&1 | max_pending: 2})
      {peer, url} = peer!()
      tasks = burst(url, backend, 5)

      barrier(peer, pool, fn counts, state ->
        counts["accepted"] == 1 and pending(state) == 2 and
          Enum.count(tasks, &(not Process.alive?(&1.pid))) == 2
      end)

      command(peer, "handshake")
      command(peer, "respond")
      results = Task.await_many(tasks, 5_000)
      assert Enum.count(results, &(&1 == {:error, :pending_capacity})) == 2

      for result <- results,
          match?(%HTTP.Response{}, result),
          do: assert(HTTP.Response.read_all(result) == "ok")

      assert snapshot(peer)["accepted"] == 1
      assert_idle(pool)
    end

    @tag backend: backend
    test "failed TLS handshake settles cold auto claim and queue for #{backend}", %{
      pool: pool,
      backend: backend
    } do
      {peer, url} = peer!("fail")
      tasks = burst(url, backend, 6)
      barrier(peer, pool, fn counts, state -> counts["accepted"] == 1 and pending(state) == 5 end)
      command(peer, "handshake")
      for result <- Task.await_many(tasks, 5_000), do: assert(match?({:error, _}, result))
      assert snapshot(peer)["accepted"] == 1
      assert_idle(pool)
    end

    @tag backend: backend
    test "H1 fallback releases negotiation permits for #{backend}", %{
      pool: pool,
      backend: backend
    } do
      {peer, url} = peer!("http/1.1")
      tasks = burst(url, backend, 6)

      barrier(peer, pool, fn counts, state ->
        counts["accepted"] == 6 or (counts["accepted"] >= 1 and pending(state) == 5)
      end)

      command(peer, "handshake")
      command(peer, "respond")
      assert_ok(tasks)
      assert snapshot(peer)["handshakes"] == 6
      assert_idle(pool)
    end
  end

  test "auto HTTPS streamed upload negotiates H2 through the cancellable OTP TLS adapter", %{
    pool: pool
  } do
    {peer, url} = peer!()
    command(peer, "handshake")
    {:ok, upload} = HTTP.Stream.from_enumerable(["wrapped", "-", "h2"])
    source_monitor = Process.monitor(upload)

    promise =
      HTTP.fetch(url,
        method: :post,
        headers: [{"content-length", "10"}],
        body: upload,
        duplex: :half,
        http_version: :auto,
        ssl: [cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
      )

    barrier(peer, pool, fn counts, _state -> counts["requests"] == 1 end)

    [owner] =
      for {_, entry} <- :sys.get_state(pool).entries,
          {owner, _capacity} <- entry.connections,
          do: owner

    connection = :sys.get_state(owner)
    assert connection.transport == HTTP.Transport.SSL
    assert HTTP.Transport.SSL.cancellable?(connection.socket)
    assert {:ok, "h2"} = HTTP.Transport.SSL.negotiated_protocol(connection.socket)
    assert_receive {:DOWN, ^source_monitor, :process, ^upload, :normal}, 1_000

    command(peer, "respond")
    response = HTTP.Promise.await(promise, 5_000)
    assert %HTTP.Response{status: 200, http_version: :http2} = response
    assert HTTP.Response.read_all(response) == "ok"
    assert snapshot(peer)["accepted"] == 1
    assert snapshot(peer)["handshakes"] == 1
    assert_idle(pool)
  end

  defp burst(url, backend, n) do
    for _ <- 1..n do
      Task.async(fn -> SocketClient.request(request(url, backend)) end)
    end
  end

  defp request(url, backend, options \\ []) do
    %Request{
      url: URI.parse(url),
      method: "GET",
      headers: HTTP.Headers.new([]),
      transport_options:
        Keyword.merge(
          [
            http_version: :auto,
            tls_backend: backend,
            timeout: 10_000,
            ssl: [verify: :verify_peer, cacertfile: Path.join(@fixtures, "localhost-ca.pem")]
          ],
          options
        )
    }
  end

  defp assert_ok(tasks) do
    for result <- Task.await_many(tasks, 15_000) do
      assert %HTTP.Response{status: 200} = result
      assert HTTP.Response.read_all(result) == "ok"
    end
  end

  defp peer!(protocol \\ "h2", limit \\ 1) do
    python = System.get_env("HTTP2_PEER_PYTHON") || System.find_executable("python3")

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 16_384},
        args: [
          Path.join(@root, "scripts/http2_admission_peer.py"),
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key"),
          "--protocol",
          protocol,
          "--limit",
          Integer.to_string(limit)
        ]
      ])

    on_exit(fn ->
      # The test process owns the port and can close it before this callback runs.
      try do
        Port.close(port)
      rescue
        ArgumentError -> :ok
      end
    end)

    assert_receive {^port, {:data, {:eol, line}}}, 5_000
    ready = JSON.decode!(line)
    assert ready["event"] == "ready"
    {port, "https://localhost:#{ready["port"]}/test"}
  end

  defp command(peer, command), do: Port.command(peer, command <> "\n")

  defp snapshot(peer) do
    command(peer, "snapshot")
    read_snapshot(peer)
  end

  defp read_snapshot(peer) do
    receive do
      {^peer, {:data, {:eol, line}}} ->
        event = JSON.decode!(line)
        assert event["event"] != "error", inspect(event)
        if event["event"] == "snapshot", do: event, else: read_snapshot(peer)
    after
      5_000 -> flunk("independent peer snapshot timed out")
    end
  end

  defp barrier(peer, pool, predicate, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 5_000
    counts = snapshot(peer)
    state = if pool, do: Pool.stats(pool), else: %{}

    if predicate.(counts, state) do
      counts
    else
      assert System.monotonic_time(:millisecond) < deadline,
             "barrier not reached: #{inspect(counts)} #{inspect(state)}"

      receive do
      after
        5 -> :ok
      end

      barrier(peer, pool, predicate, deadline)
    end
  end

  defp pending(state), do: Enum.sum(for {_, entry} <- state, do: entry.pending)

  defp assert_idle(pool) do
    state = :sys.get_state(pool)
    assert state.connectors == %{}
    assert state.callers == %{}
    assert state.reservations == %{}
    assert state.promotions == %{}
    assert state.deadlines == %{}
    assert pending(Pool.stats(pool)) == 0
    for {_, entry} <- Pool.stats(pool), do: assert(entry.connecting == 0 and entry.streams == 0)

    for {_, entry} <- state.entries,
        {owner, _} <- entry.connections,
        do: GenServer.stop(owner, :normal)
  end
end
