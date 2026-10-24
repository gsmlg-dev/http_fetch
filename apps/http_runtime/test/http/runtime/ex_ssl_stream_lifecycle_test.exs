defmodule HTTP.Runtime.ExSSLStreamLifecycleTest do
  use ExUnit.Case, async: false
  @moduletag :integration
  @moduletag :p3_ex_ssl_h2

  alias HTTP.HTTP2.{ConnectionOwner, Pool}
  alias HTTP.{Request, RequestLifecycle}
  alias HTTP.Runtime.Stream

  @fixtures Path.expand("../../../../http_fetch/test/support/fixtures", __DIR__)
  @lifecycle_peer Path.expand(
                    "../../../../http_fetch/test/support/ex_ssl_http2_lifecycle_peer.py",
                    __DIR__
                  )
  @peer Path.expand("../../../../../scripts/tls_migration_performance_peer.py", __DIR__)

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}] do
    test "#{version} Runtime first-dial cancellation preserves sibling and later connection reuse" do
      {peer, origin} = peer(unquote(wire))

      try do
        {first, first_generation, first_tracker, first_latch} =
          start_stream(origin <> "/perf/m-first/download", unquote(version))

        first_down = Process.monitor(first)
        tracker_down = Process.monitor(first_tracker)

        assert_receive {:http_runtime, ^first_generation, ^first,
                        {:opened, %{owner: owner, id: first_id}}},
                       5_000

        assert_receive {:http_runtime, ^first_generation, ^first,
                        {:data, bytes, _flags, _delivery}},
                       5_000

        assert byte_size(bytes) > 0

        {sibling, sibling_generation, sibling_tracker, sibling_latch} =
          start_stream(origin <> "/perf/m-sibling/reuse", unquote(version))

        sibling_down = Process.monitor(sibling)
        sibling_tracker_down = Process.monitor(sibling_tracker)

        assert_receive {:http_runtime, ^sibling_generation, ^sibling,
                        {:opened, %{owner: ^owner}}},
                       5_000

        assert_receive {:http_runtime, ^sibling_generation, ^sibling,
                        {:data, "ok", _flags, sibling_delivery}},
                       5_000

        stats = wait_stats(peer, &(length(&1["requests"]) == 2))

        assert [%{"connection" => 1, "tls" => unquote(wire), "alpn" => "h2"}] =
                 stats["handshakes"]

        assert stats["errors"] == []
        assert stats["accepted_connections"] == 1
        assert stats["closed_connections"] == 0
        assert Enum.all?(stats["requests"], &(&1["connection"] == 1))

        Stream.close(first)
        assert_receive {:DOWN, ^first_down, :process, ^first, :normal}, 1_000
        assert_receive {:DOWN, ^tracker_down, :process, ^first_tracker, :normal}, 1_000
        assert :atomics.get(first_latch, 1) == 2
        assert Process.alive?(owner)
        assert Process.alive?(sibling)
        refute first_id in ConnectionOwner.status(owner).stream_ids

        Stream.acknowledge(sibling, sibling_delivery)
        assert_receive {:DOWN, ^sibling_down, :process, ^sibling, :normal}, 1_000
        assert_receive {:DOWN, ^sibling_tracker_down, :process, ^sibling_tracker, :normal}, 1_000
        assert :atomics.get(sibling_latch, 1) == 2

        {later, later_generation, later_tracker, later_latch} =
          start_stream(origin <> "/perf/m-later/reuse", unquote(version))

        later_down = Process.monitor(later)
        later_tracker_down = Process.monitor(later_tracker)

        assert_receive {:http_runtime, ^later_generation, ^later, {:opened, %{owner: ^owner}}},
                       5_000

        assert_receive {:http_runtime, ^later_generation, ^later,
                        {:data, "ok", _flags, later_delivery}},
                       5_000

        Stream.acknowledge(later, later_delivery)
        assert_receive {:DOWN, ^later_down, :process, ^later, :normal}, 1_000
        assert_receive {:DOWN, ^later_tracker_down, :process, ^later_tracker, :normal}, 1_000
        assert :atomics.get(later_latch, 1) == 2
        stats = wait_stats(peer, &(length(&1["requests"]) == 3))
        assert stats["errors"] == []
        assert stats["accepted_connections"] == 1
        assert stats["closed_connections"] == 0
        assert Enum.all?(stats["requests"], &(&1["connection"] == 1))
      after
        stop_peer(peer)
      end
    end
  end

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}] do
    for mode <- [:exclusive, :callback] do
      test "#{version} Runtime #{mode} joins provider cleanup" do
        {peer, origin} = peer(unquote(wire))

        try do
          extra =
            if unquote(mode) == :exclusive do
              [http2_reuse: false]
            else
              callback = fn _, _, state -> {:valid, state} end
              [ssl: Keyword.put(options(unquote(version))[:ssl], :verify_fun, {callback, nil})]
            end

          {stream, generation, tracker, latch} =
            start_stream(origin <> "/perf/m-exclusive/reuse", unquote(version), extra)

          down = Process.monitor(stream)
          tracker_down = Process.monitor(tracker)
          assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000
          owner_down = Process.monitor(owner)
          assert_receive {:http_runtime, ^generation, ^stream, {:data, "ok", _, delivery}}, 5_000
          Stream.acknowledge(stream, delivery)
          assert_receive {:DOWN, ^down, :process, ^stream, :normal}, 1_000
          assert_receive {:DOWN, ^owner_down, :process, ^owner, _}, 1_000
          assert_receive {:DOWN, ^tracker_down, :process, ^tracker, :normal}, 1_000
          assert :atomics.get(latch, 1) == 2
          stats = wait_stats(peer, &(&1["closed_connections"] == 1))
          assert stats["accepted_connections"] == 1
          assert stats["errors"] == []
        after
          stop_peer(peer)
        end
      end
    end

    for failure <- [:wrong_ca, :wrong_name, :no_h2] do
      test "#{version} Runtime #{failure} sends no request and joins cleanup" do
        protocol = if unquote(failure) == :no_h2, do: "http/1.1", else: "h2"
        {peer, origin} = peer(unquote(wire), protocol)

        try do
          extra =
            if unquote(failure) == :wrong_ca,
              do: [
                ssl:
                  Keyword.put(
                    options(unquote(version))[:ssl],
                    :cacertfile,
                    Path.join(@fixtures, "pinned-ca.pem")
                  )
              ],
              else: []

          url =
            if unquote(failure) == :wrong_name,
              do: String.replace(origin, "localhost", "wrong.invalid"),
              else: origin

          {stream, generation, tracker, latch} =
            start_stream(url <> "/perf/m-never/reuse", unquote(version), extra)

          down = Process.monitor(stream)
          tracker_down = Process.monitor(tracker)
          assert_receive {:http_runtime, ^generation, ^stream, {:error, reason}}, 5_000
          if unquote(failure) == :no_h2, do: assert(reason == {:http2_not_negotiated, nil})
          assert_receive {:DOWN, ^down, :process, ^stream, :normal}, 1_000
          assert_receive {:DOWN, ^tracker_down, :process, ^tracker, :normal}, 1_000
          assert :atomics.get(latch, 1) == 2
          stats = wait_stats(peer, &(&1["closed_connections"] == 1))
          assert stats["requests"] == []
          assert stats["accepted_connections"] == 1

          if unquote(failure) == :no_h2 do
            assert [%{"tls" => unquote(wire), "alpn" => nil}] = stats["handshakes"]
            assert stats["http_bytes"] == 0
            assert stats["errors"] == []
          end
        after
          stop_peer(peer)
        end
      end
    end

    for terminal <- [:abort, :deadline] do
      test "#{version} Runtime queued #{terminal} cannot send late bytes" do
        {peer, origin} = peer(unquote(wire))
        pool = start_supervised!({Pool, []})
        :sys.suspend(pool)

        try do
          {tracker, latch} = RequestLifecycle.start()

          request = %Request{
            url: URI.parse(origin <> "/perf/m-never/reuse"),
            transport_options:
              options(unquote(version)) ++ [http2_pool: pool, request_lifecycle: tracker]
          }

          timeout = if unquote(terminal) == :deadline, do: 100, else: 5_000

          assert {:ok, stream, generation} =
                   Stream.start(request, self(), opening_timeout: timeout)

          down = Process.monitor(stream)
          tracker_down = Process.monitor(tracker)

          wait_until(fn ->
            {:messages, messages} = Process.info(pool, :messages)
            Enum.any?(messages, &match?({:"$gen_call", _, {:reserve, _, _}}, &1))
          end)

          if unquote(terminal) == :abort, do: Stream.close(stream)
          reason = if unquote(terminal) == :abort, do: :aborted, else: :opening_timeout
          assert_receive {:http_runtime, ^generation, ^stream, {:error, ^reason}}, 1_000
          assert_receive {:DOWN, ^down, :process, ^stream, :normal}, 1_000
          assert_receive {:DOWN, ^tracker_down, :process, ^tracker, :normal}, 1_000
          assert :atomics.get(latch, 1) == 2
        after
          :sys.resume(pool)
        end

        try do
          assert Pool.stats(pool) == %{}
          stats = wait_stats(peer, &(&1["accepted_connections"] == 0))
          assert stats["requests"] == []
        after
          stop_peer(peer)
        end
      end
    end

    test "#{version} Runtime automatically establishes its first-dial tracker" do
      {peer, origin} = peer(unquote(wire))

      try do
        request = %Request{
          url: URI.parse(origin <> "/perf/m-automatic/reuse"),
          transport_options: options(unquote(version))
        }

        assert {:ok, stream, generation} = Stream.start(request, self(), opening_timeout: 5_000)
        down = Process.monitor(stream)
        assert_receive {:http_runtime, ^generation, ^stream, {:opened, %{owner: owner}}}, 5_000
        assert_receive {:http_runtime, ^generation, ^stream, {:data, "ok", _, delivery}}, 5_000
        Stream.acknowledge(stream, delivery)
        assert_receive {:DOWN, ^down, :process, ^stream, :normal}, 1_000
        assert Process.alive?(owner)
        stats = wait_stats(peer, &(length(&1["requests"]) == 1))
        assert [%{"tls" => unquote(wire), "alpn" => "h2"}] = stats["handshakes"]
        assert stats["errors"] == []
        assert stats["active_connections"] == 1
      after
        stop_peer(peer)
      end
    end
  end

  for {version, wire} <- [{:"tlsv1.2", "TLSv1.2"}, {:"tlsv1.3", "TLSv1.3"}] do
    @tag :p3_proxy_ex_ssl
    test "#{wire} Runtime CONNECT automatic and supplied trackers preserve sibling reuse" do
      for mode <- [:automatic, :supplied] do
        {peer, port} = proxy_peer(unquote(wire))

        try do
          opts = options(unquote(version)) |> Keyword.delete(:connect_address)

          opts =
            Keyword.put(
              opts,
              :proxy,
              {:http, "localhost", port, [headers: [{"Proxy-Authorization", "Basic runtime"}]]}
            )

          {first, generation, tracker, latch} = proxy_stream(opts, "/hold", mode)
          first_down = Process.monitor(first)
          tracker_down = Process.monitor(tracker)

          assert_receive {:http_runtime, ^generation, ^first,
                          {:opened, %{owner: owner, id: first_id}}},
                         5_000

          state = wait_stats(peer, &(length(&1["requests"]) == 1))

          assert [%{"tls" => unquote(wire), "alpn" => "h2", "sni" => "localhost"}] =
                   state["handshakes"]

          assert [
                   %{
                     "head" =>
                       "CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\nProxy-Authorization: Basic runtime\r\n\r\n"
                   }
                 ] = state["connects"]

          assert state["errors"] == []

          {sibling, sibling_generation, sibling_tracker, sibling_latch} =
            proxy_stream(opts, "/sibling", :supplied)

          sibling_down = Process.monitor(sibling)
          sibling_tracker_down = Process.monitor(sibling_tracker)

          assert_receive {:http_runtime, ^sibling_generation, ^sibling,
                          {:opened, %{owner: ^owner}}},
                         5_000

          assert_receive {:http_runtime, ^sibling_generation, ^sibling,
                          {:data, "ok", _, delivery}},
                         5_000

          Stream.close(first)
          assert_receive {:DOWN, ^first_down, :process, ^first, :normal}, 1_000
          assert_receive {:DOWN, ^tracker_down, :process, ^tracker, :normal}, 1_000
          assert :atomics.get(latch, 1) == 2
          assert Process.alive?(owner)
          refute first_id in ConnectionOwner.status(owner).stream_ids
          Stream.acknowledge(sibling, delivery)
          assert_receive {:DOWN, ^sibling_down, :process, ^sibling, :normal}, 1_000

          assert_receive {:DOWN, ^sibling_tracker_down, :process, ^sibling_tracker, :normal},
                         1_000

          assert :atomics.get(sibling_latch, 1) == 2

          {later, later_generation, later_tracker, later_latch} =
            proxy_stream(opts, "/later", :automatic)

          later_down = Process.monitor(later)
          later_tracker_down = Process.monitor(later_tracker)

          assert_receive {:http_runtime, ^later_generation, ^later, {:opened, %{owner: ^owner}}},
                         5_000

          assert_receive {:http_runtime, ^later_generation, ^later,
                          {:data, "ok", _, later_delivery}},
                         5_000

          Stream.acknowledge(later, later_delivery)
          assert_receive {:DOWN, ^later_down, :process, ^later, :normal}, 1_000
          assert_receive {:DOWN, ^later_tracker_down, :process, ^later_tracker, :normal}, 1_000
          assert :atomics.get(later_latch, 1) == 2
          state = wait_stats(peer, &(length(&1["requests"]) == 3 and length(&1["resets"]) == 1))
          assert state["accepted_connections"] == 1
          assert state["active_connections"] == 1
          assert state["errors"] == []
          assert [%{"connection" => 1, "stream" => ^first_id, "error" => 8}] = state["resets"]
          assert Enum.all?(state["requests"], &(&1["connection"] == 1))

          assert Enum.all?(
                   state["requests"],
                   &(not Map.has_key?(&1["headers"], "proxy-authorization"))
                 )
        after
          stop_peer(peer)
        end
      end
    end
  end

  defp proxy_stream(opts, path, mode) do
    opts =
      if mode == :supplied do
        {tracker, _} = RequestLifecycle.start()
        Keyword.put(opts, :request_lifecycle, tracker)
      else
        opts
      end

    request = %Request{url: URI.parse("https://localhost:8443" <> path), transport_options: opts}
    assert {:ok, stream, generation} = Stream.start(request, self(), opening_timeout: 5_000)

    wait_until(fn ->
      case Process.info(stream, :dictionary) do
        {:dictionary, entries} -> is_pid(Keyword.get(entries, RequestLifecycle))
        _ -> false
      end
    end)

    {:dictionary, entries} = Process.info(stream, :dictionary)
    tracker = Keyword.fetch!(entries, RequestLifecycle)
    latch = :sys.get_state(tracker).latch
    {stream, generation, tracker, latch}
  end

  defp proxy_peer(version) do
    script =
      Path.expand("../../../../http_fetch/test/support/ex_ssl_proxy_lifecycle_peer.py", __DIR__)

    peer =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 65_536},
        args: [
          "-B",
          script,
          "--cert",
          Path.join(@fixtures, "localhost.pem"),
          "--key",
          Path.join(@fixtures, "localhost.key"),
          "--protocol",
          "h2",
          "--tls",
          version
        ]
      ])

    on_exit(fn -> if Port.info(peer), do: Port.close(peer) end)
    assert %{"event" => "ready", "port" => port} = event(peer)
    {peer, port}
  end

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

  defp start_stream(url, version, extra \\ []) do
    {tracker, latch} = RequestLifecycle.start()

    request = %Request{
      url: URI.parse(url),
      transport_options:
        Keyword.merge(options(version), extra) |> Keyword.put(:request_lifecycle, tracker)
    }

    assert {:ok, stream, generation} = Stream.start(request, self(), opening_timeout: 5_000)
    {stream, generation, tracker, latch}
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
        if System.get_env("P3_H2_PEER_EVIDENCE") || System.get_env("P3_PROXY_PEER_EVIDENCE"),
          do: IO.puts("P3_H2_PEER " <> line)

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
