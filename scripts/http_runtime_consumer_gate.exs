defmodule HTTPRuntimeConsumerGate do
  @apps ~w(http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)
  @clients ~w(http_fetch http_event_source http_web_socket)a

  def prepare do
    packages = System.fetch_env!("HTTP_RUNTIME_PACKAGE_DIR")
    metadata = Map.new(@apps, &{&1, metadata!(packages, &1)})
    version = Map.fetch!(metadata["http_core"], "version")
    release = System.get_env("HTTP_RUNTIME_CONSUMER_RELEASE")

    assert!(
      release == nil or release == version,
      "published package version differs from request"
    )

    for app <- @apps do
      assert!(metadata[app]["version"] == version, "#{app} package version differs from core")

      for tool <- ~w(ex_doc credo dialyxir) do
        assert!(
          not Map.has_key?(requirements(metadata[app]), tool),
          "#{app} requires developer tool #{tool}"
        )
      end
    end

    for app <- @apps -- ["http_core"] do
      assert_requirement!(metadata[app], "http_core", version)
    end

    for app <- @clients do
      requirements = requirements(metadata[Atom.to_string(app)])
      assert_requirement!(metadata[Atom.to_string(app)], "http_runtime", version)

      assert!(
        Enum.all?(@clients -- [app], &(not Map.has_key?(requirements, Atom.to_string(&1)))),
        "#{app} must not depend on another client"
      )

      assert!(not Map.has_key?(requirements, "ex_ssl"), "#{app} must resolve ex_ssl transitively")
    end

    for app <- ["http_fetch", "http_web_transport"] do
      assert!(
        not Map.has_key?(requirements(metadata[app]), "elixir_quic_http3"),
        "#{app} must reach the HTTP/3 companion only through the runtime boundary"
      )
    end

    assert_requirement!(metadata["http_runtime"], "elixir_quic_http3", version)
    assert_requirement!(metadata["http_core"], "ex_ssl", version)

    assert!(
      not Map.has_key?(requirements(metadata["http_core"]), "elixir_quic_http3"),
      "core must not depend on the HTTP/3 companion"
    )

    # Local unpublished packages are resolved transitively through these temporary paths.
    # Their original hex_metadata.config files remain untouched and were audited above.
    for app <- if(release, do: [], else: @apps) do
      path = Path.join([packages, app, "mix.exs"])
      source = File.read!(path)

      IO.puts(
        "package_mix_sha256=#{app}:#{Base.encode16(:crypto.hash(:sha256, source), case: :lower)}"
      )

      rewritten =
        Regex.replace(
          ~r/\{:(http_core|http_runtime), "~> [^"]+", in_umbrella: true, hex: :(?:http_core|http_runtime)\}/,
          source,
          fn _, dependency ->
            "{:#{dependency}, path: #{inspect(Path.join(packages, dependency))}}"
          end
        )

      assert!(
        not String.contains?(rewritten, "in_umbrella: true"),
        "#{app} has unresolved umbrella dependency"
      )

      File.write!(path, rewritten)
    end

    IO.puts(
      JSON.encode!(%{
        result: "PASS",
        gate: "original_package_metadata",
        packages: @apps,
        version: version
      })
    )
  end

  def verify do
    selected =
      System.fetch_env!("HTTP_RUNTIME_CONSUMER_CLIENTS")
      |> String.split(",")
      |> Enum.map(&String.to_existing_atom/1)

    assert!(Enum.all?(selected, &(&1 in @clients)), "unknown selected client")

    assert!(
      Keyword.keys(Mix.Project.config()[:deps]) == selected,
      "consumer has hidden direct dependencies"
    )

    for client <- selected, do: {:ok, _} = Application.ensure_all_started(client)
    resolved = Enum.map(Mix.Dep.cached(), & &1.app)

    if release = System.get_env("HTTP_RUNTIME_CONSUMER_RELEASE") do
      for app <- [:http_core, :elixir_quic_http3, :http_runtime | selected] do
        dep = Enum.find(Mix.Dep.cached(), &(&1.app == app))

        assert!(
          dep.scm == Hex.SCM and dep.opts[:hex] == Atom.to_string(app),
          "#{app} is not the published Hex app"
        )

        assert!(
          to_string(Application.spec(app, :vsn)) == release,
          "#{app} loaded version differs from published candidate"
        )
      end
    end

    for app <- [:http_core, :elixir_quic_http3, :elixir_quic, :http_runtime, :ex_ssl] do
      assert!(app in resolved, "missing transitive dependency #{app}")
      assert!(List.keymember?(Application.started_applications(), app, 0), "#{app} did not start")
    end

    if :http_fetch not in selected do
      assert!(:http_fetch not in resolved, "standalone SSE/WS consumer depends on Fetch")

      assert!(
        :code.which(HTTP) == :non_existing,
        "HTTP.fetch module visible in standalone SSE/WS consumer"
      )

      assert!(
        :code.which(HTTP.Telemetry) == :non_existing,
        "Fetch telemetry visible in standalone SSE/WS consumer"
      )
    end

    build = System.fetch_env!("MIX_BUILD_PATH")
    owner_beam = HTTP.HTTP2.ConnectionOwner |> :code.which() |> List.to_string() |> Path.expand()

    assert!(
      String.starts_with?(owner_beam, Path.join(build, "lib/http_runtime/ebin/")),
      "owner loaded outside isolated runtime"
    )

    assert!(
      not String.contains?(owner_beam, System.fetch_env!("HTTP_RUNTIME_REPO_ROOT")),
      "owner loaded from umbrella"
    )

    runtime = runtime_processes!()
    children = Supervisor.which_children(HTTPRuntime.Application)

    assert!(
      Enum.sort(Enum.map(children, &elem(&1, 0))) ==
        Enum.sort([
          :http_runtime_task_supervisor,
          :http_managed_transport_supervisor,
          HTTP.HTTP1.Pool,
          HTTP.HTTP2.ConnectionSupervisor,
          HTTP.HTTP2.Pool,
          HTTP.HTTP3.ConnectionSupervisor,
          HTTP.HTTP3.Pool
        ]),
      "runtime has unexpected supervision owners"
    )

    assert!(
      apply(HTTP.HTTP2.Pool, :stats, [runtime[:http_fetch_http2_pool]]) == %{},
      "new consumer pool is not empty"
    )

    if url = System.get_env("HTTP_RUNTIME_CONSUMER_URL"), do: traffic!(selected, url)

    for client <- selected do
      :ok = Application.stop(client)

      assert!(
        runtime_processes!() == runtime,
        "stopping #{client} restarted or killed shared runtime"
      )

      await_release!(System.monotonic_time(:millisecond) + 10_000)
    end

    IO.puts(
      JSON.encode!(%{
        result: "PASS",
        gate: "isolated_runtime_startup",
        clients: selected,
        runtime_children: length(children),
        fetch_visible: :http_fetch in selected,
        pool_keys: map_size(apply(HTTP.HTTP2.Pool, :stats, [runtime[:http_fetch_http2_pool]]))
      })
    )
  end

  defp traffic!(selected, url) do
    opts = [http_version: :h2c, connect_timeout: 30_000, http2_scope: "package-traffic"]

    source =
      if :http_event_source in selected do
        source = apply(HTTP.EventSource, :new, [url <> "/sse/hold", opts ++ [delivery: :ack]])
        event!(HTTP.EventSource, source, HTTP.EventSource.Event.Open)
        assert!(apply(HTTP.EventSource, :http_version, [source]) == :http2, "SSE used HTTP/1")
        {event, ref} = event!(HTTP.EventSource, source, HTTP.EventSource.Event.Message)
        assert!(event.data == "sibling-1", "wrong standalone SSE bytes")
        :ok = apply(HTTP.EventSource, :acknowledge, [source, ref])
        source
      end

    socket =
      if :http_web_socket in selected do
        ws_url = String.replace_prefix(url, "http://", "ws://")
        count = if length(selected) == 3, do: 2, else: 1

        socket =
          apply(HTTP.WebSocket, :new, [
            ws_url <> "/ws/echo?count=#{count}",
            [],
            opts ++ [delivery: :ack]
          ])

        event!(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Open)
        assert!(apply(HTTP.WebSocket, :http_version, [socket]) == :http2, "WS used HTTP/1")
        :ok = apply(HTTP.WebSocket, :send, [socket, "package-message"])
        {event, ref} = event!(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Message)
        assert!(event.data == "package-message", "wrong standalone WS echo")
        :ok = apply(HTTP.WebSocket, :acknowledge, [socket, ref])
        socket
      end

    if :http_fetch in selected do
      promise = apply(HTTP, :fetch, [url <> "/fetch/package", opts])
      response = apply(HTTP.Promise, :await, [promise, 30_000])
      assert!(response.status == 200, "standalone Fetch failed")

      assert!(
        apply(HTTP.Response, :read_all, [response]) == "/fetch/package",
        "wrong Fetch bytes"
      )
    end

    if not is_nil(source) and not is_nil(socket) do
      runtime = runtime_processes!()
      :ok = Application.stop(:http_fetch)
      assert!(runtime_processes!() == runtime, "Fetch shutdown killed shared owners")
      :ok = apply(HTTP.WebSocket, :send, [socket, "after-fetch-stop"])
      {event, ref} = event!(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Message)
      assert!(event.data == "after-fetch-stop", "live WS failed after Fetch shutdown")
      :ok = apply(HTTP.WebSocket, :acknowledge, [socket, ref])
      assert!(apply(HTTP.EventSource, :http_version, [source]) == :http2, "live SSE was lost")
      {:ok, _} = Application.ensure_all_started(:http_fetch)
      assert!(runtime_processes!() == runtime, "Fetch restart duplicated shared owners")
    end

    if source, do: :ok = apply(HTTP.EventSource, :close, [source])

    if socket do
      :ok = apply(HTTP.WebSocket, :close, [socket, 1000])
      close = event!(HTTP.WebSocket, socket, HTTP.WebSocket.Event.Close)
      assert!(close.code == 1000 and close.was_clean, "standalone WS close incomplete")
    end

    await_release!(System.monotonic_time(:millisecond) + 10_000)

    IO.puts(JSON.encode!(%{result: "PASS", gate: "isolated_http2_traffic", clients: selected}))
  end

  defp event!(module, client, type) do
    receive do
      {^module, ^client, %{__struct__: ^type} = event} -> event
      {^module, ^client, %{__struct__: ^type} = event, ref} -> {event, ref}
      {^module, ^client, event} -> raise "unexpected standalone event: #{inspect(event)}"
    after
      30_000 -> raise "standalone #{inspect(type)} deadline"
    end
  end

  defp await_release!(deadline) do
    stats = apply(HTTP.HTTP2.Pool, :stats, [Process.whereis(:http_fetch_http2_pool)])

    owners = DynamicSupervisor.which_children(:http_fetch_http2_connection_supervisor)

    active? =
      Enum.any?(owners, fn {_, pid, _, _} ->
        status = apply(HTTP.HTTP2.ConnectionOwner, :status, [pid])
        status.active_streams != 0 or status.protocol_streams != 0
      end)

    if active? or Task.Supervisor.children(:http_runtime_task_supervisor) != [] or
         Enum.any?(stats, fn {_key, value} -> value.streams != 0 or value.pending != 0 end) do
      assert!(System.monotonic_time(:millisecond) < deadline, "standalone reservations leaked")

      receive do
      after
        5 -> :ok
      end

      await_release!(deadline)
    end
  end

  defp runtime_processes! do
    Map.new(
      [
        HTTPRuntime.Application,
        :http_runtime_task_supervisor,
        :http_managed_transport_supervisor,
        HTTP.HTTP1.Pool,
        :http_fetch_http2_connection_supervisor,
        :http_fetch_http2_pool,
        :http_fetch_http3_connection_supervisor,
        :http_fetch_http3_pool
      ],
      fn name ->
        pid = Process.whereis(name)
        assert!(is_pid(pid) and Process.alive?(pid), "runtime process #{name} is not alive")
        {name, pid}
      end
    )
  end

  defp metadata!(packages, app) do
    {:ok, entries} =
      :file.consult(String.to_charlist(Path.join([packages, app, "hex_metadata.config"])))

    Map.new(entries)
  end

  defp requirements(metadata),
    do:
      Map.new(metadata["requirements"], fn entry ->
        requirement = Map.new(entry)
        {requirement["name"], requirement}
      end)

  defp assert_requirement!(metadata, dependency, version) do
    requirement = requirements(metadata)[dependency]

    assert!(
      requirement != nil and requirement["requirement"] == "== " <> version and
        requirement["optional"] == false,
      "invalid #{dependency} package requirement"
    )
  end

  defp assert!(true, _message), do: :ok
  defp assert!(false, message), do: raise(message)
end

case System.argv() do
  ["prepare"] -> HTTPRuntimeConsumerGate.prepare()
  ["verify"] -> HTTPRuntimeConsumerGate.verify()
  _ -> raise "expected prepare or verify"
end
