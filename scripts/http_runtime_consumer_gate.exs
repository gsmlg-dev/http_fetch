defmodule HTTPRuntimeConsumerGate do
  @apps ~w(http_core http_runtime elixir_quic_http3 http_fetch http_web_socket http_event_source http_web_transport)
  @clients ~w(http_fetch http_event_source http_web_socket)a

  def prepare do
    packages = System.fetch_env!("HTTP_RUNTIME_PACKAGE_DIR")
    metadata = Map.new(@apps, &{&1, metadata!(packages, &1)})
    version = Map.fetch!(metadata["http_core"], "version")

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
      assert_requirement!(metadata[app], "elixir_quic_http3", version)
    end

    assert!(
      requirements(metadata["http_core"])["ex_ssl"]["requirement"] == "~> 0.7.2",
      "core must retain published ex_ssl dependency"
    )

    # Local unpublished packages are resolved transitively through these temporary paths.
    # Their original hex_metadata.config files remain untouched and were audited above.
    for app <- @apps do
      path = Path.join([packages, app, "mix.exs"])
      source = File.read!(path)

      IO.puts(
        "package_mix_sha256=#{app}:#{Base.encode16(:crypto.hash(:sha256, source), case: :lower)}"
      )

      rewritten =
        Regex.replace(
          ~r/\{:(http_core|http_runtime|elixir_quic_http3), "~> [^"]+", in_umbrella: true, hex: :(?:http_core|http_runtime|elixir_quic_http3)\}/,
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

    for app <- [:http_core, :http_runtime, :ex_ssl] do
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
    assert!(length(children) == 3, "runtime has unexpected supervision owners")

    assert!(
      apply(HTTP.HTTP2.Pool, :stats, [runtime[:http_fetch_http2_pool]]) == %{},
      "new consumer pool is not empty"
    )

    for client <- selected do
      :ok = Application.stop(client)

      assert!(
        runtime_processes!() == runtime,
        "stopping #{client} restarted or killed shared runtime"
      )

      assert!(
        apply(HTTP.HTTP2.Pool, :stats, [runtime[:http_fetch_http2_pool]]) == %{},
        "shared runtime stopped responding"
      )
    end

    IO.puts(
      JSON.encode!(%{
        result: "PASS",
        gate: "isolated_runtime_startup",
        clients: selected,
        runtime_children: length(children),
        fetch_visible: :http_fetch in selected,
        pool_keys: 0
      })
    )
  end

  defp runtime_processes! do
    Map.new(
      [
        HTTPRuntime.Application,
        :http_runtime_task_supervisor,
        :http_fetch_http2_connection_supervisor,
        :http_fetch_http2_pool
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
      requirement != nil and requirement["requirement"] == "~> " <> version and
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
