defmodule NoOTP.ReleaseAudit do
  @moduledoc false
  @named_dispatches [
    make_fun: 3,
    spawn: 3,
    spawn_link: 3,
    spawn_monitor: 3,
    spawn_opt: 4,
    hibernate: 3
  ]

  @node_dispatches [spawn: 4, spawn_link: 4, spawn_monitor: 4, spawn_opt: 5]
  @fun_dispatches [
    spawn: 1,
    spawn: 2,
    spawn_link: 1,
    spawn_link: 2,
    spawn_monitor: 1,
    spawn_monitor: 2,
    spawn_opt: 2,
    spawn_opt: 3
  ]
  @dispatches @named_dispatches ++ @node_dispatches ++ @fun_dispatches

  @packages ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)
  @modules [
    HTTP,
    SSL.Connection,
    Quic,
    QuicHttp3.Session,
    HTTP.ManagedTransport,
    HTTP.WebSocket,
    HTTP.EventSource
  ]
  @otp_apps ~w(kernel stdlib elixir logger crypto asn1 public_key sasl compiler eex iex runtime_tools syntax_tools tools parsetools)

  def artifacts do
    release = System.fetch_env!("NO_OTP_RELEASE") |> Path.expand()
    project = System.fetch_env!("NO_OTP_PROJECT") |> Path.expand()
    app_files = Path.wildcard("#{release}/lib/*/ebin/*.app")
    build_files = Path.wildcard("#{project}/build/**/ebin/*.app")
    applications = Enum.map(Enum.uniq(app_files ++ build_files), &application/1)
    rel_files = Path.wildcard("#{release}/releases/**/*.rel")
    boot_files = Path.wildcard("#{release}/releases/**/*.boot")
    rel_findings = Enum.flat_map(rel_files, &release_findings/1)
    boot_findings = Enum.flat_map(boot_files, &boot_findings/1)

    # Inspect candidate and non-OTP third-party production modules. Standard OTP
    # implementation callbacks are not classified as candidate backend dispatch.
    roots = applications |> Enum.map(& &1.name) |> Enum.uniq() |> Enum.reject(&(&1 in @otp_apps))
    beams = Enum.flat_map(roots, &Path.wildcard("#{release}/lib/#{&1}-*/ebin/*.beam"))
    inspections = Enum.map(beams, &inspect_beam/1)

    versions =
      applications
      |> Enum.filter(&(&1.name in @packages and String.starts_with?(&1.path, release <> "/")))
      |> Map.new(&{&1.name, &1.version})

    duplicates =
      applications
      |> Enum.filter(&(&1.name in @packages and String.starts_with?(&1.path, release <> "/")))
      |> Enum.group_by(& &1.name)
      |> Enum.filter(fn {_name, entries} -> length(entries) != 1 end)
      |> Enum.map(fn {name, entries} ->
        %{application: name, paths: Enum.map(entries, & &1.path)}
      end)

    %{
      checked_app_files: length(applications),
      checked_rel_files: length(rel_files),
      checked_boot_files: length(boot_files),
      checked_beams: length(beams),
      package_versions: versions,
      duplicate_package_apps: duplicates,
      applications: applications,
      rel_files: rel_files,
      boot_files: boot_files,
      beam_inspections: inspections,
      ssl_app_dependencies:
        Enum.filter(applications, &(&1.name == "ssl" or "ssl" in &1.dependencies)),
      ssl_bundle_paths:
        Path.wildcard("#{release}/lib/ssl-*") ++ Path.wildcard("#{release}/lib/ssl"),
      ssl_boot_entries: rel_findings ++ boot_findings,
      direct_otp_ssl_imports: Enum.flat_map(inspections, & &1.otp_ssl_imports),
      unresolved_dispatch: Enum.flat_map(inspections, & &1.unresolved_dispatch),
      missing_abstract_code: Enum.filter(inspections, & &1.missing_abstract_code)
    }
  end

  def runtime do
    modules =
      for module <- @modules, into: %{} do
        Code.ensure_loaded!(module)
        {inspect(module), module |> :code.which() |> to_string()}
      end

    ssl_modules =
      for {module, file} <- :code.all_loaded(),
          is_list(file),
          Regex.match?(~r{(?:^|/)ssl(?:-[^/]+)?/}, to_string(file)),
          do: inspect(module)

    all_loaded =
      for {module, file} <- :code.all_loaded(),
          is_list(file),
          into: %{},
          do: {inspect(module), to_string(file)}

    paths = Enum.map(:code.get_path(), &to_string/1)

    path_evidence =
      (paths ++ Map.values(modules) ++ Map.values(all_loaded))
      |> Enum.uniq()
      |> Enum.map(&canonical_path/1)

    %{
      ssl_available: :code.which(:ssl) != :non_existing,
      ssl_loaded: :code.is_loaded(:ssl) != false or ssl_modules != [],
      ssl_application_loaded:
        Enum.any?(Application.loaded_applications(), &(elem(&1, 0) == :ssl)),
      ssl_started: Enum.any?(Application.started_applications(), &(elem(&1, 0) == :ssl)),
      code_paths: paths,
      loaded_modules: modules,
      all_loaded_paths: all_loaded,
      canonical_release: canonical_path(System.fetch_env!("NO_OTP_RELEASE")),
      canonical_path_evidence: path_evidence,
      loaded_ssl_modules: ssl_modules,
      runtime_root: :code.root_dir() |> to_string() |> Path.expand()
    }
  end

  def clean?(artifacts, runtime) do
    Enum.all?(
      [
        :ssl_app_dependencies,
        :ssl_bundle_paths,
        :ssl_boot_entries,
        :direct_otp_ssl_imports,
        :unresolved_dispatch,
        :missing_abstract_code,
        :duplicate_package_apps
      ],
      &(Map.fetch!(artifacts, &1) == [])
    ) and
      Enum.all?(
        [:checked_app_files, :checked_rel_files, :checked_boot_files, :checked_beams],
        &(Map.fetch!(artifacts, &1) > 0)
      ) and
      Enum.all?(
        [:ssl_available, :ssl_loaded, :ssl_application_loaded, :ssl_started],
        &(Map.fetch!(runtime, &1) == false)
      ) and isolated_paths?(runtime) and
      Enum.all?(
        @packages,
        &(Map.get(artifacts.package_versions, &1) == System.fetch_env!("NO_OTP_VERSION"))
      )
  end

  defp isolated_paths?(runtime) do
    paths =
      runtime.code_paths ++
        Map.values(runtime.loaded_modules) ++
        Map.values(runtime.all_loaded_paths)

    release = runtime.canonical_release.resolved
    evidence = Map.new(runtime.canonical_path_evidence, &{&1.raw, &1})

    runtime.canonical_release.error == nil and is_binary(release) and
      runtime.code_paths != [] and map_size(runtime.all_loaded_paths) > 0 and
      Enum.all?(paths, fn path ->
        case Map.fetch(evidence, path) do
          {:ok, %{resolved: resolved, error: nil}} when is_binary(resolved) ->
            String.starts_with?(resolved, release <> "/") and
              not Enum.any?(Path.split(resolved), fn part ->
                part in ["test", "support", "_build", "deps"] or String.starts_with?(part, "ssl-")
              end)

          _ ->
            false
        end
      end)
  end

  # Elixir has no assumed realpath helper here. Establish canonical identity by
  # lstat-ing every absolute component and rejecting symlink traversal entirely.
  # A missing/unreadable component is unconfirmed, never a lexical-path success.
  defp canonical_path(path) do
    if Path.type(path) != :absolute or Regex.match?(~r"(?:^|/)\.{1,2}(?:/|$)", path) do
      %{raw: path, resolved: nil, error: %{reason: "noncanonical_lexical_path"}}
    else
      canonical_components(path)
    end
  end

  defp canonical_components(path) do
    result =
      Enum.reduce_while(Path.split(path), {:ok, ""}, fn part, {:ok, parent} ->
        current = if parent == "", do: part, else: Path.join(parent, part)

        case File.lstat(current) do
          {:ok, %{type: :symlink}} ->
            target =
              case File.read_link(current) do
                {:ok, target} -> target
                {:error, reason} -> inspect(reason)
              end

            {:halt, {:error, %{reason: "symlink_component", component: current, target: target}}}

          {:ok, _} ->
            {:cont, {:ok, current}}

          {:error, reason} ->
            {:halt, {:error, %{reason: inspect(reason), component: current}}}
        end
      end)

    case result do
      {:ok, resolved} -> %{raw: path, resolved: resolved, error: nil}
      {:error, error} -> %{raw: path, resolved: nil, error: error}
    end
  end

  defp application(path) do
    {:ok, [{:application, name, properties}]} = :file.consult(String.to_charlist(path))

    dependencies =
      [:applications, :optional_applications, :included_applications]
      |> Enum.flat_map(&Keyword.get(properties, &1, []))
      |> Enum.map(&to_string/1)

    %{
      path: path,
      name: to_string(name),
      version: to_string(Keyword.fetch!(properties, :vsn)),
      dependencies: dependencies
    }
  end

  defp release_findings(path) do
    {:ok, [{:release, _name, _erts, applications}]} = :file.consult(String.to_charlist(path))
    for entry <- applications, elem(entry, 0) == :ssl, do: %{path: path, application: "ssl"}
  end

  defp boot_findings(path) do
    # Read compiled boot data, not a source grep. No boot instructions are executed.
    term = path |> File.read!() |> :erlang.binary_to_term()
    walk_boot(term, path)
  end

  defp walk_boot({:application, :ssl, _properties}, path),
    do: [%{path: path, application: "ssl"}]

  defp walk_boot({:apply, {:application, function, [:ssl | _]}}, path)
       when function in [:load, :start, :start_boot, :ensure_started, :ensure_all_started],
       do: [%{path: path, application: "ssl", function: to_string(function)}]

  defp walk_boot(term, path) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.flat_map(&walk_boot(&1, path))

  defp walk_boot(term, path) when is_list(term) do
    if List.ascii_printable?(term) do
      if Regex.match?(~r{(?:^|/)ssl(?:-[^/]+)?(?:/|$)}, to_string(term)),
        do: [%{path: path, code_path: to_string(term)}],
        else: []
    else
      Enum.flat_map(term, &walk_boot(&1, path))
    end
  end

  defp walk_boot(_term, _path), do: []

  defp inspect_beam(path) do
    {:ok, {module, chunks}} =
      :beam_lib.chunks(String.to_charlist(path), [:imports, :abstract_code])

    imports = Keyword.fetch!(chunks, :imports)

    direct =
      for {:ssl, function, arity} <- imports,
          do: %{beam: path, module: inspect(module), function: to_string(function), arity: arity}

    {dynamic, missing} =
      case Keyword.fetch!(chunks, :abstract_code) do
        {:raw_abstract_v1, forms} ->
          {walk_calls(qualify_named_dispatches(forms, imports), path), false}

        :no_abstract_code ->
          {[], true}
      end

    %{
      beam: path,
      module: inspect(module),
      sha256: digest(path),
      imports:
        Enum.map(imports, fn {target, function, arity} ->
          %{module: to_string(target), function: to_string(function), arity: arity}
        end),
      otp_ssl_imports: direct,
      unresolved_dispatch: dynamic,
      missing_abstract_code: missing
    }
  end

  # Resolve only compiled local/imported equivalents of the named erlang MFAs.
  # A same-named local function or explicit other-module import is not that BIF.
  defp qualify_named_dispatches(forms, imports) do
    explicit = for {:attribute, _, :import, {:erlang, mfas}} <- forms, mfa <- mfas, do: mfa
    imported = for {:erlang, function, arity} <- imports, do: {function, arity}
    local = for {:function, _, function, arity, _} <- forms, do: {function, arity}

    other =
      for {:attribute, _, :import, {module, mfas}} <- forms,
          module != :erlang,
          mfa <- mfas,
          do: mfa

    compile_options =
      for {:attribute, _, :compile, options} <- forms, option <- List.wrap(options), do: option

    disabled = :no_auto_import in compile_options
    excluded = for {:no_auto_import, mfas} <- compile_options, mfa <- mfas, do: mfa

    automatic =
      Enum.filter(@dispatches, fn {function, arity} = mfa ->
        not disabled and mfa not in excluded and :erl_internal.bif(function, arity)
      end)

    targets =
      Enum.filter(
        (Enum.uniq(explicit ++ imported ++ automatic) -- local) -- other,
        &(&1 in @dispatches)
      )

    qualify_named_calls(forms, targets)
  end

  defp qualify_named_calls({:call, line, {:atom, annotation, function} = callee, args}, targets) do
    callee =
      if {function, length(args)} in targets,
        do: {:remote, line, {:atom, line, :erlang}, {:atom, annotation, function}},
        else: callee

    {:call, line, callee, Enum.map(args, &qualify_named_calls(&1, targets))}
  end

  defp qualify_named_calls({:fun, line, {:function, function, arity}} = term, targets)
       when is_atom(function) and is_integer(arity) do
    if {function, arity} in targets,
      do:
        {:fun, line,
         {:function, {:atom, line, :erlang}, {:atom, line, function}, {:integer, line, arity}}},
      else: term
  end

  defp qualify_named_calls(term, targets) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.map(&qualify_named_calls(&1, targets)) |> List.to_tuple()

  defp qualify_named_calls(term, targets) when is_list(term),
    do: Enum.map(term, &qualify_named_calls(&1, targets))

  defp qualify_named_calls(term, _targets), do: term

  # Literal module and function targets are closed except executable metadispatch.
  # Variable module/function/apply dispatch is retained
  # as unconfirmed evidence, even when traffic happened to avoid its OTP branch.
  # Protocol atoms, option keys and compatibility function names are not calls.
  defp walk_calls(
         {:call, line, {:remote, _, {:atom, _, :erlang}, {:atom, _, :apply}},
          [{:atom, _, target}, function, args]} = term,
         path
       ) do
    finding =
      cond do
        target == :ssl ->
          [finding(path, line, "literal_apply_ssl")]

        not match?({:atom, _, _}, function) ->
          [finding(path, line, "unresolved_apply")]

        target == :erlang and match?({:atom, _, :apply}, function) ->
          [finding(path, line, "unresolved_apply")]

        target == :erlang and named_dispatch_function?(function) ->
          case literal_arguments(args) do
            {:ok, arguments} -> dispatch_findings(elem(function, 2), arguments, path, line)
            :unknown -> [finding(path, line, "unresolved_named_dispatch")]
          end

        true ->
          []
      end

    finding ++ walk_children(term, path)
  end

  defp walk_calls(
         {:call, line, {:remote, _, {:atom, _, :erlang}, {:atom, _, :apply}}, _args} = term,
         path
       ),
       do: [finding(path, line, "unresolved_apply") | walk_children(term, path)]

  defp walk_calls({:call, line, {:atom, _, :apply}, _args} = term, path),
    do: [finding(path, line, "unresolved_apply") | walk_children(term, path)]

  defp walk_calls(
         {:call, line, {:remote, _, {:atom, _, :erlang}, {:atom, _, function}}, args} = term,
         path
       )
       when {function, length(args)} in @dispatches do
    dispatch_findings(function, args, path, line) ++ walk_children(term, path)
  end

  defp walk_calls({:call, line, {:remote, _, target, function}, _args} = term, path) do
    finding =
      cond do
        not match?({:atom, _, _}, target) ->
          [finding(path, line, "unresolved_module_dispatch")]

        not match?({:atom, _, _}, function) ->
          [finding(path, line, "unresolved_function_dispatch")]

        true ->
          []
      end

    finding ++ walk_children(term, path)
  end

  defp walk_calls({:call, _line, {:atom, _, _}, _args} = term, path),
    do: walk_children(term, path)

  defp walk_calls({:call, _line, {:fun, _, _}, _args} = term, path),
    do: walk_children(term, path)

  defp walk_calls({:call, line, _callee, _args} = term, path),
    do: [finding(path, line, "unresolved_fun_invocation") | walk_children(term, path)]

  defp walk_calls({:fun, line, {:function, target, function, arity}} = term, path) do
    finding =
      cond do
        match?({:atom, _, :ssl}, target) ->
          [finding(path, line, "literal_fun_ssl")]

        match?({:atom, _, :erlang}, target) and
            (match?({:atom, _, :apply}, function) or match?({:atom, _, :make_fun}, function) or
               named_dispatch_capture?(function, arity)) ->
          [finding(path, line, "unresolved_fun_dispatch")]

        not match?({:atom, _, _}, target) or not match?({:atom, _, _}, function) or
            not match?({:integer, _, _}, arity) ->
          [finding(path, line, "unresolved_fun_dispatch")]

        true ->
          []
      end

    finding ++ walk_children(term, path)
  end

  defp walk_calls(term, path) when is_tuple(term), do: walk_children(term, path)
  defp walk_calls(term, path) when is_list(term), do: Enum.flat_map(term, &walk_calls(&1, path))
  defp walk_calls(_term, _path), do: []

  defp named_dispatch_function?({:atom, _, function}),
    do: Keyword.has_key?(@named_dispatches, function)

  defp named_dispatch_capture?({:atom, _, function}, {:integer, _, arity}),
    do: {function, arity} in @dispatches

  defp named_dispatch_capture?(_function, _arity), do: false

  # Node identity does not change the executable MFA. Fun overloads expose
  # only literal fun syntax; unknown values remain unresolved without evaluation.
  defp dispatch_findings(function, args, path, line) do
    arity = length(args)

    cond do
      {function, arity} in @node_dispatches ->
        named_dispatch_findings(tl(args), path, line)

      {function, arity} in @fun_dispatches ->
        fun =
          if (function == :spawn_opt and arity == 3) or
               (function != :spawn_opt and arity == 2),
             do: Enum.at(args, 1),
             else: hd(args)

        case fun do
          {:fun, _, _} -> []
          _ -> [finding(path, line, "unresolved_named_dispatch")]
        end

      {function, arity} in @named_dispatches ->
        named_dispatch_findings(args, path, line)

      true ->
        [finding(path, line, "unresolved_named_dispatch")]
    end
  end

  defp named_dispatch_findings([{:atom, _, :ssl} | _], path, line),
    do: [finding(path, line, "literal_named_dispatch_ssl")]

  defp named_dispatch_findings([{:atom, _, module}, {:atom, _, function} | _], path, line) do
    if module == :erlang and
         (function == :apply or Keyword.has_key?(@named_dispatches, function)),
       do: [finding(path, line, "unresolved_named_dispatch")],
       else: []
  end

  defp named_dispatch_findings(_args, path, line),
    do: [finding(path, line, "unresolved_named_dispatch")]

  # Decode only the literal list spine, never evaluate expressions or follow values.
  defp literal_arguments({nil, _}), do: {:ok, []}

  defp literal_arguments({:cons, _, head, tail}) do
    case literal_arguments(tail) do
      {:ok, rest} -> {:ok, [head | rest]}
      :unknown -> :unknown
    end
  end

  defp literal_arguments(_args), do: :unknown

  defp walk_children(term, path),
    do: term |> Tuple.to_list() |> Enum.flat_map(&walk_calls(&1, path))

  defp finding(path, line, kind),
    do: %{beam: path, line: :erl_anno.line(line), kind: kind, resolution: "unconfirmed"}

  defp digest(path), do: :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)
end
