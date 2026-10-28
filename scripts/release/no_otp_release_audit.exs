defmodule NoOTP.ReleaseAudit do
  @moduledoc false
  @max_finite_targets 16
  @max_finite_bytes 65_536
  @max_parameter_functions 256
  @max_parameter_calls 4_096
  @max_parameter_nodes 100_000
  @parameter_ast_nodes [
    :audit_return,
    :clause,
    :atom,
    :integer,
    :float,
    :char,
    :string,
    nil,
    :var,
    :cons,
    :tuple,
    :map,
    :map_field_assoc,
    :map_field_exact,
    :bin,
    :match,
    :block,
    :case,
    :if,
    :receive,
    :try,
    :catch,
    :op,
    :remote,
    :named_fun,
    :lc,
    :bc,
    :mc,
    :generate,
    :b_generate,
    :m_generate,
    :generate_strict,
    :b_generate_strict,
    :m_generate_strict
  ]
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
    context = return_context(release)
    inspections = Enum.map(beams, &inspect_beam(&1, context))

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
    if Path.type(path) != :absolute do
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
            # Standard releases use lib/../releases for consolidated modules.
            # Normalize only after lstat has checked the traversed component;
            # expanding first would hide a symlink immediately before "..".
            {:cont, {:ok, Path.expand(current)}}

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

  defp inspect_beam(path, context) do
    {:ok, {module, chunks}} =
      :beam_lib.chunks(String.to_charlist(path), [:imports, :exports, :abstract_code])

    imports = Keyword.fetch!(chunks, :imports)
    exports = Keyword.fetch!(chunks, :exports)

    direct =
      for {:ssl, function, arity} <- imports,
          do: %{beam: path, module: inspect(module), function: to_string(function), arity: arity}

    {dynamic, missing} =
      case Keyword.fetch!(chunks, :abstract_code) do
        {:raw_abstract_v1, forms} ->
          prepared = prove_return_calls(forms, context)

          {walk_calls(
             resolve_lexical(qualify_named_dispatches(prepared, imports), exports),
             path
           ), false}

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

  # A return proof is available only for the actual current in-release selection.
  # Standalone/offline audits never borrow the auditor host's implementation.
  defp return_context(release) do
    %{release: canonical_path(release), paths: Enum.map(:code.get_path(), &to_string/1)}
  end

  defp selected_producer(module, context) do
    with %{resolved: release, error: nil} when is_binary(release) <- context.release,
         path when is_list(path) <- :code.which(module),
         raw = to_string(path),
         %{resolved: selected, error: nil} <- canonical_path(raw),
         true <- String.starts_with?(selected, release <> "/"),
         first when is_binary(first) <-
           Enum.find_value(context.paths, fn directory ->
             candidate = Path.join(directory, Atom.to_string(module) <> ".beam")
             if File.regular?(candidate), do: candidate
           end),
         %{resolved: ^selected, error: nil} <- canonical_path(first),
         loaded <- :code.is_loaded(module),
         true <- loaded_selection?(loaded, selected),
         status when status in [:loaded, :not_loaded] <- :code.module_status(module),
         {:ok, bytes} <- File.read(selected),
         {:ok, {^module, chunks}} <-
           :beam_lib.chunks(bytes, [:imports, :exports, :abstract_code]),
         {:raw_abstract_v1, forms} <- Keyword.get(chunks, :abstract_code),
         false <- Enum.any?(forms, &match?({:attribute, _, :on_load, _}, &1)),
         false <- Enum.any?(Keyword.fetch!(chunks, :imports), &match?({:ssl, _, _}, &1)),
         true <- Enum.map(:code.get_path(), &to_string/1) == context.paths,
         ^path <- :code.which(module),
         ^loaded <- :code.is_loaded(module),
         ^status <- :code.module_status(module),
         {:ok, ^bytes} <- File.read(selected) do
      {:ok,
       %{
         module: module,
         path: selected,
         raw: raw,
         loaded: loaded,
         status: status,
         sha256: :crypto.hash(:sha256, bytes),
         exports: Keyword.fetch!(chunks, :exports),
         definitions:
           Map.new(for {:function, _, name, arity, _} = form <- forms, do: {{name, arity}, form})
       }}
    else
      _ -> :unknown
    end
  rescue
    _ -> :unknown
  catch
    _, _ -> :unknown
  end

  defp loaded_selection?(false, _selected), do: true

  defp loaded_selection?({:file, path}, selected) when is_list(path),
    do: match?(%{resolved: ^selected, error: nil}, canonical_path(to_string(path)))

  defp loaded_selection?(_loaded, _selected), do: false

  # Only a fully literal map argument starts this bounded return slice. Names,
  # source lines, module identities and stored body hashes never grant a proof.
  defp prove_return_calls(
         {:call, line, {:remote, _, {:atom, _, module}, {:atom, _, function}},
          [{:map, _, _} = argument]} = call,
         context
       ) do
    state = %{context: context, selections: %{}, stack: [], calls: 0}

    result =
      with {:ok, value} <- return_literal(argument),
           {:ok, result, state} <- return_call(module, function, [value], state, true),
           {:tuple, _, [_accumulator, {:fun, _, {:clauses, []}}]} <- result,
           true <- selections_current?(state) do
        {:audit_return, line, call, result}
      else
        _ -> call
      end

    result
  end

  defp prove_return_calls(term, context) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.map(&prove_return_calls(&1, context)) |> List.to_tuple()

  defp prove_return_calls(terms, context) when is_list(terms),
    do: Enum.map(terms, &prove_return_calls(&1, context))

  defp prove_return_calls(term, _context), do: term

  defp selections_current?(state) do
    Enum.map(:code.get_path(), &to_string/1) == state.context.paths and
      Enum.all?(state.selections, fn {module, selected} ->
        case selected_producer(module, state.context) do
          {:ok, current} -> current == selected
          _ -> false
        end
      end)
  end

  defp return_call(module, function, arguments, state, remote?) do
    key = {module, function, length(arguments)}

    with true <- state.calls < 32 and length(state.stack) < 16 and key not in state.stack,
         {:ok, selected} <- return_selection(module, state),
         true <- not remote? or {function, length(arguments)} in selected.exports,
         {:function, _, _, _, clauses} = form <-
           Map.get(selected.definitions, {function, length(arguments)}),
         true <- :erlang.external_size(form) <= @max_finite_bytes do
      stack = state.stack

      state = %{
        state
        | stack: [key | stack],
          calls: state.calls + 1,
          selections: Map.put(state.selections, module, selected)
      }

      case return_clauses(clauses, arguments, %{}, module, state) do
        {:ok, value, state} -> {:ok, value, %{state | stack: stack}}
        _ -> :unknown
      end
    else
      _ -> :unknown
    end
  end

  defp return_selection(module, state) do
    case Map.fetch(state.selections, module) do
      {:ok, selected} -> {:ok, selected}
      :error -> selected_producer(module, state.context)
    end
  end

  # Ordered matching: an unknown earlier pattern/guard prevents selecting a
  # later clause. Even definitely unselected clauses retain the ordinary scan.
  defp return_clauses([], _arguments, _environment, _module, _state), do: :unknown

  defp return_clauses(
         [{:clause, _, patterns, guards, body} = clause | rest],
         arguments,
         environment,
         module,
         state
       ) do
    with {:ok, scope} <- return_patterns(patterns, arguments, environment) do
      case return_guards(guards, scope) do
        true ->
          if Enum.all?(rest, &return_unselected_safe?/1) do
            return_sequence(body, scope, module, state)
          else
            :unknown
          end

        false ->
          if return_unselected_safe?(clause),
            do: return_clauses(rest, arguments, environment, module, state),
            else: :unknown

        :unknown ->
          :unknown
      end
    else
      :no_match ->
        if return_unselected_safe?(clause),
          do: return_clauses(rest, arguments, environment, module, state),
          else: :unknown

      _ ->
        :unknown
    end
  end

  defp return_unselected_safe?(clause),
    do:
      return_closure_syntax?(clause) and
        walk_calls(elem(resolve_clause(clause, %{}, false), 0), "return-proof") == []

  defp return_sequence([], _environment, _module, _state), do: :unknown

  defp return_sequence(expressions, environment, module, state) do
    Enum.reduce_while(expressions, {:ok, :unknown, environment, state}, fn expression,
                                                                           {:ok, _value, scope,
                                                                            state} ->
      case return_expression(expression, scope, module, state) do
        {:ok, value, scope, state} -> {:cont, {:ok, value, scope, state}}
        _ -> {:halt, :unknown}
      end
    end)
    |> case do
      {:ok, value, _scope, state} -> {:ok, value, state}
      _ -> :unknown
    end
  end

  defp return_expression({:var, _, name}, environment, _module, state) do
    case Map.fetch(environment, name) do
      {:ok, value} -> {:ok, value, environment, state}
      :error -> :unknown
    end
  end

  defp return_expression({:match, _, pattern, expression}, environment, module, state) do
    with {:ok, value, scope, state} <- return_expression(expression, environment, module, state),
         {:ok, scope} <- return_pattern(pattern, value, scope) do
      {:ok, value, scope, state}
    else
      _ -> :unknown
    end
  end

  defp return_expression({:tuple, line, expressions}, environment, module, state) do
    with {:ok, values, environment, state} <-
           return_arguments(expressions, environment, module, state),
         true <- :erlang.external_size(values) <= @max_finite_bytes do
      {:ok, {:tuple, line, values}, environment, state}
    else
      _ -> :unknown
    end
  end

  defp return_expression(
         {:fun, line, {:clauses, clauses}} = expression,
         environment,
         _module,
         state
       ) do
    resolved = elem(resolve_expression(expression, environment), 0)

    # Auxiliary local helper/capture bodies are not independently scanned by
    # the candidate-module pass. Reject them instead of assuming their effects.
    if clauses != [] and return_closure_syntax?(resolved) and
         return_no_auxiliary_helpers?(resolved, state.selections) and
         walk_calls(resolved, "return-proof") == [] do
      {:ok, {:fun, line, {:clauses, []}}, environment, state}
    else
      :unknown
    end
  end

  defp return_expression({:case, _, expression, clauses}, environment, module, state) do
    with {:ok, value, scope, state} <- return_expression(expression, environment, module, state),
         {:ok, result, state} <- return_clauses(clauses, [value], scope, module, state) do
      {:ok, result, environment, state}
    else
      _ -> :unknown
    end
  end

  defp return_expression(
         {:call, _, {:atom, _, function}, expressions},
         environment,
         module,
         state
       ) do
    with {:ok, arguments, environment, state} <-
           return_arguments(expressions, environment, module, state),
         {:ok, value, state} <- return_call(module, function, arguments, state, false) do
      {:ok, value, environment, state}
    else
      _ -> :unknown
    end
  end

  defp return_expression(
         {:call, line, {:remote, annotation, target, name}, expressions},
         environment,
         module,
         state
       ) do
    with {:ok, {:atom, _, target_module}, environment, state} <-
           return_expression(target, environment, module, state),
         {:ok, {:atom, _, function}, environment, state} <-
           return_expression(name, environment, module, state),
         {:ok, arguments, environment, state} <-
           return_arguments(expressions, environment, module, state),
         [] <-
           walk_calls(
             {:call, line,
              {:remote, annotation, {:atom, annotation, target_module},
               {:atom, annotation, function}}, arguments},
             "return-proof"
           ),
         {:ok, value, state} <- return_call(target_module, function, arguments, state, true) do
      {:ok, value, environment, state}
    else
      _ -> :unknown
    end
  end

  defp return_expression(expression, environment, _module, state) do
    case return_literal(expression) do
      {:ok, value} -> {:ok, value, environment, state}
      _ -> :unknown
    end
  end

  defp return_arguments(expressions, environment, module, state) do
    Enum.reduce_while(expressions, {:ok, [], environment, state}, fn expression,
                                                                     {:ok, values, scope, state} ->
      case return_expression(expression, scope, module, state) do
        {:ok, value, scope, state} -> {:cont, {:ok, values ++ [value], scope, state}}
        _ -> {:halt, :unknown}
      end
    end)
  end

  defp return_closure_syntax?({:call, _, {:atom, _, _}, _}), do: false
  defp return_closure_syntax?({:fun, _, {:function, _, _}}), do: false
  defp return_closure_syntax?({:fun, _, {:function, _, _, _}}), do: false
  defp return_closure_syntax?({:named_fun, _, _, _}), do: false

  defp return_closure_syntax?(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.all?(&return_closure_syntax?/1)

  defp return_closure_syntax?(terms) when is_list(terms),
    do: Enum.all?(terms, &return_closure_syntax?/1)

  defp return_closure_syntax?(_term), do: true

  defp return_literal(expression) do
    if :erlang.external_size(expression) <= @max_finite_bytes,
      do: return_literal_node(expression),
      else: :unknown
  end

  defp return_literal_node({:map, line, fields}) do
    Enum.reduce_while(fields, {:ok, []}, fn
      {:map_field_assoc, annotation, key, value}, {:ok, fields} ->
        with {:ok, key} <- return_literal(key),
             {:ok, value} <- return_literal(value),
             {:ok, data_key} <- return_data(key),
             :missing <- return_map_value(fields, data_key) do
          {:cont, {:ok, fields ++ [{:map_field_assoc, annotation, key, value}]}}
        else
          _ -> {:halt, :unknown}
        end

      _, _ ->
        {:halt, :unknown}
    end)
    |> case do
      {:ok, fields} -> {:ok, {:map, line, fields}}
      _ -> :unknown
    end
  end

  defp return_literal_node(expression) do
    case literal_value(expression) do
      :unknown -> :unknown
      value -> {:ok, value}
    end
  end

  defp return_patterns(patterns, values, environment) when length(patterns) == length(values) do
    Enum.zip(patterns, values)
    |> Enum.reduce_while({:ok, environment}, fn {pattern, value}, {:ok, scope} ->
      case return_pattern(pattern, value, scope) do
        {:ok, scope} -> {:cont, {:ok, scope}}
        other -> {:halt, other}
      end
    end)
  end

  defp return_patterns(_patterns, _values, _environment), do: :unknown

  defp return_pattern({:var, _, :_}, _value, environment), do: {:ok, environment}

  defp return_pattern({:var, _, name}, value, environment) do
    case Map.fetch(environment, name) do
      :error ->
        {:ok, Map.put(environment, name, value)}

      {:ok, old} ->
        return_equal_pattern(old, value, environment)
    end
  end

  defp return_pattern({:match, _, left, right}, value, environment) do
    with {:ok, environment} <- return_pattern(left, value, environment),
         {:ok, environment} <- return_pattern(right, value, environment),
         do: {:ok, environment}
  end

  defp return_pattern({:tuple, _, patterns}, {:tuple, _, values}, environment),
    do: return_patterns(patterns, values, environment)

  defp return_pattern({:map, _, patterns}, {:map, _, fields}, environment) do
    Enum.reduce_while(patterns, {:ok, environment}, fn
      {:map_field_exact, _, key, pattern}, {:ok, scope} ->
        with {:ok, data_key} <- return_pattern_key(key, scope),
             {:ok, value} <- return_map_value(fields, data_key) do
          case return_pattern(pattern, value, scope) do
            {:ok, scope} -> {:cont, {:ok, scope}}
            other -> {:halt, other}
          end
        else
          :missing -> {:halt, :no_match}
          _ -> {:halt, :unknown}
        end

      _, _ ->
        {:halt, :unknown}
    end)
  end

  defp return_pattern(pattern, value, environment) do
    with {:ok, literal} <- return_literal(pattern) do
      return_equal_pattern(literal, value, environment)
    else
      _ -> :unknown
    end
  end

  # A bound key variable is an expression, not a literal AST key. Unsupported
  # key expressions cannot establish that an earlier map clause fails.
  defp return_pattern_key({:var, _, name}, environment) do
    with {:ok, value} <- Map.fetch(environment, name), do: return_data(value)
  end

  defp return_pattern_key(expression, _environment), do: return_data(expression)

  defp return_map_value([], _data_key), do: :missing

  defp return_map_value([{:map_field_assoc, _, key, value} | rest], data_key) do
    case return_data(key) do
      {:ok, existing} ->
        if existing === data_key, do: {:ok, value}, else: return_map_value(rest, data_key)

      _ ->
        :unknown
    end
  end

  defp return_map_value(_fields, _data_key), do: :unknown

  defp return_equal_pattern(left, right, environment) do
    with {:ok, left} <- return_data(left),
         {:ok, right} <- return_data(right) do
      if left === right, do: {:ok, environment}, else: :no_match
    else
      _ -> :unknown
    end
  end

  defp return_guards([], _environment), do: true

  defp return_guards(alternatives, environment) do
    alternatives
    |> Enum.map(fn sequence ->
      values = Enum.map(sequence, &return_guard(&1, environment))

      cond do
        false in values -> false
        :unknown in values -> :unknown
        true -> true
      end
    end)
    |> then(fn values ->
      cond do
        true in values -> true
        :unknown in values -> :unknown
        true -> false
      end
    end)
  end

  defp return_guard({:op, _, operator, left, right}, environment)
       when operator in [:"=:=", :==] do
    with {:ok, {kind_a, _, a}} when kind_a in [:atom, :integer] <-
           return_guard_value(left, environment),
         {:ok, {kind_b, _, b}} when kind_b in [:atom, :integer] <-
           return_guard_value(right, environment) do
      kind_a == kind_b and a == b
    else
      _ -> :unknown
    end
  end

  defp return_guard({:op, _, operator, left, right}, environment)
       when operator in [:orelse, :andalso] do
    case {operator, return_guard(left, environment), return_guard(right, environment)} do
      {:orelse, true, _} -> true
      {:orelse, false, right} when is_boolean(right) -> right
      {:andalso, false, _} -> false
      {:andalso, true, right} when is_boolean(right) -> right
      _ -> :unknown
    end
  end

  defp return_guard(
         {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :is_atom}}, [value]},
         environment
       ) do
    case return_guard_value(value, environment) do
      {:ok, {:atom, _, _}} -> true
      {:ok, _} -> false
      _ -> :unknown
    end
  end

  defp return_guard({:atom, _, value}, _environment) when is_boolean(value), do: value
  defp return_guard(_guard, _environment), do: :unknown

  defp return_guard_value({:var, _, name}, environment), do: Map.fetch(environment, name)
  defp return_guard_value(expression, _environment), do: return_literal(expression)

  # Decode only bounded, inert literal data. Native exact equality supplies
  # Erlang map-key semantics and ignores AST annotations and field ordering.
  # Functions, variables, floats and unsupported constructors stay unknown.
  defp return_data(expression) do
    if :erlang.external_size(expression) <= @max_finite_bytes,
      do: return_data_node(expression),
      else: :unknown
  end

  defp return_data_node({:atom, _, value}) when is_atom(value), do: {:ok, value}
  defp return_data_node({:integer, _, value}) when is_integer(value), do: {:ok, value}
  defp return_data_node({nil, _}), do: {:ok, []}

  defp return_data_node({:tuple, _, elements}) do
    case return_data_elements(elements) do
      {:ok, values} -> {:ok, List.to_tuple(values)}
      _ -> :unknown
    end
  end

  defp return_data_node({:cons, _, head, tail}) do
    with {:ok, head} <- return_data(head),
         {:ok, tail} <- return_data(tail),
         do: {:ok, [head | tail]}
  end

  defp return_data_node({:map, _, fields}) do
    Enum.reduce_while(fields, {:ok, %{}}, fn
      {:map_field_assoc, _, key, value}, {:ok, data} ->
        with {:ok, key} <- return_data(key),
             {:ok, value} <- return_data(value) do
          {:cont, {:ok, Map.put(data, key, value)}}
        else
          _ -> {:halt, :unknown}
        end

      _, _ ->
        {:halt, :unknown}
    end)
  end

  defp return_data_node(_expression), do: :unknown

  defp return_data_elements(elements) do
    Enum.reduce_while(elements, {:ok, []}, fn expression, {:ok, values} ->
      case return_data(expression) do
        {:ok, value} -> {:cont, {:ok, [value | values]}}
        _ -> {:halt, :unknown}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      _ -> :unknown
    end
  end

  # A remote self/helper call in the auxiliary producer directory would hide
  # a body outside the returned closure. This bounded slice does not prove it.
  defp return_no_auxiliary_helpers?(
         {:call, _, {:remote, _, {:atom, _, module}, _}, arguments},
         selections
       ) do
    helper? =
      case :code.which(module) do
        path when is_list(path) ->
          case canonical_path(to_string(path)) do
            %{resolved: resolved, error: nil} ->
              Enum.any?(selections, fn {_module, selected} ->
                Path.dirname(selected.path) == Path.dirname(resolved)
              end)

            _ ->
              true
          end

        :preloaded ->
          false

        _ ->
          true
      end

    not helper? and return_no_auxiliary_helpers?(arguments, selections)
  end

  defp return_no_auxiliary_helpers?(term, selections) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.all?(&return_no_auxiliary_helpers?(&1, selections))

  defp return_no_auxiliary_helpers?(terms, selections) when is_list(terms),
    do: Enum.all?(terms, &return_no_auxiliary_helpers?(&1, selections))

  defp return_no_auxiliary_helpers?(_term, _selections), do: true

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

  # Complete compiled caller domains can seed private parameters. General finite
  # targets require acyclic callers; literal closure parameters also admit a
  # separately checked acyclic argument-dependency proof. Exports and captures
  # remain open; neither rule infers function returns or global state.
  defp resolve_lexical(forms, beam_exports) do
    definitions =
      Map.new(for {:function, _, name, arity, _} = form <- forms, do: {{name, arity}, form})

    exports = for {:attribute, _, :export, entries} <- forms, entry <- entries, do: entry

    options =
      for {:attribute, _, :compile, values} <- forms, value <- List.wrap(values), do: value

    exported = MapSet.new(beam_exports ++ exports)

    analysis = %{
      definitions: definitions,
      edges: MapSet.new(),
      captures: MapSet.new(),
      complete: true,
      nodes: 0,
      calls: 0
    }

    resolved =
      if :export_all in options or map_size(definitions) > @max_parameter_functions do
        %{}
      else
        analysis =
          Enum.reduce(definitions, analysis, fn {owner, {:function, _, _, _, clauses}}, state ->
            caller_syntax(clauses, owner, state)
          end)

        if analysis.complete do
          callers =
            Enum.reduce(analysis.edges, %{}, fn {caller, callee}, acc ->
              Map.update(acc, callee, MapSet.new([caller]), &MapSet.put(&1, caller))
            end)

          closures = independent_closure_parameters(definitions, exported, analysis)

          closed_parameters(definitions, callers, exported, analysis.captures, %{}, %{}, closures)
        else
          %{}
        end
      end

    Enum.map(forms, fn
      {:function, _, name, arity, _} = form ->
        Map.get_lazy(resolved, {name, arity}, fn ->
          resolve_function(form, List.duplicate(:unknown, arity))
        end)

      form ->
        form
    end)
  end

  # Remove ready vertices, never iterate a recursive proof to an arbitrary cap.
  # Cycles retain unknown general targets; checked closure seeds are independent.
  defp closed_parameters(remaining, callers, exported, captures, incoming, resolved, closures) do
    ready =
      Enum.reject(remaining, fn {key, _form} ->
        Enum.any?(Map.get(callers, key, MapSet.new()), &Map.has_key?(remaining, &1))
      end)

    if ready == [] do
      Enum.reduce(remaining, resolved, fn {{_, arity} = key, form}, output ->
        values = closure_parameter_values(key, List.duplicate(:unknown, arity), closures)
        Map.put(output, key, resolve_function(form, values))
      end)
    else
      {incoming, resolved} =
        Enum.reduce(ready, {incoming, resolved}, fn {{_, arity} = key, form}, {args, output} ->
          values =
            if not MapSet.member?(exported, key) and not MapSet.member?(captures, key),
              do: Map.get(args, key, List.duplicate(:unknown, arity)),
              else: List.duplicate(:unknown, arity)

          values = closure_parameter_values(key, values, closures)
          form = resolve_function(form, values)
          {collect_local_arguments(form, remaining, args), Map.put(output, key, form)}
        end)

      remaining = Map.drop(remaining, Enum.map(ready, &elem(&1, 0)))
      closed_parameters(remaining, callers, exported, captures, incoming, resolved, closures)
    end
  end

  # Each proof edge is an argument origin, not a function call edge. A caller's
  # unrelated recursion cannot invent a parameter value. Direct self-recursive
  # callers remain deliberately unsupported by this bounded extension, as do
  # unknown origins and all recursive parameter dependencies.
  defp independent_closure_parameters(definitions, exported, analysis) do
    blocked =
      Enum.reduce(analysis.edges, MapSet.union(exported, analysis.captures), fn
        {key, key}, blocked -> MapSet.put(blocked, key)
        _, blocked -> blocked
      end)

    dependencies =
      Enum.reduce(definitions, %{}, fn {{_, arity} = owner, form}, dependencies ->
        {:function, _, _, _, clauses} =
          resolve_function(form, List.duplicate(:unknown, arity))

        Enum.reduce(clauses, dependencies, fn {:clause, _, patterns, guards, body}, acc ->
          parameters =
            patterns
            |> Enum.with_index()
            |> Enum.flat_map(fn
              {{:var, _, name}, index} -> [{name, {owner, index}}]
              _ -> []
            end)
            |> Map.new()

          parameters = if MapSet.member?(blocked, owner), do: %{}, else: parameters
          self_recursive? = MapSet.member?(analysis.edges, {owner, owner})

          closure_dependencies(
            [guards, body],
            definitions,
            parameters,
            self_recursive?,
            acc
          )
        end)
      end)
      |> Map.reject(fn {{key, _index}, _origins} -> MapSet.member?(blocked, key) end)

    if map_size(dependencies) <= @max_parameter_calls,
      do: prove_closure_parameters(dependencies, MapSet.new()),
      else: MapSet.new()
  end

  defp closure_dependencies(
         {:call, _, {:atom, _, name}, args} = term,
         definitions,
         parameters,
         self_recursive?,
         dependencies
       ) do
    key = {name, length(args)}

    dependencies =
      if Map.has_key?(definitions, key) do
        args
        |> Enum.with_index()
        |> Enum.reduce(dependencies, fn {argument, index}, acc ->
          origin =
            if self_recursive?,
              do: :unknown,
              else: closure_argument_origin(argument, parameters)

          Map.update(acc, {key, index}, [origin], &[origin | &1])
        end)
      else
        dependencies
      end

    term
    |> Tuple.to_list()
    |> closure_dependencies(definitions, parameters, self_recursive?, dependencies)
  end

  # Nested clauses/comprehensions may shadow outer formals. Literal closures
  # still prove their own identity, but forwarding across these scopes is open.
  defp closure_dependencies(term, definitions, _parameters, self_recursive?, dependencies)
       when is_tuple(term) and tuple_size(term) >= 1 and
              elem(term, 0) in [:clause, :lc, :bc, :mc] do
    term
    |> Tuple.to_list()
    |> closure_dependencies(definitions, %{}, self_recursive?, dependencies)
  end

  defp closure_dependencies(term, definitions, parameters, self_recursive?, dependencies)
       when is_tuple(term) do
    term
    |> Tuple.to_list()
    |> closure_dependencies(definitions, parameters, self_recursive?, dependencies)
  end

  defp closure_dependencies(terms, definitions, parameters, self_recursive?, dependencies)
       when is_list(terms) do
    Enum.reduce(terms, dependencies, fn term, acc ->
      closure_dependencies(term, definitions, parameters, self_recursive?, acc)
    end)
  end

  defp closure_dependencies(_term, _definitions, _parameters, _self_recursive?, dependencies),
    do: dependencies

  defp closure_argument_origin({:var, _, name}, parameters),
    do: Map.get(parameters, name, :unknown)

  defp closure_argument_origin(argument, _parameters) do
    case caller_argument_value(argument) do
      {:fun, _, {:clauses, []}} -> :literal_closure
      _ -> :unknown
    end
  end

  # Remove proven vertices. Each successful pass strictly shrinks the finite
  # dependency graph; a cycle has no ready vertex and remains unknown. There is
  # no assumed seed, widening or iteration cutoff that turns an unknown safe.
  defp prove_closure_parameters(dependencies, proven) do
    ready =
      for {parameter, origins} <- dependencies,
          origins != [],
          Enum.all?(origins, &(&1 == :literal_closure or MapSet.member?(proven, &1))),
          do: parameter

    if ready == [] do
      proven
    else
      prove_closure_parameters(
        Map.drop(dependencies, ready),
        Enum.reduce(ready, proven, &MapSet.put(&2, &1))
      )
    end
  end

  defp closure_parameter_values(key, values, closures) do
    values
    |> Enum.with_index()
    |> Enum.map(fn {value, index} ->
      if value == :unknown and MapSet.member?(closures, {key, index}),
        do: {:fun, 0, {:clauses, []}},
        else: value
    end)
  end

  defp resolve_function({:function, line, name, arity, clauses}, values) do
    clauses =
      Enum.map(clauses, fn {:clause, _, patterns, _, _} = clause ->
        scope =
          Enum.zip(patterns, values)
          |> Enum.reduce(%{}, fn {pattern, value}, env -> bind_pattern(pattern, value, env) end)
          |> Map.reject(fn {_name, value} -> value == :unknown end)

        elem(resolve_clause(clause, scope, false), 0)
      end)

    {:function, line, name, arity, clauses}
  end

  # Count and recognize executable AST constructors before claiming completeness.
  # Unsupported nodes make the entire added parameter proof unavailable.
  defp caller_syntax(_term, _owner, %{complete: false} = state), do: state

  defp caller_syntax(term, owner, state) do
    state = %{state | nodes: state.nodes + 1}

    if state.nodes > @max_parameter_nodes,
      do: %{state | complete: false},
      else: caller_node(term, owner, state)
  end

  defp caller_node({:call, _, callee, args}, owner, state) do
    state = %{state | calls: state.calls + 1}

    state =
      case callee do
        {:atom, _, name} ->
          key = {name, length(args)}

          if Map.has_key?(state.definitions, key),
            do: %{state | edges: MapSet.put(state.edges, {owner, key})},
            else: state

        _ ->
          state
      end

    if state.calls > @max_parameter_calls,
      do: %{state | complete: false},
      else: caller_syntax([callee, args], owner, state)
  end

  # Even a non-escaping local capture is deliberately open in this small batch.
  defp caller_node({:fun, _, {:function, name, arity}}, _owner, state)
       when is_atom(name) and is_integer(arity),
       do: %{state | captures: MapSet.put(state.captures, {name, arity})}

  defp caller_node(
         {:fun, _, {:function, module, {:atom, _, name}, {:integer, _, arity}}},
         owner,
         state
       ) do
    # Conservatively include same-named remote captures, even if a remote module
    # would need an exported function. Unknown names/arities disable this proof.
    state = %{state | captures: MapSet.put(state.captures, {name, arity})}
    caller_syntax(module, owner, state)
  end

  defp caller_node({:fun, _, {:clauses, clauses}}, owner, state),
    do: caller_syntax(clauses, owner, state)

  defp caller_node({:bin_element, _, value, size, _types}, owner, state),
    do: caller_syntax([value, size], owner, state)

  defp caller_node(term, owner, state)
       when is_tuple(term) and tuple_size(term) >= 2 and
              elem(term, 0) in @parameter_ast_nodes,
       do: term |> Tuple.to_list() |> Enum.drop(2) |> caller_syntax(owner, state)

  defp caller_node(term, owner, state) when is_list(term),
    do: Enum.reduce(term, state, &caller_syntax(&1, owner, &2))

  defp caller_node(term, _owner, state) when is_tuple(term), do: %{state | complete: false}
  defp caller_node(_term, _owner, state), do: state

  defp collect_local_arguments({:call, _, {:atom, _, name}, args} = term, definitions, incoming) do
    key = {name, length(args)}

    incoming =
      if Map.has_key?(definitions, key) do
        # Reuse only lexical expression values; never execute or infer a return.
        # Literal closure bodies stay in the original AST, not in these domains.
        values =
          Enum.map(args, fn arg -> common_value([caller_argument_value(arg)]) end)
          |> bounded_arguments()

        Map.update(incoming, key, values, fn previous ->
          Enum.zip(previous, values)
          |> Enum.map(fn {a, b} -> common_value([a, b]) end)
          |> bounded_arguments()
        end)
      else
        incoming
      end

    term
    |> Tuple.to_list()
    |> Enum.reduce(incoming, &collect_local_arguments(&1, definitions, &2))
  end

  defp collect_local_arguments(term, definitions, incoming) when is_tuple(term),
    do: term |> Tuple.to_list() |> collect_local_arguments(definitions, incoming)

  defp collect_local_arguments(term, definitions, incoming) when is_list(term),
    do: Enum.reduce(term, incoming, &collect_local_arguments(&1, definitions, &2))

  defp collect_local_arguments(_term, _definitions, incoming), do: incoming

  defp caller_argument_value({:fun, line, {:clauses, _}}),
    do: {:fun, line, {:clauses, []}}

  defp caller_argument_value({:named_fun, line, _name, _clauses}),
    do: {:fun, line, {:clauses, []}}

  defp caller_argument_value(expression) do
    if :erlang.external_size(expression) <= @max_finite_bytes,
      do: elem(resolve_expression(expression, %{}), 2),
      else: :unknown
  end

  defp bounded_arguments(values) do
    if :erlang.external_size(values) <= @max_finite_bytes,
      do: values,
      else: List.duplicate(:unknown, length(values))
  end

  defp resolve_clause({:clause, line, patterns, guards, body}, environment, shadow) do
    environment =
      if shadow, do: Map.drop(environment, pattern_variables(patterns)), else: environment

    body_environment = successful_guard_environment(guards, environment)
    guards = Enum.map(guards, fn guard -> elem(resolve_sequence(guard, environment), 0) end)
    {body, environment, value} = resolve_sequence(body, body_environment)
    {{:clause, line, patterns, guards, body}, environment, value}
  end

  # A successful clause supplies facts only from positive atom equalities.
  # Guard sequences are alternatives; every alternative must establish a fact.
  # Existing domains stay conservative, and the original guards are still scanned.
  defp successful_guard_environment([], environment), do: environment

  defp successful_guard_environment(guards, environment) do
    if :erlang.external_size(guards) <= @max_finite_bytes do
      guards
      |> Enum.map(fn sequence -> Enum.reduce(sequence, environment, &guard_atom_fact/2) end)
      |> join_environments()
    else
      environment
    end
  end

  defp guard_atom_fact({:op, _, :andalso, left, right}, environment) do
    guard_atom_fact(right, guard_atom_fact(left, environment))
  end

  defp guard_atom_fact({:op, _, :orelse, left, right}, environment) do
    join_environments([
      guard_atom_fact(left, environment),
      guard_atom_fact(right, environment)
    ])
  end

  defp guard_atom_fact({:op, _, operator, {:var, _, name}, {:atom, _, _} = value}, environment)
       when operator in [:==, :"=:="] do
    guard_atom_binding(name, value, environment)
  end

  defp guard_atom_fact({:op, _, operator, {:atom, _, _} = value, {:var, _, name}}, environment)
       when operator in [:==, :"=:="] do
    guard_atom_binding(name, value, environment)
  end

  defp guard_atom_fact(_guard, environment), do: environment

  defp guard_atom_binding(name, value, environment) do
    if Map.get(environment, name, :unknown) == :unknown,
      do: Map.put(environment, name, value),
      else: environment
  end

  defp resolve_sequence(expressions, environment) do
    {resolved, {environment, value}} =
      Enum.map_reduce(expressions, {environment, :unknown}, fn expression, {scope, _value} ->
        {expression, scope, value} = resolve_expression(expression, scope)
        {expression, {scope, value}}
      end)

    {resolved, environment, value}
  end

  # Keep the complete original producer call in the ordinary scan. Only its
  # separately checked return value may seed the following lexical binding.
  defp resolve_expression({:audit_return, line, call, value}, environment) do
    {call, environment, _} = resolve_expression(call, environment)
    {{:audit_return, line, call}, environment, value}
  end

  defp resolve_expression({:var, _, name} = expression, environment) do
    value = Map.get(environment, name, :unknown)
    {if(value == :unknown, do: expression, else: value), environment, value}
  end

  defp resolve_expression({:match, line, pattern, expression}, environment) do
    {expression, environment, value} = resolve_expression(expression, environment)
    environment = bind_pattern(pattern, value, environment)
    {{:match, line, pattern, expression}, environment, value}
  end

  defp resolve_expression({:block, line, body}, environment) do
    {body, environment, value} = resolve_sequence(body, environment)
    {{:block, line, body}, environment, value}
  end

  defp resolve_expression({:fun, line, {:clauses, clauses}}, environment) do
    clauses =
      Enum.map(clauses, fn clause -> elem(resolve_clause(clause, environment, true), 0) end)

    {{:fun, line, {:clauses, clauses}}, environment, {:fun, line, {:clauses, []}}}
  end

  defp resolve_expression({:named_fun, line, name, clauses}, environment) do
    identity = {:fun, line, {:clauses, []}}
    captured = Map.put(environment, name, identity)
    clauses = Enum.map(clauses, fn clause -> elem(resolve_clause(clause, captured, true), 0) end)
    {{:named_fun, line, name, clauses}, environment, identity}
  end

  defp resolve_expression({:case, line, expression, clauses}, environment) do
    {expression, environment, _value} = resolve_expression(expression, environment)
    {clauses, environment, value} = resolve_branches(clauses, environment)
    {{:case, line, expression, clauses}, environment, value}
  end

  defp resolve_expression({:if, line, clauses}, environment) do
    {clauses, environment, value} = resolve_branches(clauses, environment)
    {{:if, line, clauses}, environment, value}
  end

  defp resolve_expression({:receive, line, clauses}, environment) do
    {clauses, environment, value} = resolve_branches(clauses, environment)
    {{:receive, line, clauses}, environment, value}
  end

  defp resolve_expression({:receive, line, clauses, timeout, body}, environment) do
    {timeout, environment, _value} = resolve_expression(timeout, environment)
    branches = Enum.map(clauses, &resolve_clause(&1, environment, false))
    {body, after_environment, after_value} = resolve_sequence(body, environment)
    environments = [after_environment | Enum.map(branches, &elem(&1, 1))]
    values = [after_value | Enum.map(branches, &elem(&1, 2))]

    {{:receive, line, Enum.map(branches, &elem(&1, 0)), timeout, body},
     join_environments(environments), common_value(values)}
  end

  defp resolve_expression({:try, line, body, clauses, catches, after_body}, environment) do
    {body, body_environment, _value} = resolve_sequence(body, environment)
    clauses = Enum.map(clauses, &elem(resolve_clause(&1, body_environment, false), 0))
    catches = Enum.map(catches, &elem(resolve_clause(&1, environment, false), 0))
    {after_body, _, _} = resolve_sequence(after_body, environment)
    {{:try, line, body, clauses, catches, after_body}, environment, :unknown}
  end

  defp resolve_expression({:catch, line, expression}, environment) do
    {expression, _, _} = resolve_expression(expression, environment)
    {{:catch, line, expression}, environment, :unknown}
  end

  defp resolve_expression({kind, line, expression, qualifiers}, environment)
       when kind in [:lc, :bc, :mc] do
    {qualifiers, scope} =
      Enum.map_reduce(qualifiers, environment, fn
        {generator, annotation, pattern, source}, scope
        when generator in [
               :generate,
               :b_generate,
               :m_generate,
               :generate_strict,
               :b_generate_strict,
               :m_generate_strict
             ] ->
          {source, scope, _} = resolve_expression(source, scope)
          {{generator, annotation, pattern, source}, Map.drop(scope, pattern_variables(pattern))}

        filter, scope ->
          {filter, scope, _} = resolve_expression(filter, scope)
          {filter, scope}
      end)

    {expression, _, _} = resolve_expression(expression, scope)
    {{kind, line, expression, qualifiers}, environment, :unknown}
  end

  defp resolve_expression({:op, line, operator, left, right}, environment)
       when operator in [:andalso, :orelse] do
    {left, environment, _} = resolve_expression(left, environment)
    {right, _, _} = resolve_expression(right, environment)
    {{:op, line, operator, left, right}, environment, :unknown}
  end

  defp resolve_expression({:call, line, callee, args}, environment) do
    variable_callee? = match?({:var, _, _}, callee)
    {callee, environment, _} = resolve_expression(callee, environment)
    # Data atoms obtained from variables are not source-level local calls.
    callee = if variable_callee?, do: {:audit_fun_value, line, callee}, else: callee
    {args, environment, _} = resolve_sequence(args, environment)
    {{:call, line, callee, args}, environment, :unknown}
  end

  # Track tuple components independently without inventing values for unknown
  # components. Keep the executable elements (including closure bodies) intact.
  defp resolve_expression({:tuple, line, elements}, environment) do
    {elements, environment} =
      Enum.map_reduce(elements, environment, fn element, scope ->
        {element, scope, value} = resolve_expression(element, scope)
        {{element, value}, scope}
      end)

    {elements, values} = Enum.unzip(elements)
    expression = {:tuple, line, elements}
    value = {:tuple, line, values}

    value =
      if :erlang.external_size(expression) <= @max_finite_bytes and
           :erlang.external_size(value) <= @max_finite_bytes,
         do: value,
         else: :unknown

    {expression, environment, value}
  end

  defp resolve_expression(expression, environment) when is_tuple(expression) do
    # Remaining constructors have no special lexical scope. Literal values are
    # deliberately limited; computed return values stay unknown.
    {parts, environment, _} = resolve_sequence(Tuple.to_list(expression), environment)
    expression = List.to_tuple(parts)
    {expression, environment, literal_value(expression)}
  end

  defp resolve_expression(expressions, environment) when is_list(expressions),
    do: resolve_sequence(expressions, environment)

  defp resolve_expression(expression, environment), do: {expression, environment, :unknown}

  defp resolve_branches(clauses, environment) do
    branches = Enum.map(clauses, &resolve_clause(&1, environment, false))

    {Enum.map(branches, &elem(&1, 0)), join_environments(Enum.map(branches, &elem(&1, 1))),
     common_value(Enum.map(branches, &elem(&1, 2)))}
  end

  defp join_environments([]), do: %{}

  defp join_environments([first | rest]) do
    Map.new(first, fn {name, value} ->
      {name, common_value([value | Enum.map(rest, &Map.get(&1, name, :unknown))])}
    end)
    |> Map.reject(fn {_name, value} -> value == :unknown end)
  end

  # A union is a conservative domain, not a correlated set of branch bindings.
  # Unknown alternatives or exhausted bounds always discard the proof.
  defp common_value(values) do
    values = Enum.flat_map(values, &finite_choices/1)

    case bounded_choices(values) do
      {:ok, []} -> :unknown
      {:ok, [value]} -> value
      {:ok, values} -> {:audit_union, 0, values}
      :overflow -> :unknown
    end
  end

  defp finite_choices({:audit_union, _, values}), do: values
  defp finite_choices(value), do: [value]

  defp bounded_choices(values) do
    values = Enum.uniq_by(values, &canonical_value/1)

    if :unknown not in values and length(values) <= @max_finite_targets and
         :erlang.external_size(values) <= @max_finite_bytes,
       do: {:ok, values},
       else: :overflow
  end

  # Only proof constructors carry annotations; the function descriptor's
  # second element is data, and must not be erased during canonicalization.
  defp canonical_value({kind, _annotation, value})
       when kind in [:atom, :integer, :fun, :tuple, :audit_union],
       do: {kind, 0, canonical_value(value)}

  defp canonical_value({nil, _annotation}), do: {nil, 0}

  defp canonical_value({:cons, _annotation, head, tail}),
    do: {:cons, 0, canonical_value(head), canonical_value(tail)}

  defp canonical_value(value) when is_tuple(value),
    do: value |> Tuple.to_list() |> Enum.map(&canonical_value/1) |> List.to_tuple()

  defp canonical_value(value) when is_list(value), do: Enum.map(value, &canonical_value/1)
  defp canonical_value(value), do: value

  defp literal_value({:audit_union, _, _} = expression), do: expression
  defp literal_value({:fun, _, {:clauses, []}} = expression), do: expression

  defp literal_value({kind, _, value} = expression)
       when kind in [:atom, :integer] and (is_atom(value) or is_integer(value)),
       do: expression

  defp literal_value({nil, _} = expression), do: expression

  defp literal_value({:fun, _, {:function, name, arity}} = expression)
       when is_atom(name) and is_integer(arity),
       do: expression

  defp literal_value({:fun, _, {:function, module, function, arity}} = expression),
    do: bounded_literal(expression, [module, function, arity])

  defp literal_value({:tuple, _, elements} = expression),
    do: bounded_literal(expression, elements)

  defp literal_value({:cons, _, head, tail} = expression),
    do: bounded_literal(expression, [head, tail])

  defp literal_value(_expression), do: :unknown

  defp bounded_literal(expression, children) do
    if :erlang.external_size(expression) <= @max_finite_bytes and
         Enum.all?(children, &(literal_value(&1) != :unknown)),
       do: expression,
       else: :unknown
  end

  defp bind_pattern(pattern, {:audit_union, _, values}, environment) do
    values
    |> Enum.map(&bind_pattern(pattern, &1, environment))
    |> join_environments()
  end

  defp bind_pattern({:var, _, :_}, _value, environment), do: environment

  defp bind_pattern({:var, _, name}, :unknown, environment),
    do: environment |> Map.put_new(name, :unknown)

  defp bind_pattern({:var, _, name}, value, environment),
    do: Map.put_new(environment, name, value)

  defp bind_pattern({:tuple, _, patterns}, {:tuple, _, values}, environment)
       when length(patterns) == length(values),
       do:
         Enum.zip(patterns, values)
         |> Enum.reduce(environment, fn {p, v}, env -> bind_pattern(p, v, env) end)

  defp bind_pattern({:cons, _, head, tail}, {:cons, _, value, rest}, environment),
    do: bind_pattern(tail, rest, bind_pattern(head, value, environment))

  defp bind_pattern(pattern, _value, environment),
    do: Enum.reduce(pattern_variables(pattern), environment, &Map.put_new(&2, &1, :unknown))

  defp pattern_variables({:var, _, name}), do: [name]

  defp pattern_variables(term) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.flat_map(&pattern_variables/1)

  defp pattern_variables(term) when is_list(term), do: Enum.flat_map(term, &pattern_variables/1)
  defp pattern_variables(_term), do: []

  # Assess each bounded target, but scan the original nested syntax only once.
  # Expansion never substitutes closure bodies or evaluates the inspected code.
  defp walk_calls({:call, line, _callee, _args} = term, path) do
    findings =
      case call_candidates(term) do
        {:ok, calls} -> Enum.flat_map(calls, &call_findings(&1, path))
        :overflow -> [finding(path, line, "unresolved_finite_dispatch")]
      end

    Enum.uniq_by(findings, & &1.kind) ++ walk_children(term, path)
  end

  defp walk_calls({:fun, line, {:function, _, _, _}} = term, path) do
    findings =
      case expand_finite(term) do
        {:ok, captures} -> Enum.flat_map(captures, &capture_findings(&1, path))
        :overflow -> [finding(path, line, "unresolved_fun_dispatch")]
      end

    Enum.uniq_by(findings, & &1.kind) ++ walk_children(term, path)
  end

  defp walk_calls(term, path) when is_tuple(term), do: walk_children(term, path)
  defp walk_calls(term, path) when is_list(term), do: Enum.flat_map(term, &walk_calls(&1, path))
  defp walk_calls(_term, _path), do: []

  defp call_candidates({:call, line, callee, args}) do
    with {:ok, callees} <- expand_finite(callee) do
      Enum.reduce_while(callees, {:ok, []}, fn callee, {:ok, calls} ->
        arguments =
          case callee do
            {:remote, _, {:atom, _, :erlang}, {:atom, _, function}}
            when function == :apply or {function, length(args)} in @dispatches ->
              expand_finite(args)

            _ ->
              {:ok, [args]}
          end

        case arguments do
          {:ok, alternatives} ->
            candidates = Enum.map(alternatives, &{:call, line, callee, &1})

            if length(calls) + length(candidates) <= @max_finite_targets,
              do: {:cont, {:ok, calls ++ candidates}},
              else: {:halt, :overflow}

          :overflow ->
            {:halt, :overflow}
        end
      end)
    end
  end

  defp expand_finite({:audit_union, _, values}) do
    Enum.reduce_while(values, {:ok, []}, fn value, {:ok, expanded} ->
      case expand_finite(value) do
        {:ok, choices} -> bounded_continue(bounded_choices(expanded ++ choices))
        :overflow -> {:halt, :overflow}
      end
    end)
  end

  defp expand_finite({:fun, _, {:clauses, _}} = value), do: {:ok, [value]}
  defp expand_finite({:named_fun, _, _, _} = value), do: {:ok, [value]}
  defp expand_finite({:call, _, _, _} = value), do: {:ok, [value]}

  defp expand_finite(value) when is_tuple(value) do
    with {:ok, choices} <- expand_finite(Tuple.to_list(value)),
         do: {:ok, Enum.map(choices, &List.to_tuple/1)}
  end

  defp expand_finite(values) when is_list(values) do
    result =
      Enum.reduce_while(values, {:ok, [[]]}, fn value, {:ok, prefixes} ->
        case expand_finite(value) do
          {:ok, choices} ->
            product = for prefix <- prefixes, choice <- choices, do: [choice | prefix]
            bounded_continue(bounded_choices(product))

          :overflow ->
            {:halt, :overflow}
        end
      end)

    case result do
      {:ok, choices} -> {:ok, Enum.map(choices, &Enum.reverse/1)}
      :overflow -> :overflow
    end
  end

  defp expand_finite(value), do: {:ok, [value]}

  defp bounded_continue({:ok, choices}), do: {:cont, {:ok, choices}}
  defp bounded_continue(:overflow), do: {:halt, :overflow}

  # apply/2 invokes a function value rather than selecting a module. Only literal
  # syntax (including lexically resolved proofs) closes that target; its body or
  # captured MFA still passes through the same recursive unsafe-dispatch checks.
  defp call_findings(
         {:call, _line, {:remote, _, {:atom, _, :erlang}, {:atom, _, :apply}},
          [{:fun, _, _}, _arguments]},
         _path
       ),
       do: []

  # Literal module and function targets are closed except executable metadispatch.
  # Variable module/function/apply dispatch is retained
  # as unconfirmed evidence, even when traffic happened to avoid its OTP branch.
  # Protocol atoms, option keys and compatibility function names are not calls.
  defp call_findings(
         {:call, line, {:remote, _, {:atom, _, :erlang}, {:atom, _, :apply}},
          [{:atom, _, target}, function, args]},
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

    finding
  end

  defp call_findings(
         {:call, line, {:remote, _, {:atom, _, :erlang}, {:atom, _, :apply}}, _args},
         path
       ),
       do: [finding(path, line, "unresolved_apply")]

  defp call_findings({:call, line, {:atom, _, :apply}, _args}, path),
    do: [finding(path, line, "unresolved_apply")]

  defp call_findings(
         {:call, line, {:remote, _, {:atom, _, :erlang}, {:atom, _, function}}, args},
         path
       )
       when {function, length(args)} in @dispatches do
    dispatch_findings(function, args, path, line)
  end

  defp call_findings({:call, line, {:remote, _, target, function}, _args}, path) do
    finding =
      cond do
        match?({:atom, _, :ssl}, target) ->
          [finding(path, line, "literal_module_ssl")]

        not match?({:atom, _, _}, target) ->
          [finding(path, line, "unresolved_module_dispatch")]

        not match?({:atom, _, _}, function) ->
          [finding(path, line, "unresolved_function_dispatch")]

        true ->
          []
      end

    finding
  end

  defp call_findings({:call, _line, {:atom, _, _}, _args}, _path),
    do: []

  defp call_findings({:call, _line, {:fun, _, _}, _args}, _path),
    do: []

  defp call_findings({:call, _line, {:audit_fun_value, _, {:fun, _, _}}, _args}, _path),
    do: []

  defp call_findings({:call, _line, {:named_fun, _, _, _}, _args}, _path),
    do: []

  defp call_findings({:call, line, _callee, _args}, path),
    do: [finding(path, line, "unresolved_fun_invocation")]

  defp capture_findings({:fun, line, {:function, target, function, arity}}, path) do
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

    finding
  end

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
