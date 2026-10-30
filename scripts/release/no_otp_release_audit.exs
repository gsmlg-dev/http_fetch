defmodule NoOTP.ReleaseAudit do
  @moduledoc false
  @max_finite_targets 16
  @max_finite_bytes 65_536
  @max_parameter_functions 256
  @max_parameter_calls 4_096
  @max_parameter_nodes 100_000
  @callable_header_sizes %{
    clause: [5],
    atom: [3],
    integer: [3],
    float: [3],
    char: [3],
    string: [3],
    nil: [2],
    var: [3],
    cons: [4],
    tuple: [3],
    map: [3, 4],
    map_field_assoc: [4],
    map_field_exact: [4],
    bin: [3],
    bin_element: [5],
    match: [4],
    block: [3],
    case: [4],
    if: [3],
    receive: [3, 5],
    try: [6],
    catch: [3],
    op: [4, 5],
    remote: [4],
    named_fun: [4],
    lc: [4],
    bc: [4],
    mc: [4],
    generate: [4],
    b_generate: [4],
    m_generate: [4],
    generate_strict: [4],
    b_generate_strict: [4],
    m_generate_strict: [4],
    call: [4],
    fun: [3],
    record: [4, 5],
    record_field: [3, 4, 5],
    record_index: [4]
  }
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

  def artifacts(options \\ []) do
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
    context = Map.put(return_context(release), :audited_beams, MapSet.new(beams))
    invariants = Keyword.get(options, :parameter_invariants, %{})
    inspections = Enum.map(beams, &inspect_beam(&1, context, invariants))

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

    report = %{
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

    report = field_preflight(report, context, Keyword.fetch(options, :private_field_invariants))

    callable_preflight(
      report,
      beams,
      Map.put(
        context,
        :incoming_target_derivations,
        Keyword.fetch(options, :incoming_target_derivations)
      ),
      Keyword.fetch(options, :public_callable_roots),
      Keyword.fetch(options, :private_shape_invariants)
    )
  end

  # Auxiliary facts only. No partial map is substituted into executable forms.
  # Each fact records guaranteed key presence, a finite atom domain and its
  # origin independently; a matching map pattern is never an origin proof.
  defp field_preflight(report, _context, :error), do: report

  defp field_preflight(report, context, {:ok, requests}) do
    valid? =
      is_map(requests) and map_size(requests) <= 64 and
        :erlang.external_size(requests) <= @max_finite_bytes and
        Enum.all?(requests, fn {module, entries} ->
          is_atom(module) and is_list(entries) and entries != [] and
            length(entries) <= @max_parameter_functions and
            Enum.all?(entries, &field_request?/1) and
            length(Enum.uniq_by(entries, fn {key, index, field, _} -> {key, index, field} end)) ==
              length(entries)
        end)

    modules =
      if valid? do
        requests
        |> Enum.sort()
        |> Enum.map(fn {module, entries} ->
          inspection = Enum.find(report.beam_inspections, &(&1.module == inspect(module)))
          field_module(module, entries, inspection, context)
        end)
      else
        []
      end

    Map.put(report, :private_field_derivations, %{
      schema: 1,
      stage: "diagnostic_only",
      requests_valid: valid?,
      modules: modules
    })
  end

  defp field_request?({{name, arity}, index, field, atoms}) do
    is_atom(name) and is_integer(arity) and arity in 1..255 and
      is_integer(index) and index in 0..(arity - 1) and is_atom(field) and
      is_list(atoms) and atoms != [] and length(atoms) <= @max_finite_targets and
      Enum.all?(atoms, &is_atom/1) and length(Enum.uniq(atoms)) == length(atoms)
  end

  defp field_request?(_), do: false

  defp field_module(module, entries, inspection, context) do
    base = %{
      module: inspect(module),
      beam: if(inspection, do: inspection.beam, else: nil),
      sha256: if(inspection, do: inspection.sha256, else: nil),
      status: "unconfirmed",
      selected: false,
      inventory: nil,
      slots: [],
      callers: [],
      constructions: [],
      conditional_returns: []
    }

    with %{missing_abstract_code: false} <- inspection,
         {:ok, producer} <- selected_producer(module, context),
         true <- producer.path == inspection.beam,
         true <- Base.encode16(producer.sha256, case: :lower) == inspection.sha256,
         {:ok, {^module, chunks}} <-
           :beam_lib.chunks(String.to_charlist(inspection.beam), [:abstract_code]),
         {:raw_abstract_v1, forms} <- Keyword.fetch!(chunks, :abstract_code),
         {:ok, result} <- field_proof(forms, producer.exports, entries, inspection),
         true <- digest(inspection.beam) == inspection.sha256 do
      Map.merge(base, Map.put(result, :selected, true))
    else
      _ -> base
    end
  end

  defp field_proof(forms, exports, entries, inspection) do
    definitions = Map.new(for {:function, _, name, arity, _} = f <- forms, do: {{name, arity}, f})
    declared = for {:attribute, _, :export, items} <- forms, item <- items, do: item
    options = for {:attribute, _, :compile, items} <- forms, item <- List.wrap(items), do: item
    exported = MapSet.new(exports ++ declared)

    inventory = %{
      definitions: definitions,
      edges: MapSet.new(),
      captures: MapSet.new(),
      complete: true,
      nodes: 0,
      calls: 0
    }

    inventory =
      Enum.reduce(definitions, inventory, fn {owner, {:function, _, _, _, clauses}}, acc ->
        caller_syntax(clauses, owner, acc)
      end)

    domains = Map.new(entries, fn {key, index, field, atoms} -> {{key, index, field}, atoms} end)

    eligible? =
      inventory.complete and :export_all not in options and
        map_size(definitions) == Enum.count(forms, &match?({:function, _, _, _, _}, &1)) and
        map_size(definitions) <= @max_parameter_functions and
        Enum.all?(domains, fn {{key, index, _field}, _atoms} ->
          not MapSet.member?(exported, key) and not MapSet.member?(inventory.captures, key) and
            field_formals?(Map.get(definitions, key), index)
        end)

    if eligible? do
      context = %{
        domains: domains,
        scalars: field_checked_scalars(inspection.parameter_invariant_derivation, definitions),
        summaries: %{},
        record: false
      }

      # Conditional summaries start with field identities, not trusted values
      # from callers. One non-recursive pass is enough for direct preservation;
      # unknown local/remote returns remain unknown, including with passthrough.
      {summaries, summary_state} = field_functions(forms, context, field_state())
      context = %{context | summaries: summaries, record: true}
      {_returns, state} = field_functions(forms, context, field_state())
      expected = field_incoming_inventory(forms, domains)
      actual = MapSet.new(state.callers, fn {slot, _origin, _fact, site} -> {slot, site.path} end)

      complete? =
        summary_state.complete and state.complete and expected.complete and
          actual == expected.sites and MapSet.size(actual) == length(state.callers)

      origins =
        Enum.reduce(state.callers, Map.new(domains, fn {slot, _} -> {slot, []} end), fn
          {slot, origin, _fact, _site}, acc -> Map.update!(acc, slot, &[origin | &1])
        end)

      checked? =
        complete? and
          Enum.all?(origins, fn {_slot, incoming} ->
            incoming != [] and Enum.all?(incoming, &(&1 != :unknown))
          end) and invariant_seeded?(origins, MapSet.new())

      {:ok,
       %{
         status: if(checked?, do: "checked", else: "unconfirmed"),
         inventory: %{
           complete: complete?,
           nodes: inventory.nodes,
           calls: inventory.calls,
           evaluated_nodes: summary_state.nodes + state.nodes
         },
         slots:
           Enum.map(entries, fn {key, index, field, atoms} ->
             Map.put(field_slot({key, index, field}), :targets, field_atoms(atoms))
           end),
         callers:
           Enum.reverse(state.callers)
           |> Enum.map(fn {slot, origin, fact, site} ->
             %{
               target: field_slot(slot),
               origin: field_origin_json(origin),
               fact: field_value_json(fact),
               site: site
             }
           end),
         constructions: Enum.reverse(state.constructions),
         conditional_returns:
           context.domains
           |> Enum.map(fn {{key, _, _}, _} -> key end)
           |> Enum.uniq()
           |> Enum.sort()
           |> Enum.map(fn {name, arity} = key ->
             %{
               function: to_string(name),
               arity: arity,
               value: field_value_json(Map.get(summaries, key, :unknown))
             }
           end)
       }}
    else
      :unknown
    end
  end

  # Independently match the transfer walk against every raw compiled local
  # occurrence. Unsupported scopes may lose facts but may never lose callers.
  defp field_incoming_inventory(forms, domains) do
    forms
    |> Enum.with_index()
    |> Enum.reduce(%{nodes: 0, complete: true, sites: MapSet.new()}, fn
      {{:function, _, _, _, clauses}, index}, acc ->
        field_incoming_sites(clauses, [index, 4], domains, acc)

      _, acc ->
        acc
    end)
  end

  defp field_incoming_sites(_term, _path, _domains, %{complete: false} = state), do: state

  defp field_incoming_sites(term, path, domains, state) do
    state = %{state | nodes: state.nodes + 1}

    if state.nodes > @max_parameter_nodes do
      %{state | complete: false}
    else
      state =
        case term do
          {:call, _, {:atom, _, name}, args} ->
            key = {name, length(args)}

            sites =
              Enum.reduce(domains, state.sites, fn
                {{^key, _, _} = slot, _}, acc -> MapSet.put(acc, {slot, path})
                _, acc -> acc
              end)

            %{state | sites: sites}

          _ ->
            state
        end

      Enum.reduce(callable_children(term), state, fn {child, index}, acc ->
        field_incoming_sites(child, path ++ [index], domains, acc)
      end)
    end
  end

  defp field_formals?({:function, _, _, _, clauses}, index) do
    clauses != [] and
      Enum.all?(clauses, fn {:clause, _, patterns, _, _} ->
        case Enum.at(patterns, index) do
          {:var, _, name} -> name != :_
          {:match, _, {:var, _, name}, {:map, _, _}} -> name != :_
          {:match, _, {:map, _, _}, {:var, _, name}} -> name != :_
          _ -> false
        end
      end)
  end

  defp field_formals?(_, _), do: false

  defp field_checked_scalars(proof, definitions) do
    for slot <- proof.checked_slots,
        {key = {name, arity}, _} <- definitions,
        to_string(name) == slot.function and arity == slot.arity,
        into: %{} do
      # The existing scalar proof supplies serialized atoms; no request is
      # consulted and no new atom is created by this diagnostic pass.
      atoms = Enum.map(slot.targets, &String.to_existing_atom/1)

      {{key, slot.parameter_index},
       {:atoms, atoms, [{:checked_parameter, key, slot.parameter_index}]}}
    end
  end

  defp field_state, do: %{nodes: 0, complete: true, callers: [], constructions: []}

  defp field_functions(forms, context, state) do
    forms
    |> Enum.with_index()
    |> Enum.reduce({%{}, state}, fn
      {{:function, _, name, arity, clauses}, index}, {returns, state} ->
        owner = {name, arity}

        {values, state} =
          clauses
          |> Enum.with_index()
          |> Enum.map_reduce(state, fn {{:clause, _, patterns, guards, body}, ci}, acc ->
            environment =
              patterns
              |> Enum.with_index()
              |> Enum.reduce(%{}, fn {pattern, parameter}, env ->
                fields =
                  for {{^owner, ^parameter, field} = slot, atoms} <- context.domains,
                      into: %{},
                      do: {field, {:atoms, atoms, [{:field_identity, slot}]}}

                value =
                  if map_size(fields) > 0,
                    do: {:partial_map, fields},
                    else: Map.get(context.scalars, {owner, parameter}, :unknown)

                {_certainty, env} = field_bind(pattern, value, env)
                env
              end)

            path = [index, 4, ci]

            {_guard, _env, acc} =
              field_expression(guards, environment, owner, path ++ [3], context, acc)

            {value, _env, acc} =
              field_sequence(body, environment, owner, path ++ [4], context, acc)

            {value, acc}
          end)

        value = field_join(values)
        value = if :erlang.external_size(value) <= @max_finite_bytes, do: value, else: :unknown
        {Map.put(returns, owner, value), state}

      _, acc ->
        acc
    end)
  end

  defp field_sequence(expressions, environment, owner, path, context, state) do
    expressions
    |> Enum.with_index()
    |> Enum.reduce({:unknown, environment, state}, fn {expression, index}, {_value, env, acc} ->
      field_expression(expression, env, owner, path ++ [index], context, acc)
    end)
  end

  defp field_expression(_term, environment, _owner, _path, _context, %{complete: false} = state),
    do: {:unknown, environment, state}

  defp field_expression(term, environment, owner, path, context, state) do
    state = %{state | nodes: state.nodes + 1}

    if state.nodes > @max_parameter_nodes do
      {:unknown, environment, %{state | complete: false}}
    else
      {value, environment, state} = field_value(term, environment, owner, path, context, state)
      value = if :erlang.external_size(value) <= @max_finite_bytes, do: value, else: :unknown
      {value, environment, state}
    end
  end

  defp field_value({:var, _, name}, env, _owner, _path, _context, state),
    do: {Map.get(env, name, :unknown), env, state}

  defp field_value({:atom, _, atom}, env, owner, path, _context, state),
    do: {{:atoms, [atom], [{:literal, owner, path}]}, env, state}

  defp field_value({:tuple, _, terms}, env, owner, path, context, state) do
    {values, env, state} = field_arguments(terms, env, owner, path ++ [2], context, state)
    {{:tuple_value, values}, env, state}
  end

  defp field_value({:map, _, fields}, env, owner, path, context, state),
    do: field_map(fields, {:partial_map, %{}}, env, owner, path, 2, context, state)

  defp field_value({:map, _, base, fields}, env, owner, path, context, state) do
    {value, env, state} = field_expression(base, env, owner, path ++ [2], context, state)
    field_map(fields, value, env, owner, path, 3, context, state)
  end

  defp field_value({:match, _, pattern, expression}, env, owner, path, context, state) do
    {value, env, state} = field_expression(expression, env, owner, path ++ [3], context, state)
    {_certainty, env} = field_bind(pattern, value, env)
    {value, env, state}
  end

  defp field_value({:block, _, expressions}, env, owner, path, context, state),
    do: field_sequence(expressions, env, owner, path ++ [2], context, state)

  defp field_value({:case, _, expression, clauses}, env, owner, path, context, state) do
    {value, env, state} = field_expression(expression, env, owner, path ++ [2], context, state)
    field_cases(clauses, value, env, owner, path ++ [3], context, state)
  end

  defp field_value({:call, _, {:atom, _, name}, args} = term, env, owner, path, context, state) do
    {values, env, state} = field_arguments(args, env, owner, path ++ [3], context, state)
    key = {name, length(args)}
    site = field_site(term, owner, path)

    state =
      if context.record do
        Enum.reduce(context.domains, state, fn
          {{^key, index, field} = slot, atoms}, acc ->
            fact = field_get(Enum.at(values, index), field)
            origin = field_incoming(fact, owner, field, atoms, context.domains)
            %{acc | callers: [{slot, origin, fact, site} | acc.callers]}

          _, acc ->
            acc
        end)
      else
        state
      end

    value = field_call_value(key, values, context)
    {value, env, state}
  end

  defp field_value(
         {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :map_get}},
          [{:atom, _, key}, expression]},
         env,
         owner,
         path,
         context,
         state
       ) do
    {value, env, state} = field_expression(expression, env, owner, path ++ [3, 1], context, state)
    {field_get(value, key), env, state}
  end

  defp field_value({:fun, _, {:clauses, clauses}}, env, owner, path, context, state),
    do: field_callback(clauses, env, owner, path ++ [2, 1], context, state)

  defp field_value({:named_fun, _, name, clauses}, env, owner, path, context, state),
    do: field_callback(clauses, Map.delete(env, name), owner, path ++ [3], context, state)

  # Unsupported control flow still contributes every syntactic incoming call.
  # Its result and newly bound variables are unknown. In particular neither
  # actor replies nor reducer callback parameters inherit a caller's state.
  defp field_value(term, env, owner, path, context, state) do
    scope =
      if is_tuple(term) and tuple_size(term) > 0 and
           elem(term, 0) in [:lc, :bc, :mc, :try, :receive],
         do: %{},
         else: env

    state =
      Enum.reduce(callable_children(term), state, fn {child, index}, acc ->
        {_value, _scope, acc} =
          field_expression(child, scope, owner, path ++ [index], context, acc)

        acc
      end)

    {:unknown, env, state}
  end

  defp field_arguments(terms, env, owner, path, context, state) do
    {values, {env, state}} =
      terms
      |> Enum.with_index()
      |> Enum.map_reduce({env, state}, fn {term, index}, {scope, acc} ->
        {value, scope, acc} = field_expression(term, scope, owner, path ++ [index], context, acc)
        {value, {scope, acc}}
      end)

    {values, env, state}
  end

  defp field_map(fields, base, env, owner, path, offset, context, state) do
    initial =
      case base do
        {:partial_map, known} -> known
        _ -> %{}
      end

    {known, env, state} =
      fields
      |> Enum.with_index()
      |> Enum.reduce({initial, env, state}, fn
        {{kind, _, key, expression}, index}, {known, env, state}
        when kind in [:map_field_assoc, :map_field_exact] ->
          field_path = path ++ [offset, index]

          {_key, env, state} =
            field_expression(key, env, owner, field_path ++ [2], context, state)

          {value, env, state} =
            field_expression(expression, env, owner, field_path ++ [3], context, state)

          known =
            case {key, value} do
              {{:atom, _, atom}, {:atoms, _, _}} -> Map.put(known, atom, value)
              {{:atom, _, atom}, _} -> Map.delete(known, atom)
              _ -> %{}
            end

          {known, env, state}

        _, {_known, env, state} ->
          {%{}, env, %{state | complete: false}}
      end)

    value = {:partial_map, known}
    value = if :erlang.external_size(value) <= @max_finite_bytes, do: value, else: :unknown
    tracked = Enum.map(context.domains, fn {{_, _, field}, _} -> field end)

    observed? =
      Enum.any?(fields, fn
        {_, _, {:atom, _, key}, _} -> key in tracked
        _ -> false
      end)

    state =
      if context.record and observed? do
        site = %{owner: field_owner(owner), path: path, line: field_line(fields)}
        entry = %{site: site, value: field_value_json(value)}
        %{state | constructions: [entry | state.constructions]}
      else
        state
      end

    {value, env, state}
  end

  defp field_cases(clauses, value, env, owner, path, context, state) do
    {branches, state, _stopped} =
      clauses
      |> Enum.with_index()
      |> Enum.reduce({[], state, false}, fn
        {{:clause, _, [pattern], guards, body}, index}, {branches, state, stopped} ->
          {certainty, scope} = field_bind(pattern, value, env)
          # Even a nonmatching branch remains in the incoming inventory; its
          # calls are conservatively unknown rather than silently omitted.
          audit_scope = if stopped or certainty == :no_match, do: %{}, else: scope

          {_guard, _scope, state} =
            field_expression(guards, audit_scope, owner, path ++ [index, 3], context, state)

          {result, scope, state} =
            field_sequence(body, audit_scope, owner, path ++ [index, 4], context, state)

          branches =
            if stopped or certainty == :no_match, do: branches, else: [{result, scope} | branches]

          {branches, state, stopped or (certainty == :certain and guards == [])}

        {_clause, _index}, {branches, state, _} ->
          {[{:unknown, env} | branches], %{state | complete: false}, false}
      end)

    values = Enum.map(branches, &elem(&1, 0))
    scopes = Enum.map(branches, &elem(&1, 1))
    {field_join(values), field_join_scopes(scopes, env), state}
  end

  defp field_callback(clauses, env, owner, path, context, state) do
    state =
      clauses
      |> Enum.with_index()
      |> Enum.reduce(state, fn
        {{:clause, _, patterns, guards, body}, index}, acc ->
          scope = Map.drop(env, pattern_variables(patterns))

          {_guard, _env, acc} =
            field_expression(guards, scope, owner, path ++ [index, 3], context, acc)

          {_value, _env, acc} =
            field_sequence(body, scope, owner, path ++ [index, 4], context, acc)

          acc
      end)

    {:unknown, env, state}
  end

  defp field_bind({:var, _, :_}, _value, env), do: {:certain, env}

  defp field_bind({:var, _, name}, value, env) do
    case Map.fetch(env, name) do
      :error -> {:certain, Map.put(env, name, value)}
      _ -> {:possible, env}
    end
  end

  defp field_bind({:match, _, left, right}, value, env) do
    {a, env} = field_bind(left, value, env)
    {b, env} = field_bind(right, value, env)
    {field_certainty([a, b]), env}
  end

  defp field_bind({:tuple, _, patterns}, {:tuple_value, values}, env)
       when length(patterns) == length(values),
       do: field_bind_pairs(Enum.zip(patterns, values), env)

  defp field_bind({:tuple, _, _}, {:tuple_value, _}, env), do: {:no_match, env}

  defp field_bind({:atom, _, expected}, {:atoms, atoms, _}, env) do
    cond do
      expected not in atoms -> {:no_match, env}
      atoms == [expected] -> {:certain, env}
      true -> {:possible, env}
    end
  end

  defp field_bind({:map, _, fields}, {:partial_map, known}, env) do
    {certainty, env} =
      Enum.reduce(fields, {[], env}, fn
        {:map_field_exact, _, {:atom, _, key}, pattern}, {certainties, env} ->
          present? = Map.has_key?(known, key)
          {certainty, env} = field_bind(pattern, Map.get(known, key, :unknown), env)
          certainty = if present?, do: certainty, else: :possible
          {[certainty | certainties], env}

        field, {certainties, env} ->
          {[:possible | certainties],
           Map.merge(env, Map.new(pattern_variables(field), &{&1, :unknown}))}
      end)

    {field_certainty(certainty), env}
  end

  defp field_bind(pattern, _value, env),
    do: {:possible, Enum.reduce(pattern_variables(pattern), env, &Map.put_new(&2, &1, :unknown))}

  defp field_bind_pairs(pairs, env) do
    {certainties, env} =
      Enum.map_reduce(pairs, env, fn {pattern, value}, scope ->
        field_bind(pattern, value, scope)
      end)

    {field_certainty(certainties), env}
  end

  defp field_certainty(values) do
    cond do
      :no_match in values -> :no_match
      Enum.all?(values, &(&1 == :certain)) -> :certain
      true -> :possible
    end
  end

  defp field_join([]), do: :unknown
  defp field_join([value]), do: value

  defp field_join(values) do
    cond do
      Enum.all?(values, &match?({:atoms, _, _}, &1)) ->
        atoms = values |> Enum.flat_map(&elem(&1, 1)) |> Enum.uniq() |> Enum.sort()
        origins = values |> Enum.flat_map(&elem(&1, 2)) |> Enum.uniq() |> Enum.sort()

        if length(atoms) <= @max_finite_targets and length(origins) <= @max_finite_targets,
          do: {:atoms, atoms, origins},
          else: :unknown

      Enum.all?(values, &match?({:partial_map, _}, &1)) ->
        maps = Enum.map(values, &elem(&1, 1))

        fields =
          hd(maps)
          |> Map.keys()
          |> Enum.filter(fn key -> Enum.all?(maps, &Map.has_key?(&1, key)) end)

        known =
          Enum.reduce(fields, %{}, fn key, acc ->
            case field_join(Enum.map(maps, &Map.fetch!(&1, key))) do
              {:atoms, _, _} = fact -> Map.put(acc, key, fact)
              _ -> acc
            end
          end)

        {:partial_map, known}

      Enum.all?(values, &match?({:tuple_value, _}, &1)) and
          length(Enum.uniq(Enum.map(values, &length(elem(&1, 1))))) == 1 ->
        fields =
          values
          |> Enum.map(&elem(&1, 1))
          |> Enum.zip()
          |> Enum.map(&(Tuple.to_list(&1) |> field_join()))

        {:tuple_value, fields}

      true ->
        :unknown
    end
  end

  defp field_join_scopes([], fallback), do: fallback

  defp field_join_scopes([first | rest] = scopes, _fallback) do
    for key <- Map.keys(first),
        Enum.all?(rest, &Map.has_key?(&1, key)),
        into: %{},
        do: {key, field_join(Enum.map(scopes, &Map.fetch!(&1, key)))}
  end

  defp field_get({:partial_map, fields}, key), do: Map.get(fields, key, :unknown)
  defp field_get(_, _), do: :unknown

  defp field_incoming({:atoms, values, origins}, owner, field, allowed, domains) do
    inside? = Enum.any?(domains, fn {{key, _, _}, _} -> key == owner end)
    subset? = Enum.all?(values, &(&1 in allowed))

    case origins do
      [{:field_identity, {_, _, ^field} = source}] when subset? ->
        if Map.has_key?(domains, source), do: {:identity, source}, else: :unknown

      [_ | _] when subset? and not inside? ->
        if Enum.all?(origins, fn origin -> elem(origin, 0) in [:literal, :checked_parameter] end),
          do: {:seeds, values},
          else: :unknown

      _ ->
        :unknown
    end
  end

  defp field_incoming(_, _, _, _, _), do: :unknown

  defp field_call_value(key, args, context) do
    applicable? =
      Enum.all?(context.domains, fn
        {{^key, index, field}, allowed} ->
          case field_get(Enum.at(args, index), field) do
            {:atoms, values, _} -> Enum.all?(values, &(&1 in allowed))
            _ -> false
          end

        _ ->
          true
      end)

    if applicable?,
      do: field_substitute(Map.get(context.summaries, key, :unknown), key, args),
      else: :unknown
  end

  defp field_substitute({:atoms, _, [{:field_identity, {key, index, field}}]}, key, args),
    do: field_get(Enum.at(args, index), field)

  defp field_substitute({:atoms, _, origins} = value, _key, _args) do
    if Enum.any?(origins, &match?({:field_identity, _}, &1)), do: :unknown, else: value
  end

  defp field_substitute({:partial_map, fields}, key, args) do
    known =
      Enum.reduce(fields, %{}, fn {field, value}, acc ->
        case field_substitute(value, key, args) do
          {:atoms, _, _} = fact -> Map.put(acc, field, fact)
          _ -> acc
        end
      end)

    {:partial_map, known}
  end

  defp field_substitute({:tuple_value, values}, key, args),
    do: {:tuple_value, Enum.map(values, &field_substitute(&1, key, args))}

  defp field_substitute(_, _, _), do: :unknown

  defp field_atoms(atoms), do: atoms |> Enum.map(&to_string/1) |> Enum.sort()
  defp field_owner({name, arity}), do: %{function: to_string(name), arity: arity}

  defp field_slot({key, index, field}),
    do: Map.merge(field_owner(key), %{parameter_index: index, field: to_string(field)})

  defp field_site(term, owner, path),
    do: %{owner: field_owner(owner), path: path, line: field_annotation_line(elem(term, 1))}

  defp field_line([field | _]), do: field_annotation_line(elem(field, 1))
  defp field_line([]), do: 0

  defp field_annotation_line(annotation),
    do: if(callable_annotation?(annotation), do: :erl_anno.line(annotation), else: 0)

  defp field_origin_json(:unknown), do: %{kind: "unknown"}
  defp field_origin_json({:seeds, atoms}), do: %{kind: "seed", targets: field_atoms(atoms)}

  defp field_origin_json({:identity, slot}),
    do: %{kind: "field_identity", source: field_slot(slot)}

  defp field_origin_json({:field_identity, slot}),
    do: %{kind: "field_identity", source: field_slot(slot)}

  defp field_origin_json({:checked_parameter, key, index}),
    do: %{kind: "checked_parameter", source: Map.put(field_owner(key), :parameter_index, index)}

  defp field_origin_json({:literal, owner, path}),
    do: %{kind: "literal", owner: field_owner(owner), path: path}

  defp field_value_json(:unknown), do: %{kind: "unknown"}

  defp field_value_json({:atoms, atoms, origins}),
    do: %{
      kind: "atoms",
      targets: field_atoms(atoms),
      origins: Enum.map(origins, &field_origin_json/1)
    }

  defp field_value_json({:partial_map, fields}) do
    %{
      kind: "partial_map",
      fields:
        fields
        |> Enum.sort()
        |> Enum.map(fn {field, value} ->
          %{field: to_string(field), value: field_value_json(value)}
        end)
    }
  end

  defp field_value_json({:tuple_value, values}),
    do: %{kind: "tuple", elements: Enum.map(values, &field_value_json/1)}

  # This prerequisite inventories actual compiled incoming edges. It does not
  # certify argument origin or move any dispatch out of unresolved_dispatch.
  # In particular an empty direct-caller list is not an external-origin proof.
  defp callable_preflight(report, _beams, _context, :error, _shape_requests), do: report

  defp callable_preflight(report, beams, context, {:ok, requests}, shape_requests) do
    valid? =
      is_list(requests) and length(requests) <= 64 and
        Enum.all?(requests, fn
          {module, function, arity} ->
            is_atom(module) and is_atom(function) and is_integer(arity) and arity in 0..255

          _ ->
            false
        end) and length(Enum.uniq(requests)) == length(requests)

    {snapshots, state} =
      Enum.map_reduce(beams, %{nodes: 0, ordinal: 0, complete: true, sites: []}, fn beam, state ->
        {:ok, {module, chunks}} =
          :beam_lib.chunks(String.to_charlist(beam), [:imports, :exports, :abstract_code])

        hash = digest(beam)
        inspection = Enum.find(report.beam_inspections, &(&1.beam == beam))
        original? = inspection.sha256 == hash

        selected? =
          case selected_producer(module, context) do
            {:ok, producer} ->
              producer.path == beam and
                Base.encode16(producer.sha256, case: :lower) == hash

            _ ->
              false
          end

        exports = Keyword.fetch!(chunks, :exports)
        imports = Keyword.fetch!(chunks, :imports)

        {debug?, state} =
          case Keyword.fetch!(chunks, :abstract_code) do
            {:raw_abstract_v1, forms} ->
              definitions =
                for {:function, _, name, arity, _} <- forms, into: MapSet.new(), do: {name, arity}

              scope = %{beam: beam, module: module, imports: imports, definitions: definitions}

              state =
                forms
                |> Enum.with_index()
                |> Enum.reduce(state, fn
                  {{:function, _, name, arity, clauses}, index}, acc ->
                    callable_sites(clauses, [index, 4], {name, arity}, scope, acc)

                  _, acc ->
                    acc
                end)

              {true, state}

            _ ->
              {false, state}
          end

        snapshot = %{
          beam: beam,
          module: inspect(module),
          sha256: hash,
          selected: selected? and original?,
          debug: debug?,
          exports:
            Enum.map(exports, fn {name, arity} -> %{function: to_string(name), arity: arity} end)
        }

        {snapshot, %{state | complete: state.complete and original?}}
      end)

    snapshots_current? = Enum.all?(snapshots, &(digest(&1.beam) == &1.sha256))
    complete? = state.complete and snapshots_current?
    selected? = Enum.all?(snapshots, &(&1.selected and &1.debug))
    sites = Enum.reverse(state.sites)

    roots =
      if valid? do
        Enum.map(requests, fn {module, function, arity} = root ->
          target = %{module: inspect(module), function: to_string(function), arity: arity}
          snapshot = Enum.find(snapshots, &(&1.module == target.module))

          exported? =
            snapshot != nil and %{function: target.function, arity: arity} in snapshot.exports

          incoming =
            Enum.flat_map(sites, fn {site, scope, term} ->
              case callable_edge(term, scope, root) do
                nil -> []
                kind -> [Map.put(site, :kind, kind)]
              end
            end)

          %{
            root: target,
            exported: exported?,
            status:
              if(complete? and selected? and exported? and incoming == [],
                do: "no_syntactic_incoming_edges",
                else: "unconfirmed"
              ),
            incoming: incoming
          }
        end)
      else
        []
      end

    analysis = %{
      schema: 1,
      stage: "incoming_only",
      requests_valid: valid?,
      scan_complete: complete?,
      scanned_nodes: state.nodes,
      scanned_sites: state.ordinal,
      snapshots: snapshots,
      roots: roots,
      external_callable_records: []
    }

    analysis =
      case shape_requests do
        {:ok, requests} ->
          Map.put(
            analysis,
            :private_shape_derivations,
            private_shape_derivations(analysis, sites, requests)
          )

        :error ->
          analysis
      end

    analysis = incoming_target_derivations(analysis, sites, context)
    Map.put(report, :callable_provenance_preflight, analysis)
  end

  # Optional incoming-target evidence. Raw incoming records and ordinary findings
  # are never rewritten. A finite immediate target is not an external origin or
  # a proof about the target's body; every original body remains audited.
  @incoming_annotation_sizes Map.merge(@callable_header_sizes, %{
                               audit_return: [3, 4],
                               audit_selector: [4],
                               audit_fun_value: [3],
                               audit_union: [3]
                             })

  defp incoming_target_derivations(analysis, sites, context) do
    case Map.get(context, :incoming_target_derivations, :error) do
      :error ->
        analysis

      {:ok, false} ->
        analysis

      request ->
        valid? = request == {:ok, true} and analysis.requests_valid

        available? =
          valid? and analysis.scan_complete and
            Enum.all?(analysis.snapshots, &(&1.selected and &1.debug))

        requested =
          for root <- analysis.roots,
              site <- root.incoming,
              into: MapSet.new(),
              do: {site.beam, site.ordinal}

        selected_sites =
          Enum.filter(sites, fn {site, _, _} ->
            MapSet.member?(requested, {site.beam, site.ordinal})
          end)

        evidence =
          if available? do
            sites
            |> Enum.group_by(fn {site, _, _} -> site.beam end)
            |> Enum.filter(fn {beam, _} ->
              Enum.any?(selected_sites, fn {s, _, _} -> s.beam == beam end)
            end)
            |> Enum.flat_map(fn {beam, module_sites} ->
              snapshot = Enum.find(analysis.snapshots, &(&1.beam == beam))
              incoming_module_targets(snapshot, module_sites, context)
            end)
            |> Map.new()
          else
            %{}
          end

        current? = available? and incoming_snapshots_current?(analysis.snapshots, context)

        roots =
          Enum.map(analysis.roots, fn root ->
            records =
              Enum.map(root.incoming, fn site ->
                proof =
                  if current? and root.exported,
                    do: Map.get(evidence, {site.beam, site.ordinal}),
                    else: nil

                incoming_target_record(site, root.root, proof)
              end)

            %{root: root.root, records: records}
          end)

        Map.put(analysis, :target_derivations, %{
          schema: 1,
          requests_valid: valid?,
          inventory_complete: analysis.scan_complete,
          snapshots_current: current?,
          scope: "immediate_target_only",
          roots: roots
        })
    end
  end

  defp incoming_snapshots_current?(snapshots, context) do
    Enum.all?(snapshots, fn snapshot ->
      with true <- snapshot.selected and snapshot.debug,
           {:ok, {module, _}} <- :beam_lib.chunks(String.to_charlist(snapshot.beam), [:exports]),
           {:ok, selected} <- selected_producer(module, context) do
        selected.path == snapshot.beam and
          Base.encode16(selected.sha256, case: :lower) == snapshot.sha256
      else
        _ -> false
      end
    end)
  rescue
    _ -> false
  catch
    _, _ -> false
  end

  defp incoming_module_targets(snapshot, sites, context) do
    with {:ok, {module, chunks}} <-
           :beam_lib.chunks(String.to_charlist(snapshot.beam), [
             :imports,
             :exports,
             :abstract_code
           ]),
         {:raw_abstract_v1, forms} <- Keyword.fetch!(chunks, :abstract_code),
         true <- digest(snapshot.beam) == snapshot.sha256,
         {:ok, selected} <- selected_producer(module, context),
         true <-
           selected.path == snapshot.beam and
             Base.encode16(selected.sha256, case: :lower) == snapshot.sha256,
         {:ok, maximum} <- incoming_raw_syntax(forms),
         true <- length(sites) <= @max_parameter_calls do
      markers =
        Map.new(sites, fn {site, scope, term} ->
          {maximum + site.ordinal + 1, %{site: site, scope: scope, original: term}}
        end)

      paths =
        Map.new(markers, fn {marker, entry} -> {entry.site.path, {marker, entry.original}} end)

      true = map_size(paths) == length(sites)
      marked = incoming_mark(forms, [], paths)
      exports = Keyword.fetch!(chunks, :exports)
      imports = Keyword.fetch!(chunks, :imports)
      ordinary = incoming_resolve(forms, exports, imports, context)
      resolved = incoming_resolve(marked, exports, imports, context)

      # Annotations carry identity only in this private pass. Require exact
      # equality with the independently unmarked pipeline before using a result.
      true = incoming_restore(resolved, markers) == ordinary
      matches = incoming_matches(resolved, markers)
      true = digest(snapshot.beam) == snapshot.sha256
      {:ok, ^selected} = selected_producer(module, context)

      Enum.map(markers, fn {marker, entry} ->
        key = {entry.site.beam, entry.site.ordinal}

        proof =
          case Map.get(matches, marker, []) do
            [{owner, term}] when owner == entry.site.owner ->
              case incoming_finite_targets(term, entry.scope) do
                {:ok, targets} ->
                  %{
                    targets: targets,
                    source_sha256: snapshot.sha256,
                    original_node_sha256: incoming_term_digest(entry.original),
                    resolved_node_sha256: incoming_term_digest(incoming_restore(term, markers)),
                    method: "existing_finite_pipeline",
                    exact_occurrence: true,
                    annotation_equivalence: true,
                    parameter_invariants: false
                  }

                :unknown ->
                  incoming_anonymous_evidence(term, entry, markers, snapshot)
              end

            _ ->
              nil
          end

        {key, proof}
      end)
    else
      _ -> []
    end
  rescue
    _ -> []
  catch
    _, _ -> []
  end

  defp incoming_term_digest(term),
    do: :crypto.hash(:sha256, :erlang.term_to_binary(term)) |> Base.encode16(case: :lower)

  defp incoming_raw_syntax(forms) do
    functions = for {:function, _, _, _, _} = form <- forms, do: form
    keys = for {:function, _, name, arity, _} <- functions, do: {name, arity}

    true =
      length(functions) <= @max_parameter_functions and length(Enum.uniq(keys)) == length(keys)

    state =
      Enum.reduce(functions, %{nodes: 0, calls: 0, maximum: 0}, fn
        {:function, annotation, name, arity, clauses}, state
        when is_atom(name) and is_integer(arity) and arity in 0..255 and is_list(clauses) ->
          true = callable_annotation?(annotation)

          true =
            clauses != [] and
              Enum.all?(clauses, fn
                {:clause, _, patterns, guards, body}
                when is_list(patterns) and is_list(guards) and is_list(body) ->
                  length(patterns) == arity

                _ ->
                  false
              end)

          state = %{state | maximum: max(state.maximum, :erl_anno.line(annotation))}
          incoming_syntax(clauses, state)
      end)

    {:ok, state.maximum}
  end

  defp incoming_syntax(term, state) do
    state = %{state | nodes: state.nodes + 1}
    true = state.nodes <= @max_parameter_nodes
    incoming_syntax_node(term, state)
  end

  defp incoming_syntax_node({:function, name, arity}, state)
       when is_atom(name) and is_integer(arity) and arity in 0..255,
       do: state

  defp incoming_syntax_node({:function, module, function, arity}, state),
    do: incoming_syntax([module, function, arity], state)

  defp incoming_syntax_node({:clauses, clauses}, state) when is_list(clauses),
    do: incoming_syntax(clauses, state)

  defp incoming_syntax_node({:bin_element, annotation, value, size, types}, state) do
    true = callable_annotation?(annotation)

    true =
      types == :default or
        (is_list(types) and
           Enum.all?(types, fn
             value when is_atom(value) -> true
             {:unit, unit} when is_integer(unit) and unit in 1..256 -> true
             _ -> false
           end))

    state = %{state | maximum: max(state.maximum, :erl_anno.line(annotation))}
    incoming_syntax([value, size], state)
  end

  defp incoming_syntax_node(term, state) when is_tuple(term) do
    true =
      tuple_size(term) >= 2 and
        tuple_size(term) in Map.get(@callable_header_sizes, elem(term, 0), []) and
        callable_annotation?(elem(term, 1))

    calls = state.calls + if(elem(term, 0) in [:call, :fun], do: 1, else: 0)
    true = calls <= @max_parameter_calls
    state = %{state | calls: calls, maximum: max(state.maximum, :erl_anno.line(elem(term, 1)))}

    Enum.reduce(callable_children(term), state, fn {child, _}, acc ->
      incoming_syntax(child, acc)
    end)
  end

  defp incoming_syntax_node(terms, state) when is_list(terms),
    do: Enum.reduce(terms, state, &incoming_syntax/2)

  defp incoming_syntax_node(_term, state), do: state

  defp incoming_mark(terms, path, paths) when is_list(terms) do
    terms
    |> Enum.with_index()
    |> Enum.map(fn {child, index} -> incoming_mark(child, path ++ [index], paths) end)
  end

  defp incoming_mark(term, path, paths) do
    marked =
      Enum.reduce(callable_children(term), term, fn {child, index}, acc ->
        incoming_replace_child(acc, index, incoming_mark(child, path ++ [index], paths))
      end)

    case Map.fetch(paths, path) do
      {:ok, {marker, ^term}} -> put_elem(marked, 1, marker)
      :error -> marked
    end
  end

  defp incoming_replace_child(term, index, value) when is_tuple(term),
    do: put_elem(term, index, value)

  defp incoming_restore(term, markers) when is_tuple(term) do
    term = term |> Tuple.to_list() |> Enum.map(&incoming_restore(&1, markers)) |> List.to_tuple()

    if tuple_size(term) >= 2 and
         tuple_size(term) in Map.get(@incoming_annotation_sizes, elem(term, 0), []) do
      case Map.fetch(markers, elem(term, 1)) do
        {:ok, entry} -> put_elem(term, 1, elem(entry.original, 1))
        :error -> term
      end
    else
      term
    end
  end

  defp incoming_restore(terms, markers) when is_list(terms),
    do: Enum.map(terms, &incoming_restore(&1, markers))

  defp incoming_restore(term, _markers), do: term

  defp incoming_resolve(forms, exports, imports, context) do
    prepared =
      forms
      |> prove_remote_tuple_cases(context)
      |> prove_local_tuple_cases(context)
      |> prove_internal_pair_calls(context)
      |> prove_return_calls(context)
      |> qualify_named_dispatches(imports)
      |> prove_selector_returns()
      |> incoming_selector_assignments()

    {resolved, _proof} = resolve_lexical(prepared, exports, [])
    resolved
  end

  # Diagnostic only: an all-input finite atom summary may seed a direct
  # variable assignment. The ordinary selector consumer intentionally does not
  # support this shape. Preserve its complete original call and arguments.
  defp incoming_selector_assignments(forms) do
    definitions =
      Map.new(for {:function, _, name, arity, _} = form <- forms, do: {{name, arity}, form})

    analysis = %{
      definitions: definitions,
      edges: MapSet.new(),
      captures: MapSet.new(),
      complete: true,
      nodes: 0,
      calls: 0
    }

    summaries =
      if map_size(definitions) <= @max_parameter_functions do
        analysis =
          Enum.reduce(definitions, analysis, fn {owner, {:function, _, _, _, clauses}}, state ->
            caller_syntax(clauses, owner, state)
          end)

        if analysis.complete do
          edges =
            Enum.reduce(definitions, analysis.edges, fn {owner, form}, edges ->
              selector_capture_edges(form, owner, definitions, edges)
            end)

          if MapSet.size(edges) <= @max_parameter_calls,
            do: selector_returns(definitions, edges, %{}),
            else: %{}
        else
          %{}
        end
      else
        %{}
      end

    incoming_selector_assignment_nodes(forms, summaries)
  end

  defp incoming_selector_assignment_nodes(
         {:match, annotation, {:var, _, variable} = pattern,
          {:call, line, {:atom, _, name}, arguments} = call},
         summaries
       )
       when variable != :_ and is_list(arguments) do
    expression =
      case Map.fetch(summaries, {name, length(arguments)}) do
        {:ok, value} -> {:audit_selector, line, call, value}
        :error -> call
      end

    {:match, annotation, pattern, expression}
  end

  defp incoming_selector_assignment_nodes(term, summaries) when is_tuple(term),
    do:
      term
      |> Tuple.to_list()
      |> Enum.map(&incoming_selector_assignment_nodes(&1, summaries))
      |> List.to_tuple()

  defp incoming_selector_assignment_nodes(terms, summaries) when is_list(terms),
    do: Enum.map(terms, &incoming_selector_assignment_nodes(&1, summaries))

  defp incoming_selector_assignment_nodes(term, _summaries), do: term

  defp incoming_matches(forms, markers) do
    {_nodes, matches} =
      Enum.reduce(forms, {0, %{}}, fn
        {:function, _, name, arity, clauses}, state ->
          incoming_match_nodes(
            clauses,
            %{function: to_string(name), arity: arity},
            markers,
            state
          )

        _, state ->
          state
      end)

    matches
  end

  defp incoming_match_nodes(term, owner, markers, {nodes, matches}) do
    nodes = nodes + 1
    true = nodes <= @max_parameter_nodes

    matches =
      if (match?({:call, _, _, _}, term) or match?({:fun, _, {:function, _, _}}, term) or
            match?({:fun, _, {:function, _, _, _}}, term)) and
           Map.has_key?(markers, elem(term, 1)) do
        Map.update(matches, elem(term, 1), [{owner, term}], &[{owner, term} | &1])
      else
        matches
      end

    Enum.reduce(callable_children(term), {nodes, matches}, fn {child, _}, state ->
      incoming_match_nodes(child, owner, markers, state)
    end)
  end

  defp incoming_finite_targets({:call, _, _, _} = call, scope) do
    with {:ok, candidates} <- call_candidates(call),
         true <- candidates != [] do
      incoming_target_choices(Enum.map(candidates, &incoming_call_target(&1, scope)))
    else
      _ -> :unknown
    end
  end

  defp incoming_finite_targets({:fun, _, _} = capture, scope) do
    with {:ok, candidates} <- expand_finite(capture), true <- candidates != [] do
      incoming_target_choices(Enum.map(candidates, &incoming_fun_target(&1, scope)))
    else
      _ -> :unknown
    end
  end

  defp incoming_finite_targets(_, _), do: :unknown

  defp incoming_target_choices(choices) do
    if choices != [] and :unknown not in choices and length(choices) <= @max_finite_targets,
      do: {:ok, Enum.uniq(choices)},
      else: :unknown
  end

  defp incoming_call_target({:call, _, {:remote, _, {:atom, _, m}, {:atom, _, f}}, args}, _scope)
       when is_atom(m) and is_atom(f) and is_list(args),
       do: {m, f, length(args)}

  defp incoming_call_target({:call, _, {:atom, _, f}, args}, scope)
       when is_atom(f) and is_list(args) do
    key = {f, length(args)}

    cond do
      MapSet.member?(scope.definitions, key) -> {scope.module, f, length(args)}
      true -> Enum.find(scope.imports, :unknown, fn {_m, name, arity} -> {name, arity} == key end)
    end
  end

  defp incoming_call_target({:call, _, {:audit_fun_value, _, value}, _args}, scope),
    do: incoming_fun_target(value, scope)

  defp incoming_call_target({:call, _, {:fun, _, _} = value, _args}, scope),
    do: incoming_fun_target(value, scope)

  defp incoming_call_target(_, _), do: :unknown

  defp incoming_fun_target({:fun, _, {:function, name, arity}}, scope)
       when is_atom(name) and is_integer(arity) and arity in 0..255 do
    if MapSet.member?(scope.definitions, {name, arity}),
      do: {scope.module, name, arity},
      else: :unknown
  end

  defp incoming_fun_target(
         {:fun, _, {:function, {:atom, _, m}, {:atom, _, f}, {:integer, _, a}}},
         _scope
       )
       when is_atom(m) and is_atom(f) and is_integer(a) and a in 0..255,
       do: {m, f, a}

  defp incoming_fun_target(_, _), do: :unknown

  # Only the immediate callee is classified. The lexical pipeline retains every
  # original closure body, and anonymous identity is never a named MFA or a
  # statement about the callback's effects. Mixed or incomplete domains fail closed.
  defp incoming_anonymous_evidence(term, entry, markers, snapshot) do
    with {:call, _, _, arguments} when is_list(arguments) <- term,
         true <- length(arguments) <= 255,
         {:ok, candidates} <- call_candidates(term),
         true <- candidates != [] and length(candidates) <= @max_finite_targets,
         true <- Enum.all?(candidates, &incoming_anonymous_call?/1) do
      %{
        targets: [],
        anonymous_invocation: %{
          kind: "anonymous_closure",
          invocation_arity: length(arguments),
          alternative_count: length(candidates)
        },
        source_sha256: snapshot.sha256,
        original_node_sha256: incoming_term_digest(entry.original),
        resolved_node_sha256: incoming_term_digest(incoming_restore(term, markers)),
        method: "existing_finite_pipeline",
        exact_occurrence: true,
        annotation_equivalence: true,
        parameter_invariants: false
      }
    else
      _ -> nil
    end
  end

  defp incoming_anonymous_call?({:call, _, {:audit_fun_value, _, value}, _arguments}),
    do: incoming_anonymous_value?(value)

  defp incoming_anonymous_call?({:call, _, callee, _arguments}),
    do: incoming_anonymous_value?(callee)

  defp incoming_anonymous_call?(_term), do: false

  # Resolved lexical identities deliberately use empty clauses; call-site arity
  # is evidence about the invocation only, not the closure's accepted arity.
  defp incoming_anonymous_value?({:fun, _, {:clauses, clauses}}) when is_list(clauses), do: true

  defp incoming_anonymous_value?({:named_fun, _, name, clauses})
       when is_atom(name) and is_list(clauses),
       do: true

  defp incoming_anonymous_value?(_term), do: false

  defp incoming_target_record(site, _root, %{anonymous_invocation: _} = proof),
    do: %{
      site: site,
      status: "checked_anonymous_incompatible",
      targets: [],
      derivation: Map.delete(proof, :targets)
    }

  defp incoming_target_record(site, root, %{targets: targets} = proof) do
    meta? =
      Enum.any?(targets, fn {m, f, a} ->
        m == :erlang and (f == :apply or {f, a} in @dispatches)
      end)

    if meta? do
      incoming_target_record(site, root, nil)
    else
      targets =
        Enum.map(targets, fn {m, f, a} ->
          %{module: inspect(m), function: to_string(f), arity: a}
        end)

      status = if root in targets, do: "checked_finite_target", else: "checked_incompatible"
      %{site: site, status: status, targets: targets, derivation: Map.delete(proof, :targets)}
    end
  end

  defp incoming_target_record(site, _root, nil),
    do: %{site: site, status: "unknown", targets: [], derivation: nil}

  # Conditional outer-shape facts about private parameters, never callable
  # classifications. All callers are checked on raw forms; ordinary resolution
  # and every original finding remain untouched. Unknown payload fields are not
  # interpreted. These facts alone prove neither message nor state provenance.
  defp private_shape_derivations(preflight, sites, requests) do
    valid? =
      is_list(requests) and length(requests) <= 64 and
        :erlang.external_size(requests) <= @max_finite_bytes and
        Enum.all?(requests, &shape_request?/1) and
        length(Enum.uniq_by(requests, &elem(&1, 0))) == length(requests)

    records =
      if valid? do
        Enum.map(requests, fn {module, entries, observations} ->
          snapshot = Enum.find(preflight.snapshots, &(&1.module == inspect(module)))
          shape_module(preflight, sites, snapshot, module, entries, observations)
        end)
      else
        []
      end

    %{schema: 1, requests_valid: valid?, modules: records}
  end

  defp shape_request?({module, entries, observations}) do
    is_atom(module) and is_list(entries) and entries != [] and
      length(entries) <= @max_parameter_functions and
      Enum.all?(entries, fn
        {{name, arity}, index, shapes} ->
          is_atom(name) and is_integer(arity) and arity in 1..255 and
            is_integer(index) and index in 0..(arity - 1) and is_list(shapes) and
            shapes != [] and length(shapes) <= @max_finite_targets and
            Enum.all?(shapes, &outer_shape?/1) and length(Enum.uniq(shapes)) == length(shapes)

        _ ->
          false
      end) and is_list(observations) and observations != [] and length(observations) <= 64 and
      Enum.all?(observations, fn
        {{owner, arity}, index, {callee, count}, argument, path} ->
          is_atom(owner) and is_integer(arity) and arity in 1..255 and
            is_integer(index) and index in 0..(arity - 1) and is_atom(callee) and
            is_integer(count) and count in 1..255 and is_integer(argument) and
            argument in 0..(count - 1) and
            (path == :discover or
               (is_list(path) and path != [] and length(path) <= @max_parameter_nodes and
                  Enum.all?(path, &(is_integer(&1) and &1 >= 0))))

        _ ->
          false
      end) and length(Enum.uniq(observations)) == length(observations)
  end

  defp shape_request?(_), do: false
  defp outer_shape?({:atom, value}), do: is_atom(value)

  defp outer_shape?({:tuple, tag, arity}),
    do: is_atom(tag) and is_integer(arity) and arity in 1..255

  defp outer_shape?(_), do: false

  defp shape_module(preflight, sites, snapshot, module, entries, observations) do
    base = %{
      module: inspect(module),
      beam: if(snapshot, do: snapshot.beam, else: nil),
      sha256: if(snapshot, do: snapshot.sha256, else: nil),
      status: "unconfirmed",
      inventory: nil,
      slots: [],
      callers: [],
      observations: []
    }

    with true <- preflight.scan_complete,
         true <- Enum.all?(preflight.snapshots, &(&1.selected and &1.debug)),
         %{selected: true, debug: true} <- snapshot,
         {:ok, {^module, chunks}} <-
           :beam_lib.chunks(String.to_charlist(snapshot.beam), [:exports, :abstract_code]),
         {:raw_abstract_v1, forms} <- Keyword.get(chunks, :abstract_code),
         {:ok, proof} <-
           shape_proof(
             forms,
             Keyword.fetch!(chunks, :exports),
             entries,
             observations,
             Enum.filter(sites, fn {site, _, _} -> site.beam == snapshot.beam end)
           ),
         true <- digest(snapshot.beam) == snapshot.sha256 do
      Map.merge(base, Map.put(proof, :status, "checked"))
    else
      _ -> base
    end
  end

  defp shape_proof(forms, beam_exports, entries, observations, sites) do
    definitions = Map.new(for {:function, _, name, arity, _} = f <- forms, do: {{name, arity}, f})
    exports = for {:attribute, _, :export, values} <- forms, value <- values, do: value

    options =
      for {:attribute, _, :compile, values} <- forms, value <- List.wrap(values), do: value

    exported = MapSet.new(beam_exports ++ exports)

    initial = %{
      definitions: definitions,
      edges: MapSet.new(),
      captures: MapSet.new(),
      complete: true,
      nodes: 0,
      calls: 0
    }

    analysis =
      Enum.reduce(definitions, initial, fn {owner, {:function, _, _, _, clauses}}, acc ->
        caller_syntax(clauses, owner, acc)
      end)

    domains = Map.new(entries, fn {key, index, shapes} -> {{key, index}, shapes} end)

    eligible? =
      analysis.complete and :export_all not in options and
        map_size(definitions) <= @max_parameter_functions and map_size(domains) == length(entries) and
        Enum.all?(domains, fn {{key, index}, _} ->
          not MapSet.member?(exported, key) and not MapSet.member?(analysis.captures, key) and
            invariant_formals?(Map.get(definitions, key), index)
        end) and
        Enum.all?(observations, fn {owner, index, callee, _, _} ->
          Map.has_key?(domains, {owner, index}) and Map.has_key?(definitions, callee)
        end)

    if eligible? do
      context = %{
        domains: domains,
        observations: observations,
        sites: Map.new(sites, fn {site, _, _} -> {site.path, site} end)
      }

      result =
        forms
        |> Enum.with_index()
        |> Enum.reduce(%{callers: [], observations: []}, fn
          {{:function, _, name, arity, clauses}, index}, acc ->
            owner = {name, arity}

            clauses
            |> Enum.with_index()
            |> Enum.reduce(acc, fn {{:clause, _, patterns, _, _} = clause, clause_index}, state ->
              scope =
                for {{^owner, slot}, _} <- domains, into: %{} do
                  {:var, _, variable} = Enum.at(patterns, slot)
                  {variable, {owner, slot}}
                end

              shape_walk(clause, [index, 4, clause_index], owner, scope, context, state)
            end)

          _, acc ->
            acc
        end)

      origins =
        Enum.reduce(result.callers, Map.new(domains, fn {slot, _} -> {slot, []} end), fn {slot,
                                                                                          origin,
                                                                                          _site},
                                                                                         acc ->
          Map.update!(acc, slot, &[origin | &1])
        end)

      all_origins? =
        Enum.all?(origins, fn {slot, values} ->
          values != [] and
            Enum.all?(values, fn
              {:seed, shape} ->
                shape in Map.fetch!(domains, slot)

              {:identity, source} ->
                Map.has_key?(domains, source) and
                  Enum.all?(Map.fetch!(domains, source), &(&1 in Map.fetch!(domains, slot)))

              _ ->
                false
            end)
        end)

      observed =
        Enum.map(observations, fn request ->
          matches = Enum.filter(result.observations, fn {actual, _, _} -> actual == request end)
          {request, matches}
        end)

      observations_valid? =
        Enum.all?(observed, fn
          {{owner, index, _, _, expected}, [{_, {:identity, source}, site}]} ->
            source == {owner, index} and (expected == :discover or expected == site.path)

          _ ->
            false
        end)

      if all_origins? and invariant_seeded?(origins, MapSet.new()) and observations_valid? do
        {:ok,
         %{
           inventory: %{complete: true, nodes: analysis.nodes, calls: analysis.calls},
           slots:
             Enum.map(entries, fn {key, index, shapes} ->
               Map.put(shape_slot({key, index}), :shapes, Enum.map(shapes, &shape_json/1))
             end),
           callers:
             Enum.reverse(result.callers)
             |> Enum.map(fn {slot, origin, site} ->
               %{target: shape_slot(slot), origin: shape_origin_json(origin), site: site}
             end),
           observations:
             Enum.map(observed, fn
               {{owner, index, {callee, count}, argument, expected}, [{_, _, site}]} ->
                 %{
                   source: shape_slot({owner, index}),
                   callee: %{function: to_string(callee), arity: count, argument_index: argument},
                   expected_path: if(expected == :discover, do: nil, else: expected),
                   site: site,
                   shapes: Enum.map(Map.fetch!(domains, {owner, index}), &shape_json/1)
                 }
             end)
         }}
      else
        :unknown
      end
    else
      :unknown
    end
  end

  defp shape_walk({:fun, _, {:clauses, clauses}}, path, owner, scope, context, result),
    do: shape_fun(clauses, path ++ [2, 1], owner, scope, context, result)

  defp shape_walk({:named_fun, _, name, clauses}, path, owner, scope, context, result),
    do: shape_fun(clauses, path ++ [3], owner, Map.delete(scope, name), context, result)

  defp shape_walk(term, path, owner, scope, context, result) do
    scope =
      if is_tuple(term) and tuple_size(term) > 0 and elem(term, 0) in [:lc, :bc, :mc],
        do: %{},
        else: scope

    result =
      case term do
        {:call, _, {:atom, _, name}, args} ->
          callee = {name, length(args)}
          site = Map.fetch!(context.sites, path)

          result =
            Enum.reduce(context.domains, result, fn
              {{^callee, index} = slot, _}, acc ->
                origin = shape_origin(Enum.at(args, index), owner, scope, context.domains)
                %{acc | callers: [{slot, origin, site} | acc.callers]}

              _, acc ->
                acc
            end)

          Enum.reduce(context.observations, result, fn
            {^owner, _source, ^callee, index, _path} = request, acc ->
              origin = shape_origin(Enum.at(args, index), owner, scope, context.domains)
              %{acc | observations: [{request, origin, site} | acc.observations]}

            _, acc ->
              acc
          end)

        _ ->
          result
      end

    Enum.reduce(callable_children(term), result, fn {child, index}, acc ->
      shape_walk(child, path ++ [index], owner, scope, context, acc)
    end)
  end

  defp shape_fun(clauses, path, owner, scope, context, result) do
    clauses
    |> Enum.with_index()
    |> Enum.reduce(result, fn
      {{:clause, _, patterns, _, _} = clause, index}, acc ->
        shape_walk(
          clause,
          path ++ [index],
          owner,
          Map.drop(scope, pattern_variables(patterns)),
          context,
          acc
        )
    end)
  end

  defp shape_origin({:var, _, variable}, _owner, scope, _domains) do
    case Map.fetch(scope, variable) do
      {:ok, slot} -> {:identity, slot}
      :error -> :unknown
    end
  end

  defp shape_origin(expression, owner, _scope, domains) do
    # Literal seeds must enter from outside the proposed recursive invariant.
    if Enum.any?(domains, fn {{key, _}, _} -> key == owner end) do
      :unknown
    else
      case expression do
        {:atom, _, value} ->
          {:seed, {:atom, value}}

        {:tuple, _, [{:atom, _, tag} | _] = fields} when length(fields) <= 255 ->
          {:seed, {:tuple, tag, length(fields)}}

        _ ->
          :unknown
      end
    end
  end

  defp shape_slot({{name, arity}, index}),
    do: %{function: to_string(name), arity: arity, parameter_index: index}

  defp shape_json({:atom, value}), do: %{kind: "atom", value: to_string(value)}
  defp shape_json({:tuple, tag, arity}), do: %{kind: "tuple", tag: to_string(tag), arity: arity}
  defp shape_origin_json({:seed, shape}), do: %{kind: "seed", shape: shape_json(shape)}
  defp shape_origin_json({:identity, slot}), do: %{kind: "parameter", source: shape_slot(slot)}

  defp callable_sites(_term, _path, _owner, _scope, %{complete: false} = state), do: state

  defp callable_sites(term, path, owner, scope, state) do
    state = %{state | nodes: state.nodes + 1}

    if state.nodes > 2_000_000 or state.ordinal >= 100_000 do
      %{state | complete: false}
    else
      state =
        if match?({:call, _, _, _}, term) or match?({:fun, _, {:function, _, _}}, term) or
             match?({:fun, _, {:function, _, _, _}}, term) do
          {name, arity} = owner

          site = %{
            beam: scope.beam,
            module: inspect(scope.module),
            owner: %{function: to_string(name), arity: arity},
            path: path,
            ordinal: state.ordinal,
            line: :erl_anno.line(elem(term, 1))
          }

          %{state | ordinal: state.ordinal + 1, sites: [{site, scope, term} | state.sites]}
        else
          state
        end

      term
      |> callable_children()
      |> Enum.reduce(state, fn {child, index}, acc ->
        callable_sites(child, path ++ [index], owner, scope, acc)
      end)
    end
  end

  # Skip only AST headers whose exact tag/arity and data-only annotation are
  # recognized. Retain raw tuple/list indices, including gaps, so every call
  # and capture keeps its original path and preorder ordinal. Unknown shapes
  # and malformed annotations take the complete raw traversal instead.
  defp callable_children(term) when is_tuple(term) do
    children = term |> Tuple.to_list() |> Enum.with_index()

    header? =
      tuple_size(term) >= 2 and
        tuple_size(term) in Map.get(@callable_header_sizes, elem(term, 0), []) and
        callable_annotation?(elem(term, 1))

    if header?, do: Enum.drop(children, 2), else: children
  end

  defp callable_children(term) when is_list(term), do: Enum.with_index(term)
  defp callable_children(_term), do: []

  defp callable_annotation?(line) when is_integer(line) and line >= 0, do: true

  defp callable_annotation?({line, column})
       when is_integer(line) and line >= 0 and is_integer(column) and column >= 1,
       do: true

  defp callable_annotation?(properties) when is_list(properties),
    do: callable_annotation_properties?(properties, 16, false)

  defp callable_annotation?(_unknown), do: false

  defp callable_annotation_properties?([], _remaining, location?), do: location?

  defp callable_annotation_properties?([{key, value} | rest], remaining, location?)
       when remaining > 0 do
    callable_annotation_property?(key, value) and
      callable_annotation_properties?(rest, remaining - 1, location? or key == :location)
  end

  defp callable_annotation_properties?(_unknown, _remaining, _location?), do: false

  defp callable_annotation_property?(key, value) when key in [:location, :end_location] do
    case value do
      line when is_integer(line) and line >= 0 ->
        true

      {line, column}
      when is_integer(line) and line >= 0 and is_integer(column) and column >= 1 ->
        true

      _ ->
        false
    end
  end

  defp callable_annotation_property?(key, true) when key in [:generated, :record], do: true

  defp callable_annotation_property?(:file, value) when is_binary(value),
    do: byte_size(value) <= 4_096

  defp callable_annotation_property?(key, value) when key in [:file, :text],
    do: callable_annotation_characters?(value, 4_096)

  defp callable_annotation_property?(_key, _value), do: false

  # erl_anno:is_anno/1 accepts arbitrary lists for file/text. Validate each
  # character ourselves so executable-shaped terms in those lists cannot be
  # hidden as metadata. Bounds limit validation work; excess falls back raw.
  defp callable_annotation_characters?([], _remaining), do: true

  defp callable_annotation_characters?([character | rest], remaining)
       when remaining > 0 and is_integer(character) and character in 0..0x10FFFF,
       do: callable_annotation_characters?(rest, remaining - 1)

  defp callable_annotation_characters?(_unknown, _remaining), do: false

  defp callable_edge({:call, _, {:atom, _, name}, args}, scope, root) do
    key = {name, length(args)}

    module =
      if MapSet.member?(scope.definitions, key) do
        scope.module
      else
        Enum.find_value(scope.imports, :erlang, fn
          {module, ^name, arity} when arity == length(args) -> module
          _ -> nil
        end)
      end

    callable_remote_edge({:atom, 0, module}, {:atom, 0, name}, args, scope, root)
  end

  defp callable_edge({:call, _, {:remote, _, module, function}, args}, scope, root),
    do: callable_remote_edge(module, function, args, scope, root)

  defp callable_edge({:call, _, callee, args}, scope, root),
    do: callable_fun_edge(callee, length(args), scope, root)

  defp callable_edge({:fun, _, {:function, name, arity}}, scope, root)
       when is_atom(name) and is_integer(arity),
       do: callable_named_edge(scope.module, name, arity, root, "capture")

  defp callable_edge({:fun, _, {:function, module, function, arity}}, _scope, root),
    do: callable_capture_edge(module, function, arity, root)

  defp callable_remote_edge({:atom, _, :erlang}, {:atom, _, :apply}, [fun, args], scope, root) do
    arity =
      case literal_arguments(args) do
        {:ok, values} -> length(values)
        :unknown -> :unknown
      end

    callable_fun_edge(fun, arity, scope, root)
  end

  defp callable_remote_edge(
         {:atom, _, :erlang},
         {:atom, _, :apply},
         [module, function, args],
         _scope,
         root
       ) do
    callable_mfa_edge(module, function, args, root, "apply")
  end

  defp callable_remote_edge(module, function, args, _scope, {target, name, arity}) do
    cond do
      callable_possible_atom?(module, :erlang) and callable_metadispatch?(function) ->
        "metadispatch_requires_proof"

      callable_possible_atom?(module, target) and callable_possible_atom?(function, name) and
          length(args) == arity ->
        if match?({:atom, _, _}, module) and match?({:atom, _, _}, function),
          do: "direct_arguments_require_proof",
          else: "dynamic_target_requires_proof"

      # An unknown function may select erlang:apply/spawn regardless of the
      # eventual target's arity. Never exclude that edge using outer arity alone.
      callable_possible_atom?(module, :erlang) and not match?({:atom, _, _}, function) ->
        "metadispatch_requires_proof"

      true ->
        nil
    end
  end

  defp callable_fun_edge({:fun, _, {:clauses, _}}, _arity, _scope, _root), do: nil
  defp callable_fun_edge({:named_fun, _, _, _}, _arity, _scope, _root), do: nil

  defp callable_fun_edge({:fun, _, {:function, name, arity}}, _invoked, scope, root)
       when is_atom(name) and is_integer(arity),
       do: callable_named_edge(scope.module, name, arity, root, "capture_invocation")

  defp callable_fun_edge({:fun, _, {:function, module, function, arity}}, _invoked, _scope, root),
    do: callable_capture_edge(module, function, arity, root)

  defp callable_fun_edge(_fun, arity, _scope, {_module, _function, target_arity}) do
    cond do
      arity == :unknown -> "unknown_callable_arity"
      arity in [1, 2, 3, 4, 5] -> "callable_or_metadispatch_requires_proof"
      arity == target_arity -> "callable_target_requires_proof"
      true -> nil
    end
  end

  defp callable_capture_edge(module, function, arity, {target, name, count}) do
    cond do
      callable_possible_atom?(module, :erlang) and callable_metadispatch?(function) ->
        "metadispatch_capture_requires_proof"

      callable_possible_atom?(module, target) and callable_possible_atom?(function, name) and
          (not match?({:integer, _, _}, arity) or elem(arity, 2) == count) ->
        "capture"

      true ->
        nil
    end
  end

  defp callable_named_edge(module, function, arity, {module, function, arity}, kind), do: kind
  defp callable_named_edge(_module, _function, _arity, _root, _kind), do: nil

  defp callable_mfa_edge(module, function, arguments, {target, name, arity}, kind) do
    count =
      case literal_arguments(arguments) do
        {:ok, args} -> length(args)
        :unknown -> :unknown
      end

    cond do
      callable_possible_atom?(module, :erlang) and callable_metadispatch?(function) ->
        "metadispatch_requires_proof"

      callable_possible_atom?(module, target) and callable_possible_atom?(function, name) and
          count in [:unknown, arity] ->
        kind

      true ->
        nil
    end
  end

  defp callable_possible_atom?({:atom, _, actual}, expected), do: actual == expected
  defp callable_possible_atom?(_unknown, _expected), do: true

  defp callable_metadispatch?({:atom, _, name}),
    do: name == :apply or Keyword.has_key?(@dispatches, name)

  defp callable_metadispatch?(_unknown), do: true

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

  defp inspect_beam(path, context, invariants) do
    {:ok, {module, chunks}} =
      :beam_lib.chunks(String.to_charlist(path), [:imports, :exports, :abstract_code])

    imports = Keyword.fetch!(chunks, :imports)
    exports = Keyword.fetch!(chunks, :exports)

    direct =
      for {:ssl, function, arity} <- imports,
          do: %{beam: path, module: inspect(module), function: to_string(function), arity: arity}

    {dynamic, missing, invariant_proof} =
      case Keyword.fetch!(chunks, :abstract_code) do
        {:raw_abstract_v1, forms} ->
          prepared =
            forms
            |> prove_remote_tuple_cases(context)
            |> prove_local_tuple_cases(context)
            |> prove_internal_pair_calls(context)
            |> prove_return_calls(context)
            |> qualify_named_dispatches(imports)
            |> prove_selector_returns()

          {resolved, proof} =
            resolve_lexical(prepared, exports, Map.get(invariants, module, []))

          {walk_calls(resolved, path), false, proof}

        :no_abstract_code ->
          {[], true,
           parameter_invariant_proof(Map.get(invariants, module, []), %{}, "missing_debug")}
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
      missing_abstract_code: missing,
      parameter_invariant_derivation: invariant_proof
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

  # Conditional return projection for a selected candidate's remote call.
  # Every normal return is overapproximated: unknown passthrough can still be a
  # matching four-tuple, while known other arities/tags cannot. Original calls,
  # helpers, guards and nested bodies remain in the ordinary artifact scan.
  defp prove_remote_tuple_cases(forms, context) do
    state = %{
      context: context,
      forwarders: tagged_remote_forwarders(forms),
      requests: MapSet.new(),
      selections: %{},
      summaries: %{},
      visiting: MapSet.new(),
      nodes: 0,
      calls: 0,
      complete: true
    }

    state = tagged_case_requests(forms, state)

    {projections, state} =
      Enum.map_reduce(state.requests, state, fn {module, function, arity, tag} = key, acc ->
        {value, acc} = tagged_return_call(module, function, arity, true, acc)
        {{key, tagged_projection(value, tag)}, acc}
      end)

    current? =
      Enum.all?(state.selections, fn {module, selected} ->
        selected_producer(module, context) == {:ok, selected}
      end)

    if state.complete and current?,
      do: remote_tuple_cases(forms, Map.new(projections), state.forwarders),
      else: forms
  end

  # A single complete local wrapper may forward to a selected remote producer.
  # Its return domain is all-input, so argument expressions cannot narrow it;
  # the original wrapper and all argument effects remain in the artifact scan.
  # Local mixed-return producers retain the separate uniform-tuple rule.
  defp tagged_remote_forwarders(forms) do
    definitions = for {:function, _, _, _, _} = form <- forms, do: form

    keys = Enum.map(definitions, fn {:function, _, name, arity, _} -> {name, arity} end)

    if length(definitions) <= @max_parameter_functions and
         length(Enum.uniq(keys)) == length(keys) do
      Map.new(
        for {:function, _, name, arity,
             [
               {:clause, _, _, [],
                [{:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, args}]}
             ]} = form <-
              definitions,
            is_atom(module) and is_atom(function) and is_list(args),
            tuple_projection_form?(form),
            do: {{name, arity}, {module, function, length(args)}}
      )
    else
      %{}
    end
  end

  defp tagged_case_call(
         {:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, args},
         _forwarders
       )
       when is_atom(module) and is_atom(function) and is_list(args),
       do: {module, function, length(args)}

  defp tagged_case_call({:call, _, {:atom, _, name}, args}, forwarders)
       when is_atom(name) and is_list(args),
       do: Map.get(forwarders, {name, length(args)}, :unknown)

  defp tagged_case_call(_source, _forwarders), do: :unknown

  defp tagged_case_requests(_term, %{complete: false} = state), do: state

  defp tagged_case_requests(term, state) do
    state = %{state | nodes: state.nodes + 1}

    if state.nodes > @max_parameter_nodes do
      %{state | complete: false}
    else
      requests =
        case term do
          {:case, _, source, clauses} when is_list(clauses) ->
            case tagged_case_call(source, state.forwarders) do
              {module, function, arity} ->
                Enum.reduce(clauses, state.requests, fn
                  {:clause, _, [{:tuple, _, [{:atom, _, tag}, {:var, _, name}, _, _]}], _, _}, acc
                  when is_atom(tag) and name != :_ ->
                    MapSet.put(acc, {module, function, arity, tag})

                  _, acc ->
                    acc
                end)

              :unknown ->
                state.requests
            end

          _ ->
            state.requests
        end

      state = %{state | requests: requests, complete: MapSet.size(requests) <= 64}
      Enum.reduce(tagged_children(term), state, &tagged_case_requests/2)
    end
  end

  # Reuse the raw inventory's exact header/annotation recognition. Only proven
  # data-only headers are skipped; malformed metadata keeps its raw traversal.
  defp tagged_children(term), do: Enum.map(callable_children(term), &elem(&1, 0))

  defp tagged_selection(module, state) do
    case Map.fetch(state.selections, module) do
      {:ok, selected} ->
        {:ok, selected, state}

      :error ->
        with true <- map_size(state.selections) < 32,
             {:ok, selected} <- selected_producer(module, state.context),
             true <- MapSet.member?(state.context.audited_beams, selected.path),
             true <- map_size(selected.definitions) <= @max_parameter_functions do
          {:ok, selected, %{state | selections: Map.put(state.selections, module, selected)}}
        else
          _ -> :unknown
        end
    end
  end

  defp tagged_return_call(_module, _function, _arity, _remote?, %{complete: false} = state),
    do: {:unknown, state}

  defp tagged_return_call(module, function, arity, remote?, state) do
    key = {module, function, arity}
    state = %{state | calls: state.calls + 1}

    cond do
      state.calls > @max_parameter_calls or MapSet.size(state.visiting) >= 32 ->
        {:unknown, %{state | complete: false}}

      MapSet.member?(state.visiting, key) ->
        {:unknown, state}

      true ->
        with {:ok, selected, state} <- tagged_selection(module, state),
             true <- not remote? or {function, arity} in selected.exports,
             form when not is_nil(form) <- Map.get(selected.definitions, {function, arity}),
             true <- tuple_projection_form?(form) do
          case Map.fetch(state.summaries, key) do
            {:ok, value} ->
              {value, state}

            :error ->
              if map_size(state.summaries) >= @max_parameter_functions do
                {:unknown, %{state | complete: false}}
              else
                {:function, _, _, _, clauses} = form
                state = %{state | visiting: MapSet.put(state.visiting, key)}

                {values, state} =
                  Enum.map_reduce(clauses, state, fn
                    {:clause, _, patterns, _guards, body}, acc ->
                      scope = Enum.reduce(patterns, %{}, &tagged_unknown_pattern/2)
                      {value, _scope, acc} = tagged_sequence(body, scope, module, acc)
                      {value, acc}
                  end)

                value = tagged_join(values)

                state = %{
                  state
                  | visiting: MapSet.delete(state.visiting, key),
                    summaries: Map.put(state.summaries, key, value)
                }

                {value, state}
              end
          end
        else
          _ -> {:unknown, state}
        end
    end
  end

  defp tagged_sequence(expressions, environment, module, state) do
    Enum.reduce(expressions, {:unknown, environment, state}, fn expression,
                                                                {_value, scope, acc} ->
      tagged_expression(expression, scope, module, acc)
    end)
  end

  defp tagged_expression(_expression, environment, _module, %{complete: false} = state),
    do: {:unknown, environment, state}

  defp tagged_expression(expression, environment, module, state) do
    state = %{state | nodes: state.nodes + 1}

    if state.nodes > @max_parameter_nodes,
      do: {:unknown, environment, %{state | complete: false}},
      else: tagged_value(expression, environment, module, state)
  end

  defp tagged_value({:var, _, name}, environment, _module, state) when is_atom(name),
    do: {Map.get(environment, name, :unknown), environment, state}

  defp tagged_value({:atom, _, value} = expression, environment, _module, state)
       when is_atom(value),
       do: {expression, environment, state}

  defp tagged_value({:integer, _, value} = expression, environment, _module, state)
       when is_integer(value),
       do: {expression, environment, state}

  defp tagged_value({nil, _} = value, environment, _module, state),
    do: {value, environment, state}

  defp tagged_value({:tuple, annotation, expressions}, environment, module, state)
       when is_list(expressions) do
    {values, {environment, state}} =
      Enum.map_reduce(expressions, {environment, state}, fn expression, {scope, acc} ->
        {value, scope, acc} = tagged_expression(expression, scope, module, acc)
        {value, {scope, acc}}
      end)

    value = {:tuple, annotation, values}
    value = if :erlang.external_size(value) <= @max_finite_bytes, do: value, else: :unknown
    {value, environment, state}
  end

  defp tagged_value({:match, _, pattern, expression}, environment, module, state) do
    {value, environment, state} = tagged_expression(expression, environment, module, state)

    scope =
      case tagged_bind(pattern, value, environment) do
        {:ok, scope} -> scope
        :no_match -> environment
      end

    {value, scope, state}
  end

  defp tagged_value({:block, _, body}, environment, module, state) when is_list(body),
    do: tagged_sequence(body, environment, module, state)

  defp tagged_value({:case, _, source, clauses}, environment, module, state)
       when is_list(clauses) do
    {value, environment, state} = tagged_expression(source, environment, module, state)

    {values, state} =
      Enum.map_reduce(clauses, state, fn
        {:clause, _, [pattern], _guards, body}, acc when is_list(body) ->
          {results, acc} =
            Enum.map_reduce(finite_choices(value), acc, fn alternative, acc ->
              case tagged_bind(pattern, alternative, environment) do
                {:ok, scope} ->
                  {result, _scope, acc} = tagged_sequence(body, scope, module, acc)
                  {[result], acc}

                :no_match ->
                  {[], acc}
              end
            end)

          {List.flatten(results), acc}

        _, acc ->
          {[:unknown], acc}
      end)

    {tagged_join(List.flatten(values)), environment, state}
  end

  defp tagged_value({:call, _, {:atom, _, function}, args}, environment, module, state)
       when is_atom(function) and is_list(args) do
    {value, state} = tagged_return_call(module, function, length(args), false, state)
    {value, environment, state}
  end

  defp tagged_value(
         {:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, args},
         environment,
         _owner,
         state
       )
       when is_atom(module) and is_atom(function) and is_list(args) do
    {value, state} = tagged_return_call(module, function, length(args), true, state)
    {value, environment, state}
  end

  defp tagged_value(_expression, environment, _module, state),
    do: {:unknown, environment, state}

  defp tagged_unknown_pattern(pattern, environment),
    do: Enum.reduce(pattern_variables(pattern), environment, &Map.put_new(&2, &1, :unknown))

  defp tagged_bind({:var, _, :_}, _value, environment), do: {:ok, environment}

  defp tagged_bind({:var, _, name}, value, environment),
    do: {:ok, Map.put_new(environment, name, value)}

  defp tagged_bind({:match, _, first, second}, value, environment) do
    with {:ok, environment} <- tagged_bind(first, value, environment),
         do: tagged_bind(second, value, environment)
  end

  defp tagged_bind({:tuple, _, patterns}, {:tuple, _, values}, environment)
       when is_list(patterns) and is_list(values) and length(patterns) == length(values) do
    Enum.zip(patterns, values)
    |> Enum.reduce_while({:ok, environment}, fn {pattern, value}, {:ok, scope} ->
      case tagged_bind(pattern, value, scope) do
        {:ok, scope} -> {:cont, {:ok, scope}}
        :no_match -> {:halt, :no_match}
      end
    end)
  end

  defp tagged_bind({:atom, _, expected}, {:atom, _, actual}, environment),
    do: if(expected == actual, do: {:ok, environment}, else: :no_match)

  defp tagged_bind({:integer, _, expected}, {:integer, _, actual}, environment),
    do: if(expected == actual, do: {:ok, environment}, else: :no_match)

  defp tagged_bind(pattern, value, environment) do
    expected = tagged_kind(pattern)
    actual = tagged_kind(value)

    if expected != :unknown and actual != :unknown and expected != actual,
      do: :no_match,
      else: {:ok, tagged_unknown_pattern(pattern, environment)}
  end

  defp tagged_kind({:tuple, _, fields}) when is_list(fields), do: {:tuple, length(fields)}
  defp tagged_kind({:map, _, _}), do: :map
  defp tagged_kind({:atom, _, _}), do: :atom
  defp tagged_kind({:integer, _, _}), do: :integer
  defp tagged_kind({nil, _}), do: :list
  defp tagged_kind(_), do: :unknown

  # Coalesce equal tuple tags/arities componentwise. Unrelated payload fields
  # may become unknown; a single unknown matching module field cannot vanish.
  defp tagged_join(values) do
    values = Enum.flat_map(values, &finite_choices/1)

    if :unknown in values or values == [] do
      :unknown
    else
      values
      |> Enum.group_by(fn
        {:tuple, _, [{:atom, _, tag} | fields]} -> {:tagged, tag, length(fields)}
        value -> {:value, canonical_value(value)}
      end)
      |> Enum.map(fn
        {{:tagged, _, _}, [{:tuple, annotation, fields} | _] = group} ->
          fields =
            fields
            |> Enum.with_index()
            |> Enum.map(fn {_field, index} ->
              group |> Enum.map(&(elem(&1, 2) |> Enum.at(index))) |> common_value()
            end)

          {:tuple, annotation, fields}

        {_key, [value | _]} ->
          value
      end)
      |> common_value()
    end
  end

  defp tagged_projection(value, tag) do
    values =
      Enum.map(finite_choices(value), fn
        {:tuple, _, [{:atom, _, ^tag}, target, _, _]} ->
          if Enum.all?(finite_choices(target), &match?({:atom, _, atom} when is_atom(atom), &1)),
            do: [target],
            else: [:unknown]

        {:tuple, _, [{:atom, _, _}, _, _, _]} ->
          []

        {:tuple, _, fields} when length(fields) != 4 ->
          []

        {kind, _, _} when kind in [:atom, :integer] ->
          []

        {nil, _} ->
          []

        _ ->
          [:unknown]
      end)

    values |> List.flatten() |> common_value()
  end

  defp remote_tuple_cases({:case, annotation, source, clauses}, projections, forwarders)
       when is_list(clauses) do
    clauses = remote_tuple_cases(clauses, projections, forwarders)

    clauses =
      case tagged_case_call(source, forwarders) do
        {module, function, arity} ->
          if callable_annotation?(annotation) and tuple_projection_headers?(source) do
            Enum.map(clauses, fn
              {:clause, _, [{:tuple, _, [{:atom, _, tag}, {:var, _, _}, _, _]}], _, _} = clause ->
                case Map.get(projections, {module, function, arity, tag}, :unknown) do
                  :unknown -> clause
                  targets -> local_tuple_case_clause(clause, tag, targets)
                end

              clause ->
                clause
            end)
          else
            clauses
          end

        :unknown ->
          clauses
      end

    {:case, annotation, remote_tuple_cases(source, projections, forwarders), clauses}
  end

  defp remote_tuple_cases(term, projections, forwarders) when is_tuple(term),
    do:
      term
      |> Tuple.to_list()
      |> Enum.map(&remote_tuple_cases(&1, projections, forwarders))
      |> List.to_tuple()

  defp remote_tuple_cases(terms, projections, forwarders) when is_list(terms),
    do: Enum.map(terms, &remote_tuple_cases(&1, projections, forwarders))

  defp remote_tuple_cases(term, _projections, _forwarders), do: term

  # Prove only an immediate local case over uniform tagged four-tuples. Every
  # producer clause must construct the same tag and a finite atom in slot two;
  # the remaining fields are opaque. This all-input return fact needs no caller
  # assumption, and never follows aliases, state, messages or callback inputs.
  defp prove_local_tuple_cases(forms, context) do
    definitions =
      Map.new(for {:function, _, name, arity, _} = form <- forms, do: {{name, arity}, form})

    initial = %{
      definitions: definitions,
      edges: MapSet.new(),
      captures: MapSet.new(),
      complete: true,
      nodes: 0,
      calls: 0
    }

    summaries =
      if map_size(definitions) <= @max_parameter_functions do
        syntax =
          Enum.reduce(definitions, initial, fn {owner, {:function, _, _, _, clauses}}, acc ->
            caller_syntax(clauses, owner, acc)
          end)

        if syntax.complete do
          Map.new(definitions, fn {key, form} ->
            {key, local_tuple_projection(form, context)}
          end)
        else
          %{}
        end
      else
        %{}
      end

    local_tuple_cases(forms, summaries)
  end

  defp local_tuple_projection({:function, _, _, _, clauses} = form, context) do
    if tuple_projection_form?(form) do
      projections =
        Enum.map(clauses, fn {:clause, _, _, _, body} = clause ->
          case List.last(body) do
            {:tuple, _, [{:atom, _, tag}, target, _, _]} ->
              {resolved, _, _} = resolve_clause(clause, %{}, false)
              value = tuple_projection_atom(target, context)

              if is_atom(tag) and value != :unknown and
                   walk_calls(resolved, "tuple-projection") == [],
                 do: {tag, value},
                 else: :unknown

            _ ->
              :unknown
          end
        end)

      case Enum.uniq(
             Enum.map(projections, fn
               {tag, _} -> tag
               :unknown -> :unknown
             end)
           ) do
        [tag] when tag != :unknown ->
          targets = common_value(Enum.map(projections, &elem(&1, 1)))
          if targets == :unknown, do: :unknown, else: {tag, targets}

        _ ->
          :unknown
      end
    else
      :unknown
    end
  end

  defp tuple_projection_atom({:atom, _, target} = value, _context) when is_atom(target),
    do: value

  defp tuple_projection_atom(
         {:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, arguments},
         context
       )
       when is_list(arguments) do
    arity = length(arguments)

    with {:ok, selected} <- selected_producer(module, context),
         true <- MapSet.member?(context.audited_beams, selected.path),
         true <- {function, arity} in selected.exports,
         true <- map_size(selected.definitions) <= @max_parameter_functions,
         {:function, _, ^function, ^arity, clauses} = form <-
           Map.get(selected.definitions, {function, arity}),
         true <- tuple_projection_form?(form) do
      values =
        Enum.map(clauses, fn {:clause, _, _, _, body} = clause ->
          {resolved, _, _} = resolve_clause(clause, %{}, false)

          case List.last(body) do
            {:atom, _, target} = value when is_atom(target) ->
              if walk_calls(resolved, "tuple-atom-leaf") == [], do: value, else: :unknown

            _ ->
              :unknown
          end
        end)

      value = common_value(values)
      if selected_producer(module, context) == {:ok, selected}, do: value, else: :unknown
    else
      _ -> :unknown
    end
  end

  defp tuple_projection_atom(_expression, _context), do: :unknown

  defp tuple_projection_form?({:function, annotation, name, arity, clauses} = form) do
    callable_annotation?(annotation) and is_atom(name) and is_integer(arity) and
      arity >= 0 and arity <= 255 and is_list(clauses) and clauses != [] and
      length(clauses) <= @max_finite_targets and
      :erlang.external_size(form) <= @max_finite_bytes and
      Enum.all?(clauses, fn
        {:clause, _, patterns, guards, body} = clause ->
          is_list(patterns) and length(patterns) == arity and is_list(guards) and
            is_list(body) and body != [] and tuple_projection_headers?(clause)

        _ ->
          false
      end)
  end

  # Metadata cannot hide executable syntax in this added proof. Fun descriptors
  # and binary type descriptors are data only in these exact recognized shapes.
  defp tuple_projection_headers?({:fun, annotation, {:clauses, clauses}}),
    do: callable_annotation?(annotation) and tuple_projection_headers?(clauses)

  defp tuple_projection_headers?({:fun, annotation, {:function, name, arity}}),
    do: callable_annotation?(annotation) and is_atom(name) and is_integer(arity) and arity >= 0

  defp tuple_projection_headers?({:fun, annotation, {:function, module, name, arity}}),
    do:
      callable_annotation?(annotation) and
        tuple_projection_headers?([module, name, arity])

  defp tuple_projection_headers?({:bin_element, annotation, value, size, types}),
    do:
      callable_annotation?(annotation) and tuple_projection_headers?([value, size]) and
        (types == :default or
           (is_list(types) and
              Enum.all?(types, fn
                type when is_atom(type) -> true
                {:unit, unit} when is_integer(unit) and unit >= 1 and unit <= 256 -> true
                _ -> false
              end)))

  defp tuple_projection_headers?(term) when is_tuple(term) do
    tuple_size(term) >= 2 and
      tuple_size(term) in Map.get(@callable_header_sizes, elem(term, 0), []) and
      callable_annotation?(elem(term, 1)) and
      term |> Tuple.to_list() |> Enum.drop(2) |> Enum.all?(&tuple_projection_headers?/1)
  end

  defp tuple_projection_headers?(terms) when is_list(terms),
    do: Enum.all?(terms, &tuple_projection_headers?/1)

  defp tuple_projection_headers?(term)
       when is_atom(term) or is_integer(term) or is_float(term) or is_binary(term),
       do: true

  defp tuple_projection_headers?(_term), do: false

  defp local_tuple_cases(
         {:case, annotation, {:call, _, {:atom, _, name}, arguments} = source, clauses},
         summaries
       )
       when is_list(arguments) and is_list(clauses) do
    clauses = local_tuple_cases(clauses, summaries)

    clauses =
      case {callable_annotation?(annotation) and tuple_projection_headers?(source),
            Map.get(summaries, {name, length(arguments)}, :unknown)} do
        {true, {tag, targets}} ->
          Enum.map(clauses, &local_tuple_case_clause(&1, tag, targets))

        _ ->
          clauses
      end

    {:case, annotation, local_tuple_cases(source, summaries), clauses}
  end

  defp local_tuple_cases(term, summaries) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.map(&local_tuple_cases(&1, summaries)) |> List.to_tuple()

  defp local_tuple_cases(terms, summaries) when is_list(terms),
    do: Enum.map(terms, &local_tuple_cases(&1, summaries))

  defp local_tuple_cases(term, _summaries), do: term

  defp local_tuple_case_clause(
         {:clause, _, [{:tuple, _, [{:atom, _, tag}, {:var, _, name}, _, _]}] = patterns, _, _} =
           clause,
         tag,
         targets
       ) do
    if name != :_ and Enum.count(pattern_variables(patterns), &(&1 == name)) == 1 and
         :erlang.external_size(clause) <= @max_finite_bytes and
         tuple_projection_headers?(clause) do
      elem(resolve_clause(clause, %{name => targets}, false), 0)
    else
      clause
    end
  end

  defp local_tuple_case_clause(clause, _tag, _targets), do: clause

  # A selected candidate producer can return a literal closure paired with
  # arbitrary state. Unlike auxiliary collector implementations, its complete
  # original body and local helpers remain in this same artifact audit. Prove
  # every normal-return clause; exports/defaults never establish a domain.
  # This deliberately covers only direct two-component destructuring of a
  # static remote arity-two producer, not general return/state propagation.
  defp prove_internal_pair_calls(
         {:match, line, {:tuple, _, [_, _]} = pattern,
          {:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, [_, _]} = call},
         context
       ) do
    call = internal_pair_children(call, context)

    expression =
      case internal_pair_return(module, function, context) do
        {:ok, value} -> {:audit_return, elem(call, 1), call, value}
        :unknown -> call
      end

    {:match, line, prove_internal_pair_calls(pattern, context), expression}
  end

  defp prove_internal_pair_calls(term, context), do: internal_pair_children(term, context)

  defp internal_pair_children(term, context) when is_tuple(term),
    do:
      term
      |> Tuple.to_list()
      |> Enum.map(&prove_internal_pair_calls(&1, context))
      |> List.to_tuple()

  defp internal_pair_children(terms, context) when is_list(terms),
    do: Enum.map(terms, &prove_internal_pair_calls(&1, context))

  defp internal_pair_children(term, _context), do: term

  defp internal_pair_return(module, function, context) do
    with {:ok, selected} <- selected_producer(module, context),
         true <- MapSet.member?(context.audited_beams, selected.path),
         true <- {function, 2} in selected.exports,
         true <- map_size(selected.definitions) <= @max_parameter_functions,
         {:function, _, ^function, 2, clauses} = form <-
           Map.get(selected.definitions, {function, 2}),
         true <- clauses != [] and length(clauses) <= @max_finite_targets,
         true <- :erlang.external_size(form) <= @max_finite_bytes do
      initial = %{
        definitions: selected.definitions,
        edges: MapSet.new(),
        captures: MapSet.new(),
        complete: true,
        nodes: 0,
        calls: 0
      }

      syntax = caller_syntax(clauses, {function, 2}, initial)

      proven? =
        syntax.complete and
          Enum.all?(clauses, fn clause ->
            {resolved, _scope, value} = resolve_clause(clause, %{}, false)

            # The second component is deliberately not propagated. Nested
            # unsafe/unknown calls in the wrapper itself prevent this rule;
            # local helper bodies still retain their original module scan.
            match?({:tuple, _, [{:fun, _, {:clauses, []}}, _]}, value) and
              walk_calls(resolved, "internal-pair-proof") == []
          end)

      if proven? and selected_producer(module, context) == {:ok, selected} do
        {:ok, {:tuple, 0, [{:fun, 0, {:clauses, []}}, :unknown]}}
      else
        :unknown
      end
    else
      _ -> :unknown
    end
  end

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

  # These same-module summaries hold for every input, not only known callers.
  # Join every clause/branch; a possibly returning unknown alternative prevents
  # a proof. Only atom results are admitted, never returned callbacks or state.
  defp prove_selector_returns(forms) do
    definitions =
      Map.new(for {:function, _, name, arity, _} = form <- forms, do: {{name, arity}, form})

    analysis = %{
      definitions: definitions,
      edges: MapSet.new(),
      captures: MapSet.new(),
      complete: true,
      nodes: 0,
      calls: 0
    }

    summaries =
      if map_size(definitions) <= @max_parameter_functions do
        analysis =
          Enum.reduce(definitions, analysis, fn {owner, {:function, _, _, _, clauses}}, state ->
            caller_syntax(clauses, owner, state)
          end)

        if analysis.complete do
          edges =
            Enum.reduce(definitions, analysis.edges, fn {owner, form}, edges ->
              selector_capture_edges(form, owner, definitions, edges)
            end)

          if MapSet.size(edges) <= @max_parameter_calls,
            do: selector_returns(definitions, edges, %{}),
            else: %{}
        else
          %{}
        end
      else
        %{}
      end

    selector_targets(forms, summaries)
  end

  # Captures also form possible local dependencies. Conservatively include a
  # same-named remote capture instead of assuming it cannot call a local body.
  defp selector_capture_edges({:fun, _, {:function, name, arity}}, owner, definitions, edges)
       when is_atom(name) and is_integer(arity) do
    if Map.has_key?(definitions, {name, arity}),
      do: MapSet.put(edges, {owner, {name, arity}}),
      else: edges
  end

  defp selector_capture_edges(
         {:fun, _, {:function, _module, {:atom, _, name}, {:integer, _, arity}}},
         owner,
         definitions,
         edges
       ),
       do: selector_capture_edges({:fun, 0, {:function, name, arity}}, owner, definitions, edges)

  defp selector_capture_edges(term, owner, definitions, edges) when is_tuple(term),
    do: term |> Tuple.to_list() |> selector_capture_edges(owner, definitions, edges)

  defp selector_capture_edges(terms, owner, definitions, edges) when is_list(terms),
    do: Enum.reduce(terms, edges, &selector_capture_edges(&1, owner, definitions, &2))

  defp selector_capture_edges(_term, _owner, _definitions, edges), do: edges

  # Each pass removes vertices. Any local-call cycle and its dependents stay
  # unknown; an iteration/depth cutoff can never stand in for an invariant.
  defp selector_returns(remaining, edges, summaries) do
    ready =
      Enum.reject(remaining, fn {key, _form} ->
        Enum.any?(edges, fn {caller, callee} ->
          caller == key and Map.has_key?(remaining, callee)
        end)
      end)

    if ready == [] do
      summaries
    else
      summaries =
        Enum.reduce(ready, summaries, fn {key, form}, known ->
          case selector_value(form, summaries) do
            :unknown -> known
            value -> Map.put(known, key, value)
          end
        end)

      selector_returns(Map.drop(remaining, Enum.map(ready, &elem(&1, 0))), edges, summaries)
    end
  end

  defp selector_value({:function, _, _, _, clauses} = form, summaries) do
    if clauses != [] and :erlang.external_size(form) <= @max_finite_bytes do
      value =
        clauses
        |> Enum.map(fn clause ->
          clause = selector_calls(clause, summaries)
          elem(resolve_clause(clause, %{}, false), 2)
        end)
        |> common_value()

      if Enum.all?(finite_choices(value), &match?({:atom, _, atom} when is_atom(atom), &1)),
        do: value,
        else: :unknown
    else
      :unknown
    end
  end

  # Preserve each original call and its arguments for the ordinary traversal.
  # The attached summary is atom-only, so it cannot duplicate executable bodies.
  defp selector_calls({:call, line, {:atom, _, name} = callee, arguments}, summaries) do
    call = {:call, line, callee, selector_calls(arguments, summaries)}

    case Map.fetch(summaries, {name, length(arguments)}) do
      {:ok, value} -> {:audit_selector, line, call, value}
      :error -> call
    end
  end

  defp selector_calls(term, summaries) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.map(&selector_calls(&1, summaries)) |> List.to_tuple()

  defp selector_calls(terms, summaries) when is_list(terms),
    do: Enum.map(terms, &selector_calls(&1, summaries))

  defp selector_calls(term, _summaries), do: term

  # The first consumer boundary is a direct local producer in module position.
  # Do not introduce assignment, argument, remote-return or state propagation.
  # A compiler may wrap that expression in an immediate case. Refine only a
  # single-variable clause whose entire body dispatches on that exact receiver;
  # keep every original branch and the producer syntax for the ordinary scan.
  defp selector_targets(
         {:case, annotation, {:call, _, {:atom, _, name}, arguments} = source, clauses},
         summaries
       ) do
    source = selector_targets(source, summaries)
    clauses = selector_targets(clauses, summaries)

    clauses =
      case Map.fetch(summaries, {name, length(arguments)}) do
        {:ok, value} -> Enum.map(clauses, &selector_case_clause(&1, value))
        :error -> clauses
      end

    {:case, annotation, source, clauses}
  end

  defp selector_targets(
         {:remote, annotation, {:call, line, {:atom, _, name} = callee, arguments}, function},
         summaries
       ) do
    call = {:call, line, callee, selector_targets(arguments, summaries)}

    target =
      case Map.fetch(summaries, {name, length(arguments)}) do
        {:ok, value} -> {:audit_selector, line, call, value}
        :error -> call
      end

    {:remote, annotation, target, selector_targets(function, summaries)}
  end

  defp selector_targets(term, summaries) when is_tuple(term),
    do: term |> Tuple.to_list() |> Enum.map(&selector_targets(&1, summaries)) |> List.to_tuple()

  defp selector_targets(terms, summaries) when is_list(terms),
    do: Enum.map(terms, &selector_targets(&1, summaries))

  defp selector_targets(term, _summaries), do: term

  defp selector_case_clause(
         {:clause, annotation, [{:var, _, name}] = patterns, [],
          [
            {:call, line,
             {:remote, remote_line, {:var, receiver_line, receiver_name} = receiver, function},
             arguments}
          ]},
         value
       )
       when name == receiver_name and name != :_ do
    target = {:audit_selector, receiver_line, receiver, value}
    call = {:call, line, {:remote, remote_line, target, function}, arguments}
    {:clause, annotation, patterns, [], [call]}
  end

  defp selector_case_clause(clause, _value), do: clause

  # Complete compiled caller domains can seed private parameters. General finite
  # targets require acyclic callers; literal closure parameters also admit a
  # separately checked acyclic argument-dependency proof. Exports and captures
  # remain open; neither rule infers function returns or global state.
  defp resolve_lexical(forms, beam_exports, invariant_entries) do
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

    {resolved, checked} =
      if :export_all in options or map_size(definitions) > @max_parameter_functions do
        {%{}, %{}}
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

          checked =
            checked_parameter_invariants(invariant_entries, definitions, exported, analysis)

          resolved =
            closed_parameters(
              definitions,
              callers,
              exported,
              analysis.captures,
              %{},
              %{},
              closures,
              checked
            )

          {resolved, checked}
        else
          {%{}, %{}}
        end
      end

    forms =
      Enum.map(forms, fn
        {:function, _, name, arity, _} = form ->
          Map.get_lazy(resolved, {name, arity}, fn ->
            resolve_function(form, List.duplicate(:unknown, arity))
          end)

        form ->
          form
      end)

    {forms, parameter_invariant_proof(invariant_entries, checked, "rejected")}
  end

  defp parameter_invariant_proof(entries, checked, rejected_status) do
    status =
      cond do
        entries == [] -> "not_requested"
        map_size(checked) > 0 -> "checked"
        true -> rejected_status
      end

    slots =
      for {{{name, arity}, index}, value} <- checked do
        targets = for {:atom, _, atom} <- finite_choices(value), do: to_string(atom)

        %{
          function: to_string(name),
          arity: arity,
          parameter_index: index,
          targets: Enum.sort(targets)
        }
      end

    %{
      status: status,
      checked_slots: Enum.sort_by(slots, &{&1.function, &1.arity, &1.parameter_index})
    }
  end

  # Opt-in derivations contain finite atom domains, never trusted caller lists.
  # Check all compiled calls before using the induction hypothesis at any sink.
  # Existing recursive closure controls do not opt in and retain their semantics.
  defp checked_parameter_invariants([], _definitions, _exported, _analysis), do: %{}

  defp checked_parameter_invariants(entries, definitions, exported, analysis) do
    with true <- is_list(entries),
         true <- length(entries) <= @max_parameter_functions,
         true <- :erlang.external_size(entries) <= @max_finite_bytes,
         {:ok, domains} <- invariant_domains(entries, definitions, exported, analysis.captures),
         origins <- invariant_call_origins(definitions, domains),
         true <- invariant_origins_valid?(origins, domains),
         true <- invariant_seeded?(origins, MapSet.new()) do
      Map.new(domains, fn {slot, atoms} ->
        {slot, common_value(Enum.map(atoms, &{:atom, 0, &1}))}
      end)
    else
      _ -> %{}
    end
  end

  defp invariant_domains(entries, definitions, exported, captures) do
    Enum.reduce_while(entries, {:ok, %{}}, fn
      {{name, arity} = key, index, atoms}, {:ok, domains}
      when is_atom(name) and is_integer(arity) and arity >= 0 and
             is_integer(index) and index >= 0 and index < arity and is_list(atoms) ->
        slot = {key, index}

        valid? =
          atoms != [] and length(atoms) <= @max_finite_targets and
            Enum.all?(atoms, &is_atom/1) and length(Enum.uniq(atoms)) == length(atoms) and
            Map.has_key?(definitions, key) and not Map.has_key?(domains, slot) and
            not MapSet.member?(exported, key) and not MapSet.member?(captures, key) and
            invariant_formals?(Map.get(definitions, key), index)

        if valid?,
          do: {:cont, {:ok, Map.put(domains, slot, atoms)}},
          else: {:halt, :unknown}

      _, _ ->
        {:halt, :unknown}
    end)
  end

  defp invariant_formals?({:function, _, _, _, clauses}, index) do
    clauses != [] and
      Enum.all?(clauses, fn
        {:clause, _, patterns, _, _} ->
          case Enum.at(patterns, index) do
            {:var, _, name} -> name != :_
            _ -> false
          end

        _ ->
          false
      end)
  end

  defp invariant_formals?(_form, _index), do: false

  defp invariant_call_origins(definitions, domains) do
    slots =
      Enum.reduce(domains, %{}, fn {{key, index}, _}, acc ->
        Map.update(acc, key, [index], &[index | &1])
      end)

    initial = Map.new(domains, fn {slot, _} -> {slot, []} end)

    Enum.reduce(definitions, initial, fn {owner, {:function, _, _, _, clauses}}, origins ->
      Enum.reduce(clauses, origins, fn {:clause, _, patterns, guards, body}, acc ->
        scope =
          Map.new(Map.get(slots, owner, []), fn index ->
            {:var, _, name} = Enum.at(patterns, index)
            {name, {owner, index}}
          end)

        invariant_origins([guards, body], owner, scope, slots, acc)
      end)
    end)
  end

  defp invariant_origins({:audit_selector, _, call, _}, owner, scope, slots, origins),
    do: invariant_origins(call, owner, scope, slots, origins)

  defp invariant_origins({:audit_return, _, call, _}, owner, scope, slots, origins),
    do: invariant_origins(call, owner, scope, slots, origins)

  defp invariant_origins({:call, _, {:atom, _, name}, args} = term, owner, scope, slots, origins) do
    key = {name, length(args)}

    origins =
      Enum.reduce(Map.get(slots, key, []), origins, fn index, acc ->
        origin =
          case Enum.at(args, index) do
            {:var, _, variable} ->
              case Map.fetch(scope, variable) do
                {:ok, slot} -> {:identity, slot}
                :error -> :unknown
              end

            {:atom, _, atom} ->
              if Map.has_key?(slots, owner), do: :unknown, else: {:seed, atom}

            {:audit_union, _, _} = union ->
              if Map.has_key?(slots, owner), do: :unknown, else: invariant_union_seed(union)

            _ ->
              :unknown
          end

        Map.update!(acc, {key, index}, &[origin | &1])
      end)

    term |> Tuple.to_list() |> invariant_origins(owner, scope, slots, origins)
  end

  # Erlang fun parameters shadow outer variables; case/receive patterns do not.
  # Comprehension forwarding is deliberately unsupported, including aliases.
  defp invariant_origins({:fun, _, {:clauses, clauses}}, owner, scope, slots, origins),
    do: invariant_fun_origins(clauses, owner, scope, slots, origins)

  defp invariant_origins({:named_fun, _, name, clauses}, owner, scope, slots, origins),
    do: invariant_fun_origins(clauses, owner, Map.delete(scope, name), slots, origins)

  defp invariant_origins(term, owner, _scope, slots, origins)
       when is_tuple(term) and tuple_size(term) >= 1 and elem(term, 0) in [:lc, :bc, :mc],
       do: term |> Tuple.to_list() |> invariant_origins(owner, %{}, slots, origins)

  defp invariant_origins(term, owner, scope, slots, origins) when is_tuple(term),
    do: term |> Tuple.to_list() |> invariant_origins(owner, scope, slots, origins)

  defp invariant_origins(terms, owner, scope, slots, origins) when is_list(terms),
    do: Enum.reduce(terms, origins, &invariant_origins(&1, owner, scope, slots, &2))

  defp invariant_origins(_term, _owner, _scope, _slots, origins), do: origins

  defp invariant_fun_origins(clauses, owner, scope, slots, origins) do
    Enum.reduce(clauses, origins, fn {:clause, _, patterns, guards, body}, acc ->
      scope = Map.drop(scope, pattern_variables(patterns))
      invariant_origins([guards, body], owner, scope, slots, acc)
    end)
  end

  # A previously checked selector may supply multiple finite entry targets.
  # Admit only bounded atom proof data; recursive edges still require the
  # original parameter identity, never a replacement union or computed value.
  defp invariant_union_seed({:audit_union, annotation, values} = term) when is_list(values) do
    valid? =
      callable_annotation?(annotation) and values != [] and
        length(values) <= @max_finite_targets and
        :erlang.external_size(term) <= @max_finite_bytes and
        Enum.all?(values, fn
          {:atom, atom_annotation, value} ->
            is_atom(value) and callable_annotation?(atom_annotation)

          _ ->
            false
        end)

    if valid?, do: {:seeds, Enum.map(values, &elem(&1, 2))}, else: :unknown
  end

  defp invariant_union_seed(_term), do: :unknown

  defp invariant_origins_valid?(origins, domains) do
    Enum.all?(origins, fn {slot, inputs} ->
      target = Map.fetch!(domains, slot)

      inputs != [] and
        Enum.all?(inputs, fn
          {:seed, atom} -> atom in target
          {:seeds, atoms} -> Enum.all?(atoms, &(&1 in target))
          {:identity, source} -> Enum.all?(Map.fetch!(domains, source), &(&1 in target))
          _ -> false
        end)
    end)
  end

  # Reachability is not a fixed-point value guess: every step removes at least
  # one finite vertex, and all seeds/backedges were checked before this step.
  defp invariant_seeded?(origins, reached) when map_size(origins) == 0,
    do: MapSet.size(reached) > 0

  defp invariant_seeded?(origins, reached) do
    ready =
      for {slot, inputs} <- origins,
          Enum.any?(inputs, fn
            {:seed, _} -> true
            {:seeds, _} -> true
            {:identity, source} -> MapSet.member?(reached, source)
          end),
          do: slot

    ready != [] and
      invariant_seeded?(
        Map.drop(origins, ready),
        Enum.reduce(ready, reached, &MapSet.put(&2, &1))
      )
  end

  defp checked_parameter_values(values, key, checked) do
    values
    |> Enum.with_index()
    |> Enum.map(fn {value, index} ->
      if value == :unknown, do: Map.get(checked, {key, index}, value), else: value
    end)
  end

  # Remove ready vertices, never iterate a recursive proof to an arbitrary cap.
  # Cycles retain unknown general targets; checked closure seeds are independent.
  defp closed_parameters(
         remaining,
         callers,
         exported,
         captures,
         incoming,
         resolved,
         closures,
         checked
       ) do
    ready =
      Enum.reject(remaining, fn {key, _form} ->
        Enum.any?(Map.get(callers, key, MapSet.new()), &Map.has_key?(remaining, &1))
      end)

    if ready == [] do
      Enum.reduce(remaining, resolved, fn {{_, arity} = key, form}, output ->
        values =
          key
          |> closure_parameter_values(List.duplicate(:unknown, arity), closures)
          |> checked_parameter_values(key, checked)

        Map.put(output, key, resolve_function(form, values))
      end)
    else
      {incoming, resolved} =
        Enum.reduce(ready, {incoming, resolved}, fn {{_, arity} = key, form}, {args, output} ->
          values =
            if not MapSet.member?(exported, key) and not MapSet.member?(captures, key),
              do: Map.get(args, key, List.duplicate(:unknown, arity)),
              else: List.duplicate(:unknown, arity)

          values =
            key
            |> closure_parameter_values(values, closures)
            |> checked_parameter_values(key, checked)

          form = resolve_function(form, values)
          {collect_local_arguments(form, remaining, args), Map.put(output, key, form)}
        end)

      remaining = Map.drop(remaining, Enum.map(ready, &elem(&1, 0)))

      closed_parameters(
        remaining,
        callers,
        exported,
        captures,
        incoming,
        resolved,
        closures,
        checked
      )
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
  defp caller_syntax({:audit_selector, _, call, _value}, owner, state),
    do: caller_syntax(call, owner, state)

  defp caller_syntax(_term, _owner, %{complete: false} = state), do: state

  defp caller_syntax(term, owner, state) do
    state = %{state | nodes: state.nodes + 1}

    if state.nodes > @max_parameter_nodes,
      do: %{state | complete: false},
      else: caller_node(term, owner, state)
  end

  # Early lexical preparation marks variable callees so a data atom cannot
  # become a source-level local call. Traverse that marker's complete payload
  # for caller edges and captures; it supplies no callable or parameter fact.
  defp caller_node({:audit_fun_value, annotation, callee} = term, owner, state) do
    if callable_annotation?(annotation) and
         :erlang.external_size(term) <= @max_finite_bytes,
       do: caller_syntax(callee, owner, state),
       else: %{state | complete: false}
  end

  # Earlier checked return preparation can place a finite atom domain directly
  # in a caller argument. Accept only that data-only proof node; otherwise the
  # entire existing private-parameter analysis must remain unavailable.
  defp caller_node({:audit_union, annotation, values} = term, owner, state)
       when is_list(values) do
    valid? =
      callable_annotation?(annotation) and values != [] and
        length(values) <= @max_finite_targets and
        :erlang.external_size(term) <= @max_finite_bytes and
        Enum.all?(values, fn
          {:atom, atom_annotation, value} ->
            is_atom(value) and callable_annotation?(atom_annotation)

          _ ->
            false
        end)

    if valid?, do: caller_syntax(values, owner, state), else: %{state | complete: false}
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

  # Only a literal-true case arm establishes that its scrutinee succeeded.
  # Elixir compiles strict `and` to false/true cases; their false arm must
  # return literal false before truth can imply both operands. No falsy,
  # wildcard, negated or arbitrary predicate establishes an atom identity.
  defp successful_case_environment(
         source,
         {:clause, annotation, [{:atom, pattern_annotation, true}], _guards, _body},
         environment
       ) do
    with true <- callable_annotation?(annotation),
         true <- callable_annotation?(pattern_annotation),
         true <- :erlang.external_size(source) <= @max_finite_bytes,
         true <- tuple_projection_headers?(source),
         {:ok, scope} <- positive_case_facts(source, environment, 32) do
      scope
    else
      _ -> environment
    end
  end

  defp successful_case_environment(_source, _clause, environment), do: environment

  defp positive_case_facts(_expression, _environment, 0), do: :unknown

  defp positive_case_facts({:op, _, :andalso, left, right}, environment, remaining) do
    with {:ok, scope} <- positive_case_facts(left, environment, remaining - 1),
         do: positive_case_facts(right, scope, remaining - 1)
  end

  defp positive_case_facts({:op, _, :orelse, left, right}, environment, remaining) do
    with {:ok, first} <- positive_case_facts(left, environment, remaining - 1),
         {:ok, second} <- positive_case_facts(right, environment, remaining - 1),
         do: {:ok, join_environments([first, second])}
  end

  defp positive_case_facts(
         {:case, _, left,
          [
            {:clause, _, [{:atom, _, false}], [], [{:atom, _, false}]},
            {:clause, _, [{:atom, _, true}], [], [right]}
          ]},
         environment,
         remaining
       ) do
    with {:ok, scope} <- positive_case_facts(left, environment, remaining - 1),
         do: positive_case_facts(right, scope, remaining - 1)
  end

  defp positive_case_facts(expression, environment, _remaining),
    do: {:ok, guard_atom_fact(expression, environment)}

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

  defp resolve_expression({:audit_selector, line, call, value}, environment) do
    {call, environment, _} = resolve_expression(call, environment)
    {{:audit_selector, line, call, value}, environment, value}
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
    source = expression
    {expression, environment, _value} = resolve_expression(expression, environment)
    {clauses, environment, value} = resolve_branches(clauses, environment, source)
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
    variable_callee? =
      match?({:var, _, _}, callee) or match?({:audit_selector, _, _, _}, callee)

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

  defp resolve_branches(clauses, environment, source \\ nil) do
    branches =
      Enum.map(clauses, fn clause ->
        scope = successful_case_environment(source, clause, environment)
        resolve_clause(clause, scope, false)
      end)

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

  defp expand_finite({:audit_selector, _, _call, value}), do: expand_finite(value)

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
