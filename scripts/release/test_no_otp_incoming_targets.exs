Code.require_file("no_otp_release_audit.exs", __DIR__)
ExUnit.start()

defmodule NoOTP.IncomingTargetTest do
  use ExUnit.Case, async: false

  setup do
    directory =
      Path.join(System.tmp_dir!(), "no-otp-incoming-#{System.unique_integer([:positive])}")

    ebin = Path.join(directory, "lib/incoming_fixture-1/ebin")
    File.mkdir_p!(ebin)
    directory = physical(directory)
    ebin = physical(ebin)

    File.write!(
      Path.join(ebin, "incoming_fixture.app"),
      "{application,incoming_fixture,[{vsn,\"1\"},{applications,[kernel,stdlib]}]}."
    )

    saved = Map.new(["NO_OTP_RELEASE", "NO_OTP_PROJECT"], &{&1, System.get_env(&1)})
    Enum.each(saved, fn {key, _} -> System.put_env(key, directory) end)
    true = :code.add_patha(String.to_charlist(ebin))
    modules = [:incoming_root, :incoming_case, :incoming_renamed, :incoming_provider]
    Enum.each(modules, fn module -> assert :code.is_loaded(module) == false end)

    on_exit(fn ->
      Enum.each(modules, fn module ->
        :code.purge(module)
        :code.delete(module)
      end)

      :code.del_path(String.to_charlist(ebin))

      Enum.each(saved, fn {key, value} ->
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end)

      File.rm_rf!(directory)
    end)

    context = %{directory: directory, ebin: ebin, roots: [{:incoming_root, :entry, 2}]}
    install(context, :incoming_root, "-export([entry/2]). entry(A,B) -> {A,B}.")
    context
  end

  test "I01 opt-in evidence preserves every ordinary field and raw incoming record", context do
    install(context, :incoming_case, "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X).")
    before = audit(context, false)
    after_report = audit(context)
    assert ordinary(after_report) == before
    assert after_report.callable_provenance_preflight.external_callable_records == []
    [root] = after_report.callable_provenance_preflight.roots
    [derived] = after_report.callable_provenance_preflight.target_derivations.roots
    assert Enum.map(derived.records, & &1.site) == root.incoming
    assert Enum.any?(derived.records, &(&1.status == "checked_incompatible"))
  end

  test "I02 module and function aliases produce exact finite MFA evidence", context do
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> M=lists, N=M, F=reverse, N:F(X)."
    )

    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "checked_incompatible"
    assert record.targets == [%{module: ":lists", function: "reverse", arity: 1}]
    assert record.derivation.exact_occurrence
    assert record.derivation.annotation_equivalence
    refute record.derivation.parameter_invariants
  end

  test "I03 renamed private callback forwarding reuses complete lexical callers", context do
    for {module, entry, helper} <- [
          {:incoming_case, "run", "invoke"},
          {:incoming_renamed, "start", "forward"}
        ] do
      source =
        "-export([#{entry}/1]). #{entry}(X) -> #{helper}(fun lists:reverse/1,X). #{helper}(F,X) -> F(X)."

      install(context, module, source)
      [record] = records(audit(context), module, helper)
      assert record.status == "checked_incompatible"
      assert record.targets == [%{module: ":lists", function: "reverse", arity: 1}]
    end
  end

  test "I04 every same-module selector alternative is retained", context do
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> M=pick(X), M:entry(X,X). pick(a) -> lists; pick(_) -> maps."
    )

    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "checked_incompatible"

    assert Enum.sort(record.targets) ==
             Enum.sort([
               %{module: ":lists", function: "entry", arity: 2},
               %{module: ":maps", function: "entry", arity: 2}
             ])
  end

  test "I05 an exact capture of the requested root still requires argument provenance", context do
    install(context, :incoming_case, "-export([run/0]). run() -> fun incoming_root:entry/2.")
    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "checked_finite_target"
    assert record.targets == [%{module: ":incoming_root", function: "entry", arity: 2}]
    assert audit(context).callable_provenance_preflight.external_callable_records == []
  end

  test "I06 direct root calls are never marked incompatible", context do
    install(context, :incoming_case, "-export([run/2]). run(A,B) -> incoming_root:entry(A,B).")
    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "checked_finite_target"
    assert record.site.kind == "direct_arguments_require_proof"
  end

  test "I07 exported parameters and escaping private helpers remain unknown", context do
    install(
      context,
      :incoming_case,
      "-export([run/2,leak/0]). run(F,X) -> invoke(F,X). leak() -> fun invoke/2. invoke(F,X) -> F(X)."
    )

    [record] = records(audit(context), :incoming_case, "invoke")
    assert record.status == "unknown"
    assert record.targets == []
  end

  test "I08 indirect apply and spawn targets never become incompatible", context do
    install(
      context,
      :incoming_case,
      "-export([run/2,launch/1,unknown/2]). run(F,A) -> Apply=fun erlang:apply/2, Apply(F,A). launch(F) -> Spawn=fun erlang:spawn/1, Spawn(F). unknown(F,X) -> F(X)."
    )

    report = audit(context)

    for owner <- ["run", "launch", "unknown"] do
      found = records(report, :incoming_case, owner)
      assert found != []
      assert Enum.all?(found, &(&1.status == "unknown"))
    end

    assert report.unresolved_dispatch != []
  end

  test "I09 a data atom in function position is not a local or remote target", context do
    install(context, :incoming_case, "-export([run/1]). run(X) -> F=lists, F(X).")
    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "unknown"
  end

  test "I10 equal annotations and duplicate calls retain distinct original identities", context do
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X), F(X)."
    )

    before = audit(context, false)
    after_report = audit(context)
    [first, second] = records(after_report, :incoming_case, "run")
    assert first.site.line == second.site.line
    refute first.site.path == second.site.path
    refute first.site.ordinal == second.site.ordinal
    assert first.status == "checked_incompatible" and second.status == "checked_incompatible"
    assert ordinary(after_report) == before
  end

  test "I11 nested unsafe bodies remain ordinary findings even beside a finite target", context do
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> F=fun lists:reverse/1, G=fun(Y) -> ssl:connect(Y,443,[]) end, F(X), G(X)."
    )

    before = audit(context, false)
    after_report = audit(context)
    assert Enum.any?(before.unresolved_dispatch, &(&1.kind == "literal_module_ssl"))
    assert ordinary(after_report) == before
    assert after_report.callable_provenance_preflight.external_callable_records == []
  end

  test "I12 scanned callers producers and callbacks never execute", context do
    Process.delete(:incoming_target_executed)

    install(
      context,
      :incoming_case,
      "-export([run/1,pair/0]). run(X) -> erlang:put(incoming_target_executed,true), erlang:error(scanned_caller_must_not_execute), F=fun lists:reverse/1, F(X). pair() -> {Callback,_}=incoming_provider:wrap(a,b), Callback(c)."
    )

    install(
      context,
      :incoming_provider,
      "-export([wrap/2]). wrap(_,S) -> erlang:put(incoming_target_executed,true), {fun(X) -> erlang:error(scanned_callback_must_not_execute), X end,S}."
    )

    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "checked_incompatible"
    assert Process.get(:incoming_target_executed) == nil
    assert :code.is_loaded(:incoming_case) == false
    assert :code.is_loaded(:incoming_provider) == false
  end

  test "I13 missing debug in the universe prevents checked evidence", context do
    install(context, :incoming_case, "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X).")
    install(context, :incoming_provider, "-export([run/0]). run() -> ok.", false)
    report = audit(context)
    refute report.callable_provenance_preflight.target_derivations.snapshots_current
    assert Enum.all?(records(report, :incoming_case, "run"), &(&1.status == "unknown"))
    assert report.missing_abstract_code != []
  end

  test "I14 a shadowed selected artifact prevents checked evidence", context do
    bytes =
      install(context, :incoming_case, "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X).")

    shadow = Path.join(context.directory, "shadow")
    File.mkdir_p!(shadow)
    File.write!(Path.join(shadow, "incoming_case.beam"), bytes)
    true = :code.add_patha(String.to_charlist(shadow))
    on_exit(fn -> :code.del_path(String.to_charlist(shadow)) end)
    report = audit(context)
    assert Enum.all?(records(report, :incoming_case, "run"), &(&1.status == "unknown"))
    refute report.callable_provenance_preflight.target_derivations.snapshots_current
  end

  test "I15 loaded stale code cannot borrow the replacement file's proof", context do
    old = install(context, :incoming_case, "-export([run/1]). run(X) -> X.")
    selected = Path.join(context.ebin, "incoming_case.beam")

    assert {:module, :incoming_case} =
             :code.load_binary(:incoming_case, String.to_charlist(selected), old)

    install(context, :incoming_case, "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X).")
    assert :code.module_status(:incoming_case) == :modified
    report = audit(context)
    assert Enum.all?(records(report, :incoming_case, "run"), &(&1.status == "unknown"))
  end

  test "I16 malformed annotations and raw proof nodes are not derivations", context do
    for mutation <- [:proof_node, :annotation] do
      install(context, :incoming_case, "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X).")

      rewrite(context, :incoming_case, fn forms ->
        Enum.map(forms, fn
          {:function, a, :run, 1, [{:clause, c, p, g, body}]} ->
            body =
              case mutation do
                :proof_node ->
                  [{:audit_union, 1, [{:atom, 1, :lists}]} | body]

                :annotation ->
                  List.update_at(body, -1, &put_elem(&1, 1, location: 1, text: :invalid))
              end

            {:function, a, :run, 1, [{:clause, c, p, g, body}]}

          form ->
            form
        end)
      end)

      report = audit(context)
      [record] = records(report, :incoming_case, "run")
      assert record.status == "unknown"
      assert ordinary(report) == audit(context, false)
    end
  end

  test "I17 definition and call budgets reject the complete module derivation", context do
    source = "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X)."

    for budget <- [:definitions, :calls] do
      install(context, :incoming_case, source)

      rewrite(context, :incoming_case, fn forms ->
        extras =
          case budget do
            :definitions ->
              for index <- 1..257 do
                {:function, 1, String.to_atom("incoming_budget_#{index}"), 0,
                 [{:clause, 1, [], [], [{:atom, 1, :ok}]}]}
              end

            :calls ->
              body = List.duplicate({:call, 1, {:atom, 1, :helper}, []}, 4_097)
              [{:function, 1, :budget, 0, [{:clause, 1, [], [], body}]}]
          end

        forms ++ extras
      end)

      [record] = records(audit(context), :incoming_case, "run")
      assert record.status == "unknown"
    end
  end

  test "I18 malformed diagnostic requests cannot enable finite evidence", context do
    install(context, :incoming_case, "-export([run/1]). run(X) -> F=fun lists:reverse/1, F(X).")

    for request <- [:enabled, %{external: true}, [true]] do
      report = audit(context, request)
      refute report.callable_provenance_preflight.target_derivations.requests_valid
      assert Enum.all?(records(report, :incoming_case, "run"), &(&1.status == "unknown"))
      assert ordinary(report) == audit(context, false)
    end

    missing = %{context | roots: [{:incoming_absent, :entry, 2}]}
    report = audit(missing)
    [root] = report.callable_provenance_preflight.roots
    refute root.exported
    assert Enum.all?(records(report, :incoming_case, "run"), &(&1.status == "unknown"))
  end

  test "I19 selected remote tagged returns retain the complete finite domain", context do
    install(
      context,
      :incoming_provider,
      "-export([pick/1]). pick(a) -> {ok,lists,a,0}; pick(X) -> {ok,maps,X,1}."
    )

    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> case incoming_provider:pick(X) of {ok,M,_,_} -> M:entry(X,X) end."
    )

    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "checked_incompatible"

    assert Enum.sort(record.targets) ==
             Enum.sort([
               %{module: ":lists", function: "entry", arity: 2},
               %{module: ":maps", function: "entry", arity: 2}
             ])
  end

  defp audit(context, request \\ true),
    do:
      NoOTP.ReleaseAudit.artifacts(
        public_callable_roots: context.roots,
        incoming_target_derivations: request
      )

  defp ordinary(report),
    do: Map.update!(report, :callable_provenance_preflight, &Map.delete(&1, :target_derivations))

  defp records(report, module, owner) do
    [root] = report.callable_provenance_preflight.target_derivations.roots

    Enum.filter(
      root.records,
      &(&1.site.module == inspect(module) and &1.site.owner.function == owner)
    )
  end

  defp install(context, module, body, debug \\ true) do
    source = "-module(#{module}). " <> body
    {:ok, tokens, _} = :erl_scan.string(String.to_charlist(source))

    forms =
      tokens
      |> Enum.chunk_by(&match?({:dot, _}, &1))
      |> Enum.chunk_every(2)
      |> Enum.map(fn [form, dot] ->
        {:ok, parsed} = :erl_parse.parse_form(form ++ dot)
        parsed
      end)

    options =
      [:binary, :return_errors, :return_warnings] ++ if(debug, do: [:debug_info], else: [])

    assert {:ok, ^module, bytes, _warnings} = :compile.forms(forms, options)
    File.write!(Path.join(context.ebin, Atom.to_string(module) <> ".beam"), bytes)
    bytes
  end

  defp rewrite(context, module, transform) do
    file = Path.join(context.ebin, Atom.to_string(module) <> ".beam")
    {:ok, ^module, chunks} = :beam_lib.all_chunks(File.read!(file))
    {~c"Dbgi", debug} = List.keyfind(chunks, ~c"Dbgi", 0)
    {:debug_info_v1, :erl_abstract_code, {forms, options}} = :erlang.binary_to_term(debug)

    debug =
      :erlang.term_to_binary({:debug_info_v1, :erl_abstract_code, {transform.(forms), options}}, [
        :compressed
      ])

    {:ok, bytes} = :beam_lib.build_module(List.keyreplace(chunks, ~c"Dbgi", 0, {~c"Dbgi", debug}))
    File.write!(file, bytes)
  end

  defp physical(path, remaining \\ 16)
  defp physical(_path, 0), do: raise("fixture symlink depth exceeded")

  defp physical(path, remaining) do
    Path.expand(path)
    |> Path.split()
    |> Enum.reduce("", fn part, parent ->
      candidate = if parent == "", do: part, else: Path.join(parent, part)

      case File.read_link(candidate) do
        {:ok, target} -> physical(Path.expand(target, Path.dirname(candidate)), remaining - 1)
        {:error, :einval} -> candidate
        other -> raise("fixture path cannot be resolved: #{inspect(other)}")
      end
    end)
  end
end
