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

  test "I20 anonymous aliases retain duplicate invocation identities without named targets",
       context do
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> Captured=X, F=fun(Y) -> {Captured,Y} end, G=F, G(X), G(X)."
    )

    before = audit(context, false)
    after_report = audit(context)
    [first, second] = records(after_report, :incoming_case, "run")
    anonymous_record(first, 1)
    anonymous_record(second, 1)
    refute first.site.path == second.site.path
    refute first.site.ordinal == second.site.ordinal
    assert ordinary(after_report) == before
    [root] = after_report.callable_provenance_preflight.roots
    [derived] = after_report.callable_provenance_preflight.target_derivations.roots
    assert Enum.map(derived.records, & &1.site) == root.incoming
  end

  test "I21 actual Elixir with else closure invocations gain only anonymous evidence", context do
    install_elixir(context, """
    defmodule NoOTPIncomingAnonymousFixture do
      def run(value) do
        with {:ok, first} <- step(value),
             true <- is_integer(first),
             {:ok, second} <- step(first) do
          {:ok, second}
        else
          false -> :not_integer
          other -> other
        end
      end
      defp step(value), do: {:ok, value}
    end
    """)

    before = audit(context, false)
    report = audit(context)
    found = records(report, NoOTPIncomingAnonymousFixture, "run")
    assert length(found) >= 2
    Enum.each(found, &anonymous_record(&1, 1))
    assert ordinary(report) == before
    assert report.callable_provenance_preflight.external_callable_records == []
    refute :code.is_loaded(NoOTPIncomingAnonymousFixture)
  end

  test "I22 a complete finite union of anonymous closures is incompatible with named roots",
       context do
    install(
      context,
      :incoming_case,
      "-export([run/2]). run(Tag,X) -> F=case Tag of a -> fun(Y) -> {a,Y} end; _ -> fun(Y) -> {b,Y} end end, F(X)."
    )

    [record] = records(audit(context), :incoming_case, "run")
    anonymous_record(record, 1)
  end

  test "I23 unknown and named alternatives never borrow anonymous evidence", context do
    install(
      context,
      :incoming_case,
      "-export([unknown/2,mixed/2,data/1,named/0,direct/2]). unknown(F,X) -> G=case X of a -> fun(Y) -> Y end; _ -> F end, G(X). mixed(Tag,X) -> F=case Tag of a -> fun(A,B) -> {A,B} end; _ -> fun incoming_root:entry/2 end, F(X,X). data(X) -> F=entry, F(X). named() -> fun incoming_root:entry/2. direct(A,B) -> incoming_root:entry(A,B)."
    )

    before = audit(context, false)
    report = audit(context)

    for owner <- ["unknown", "data"] do
      [record] = records(report, :incoming_case, owner)
      assert record.status == "unknown"
    end

    # The mixed capture is copied into the invocation's finite domain. Its
    # marker is no longer unique, so it remains an obligation, not a proof.
    mixed = records(report, :incoming_case, "mixed")
    assert length(mixed) == 2
    [capture] = Enum.filter(mixed, &(&1.site.kind == "capture"))

    [invocation] =
      Enum.filter(mixed, &(&1.site.kind == "callable_or_metadispatch_requires_proof"))

    assert capture.status == "unknown" and capture.derivation == nil
    assert invocation.status == "unknown" and invocation.derivation == nil
    assert capture.targets == [] and invocation.targets == []
    refute capture.site.path == invocation.site.path
    refute capture.site.ordinal == invocation.site.ordinal
    assert Enum.any?(mixed, &(&1.status == "unknown"))
    refute Enum.any?(mixed, &(&1.status == "checked_anonymous_incompatible"))

    # Independent single-occurrence named edges retain the positive contract.
    for {owner, kind} <- [{"named", "capture"}, {"direct", "direct_arguments_require_proof"}] do
      [record] = records(report, :incoming_case, owner)
      assert record.status == "checked_finite_target"
      assert record.site.kind == kind
      assert record.targets == [%{module: ":incoming_root", function: "entry", arity: 2}]
      assert record.derivation.exact_occurrence
      assert record.derivation.annotation_equivalence
    end

    [raw_root] = report.callable_provenance_preflight.roots
    [derived_root] = report.callable_provenance_preflight.target_derivations.roots
    assert Enum.map(derived_root.records, & &1.site) == raw_root.incoming

    raw_mixed =
      Enum.filter(
        raw_root.incoming,
        &(&1.module == ":incoming_case" and &1.owner.function == "mixed")
      )

    assert raw_mixed == Enum.map(mixed, & &1.site)
    assert ordinary(report) == before
    assert report.callable_provenance_preflight.external_callable_records == []
  end

  test "I24 shadowed closure parameters retain their unknown inner invocation", context do
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> F=fun(Y) -> Y end, G=fun(F) -> F(X) end, G(X)."
    )

    before = audit(context, false)
    report = audit(context)
    found = records(report, :incoming_case, "run")
    assert Enum.count(found, &(&1.status == "unknown")) == 1
    [outer] = Enum.filter(found, &(&1.status == "checked_anonymous_incompatible"))
    anonymous_record(outer, 1)
    assert ordinary(report) == before
    assert report.unresolved_dispatch != []
  end

  test "I25 anonymous bodies retain named root and OTP obligations without executing", context do
    Process.delete(:incoming_anonymous_executed)

    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> F=fun(Y) -> erlang:put(incoming_anonymous_executed,true), incoming_root:entry(Y,Y) end, F(X)."
    )

    before = audit(context, false)
    report = audit(context)
    found = records(report, :incoming_case, "run")
    assert Enum.any?(found, &(&1.status == "checked_finite_target"))
    [anonymous] = Enum.filter(found, &(&1.status == "checked_anonymous_incompatible"))
    anonymous_record(anonymous, 1)
    assert ordinary(report) == before
    assert report.callable_provenance_preflight.external_callable_records == []
    assert Process.get(:incoming_anonymous_executed) == nil
    refute :code.is_loaded(:incoming_case)

    # Direct OTP imports must still reject selected-producer evidence globally.
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> F=fun(Y) -> ssl:connect(Y,443,[]), incoming_root:entry(Y,Y) end, F(X)."
    )

    before = audit(context, false)
    report = audit(context)
    assert Enum.all?(records(report, :incoming_case, "run"), &(&1.status == "unknown"))
    assert Enum.any?(report.unresolved_dispatch, &(&1.kind == "literal_module_ssl"))
    assert report.direct_otp_ssl_imports != []
    assert ordinary(report) == before
  end

  test "I26 anonymous arguments do not turn apply or spawn into immediate closure calls",
       context do
    install(
      context,
      :incoming_case,
      "-export([run/1,launch/1]). run(X) -> F=fun(Y) -> Y end, Apply=fun erlang:apply/2, Apply(F,[X]). launch(X) -> F=fun() -> X end, Spawn=fun erlang:spawn/1, Spawn(F)."
    )

    report = audit(context)

    for owner <- ["run", "launch"] do
      found = records(report, :incoming_case, owner)
      assert found != []
      assert Enum.all?(found, &(&1.status == "unknown"))
    end
  end

  test "I27 recursive anonymous identities retain unknown captured callback bodies", context do
    install(
      context,
      :incoming_case,
      "-export([run/1]). run(X) -> F=fun Loop(0) -> X(0); Loop(N) -> Loop(N-1) end, F(1)."
    )

    before = audit(context, false)
    report = audit(context)
    found = records(report, :incoming_case, "run")
    assert Enum.count(found, &(&1.status == "unknown")) == 1
    anonymous = Enum.filter(found, &(&1.status == "checked_anonymous_incompatible"))
    assert length(anonymous) == 2
    Enum.each(anonymous, &anonymous_record(&1, 1))
    assert report.unresolved_dispatch != []
    assert ordinary(report) == before
  end

  test "I28 anonymous proof still requires selected current debug artifacts", context do
    body = "-export([run/1]). run(X) -> F=fun(Y) -> Y end, F(X)."
    bytes = install(context, :incoming_case, body)
    shadow = Path.join(context.directory, "anonymous-shadow")
    File.mkdir_p!(shadow)
    File.write!(Path.join(shadow, "incoming_case.beam"), bytes)
    true = :code.add_patha(String.to_charlist(shadow))
    on_exit(fn -> :code.del_path(String.to_charlist(shadow)) end)
    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "unknown"
    true = :code.del_path(String.to_charlist(shadow))
    install(context, :incoming_provider, "-export([run/0]). run() -> ok.", false)
    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "unknown"
  end

  test "I29 raw anonymous-looking proof nodes and invalid annotations remain unknown", context do
    for mutation <- [:proof_node, :annotation] do
      install(context, :incoming_case, "-export([run/1]). run(X) -> F=fun(Y) -> Y end, F(X).")

      rewrite(context, :incoming_case, fn forms ->
        Enum.map(forms, fn
          {:function, a, :run, 1, [{:clause, c, p, g, body}]} ->
            body =
              case mutation do
                :proof_node ->
                  [{:audit_fun_value, 1, {:fun, 1, {:clauses, []}}} | body]

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

  test "I30 escaped unknown callbacks and closure factories do not imply caller identity",
       context do
    install(
      context,
      :incoming_case,
      "-export([run/2,leak/0,factory/1]). run(F,X) -> invoke(F,X). leak() -> fun invoke/2. invoke(F,X) -> F(X). factory(X) -> F=external:factory(X), F(X)."
    )

    report = audit(context)

    for owner <- ["invoke", "factory"] do
      [record] = records(report, :incoming_case, owner)
      assert record.status == "unknown"
      assert record.derivation == nil
    end
  end

  test "I31 anonymous evidence keeps complete-module budgets and request gates", context do
    source = "-export([run/1]). run(X) -> F=fun(Y) -> Y end, F(X)."
    install(context, :incoming_case, source)

    for request <- [:enabled, %{anonymous: true}] do
      [record] = records(audit(context, request), :incoming_case, "run")
      assert record.status == "unknown"
    end

    missing = %{context | roots: [{:incoming_absent, :entry, 2}]}
    [record] = records(audit(missing), :incoming_case, "run")
    assert record.status == "unknown"

    rewrite(context, :incoming_case, fn forms ->
      extras =
        for index <- 1..257 do
          {:function, 1, String.to_atom("incoming_anonymous_budget_#{index}"), 0,
           [{:clause, 1, [], [], [{:atom, 1, :ok}]}]}
        end

      forms ++ extras
    end)

    [record] = records(audit(context), :incoming_case, "run")
    assert record.status == "unknown"
  end

  defp anonymous_record(record, arity) do
    assert record.status == "checked_anonymous_incompatible"
    assert record.targets == []
    assert record.derivation.exact_occurrence
    assert record.derivation.annotation_equivalence
    refute record.derivation.parameter_invariants
    assert record.derivation.method == "existing_finite_pipeline"
    assert record.derivation.anonymous_invocation.kind == "anonymous_closure"
    assert record.derivation.anonymous_invocation.invocation_arity == arity
    assert record.derivation.anonymous_invocation.alternative_count in 1..16

    for key <- [:source_sha256, :original_node_sha256, :resolved_node_sha256] do
      assert Regex.match?(~r/^[0-9a-f]{64}$/, Map.fetch!(record.derivation, key))
    end
  end

  defp install_elixir(context, source) do
    module = NoOTPIncomingAnonymousFixture
    refute :code.is_loaded(module)

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
    end)

    assert [{^module, bytes}] = Code.compile_string(source)
    :code.purge(module)
    :code.delete(module)
    File.write!(Path.join(context.ebin, Atom.to_string(module) <> ".beam"), bytes)
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
