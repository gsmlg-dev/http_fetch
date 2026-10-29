Code.require_file("no_otp_release_audit.exs", __DIR__)
ExUnit.start()

defmodule NoOTP.ReleaseAuditTest do
  use ExUnit.Case, async: false

  setup do
    directory =
      Path.join(System.tmp_dir!(), "no-otp-lexical-#{System.unique_integer([:positive])}")

    ebin = Path.join(directory, "lib/audit_fixture-1/ebin")
    File.mkdir_p!(ebin)

    File.write!(
      Path.join(ebin, "audit_fixture.app"),
      "{application,audit_fixture,[{vsn,\"1\"},{applications,[kernel,stdlib]}]}."
    )

    keys = ["NO_OTP_RELEASE", "NO_OTP_PROJECT"]
    original = Map.new(keys, &{&1, System.get_env(&1)})
    Enum.each(keys, &System.put_env(&1, directory))

    on_exit(fn ->
      Enum.each(original, fn {key, value} ->
        if value, do: System.put_env(key, value), else: System.delete_env(key)
      end)

      File.rm_rf!(directory)
    end)

    %{ebin: ebin}
  end

  test "literal anonymous closure bindings are closed without executing their bodies", context do
    result = erlang(context, "run() -> F = fun(X) -> {ok,X} end, F(value).")
    assert result.unresolved_dispatch == []
  end

  test "compiler with else closure bindings are resolved from actual debug abstract code",
       context do
    source = """
    defmodule NoOTPAuditWithFixture do
      def run(first, second) do
        with true <- is_binary(first),
             true <- is_binary(second),
             {:ok, a} <- parse(first),
             {:ok, b} <- parse(second) do
          {:ok, a, b}
        else
          false -> {:error, :invalid}
          other -> other
        end
      end
      defp parse(<<a, _::binary>>), do: {:ok, a}
      defp parse(_), do: {:error, :empty}
    end
    """

    [{module, bytes}] = Code.compile_string(source)

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
    end)

    result = audit(context, module, bytes)
    assert result.unresolved_dispatch == []
  end

  test "literal module, function, aliases and tuple destructuring have closed targets", context do
    for body <- [
          "run() -> M=lists, F=reverse, M:F([]).",
          "run() -> M=lists, N=M, F=reverse, erlang:apply(N,F,[[]]).",
          "run() -> {M,F}={lists,reverse}, erlang:apply(M,F,[[]]).",
          "run() -> F=fun lists:reverse/1, G=F, G([]).",
          "run() -> F=fun() -> ok end, erlang:spawn(F).",
          "run() -> M=lists, F=reverse, erlang:make_fun(M,F,1)."
        ] do
      assert erlang(context, body).unresolved_dispatch == [], body
    end
  end

  test "same-value branch joins and branch-local closures stay closed", context do
    for body <- [
          "run(X) -> F=case X of a -> fun(Y) -> {ok,Y} end; _ -> fun(Y) -> {ok,Y} end end, F(x).",
          "run(X) -> case X of a -> M=lists; _ -> M=lists end, M:reverse([]).",
          "run(X) -> M=lists, F=fun(Y) -> case Y of a -> M:reverse([]); _ -> M:reverse([]) end end, F(X)."
        ] do
      assert erlang(context, body).unresolved_dispatch == [], body
    end
  end

  test "bound OTP targets, aliases and indirect capture bodies remain findings", context do
    for body <- [
          "run() -> ssl:connect(localhost,443,[]).",
          "run() -> M=ssl, M:connect(localhost,443,[]).",
          "run() -> M=ssl, N=M, F=connect, N:F(localhost,443,[]).",
          "run() -> {M,F}={ssl,connect}, erlang:apply(M,F,[localhost,443,[]]).",
          "run() -> M=ssl, F=fun M:connect/3, F(localhost,443,[]).",
          "run() -> M=ssl, F=fun() -> M:connect(localhost,443,[]) end, F()."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "SSL branch alternatives and captured unsafe bindings cannot become safe", context do
    for body <- [
          "run(X) -> M=case X of a -> lists; _ -> ssl end, M:connect(localhost,443,[]).",
          "run(X) -> case X of a -> M=lists; _ -> M=ssl end, M:connect(localhost,443,[]).",
          "run(X) -> F=case X of a -> fun() -> ok end; _ -> fun() -> ssl:connect(localhost,443,[]) end end, F().",
          "run() -> M=ssl, F=fun() -> M:connect(localhost,443,[]) end, (fun(M) -> M:reverse([]) end)(lists), F().",
          "run(F) -> (fun(F) -> F() end)(fun() -> ok end), F().",
          "run() -> M=ssl, F=fun(M) -> M:connect(localhost,443,[]) end, F(ssl)."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "unknown callback, module, function, apply and branch values remain unconfirmed",
       context do
    for body <- [
          "run(F) -> F().",
          "run(M) -> M:connect(localhost,443,[]).",
          "run(F) -> lists:F([]).",
          "run(F) -> erlang:apply(F,[]).",
          "run(M,F) -> erlang:apply(M,F,[]).",
          "run(X,F) -> G=case X of a -> fun() -> ok end; _ -> F end, G()."
        ] do
      result = erlang(context, body)
      assert result.unresolved_dispatch != [], body
      assert Enum.all?(result.unresolved_dispatch, &(&1.resolution == "unconfirmed"))
    end
  end

  test "fun parameters cannot inherit outer target bindings", context do
    for body <- [
          "run() -> F=fun() -> ok end, G=fun(F) -> F() end, G(fun() -> ssl:connect(localhost,443,[]) end).",
          "run() -> M=lists, F=fun(M) -> M:connect(localhost,443,[]) end, F(ssl)."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "named and captured metadispatch negatives remain fail closed", context do
    for body <- [
          "run() -> apply(ssl,connect,[localhost,443,[]]).",
          "run() -> erlang:apply(ssl,connect,[localhost,443,[]]).",
          "run() -> F=fun ssl:connect/3, F(localhost,443,[]).",
          "run() -> F=fun erlang:apply/3, F(ssl,connect,[localhost,443,[]]).",
          "run() -> erlang:make_fun(ssl,connect,3).",
          "run() -> make_fun(ssl,connect,3).",
          "run() -> spawn(ssl,connect,[localhost,443,[]]).",
          "run() -> erlang:spawn_link(node(),ssl,connect,[localhost,443,[]]).",
          "run() -> erlang:spawn_monitor(ssl,connect,[localhost,443,[]]).",
          "run() -> erlang:spawn_opt(ssl,connect,[localhost,443,[]],[]).",
          "run() -> erlang:hibernate(ssl,connect,[localhost,443,[]]).",
          "run() -> F=fun() -> ssl:connect(localhost,443,[]) end, erlang:spawn(F).",
          "run(M) -> erlang:spawn(M,connect,[localhost,443,[]]).",
          "run() -> erlang:apply(erlang,make_fun,[ssl,connect,3])."
        ] do
      assert unsafe?(erlang(context, body, "-import(erlang,[make_fun/3]). ")), body
    end
  end

  test "imported SSL and dispatch captures retain exact negative evidence", context do
    assert unsafe?(
             erlang(context, "run() -> connect(localhost,443,[]).", "-import(ssl,[connect/3]). ")
           )

    for body <- [
          "run() -> F=fun erlang:make_fun/3, F(ssl,connect,3).",
          "run() -> F=fun spawn/3, F(ssl,connect,[]).",
          "run() -> F=fun erlang:hibernate/3, F(ssl,connect,[]).",
          "run() -> M=erlang, F=apply, M:F(ssl,connect,[]).",
          "run() -> M=erlang, F=make_fun, erlang:apply(M,F,[ssl,connect,3])."
        ] do
      assert unsafe?(erlang(context, body, "-import(erlang,[make_fun/3]). ")), body
    end
  end

  test "case, receive, try and comprehension local bindings do not escape", context do
    for body <- [
          "run(X) -> M=ssl, F=fun() -> case X of a -> M:connect(localhost,443,[]); _ -> ok end end, F().",
          "run() -> M=lists, [M:connect(localhost,443,[]) || M <- [ssl]].",
          "run() -> M=lists, receive M -> M:reverse([]) after 0 -> ssl:connect(localhost,443,[]) end.",
          "run(F) -> try G=fun() -> ok end, G() catch _:_ -> F() end."
        ] do
      assert unsafe?(erlang(context, body)), body
    end

    assert erlang(
             context,
             "run(X) -> F=case X of a -> fun() -> ok end; _ -> fun() -> ok end end, erlang:spawn(F)."
           ).unresolved_dispatch == []
  end

  test "findings preserve original call line and unconfirmed report shape", context do
    result = erlang(context, "run() ->\n M=ssl,\n M:connect(localhost,443,[]).")

    assert Enum.any?(result.unresolved_dispatch, fn finding ->
             finding.line == 3 and finding.kind == "literal_module_ssl" and
               finding.resolution == "unconfirmed" and is_binary(finding.beam)
           end)
  end

  test "function-value apply resolves a proven literal fun but never an unknown callback",
       context do
    for body <- [
          "run() -> F=fun() -> ok end, erlang:apply(F,[]).",
          "run() -> F=fun lists:reverse/1, erlang:apply(F,[[]])."
        ] do
      assert erlang(context, body).unresolved_dispatch == [], body
    end

    for body <- [
          "run(F) -> erlang:apply(F,[]).",
          "run() -> F=fun() -> ssl:connect(localhost,443,[]) end, erlang:apply(F,[]).",
          "run() -> F=fun ssl:connect/3, erlang:apply(F,[localhost,443,[]]).",
          "run() -> F=fun erlang:apply/3, erlang:apply(F,[ssl,connect,[]])."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "scanning literal closure bodies never executes scanned code", context do
    result = erlang(context, "run() -> F=fun() -> erlang:error(audit_must_not_execute) end, F().")
    assert result.unresolved_dispatch == []
  end

  test "same named local functions are not confused with erlang dispatch", context do
    assert erlang(
             context,
             "run() -> spawn(ssl,connect,[]). spawn(_,_,_) -> ok.",
             "-compile({no_auto_import,[{spawn,3}]}). "
           ).unresolved_dispatch == []
  end

  test "named self identities close direct and nested recursion without executing bodies",
       context do
    for body <- [
          "run() -> F=fun Loop(N) -> case N of 0 -> ok; _ -> Loop(N-1) end end, F(1).",
          "run() -> (fun Loop(0) -> ok; Loop(N) -> Loop(N-1) end)(1).",
          "run() -> F=fun Outer(N) -> G=fun Inner(0) -> ok; Inner(K) -> Inner(K-1) end, case N of 0 -> G(1); _ -> Outer(N-1) end end, F(2).",
          "run() -> Loop=ssl, F=fun Loop(0) -> ok; Loop(N) -> Loop(N-1) end, {Loop,F(1)}.",
          "run() -> F=fun Loop(N) -> erlang:error(audit_must_not_execute), Loop(N) end, F(0)."
        ] do
      assert erlang(context, body).unresolved_dispatch == [], body
    end
  end

  test "recursive bodies retain captured callback SSL and nested shadowing obligations",
       context do
    for body <- [
          "run(C) -> F=fun Loop(0) -> C(); Loop(N) -> Loop(N-1) end, F(1).",
          "run() -> F=fun Loop(0) -> ssl:connect(localhost,443,[]); Loop(N) -> Loop(N-1) end, F(1).",
          "run() -> M=ssl, F=fun Loop(0) -> M:connect(localhost,443,[]); Loop(N) -> Loop(N-1) end, F(1).",
          "run(C) -> F=fun Loop(N) -> (fun(Loop) -> Loop() end)(C), Loop(N) end, F(1).",
          "run(C) -> F=fun Outer(N) -> G=fun Inner(0) -> C(); Inner(K) -> Inner(K-1) end, G(N), Outer(N) end, F(1).",
          "run(C) -> fun Loop(0) -> fun() -> C() end; Loop(N) -> Loop(N-1) end."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "actual Erlang comprehension lowering preserves safe and open targets", context do
    assert erlang(context, "run(Xs) -> [lists:reverse(X) || X <- Xs].").unresolved_dispatch == []
    assert unsafe?(erlang(context, "run(Xs,F) -> [F(X) || X <- Xs]."))
  end

  test "actual Elixir literal collectors close while external collectors remain open", context do
    on_exit(fn ->
      :code.purge(NoOTPAuditCollectorFixture)
      :code.delete(NoOTPAuditCollectorFixture)
    end)

    for {source, closed?} <- [
          {"def run(xs), do: for(x <- xs, do: {x,x})", true},
          {"def run(xs), do: for(x <- xs, into: %{}, do: {x,x})", true},
          {"def run(xs), do: for(<<x <- xs>>, into: <<>>, do: <<x>>)", true},
          {"def run(xs, sink), do: for(x <- xs, into: sink, do: x)", false},
          {"def run(xs, f), do: for(x <- xs, do: f.(x))", false}
        ] do
      module = NoOTPAuditCollectorFixture
      :code.purge(module)
      :code.delete(module)

      [{^module, bytes}] =
        Code.compile_string("defmodule NoOTPAuditCollectorFixture do " <> source <> " end")

      result = audit(context, module, bytes)
      assert result.unresolved_dispatch == [] == closed?, source
    end
  end

  test "finite module function capture and destructured branch domains close", context do
    for body <- [
          "run(X) -> M=case X of a -> lists; _ -> maps end, M:reverse([]).",
          "run(X) -> F=case X of a -> reverse; _ -> flatten end, lists:F([]).",
          "run(X) -> F=case X of a -> fun lists:reverse/1; _ -> fun lists:flatten/1 end, F([]).",
          "run(X) -> {M,F}=case X of a -> {lists,reverse}; _ -> {maps,to_list} end, M:F([]).",
          "run(X) -> [M,F]=case X of a -> [lists,reverse]; _ -> [maps,to_list] end, erlang:apply(M,F,[[]]).",
          "run(X) -> M=case X of a -> lists; _ -> maps end, F=fun M:reverse/1, F([]).",
          "run(X) -> F=case X of a -> fun lists:reverse/1; _ -> fun lists:flatten/1 end, erlang:apply(F,[[]]).",
          "run(X) -> A=case X of a -> [lists,reverse,[[]]]; _ -> [maps,to_list,[[]]] end, erlang:apply(erlang,spawn,A)."
        ] do
      assert erlang(context, body).unresolved_dispatch == [], body
    end
  end

  test "finite domains retain SSL unknown and metadispatch alternatives", context do
    for body <- [
          "run(X) -> M=case X of a -> lists; _ -> ssl end, M:connect(localhost,443,[]).",
          "run(X,M) -> N=case X of a -> lists; _ -> M end, N:reverse([]).",
          "run(X) -> F=case X of a -> fun lists:reverse/1; _ -> fun ssl:connect/3 end, F([]).",
          "run(X) -> F=case X of a -> length; _ -> apply end, erlang:F([]).",
          "run(X) -> F=case X of a -> fun lists:reverse/1; _ -> fun erlang:apply/3 end, F([]).",
          "run(X) -> A=case X of a -> [lists,reverse,[[]]]; _ -> [ssl,connect,[]] end, erlang:apply(erlang,spawn,A).",
          "run(X,T) -> A=case X of a -> [lists,reverse,[]]; _ -> [lists,reverse|T] end, erlang:apply(erlang,spawn,A)."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "independent projection conservatively retains unsafe cross branch combinations",
       context do
    result =
      erlang(
        context,
        "run(X) -> {M,F}=case X of a -> {erlang,length}; _ -> {lists,apply} end, M:F([])."
      )

    assert Enum.any?(result.unresolved_dispatch, &(&1.kind == "unresolved_apply"))
  end

  test "data atoms and tuples never become proven callable identities", context do
    for body <- [
          "run() -> F=some_atom, F().",
          "run() -> F={lists,reverse}, F([]).",
          "run(X) -> F=case X of a -> some_atom; _ -> fun() -> ok end end, F().",
          "run(X) -> F=case X of a -> fun() -> ok end; _ -> {lists,reverse} end, F()."
        ] do
      assert Enum.any?(
               erlang(context, body).unresolved_dispatch,
               &(&1.kind == "unresolved_fun_invocation")
             ),
             body
    end
  end

  test "finite choice count Cartesian product and byte bounds fail closed", context do
    seventeen = Enum.map_join(1..17, "; ", fn n -> "#{n} -> m#{n}" end)
    assert unsafe?(erlang(context, "run(X) -> M=case X of " <> seventeen <> " end, M:f()."))

    modules = Enum.map_join(1..5, "; ", fn n -> "#{n} -> m#{n}" end)
    functions = Enum.map_join(1..5, "; ", fn n -> "#{n} -> f#{n}" end)

    assert unsafe?(
             erlang(
               context,
               "run(X,Y) -> M=case X of " <>
                 modules <> " end, F=case Y of " <> functions <> " end, M:F()."
             )
           )

    huge = Enum.map_join(1..9_000, ",", &Integer.to_string/1)

    assert unsafe?(
             erlang(
               context,
               "run(X) -> {M,_}=case X of a -> {lists,{" <>
                 huge <> "}}; _ -> {maps,{" <> huge <> "}} end, M:reverse([])."
             )
           )
  end

  test "union expansion scans nested unsafe occurrences once with exact source lines", context do
    result =
      erlang(
        context,
        "run(X,C) ->\n M=case X of a -> lists; _ -> maps end,\n M:reverse(C()),\n C()."
      )

    findings = Enum.filter(result.unresolved_dispatch, &(&1.kind == "unresolved_fun_invocation"))
    assert Enum.map(findings, & &1.line) == [3, 4]
    assert length(result.unresolved_dispatch) == 2
  end

  test "compiled producer mutation changes the hash and retains its nested obligation", context do
    safe = erlang(context, "run() -> fun Loop(0) -> ok; Loop(N) -> Loop(N-1) end.")

    unsafe =
      erlang(
        context,
        "run() -> fun Loop(0) -> ssl:connect(localhost,443,[]); Loop(N) -> Loop(N-1) end."
      )

    assert safe.unresolved_dispatch == []
    assert safe.sha256 != unsafe.sha256
    assert unsafe?(unsafe)
    assert Enum.any?(unsafe.unresolved_dispatch, &(&1.line == 1))
  end

  test "complete private callers establish literal closures including nested and transitive calls",
       context do
    for body <- [
          "run() -> helper(fun() -> ok end). helper(F) -> F().",
          "run() -> F=fun() -> ok end, helper(F). helper(F) -> F().",
          "run() -> helper(fun lists:reverse/1). helper(F) -> F([]).",
          "run() -> helper(fun Loop(0) -> ok; Loop(N) -> Loop(N-1) end). helper(F) -> F(1).",
          "run() -> F=fun() -> helper(fun() -> ok end) end, F(). helper(F) -> F().",
          "run() -> first(fun() -> ok end). first(F) -> second(F). second(F) -> F().",
          "run() -> first(lists). first(M) -> second(M). second(M) -> M:reverse([])."
        ] do
      assert private_erlang(context, body).unresolved_dispatch == [], body
    end
  end

  test "every finite private caller contributes module and function targets", context do
    for body <- [
          "run(X) -> case X of a -> helper(lists); _ -> helper(maps) end. helper(M) -> M:reverse([]).",
          "run(X) -> case X of a -> helper(reverse); _ -> helper(flatten) end. helper(F) -> lists:F([]).",
          "run(X) -> M=case X of a -> lists; _ -> maps end, helper(M). helper(M) -> M:reverse([]).",
          "run(X) -> helper(case X of a -> lists; _ -> maps end). helper(M) -> M:reverse([]).",
          "run(X) -> case X of a -> helper(fun lists:reverse/1); _ -> helper(fun lists:flatten/1) end. helper(F) -> F([])."
        ] do
      assert private_erlang(context, body, "run/1").unresolved_dispatch == [], body
    end
  end

  test "actual Elixir compiled private helper parameters use complete literal callers", context do
    on_exit(fn ->
      :code.purge(NoOTPAuditPrivateFixture)
      :code.delete(NoOTPAuditPrivateFixture)
    end)

    [{module, bytes}] =
      Code.compile_string("""
      defmodule NoOTPAuditPrivateFixture do
        def run(flag) do
          if flag, do: invoke(fn -> :ok end), else: invoke(fn -> :done end)
        end
        defp invoke(callback), do: callback.()
      end
      """)

    assert audit(context, module, bytes).unresolved_dispatch == []
  end

  test "an unknown caller poisons a private parameter despite other safe callers", context do
    for body <- [
          "run(M) -> helper(lists), helper(M).\nhelper(M) -> M:reverse([]).",
          "run(F) -> helper(fun() -> ok end), helper(F).\nhelper(F) -> F().",
          "run(F) -> helper(fun() -> ok end), W=fun(G) -> helper(G) end, W(F).\nhelper(F) -> F().",
          "run(M) -> first(lists), first(M). first(M) -> helper(M).\nhelper(M) -> M:reverse([])."
        ] do
      result = private_erlang(context, body, "run/1")
      assert Enum.any?(result.unresolved_dispatch, &(&1.line == 2)), body
    end
  end

  test "SSL and metadispatch private caller alternatives remain findings", context do
    for body <- [
          "run(X) -> case X of a -> helper(lists); _ -> helper(ssl) end. helper(M) -> M:connect(localhost,443,[]).",
          "run(X) -> case X of a -> helper(length); _ -> helper(apply) end. helper(F) -> erlang:F([]).",
          "run(X) -> case X of a -> helper(fun() -> ok end); _ -> helper(fun() -> ssl:connect(localhost,443,[]) end) end. helper(F) -> F().",
          "run(X) -> case X of a -> helper(fun lists:reverse/1); _ -> helper(fun erlang:apply/3) end. helper(F) -> F([])."
        ] do
      assert unsafe?(private_erlang(context, body, "run/1")), body
    end
  end

  test "private captures keep parameter domains open including returned and passed captures",
       context do
    for body <- [
          "run() -> helper(fun() -> ok end), fun helper/1.\nhelper(F) -> F().",
          "run() -> helper(fun() -> ok end), lists:map(fun helper/1, []).\nhelper(F) -> F().",
          "run() -> erlang:apply(fun helper/1, [fun() -> ok end]).\nhelper(F) -> F().",
          "run() -> helper(fun() -> ok end), wrapper(). wrapper() -> fun helper/1.\nhelper(F) -> F()."
        ] do
      result = private_erlang(context, body)
      assert Enum.any?(result.unresolved_dispatch, &(&1.line == 2)), body
    end
  end

  test "explicit exports and both export_all forms prevent private parameter proofs", context do
    body = "run() -> helper(fun() -> ok end).\nhelper(F) -> F()."
    explicit = private_erlang(context, body, "run/0,helper/1")
    attribute = private_erlang(context, body, "run/0", "-compile(export_all). ")
    compiler_option = private_erlang(context, body, "run/0", "", [:export_all])

    for result <- [explicit, attribute, compiler_option] do
      assert Enum.any?(result.unresolved_dispatch, &(&1.line == 2))
    end
  end

  test "literal wrappers preserve each original captured callback occurrence and line", context do
    result =
      private_erlang(
        context,
        "run(C) ->\n helper(fun() -> C() end),\n C().\nhelper(F) -> F().",
        "run/1"
      )

    findings = Enum.filter(result.unresolved_dispatch, &(&1.kind == "unresolved_fun_invocation"))
    assert Enum.map(findings, & &1.line) == [2, 3]
    assert length(result.unresolved_dispatch) == 2

    returned =
      private_erlang(
        context,
        "run(C) ->\n helper(fun() -> C() end).\nhelper(F) -> fun() -> F() end.",
        "run/1"
      )

    assert Enum.map(returned.unresolved_dispatch, & &1.line) == [2]
  end

  test "private parameter proof does not cross inner formal parameter shadowing", context do
    result =
      private_erlang(
        context,
        "run() -> helper(fun() -> ok end).\nhelper(F) -> (fun(F) -> F() end)(fun() -> ok end)."
      )

    assert Enum.any?(
             result.unresolved_dispatch,
             &(&1.line == 2 and &1.kind == "unresolved_fun_invocation")
           )
  end

  test "private clause tuple and list patterns project finite domains conservatively", context do
    for body <- [
          "run(X) -> case X of a -> helper({lists,reverse}); _ -> helper({maps,to_list}) end. helper({M,F}) -> M:F([]).",
          "run(X) -> case X of a -> helper([lists,reverse]); _ -> helper([maps,to_list]) end. helper([M,F]) -> M:F([]).",
          "run(X) -> case X of a -> helper({first,lists}); _ -> helper({second,maps}) end. helper({first,M}) -> M:reverse([]); helper({second,M}) -> M:to_list([])."
        ] do
      assert private_erlang(context, body, "run/1").unresolved_dispatch == [], body
    end

    unsafe =
      private_erlang(
        context,
        "run(X) -> case X of a -> helper({erlang,length}); _ -> helper({lists,apply}) end. helper({M,F}) -> M:F([]).",
        "run/1"
      )

    assert Enum.any?(unsafe.unresolved_dispatch, &(&1.kind == "unresolved_apply"))
  end

  test "recursive callers unseeded cycles and their dependent helpers remain unknown", context do
    for body <- [
          "run() -> helper(fun() -> ok end). helper(F) -> F(), helper(F).",
          "run() -> first(fun() -> ok end). first(F) -> second(F). second(F) -> F(), first(F).",
          "run() -> ok. first(F) -> second(F). second(F) -> F(), first(F).",
          "run() -> first(). first() -> first(), helper(fun() -> ok end). helper(F) -> F().",
          "run() -> ok. helper(F) -> F()."
        ] do
      assert unsafe?(private_erlang(context, body)), body
    end
  end

  test "private caller unions and first caller literal domains respect finite bounds", context do
    body = fn count ->
      branches = Enum.map_join(1..count, "; ", fn n -> "#{n} -> helper(m#{n})" end)
      "run(X) -> case X of " <> branches <> " end. helper(M) -> M:f()."
    end

    assert private_erlang(context, body.(16), "run/1").unresolved_dispatch == []
    assert unsafe?(private_erlang(context, body.(17), "run/1"))

    huge = Enum.map_join(1..9_000, ",", &Integer.to_string/1)

    assert unsafe?(
             private_erlang(
               context,
               "run() -> helper({lists,{" <> huge <> "}}). helper({M,_}) -> M:reverse([])."
             )
           )
  end

  test "private parameter analysis budget exhaustion retains unknown obligations", context do
    helpers = Enum.map_join(1..255, " ", fn n -> "unused#{n}() -> ok." end)

    assert unsafe?(
             private_erlang(
               context,
               "run() -> helper(lists). helper(M) -> M:reverse([]). " <> helpers
             )
           )

    calls = Enum.map_join(1..4_097, ",", fn _ -> "helper(lists)" end)

    assert unsafe?(
             private_erlang(context, "run() -> " <> calls <> ". helper(M) -> M:reverse([]).")
           )

    literal = String.duplicate("x", 100_001)

    assert unsafe?(
             private_erlang(
               context,
               "run() -> \"" <> literal <> "\", helper(lists). helper(M) -> M:reverse([])."
             )
           )
  end

  test "unknown capture domains and computed returns do not close private callers", context do
    unknown_capture =
      private_erlang(
        context,
        "run(M,F,A) -> C=fun M:F/A, helper(lists), C.\nhelper(M) -> M:reverse([]).",
        "run/3"
      )

    assert Enum.any?(unknown_capture.unresolved_dispatch, &(&1.line == 2))

    returned =
      private_erlang(
        context,
        "run() -> helper(factory()). factory() -> fun() -> ok end.\nhelper(F) -> F()."
      )

    assert Enum.any?(returned.unresolved_dispatch, &(&1.line == 2))
  end

  test "changed compiled private caller body changes hash and retains its unsafe occurrence",
       context do
    safe = private_erlang(context, "run() -> helper(fun() -> ok end). helper(F) -> F().")

    changed =
      private_erlang(
        context,
        "run() -> helper(fun() -> ssl:connect(localhost,443,[]) end). helper(F) -> F()."
      )

    assert safe.unresolved_dispatch == []
    assert safe.sha256 != changed.sha256
    findings = Enum.filter(changed.unresolved_dispatch, &(&1.kind == "literal_module_ssl"))
    assert Enum.map(findings, & &1.line) == [1]
    assert unsafe?(changed)
  end

  test "A01 successful atom equality guards resolve either operand order", context do
    for guard <- ["M == lists", "M =:= lists", "lists == M", "lists =:= M"] do
      assert erlang(context, "run(M) when " <> guard <> " -> M:reverse([]).").unresolved_dispatch ==
               [],
             guard
    end
  end

  test "A02 conjunctive successful guard facts remain local to the body", context do
    for guard <- [
          "is_list(X), M == lists",
          "M == lists, is_list(X)",
          "is_list(X) andalso M == lists",
          "M == lists andalso is_list(X)"
        ] do
      assert erlang(context, "run(M,X) when " <> guard <> " -> M:reverse(X).").unresolved_dispatch ==
               [],
             guard
    end
  end

  test "A03 every successful guard alternative contributes its finite target", context do
    for guard <- [
          "M == lists; M == maps",
          "M == lists orelse M == maps",
          "(M == lists orelse M == maps) andalso is_list(X)"
        ] do
      assert erlang(context, "run(M,X) when " <> guard <> " -> M:reverse(X).").unresolved_dispatch ==
               [],
             guard
    end
  end

  test "A04 unknown SSL and metadispatch guard alternatives remain findings", context do
    for body <- [
          "run(M) when M == lists; is_atom(M) -> M:reverse([]).",
          "run(M) when M == lists orelse is_atom(M) -> M:reverse([]).",
          "run(M) when M == lists; M == ssl -> M:connect(localhost,443,[]).",
          "run(M) when M == lists orelse M == ssl -> M:connect(localhost,443,[]).",
          "run(M) when M == ssl -> M:connect(localhost,443,[]).",
          "run(F) when F == length; F == apply -> erlang:F([])."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "A05 guard facts do not enter sibling clauses or shadowing fun parameters", context do
    for body <- [
          "run(M,F) when M == lists -> (fun(M) -> M:reverse([]) end)(F).",
          "run(M) when M == lists -> ok; run(M) -> M:reverse([]).",
          "run(M) -> case M of X when X == lists -> X:reverse([]); X -> X:reverse([]) end.",
          "run(M,F) when M == lists -> (fun Loop(M) -> M:reverse([]), Loop(M) end)(F)."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "A06 type negative numeric and variable equality tests prove no module", context do
    for body <- [
          "run(M) when is_atom(M) -> M:reverse([]).",
          "run(M) when M =/= ssl -> M:reverse([]).",
          "run(M) when not (M == ssl) -> M:reverse([]).",
          "run(M) when M == 1 -> M:reverse([]).",
          "run(M,N) when M =:= N -> M:reverse([]).",
          "run(M) -> case erlang:function_exported(M,reverse,1) of true -> M:reverse([]); false -> ok end."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "A07 actual Elixir equality guard lowering closes both Dialer shaped sinks", context do
    on_exit(fn ->
      :code.purge(NoOTPAuditGuardFixture)
      :code.delete(NoOTPAuditGuardFixture)
    end)

    [{module, bytes}] =
      Code.compile_string("""
      defmodule NoOTPAuditGuardFixture do
        def connected_protocol(transport, socket, %{mode: :force_h2})
            when transport == HTTP.Transport.ExSSL do
          transport.negotiated_protocol(socket)
        end

        def connected_protocol(transport, socket, %{mode: :auto_https})
            when transport == HTTP.Transport.ExSSL do
          transport.negotiated_protocol(socket)
        end
      end
      """)

    assert audit(context, module, bytes).unresolved_dispatch == []
  end

  test "A08 a tuple unknown data component does not discard a known callable", context do
    for body <- [
          "run(X) -> {_,F}={X,fun() -> ok end}, F().",
          "run(X) -> {_,F}={X,fun lists:reverse/1}, F([]).",
          "run(X) -> {_,{_,F}}={X,{X,fun() -> ok end}}, F().",
          "run(X) -> {_,M}={X,lists}, M:reverse([])."
        ] do
      assert erlang(context, body).unresolved_dispatch == [], body
    end
  end

  test "A09 actual Elixir tuple branches retain each WebTransport shaped closure", context do
    on_exit(fn ->
      :code.purge(NoOTPAuditTupleFixture)
      :code.delete(NoOTPAuditTupleFixture)
    end)

    [{module, bytes}] =
      Code.compile_string("""
      defmodule NoOTPAuditTupleFixture do
        def run(kind, state, removal_result) do
          {_waiters, put_fun} =
            case kind do
              :datagram ->
                {state.datagram_waiters,
                 fn session, waiters -> %{session | datagram_waiters: waiters} end}

              :incoming_bidirectional ->
                {state.incoming_bidi_waiters,
                 fn session, waiters -> %{session | incoming_bidi_waiters: waiters} end}

              :incoming_unidirectional ->
                {state.incoming_uni_waiters,
                 fn session, waiters -> %{session | incoming_uni_waiters: waiters} end}
            end

          case removal_result do
            {:ok, waiter, waiters} -> {:ok, waiter, put_fun.(state, waiters)}
            :not_found -> :not_found
          end
        end
      end
      """)

    assert audit(context, module, bytes).unresolved_dispatch == []
  end

  test "A10 unknown callable tuple components and alternatives stay unresolved", context do
    for body <- [
          "run(X,C) -> {_,F}={X,C}, F().",
          "run(X,C) -> {_,F}=case X of a -> {X,fun() -> ok end}; _ -> {X,C} end, F().",
          "run(X,C) -> {_,{_,F}}={X,{X,C}}, F().",
          "run(X,C) -> {F,_}={C,fun() -> ok end}, F()."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "A11 partial tuple proof keeps each original nested callback obligation", context do
    result =
      erlang(
        context,
        "run(X,C) ->\n {_,F}={X,fun() -> C() end},\n F()."
      )

    findings = Enum.filter(result.unresolved_dispatch, &(&1.kind == "unresolved_fun_invocation"))
    assert Enum.map(findings, & &1.line) == [2]
    assert length(result.unresolved_dispatch) == 1

    nested =
      erlang(
        context,
        "run(C) ->\n {_,F}={C(),fun() -> ok end},\n F()."
      )

    assert Enum.map(nested.unresolved_dispatch, & &1.line) == [2]
  end

  test "A12 partial tuple SSL and metadispatch components cannot become safe", context do
    for body <- [
          "run(X) -> {_,M}={X,ssl}, M:connect(localhost,443,[]).",
          "run(X) -> {_,F}={X,fun ssl:connect/3}, F(localhost,443,[]).",
          "run(X) -> {_,F}={X,fun() -> ssl:connect(localhost,443,[]) end}, F().",
          "run(X) -> {_,F}={X,fun erlang:apply/3}, F(ssl,connect,[]).",
          "run(X) -> {{_,M},F}={{X,ssl},fun() -> ok end}, M:connect(localhost,443,[]), F()."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "A13 tuple shape gaps and nested formal shadowing remain unknown", context do
    for body <- [
          "run(X,C) -> {_,F}=case X of a -> {X,fun() -> ok end}; _ -> C end, F().",
          "run(X) -> {_,F}=case X of a -> {X,fun() -> ok end}; _ -> {X,fun() -> ok end,extra} end, F().",
          "run(X,C) -> {_,F}={X,fun() -> ok end}, (fun(F) -> F() end)(C)."
        ] do
      assert unsafe?(erlang(context, body)), body
    end
  end

  test "A14 guard and tuple proof budgets and mutated producers fail closed", context do
    for count <- [16, 17] do
      guards = Enum.map_join(1..count, "; ", fn n -> "M == m#{n}" end)
      result = erlang(context, "run(M) when " <> guards <> " -> M:f().")
      assert result.unresolved_dispatch == [] == (count == 16)
    end

    alternatives =
      Enum.map_join(1..17, "; ", fn n -> "#{n} -> {X,fun m#{n}:f/0}" end)

    assert unsafe?(erlang(context, "run(X) -> {_,F}=case X of " <> alternatives <> " end, F()."))

    huge = Enum.map_join(1..9_000, ",", &Integer.to_string/1)

    assert unsafe?(
             erlang(context, "run(M,X) when M == lists, X =:= {" <> huge <> "} -> M:reverse([]).")
           )

    assert unsafe?(erlang(context, "run(X) -> {F,_}={fun() -> ok end,{" <> huge <> "}}, F(), X."))

    safe = erlang(context, "run(X,C) -> {_,F}={X,fun() -> ok end}, F(), C.")
    changed = erlang(context, "run(X,C) -> {_,F}={X,C}, F().")
    assert safe.unresolved_dispatch == []
    assert safe.sha256 != changed.sha256
    assert unsafe?(changed)
  end

  test "C01 literal helper arguments survive an unrelated mutual caller cycle", context do
    body = """
    run() -> first(a).
    first(a) -> helper(fun() -> ok end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    helper(F) -> F().
    """

    assert private_erlang(context, body).unresolved_dispatch == []
  end

  test "C02 every independent caller must supply a literal closure", context do
    body = """
    run(X) -> first(X).
    first(a) -> helper(fun() -> one end), second(b);
    first(b) -> helper(fun() -> two end);
    first(_) -> ok.
    second(X) -> first(X).
    helper(F) -> F().
    """

    assert private_erlang(context, body, "run/1").unresolved_dispatch == []
    changed = String.replace(body, "helper(fun() -> two end)", "helper(X)")
    # Keep the changed branch variable bound, without relying on unreachable code.
    changed = String.replace(changed, "first(b) ->", "first(X) when X =:= b ->")
    assert unsafe?(private_erlang(context, changed, "run/1"))
  end

  test "C03 private forwarding uses argument dependencies rather than caller SCCs", context do
    body = """
    run() -> first(a).
    first(a) -> wrapper(unknown, fun() -> ok end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    wrapper(State,F) -> helper(State,F,nil).
    helper(_State,F,_Context) -> F().
    """

    assert private_erlang(context, body).unresolved_dispatch == []
  end

  test "C04 actual Elixir default wrapper forwards only its proven callback parameter", context do
    source = """
    defmodule NoOTPAuditIndependentClosureFixture do
      def run(value), do: first(value)
      defp first(:a) do
        guarded(%{}, 1, fn -> :ok end)
        second(:b)
      end
      defp first(_), do: :ok
      defp second(value), do: first(value)
      defp guarded(state, timeout, fun, context \\\\ nil) do
        {state, timeout, context, fun.()}
      end
    end
    """

    [{module, bytes}] = Code.compile_string(source)

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
    end)

    assert audit(context, module, bytes).unresolved_dispatch == []
  end

  test "C05 an additional unknown direct caller poisons the callback parameter", context do
    body = """
    run(X) -> first(a), extra(X).
    first(a) -> wrapper(fun() -> ok end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    extra(F) -> helper(F).
    wrapper(F) -> helper(F).
    helper(F) -> F().
    """

    assert unsafe?(private_erlang(context, body, "run/1"))
  end

  test "C06 nested unsafe closure bodies retain their original occurrence", context do
    body = """
    run() -> first(a).
    first(a) -> M=ssl, helper(fun() -> M:connect(localhost,443,[]) end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    helper(F) -> F().
    """

    result = private_erlang(context, body)
    assert unsafe?(result)
    assert Enum.any?(result.unresolved_dispatch, &(&1.line == 2))
    refute Enum.any?(result.unresolved_dispatch, &(&1.line == 5))
  end

  test "C07 nested unknown captured callbacks remain unresolved", context do
    body = """
    run(F) -> first(a,F).
    first(a,F) -> helper(fun() -> F() end), second(b,F);
    first(_,_) -> ok.
    second(X,F) -> first(X,F).
    helper(F) -> F().
    """

    result = private_erlang(context, body, "run/1")
    assert Enum.any?(result.unresolved_dispatch, &(&1.line == 2))
    refute Enum.any?(result.unresolved_dispatch, &(&1.line == 5))
  end

  test "C08 returned or passed captures keep helper parameters open", context do
    for escape <- ["fun helper/1", "lists:map(fun helper/1,[])"] do
      body = """
      run() -> first(a), #{escape}.
      first(a) -> helper(fun() -> ok end), second(b);
      first(_) -> ok.
      second(X) -> first(X).
      helper(F) -> F().
      """

      assert unsafe?(private_erlang(context, body)), escape
    end
  end

  test "C09 explicit exports and export_all keep independent closure domains open", context do
    body = """
    run() -> first(a).
    first(a) -> helper(fun() -> ok end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    helper(F) -> F().
    """

    assert unsafe?(private_erlang(context, body, "run/0,helper/1"))
    assert unsafe?(private_erlang(context, body, "run/0", "-compile(export_all). "))
    assert unsafe?(private_erlang(context, body, "run/0", "", [:export_all]))
  end

  test "C10 direct self recursive callers stay outside the new proof", context do
    for body <- [
          "run() -> first(). first() -> first(), helper(fun() -> ok end). helper(F) -> F().",
          "run() -> first(a). first(a) -> helper(fun() -> ok end), first(b); first(_) -> ok. helper(F) -> F()."
        ] do
      assert unsafe?(private_erlang(context, body)), body
    end
  end

  test "C11 recursive parameter cycles cannot assume their own closure seed", context do
    for entry <- ["first(fun() -> ok end)", "ok"] do
      body = """
      run() -> #{entry}.
      first(F) -> second(F).
      second(F) -> helper(F), first(F).
      helper(F) -> F().
      """

      assert unsafe?(private_erlang(context, body)), entry
    end
  end

  test "C12 forwarding inside a shadowing anonymous clause remains unknown", context do
    body = """
    run() -> first(a).
    first(a) -> wrapper(fun() -> ok end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    wrapper(F) -> fun(F) -> helper(F) end.
    helper(F) -> F().
    """

    assert unsafe?(private_erlang(context, body))
  end

  test "C13 generic exported callbacks gain no external origin exception", context do
    for body <- [
          "run(F) -> F().",
          "run(F) -> first(a,F). first(a,F) -> helper(F), second(b,F); first(_,_) -> ok. second(X,F) -> first(X,F). helper(F) -> F()."
        ] do
      assert unsafe?(private_erlang(context, body, "run/1")), body
    end
  end

  test "C14 unknown callers remain obligations even without a known entry path", context do
    body = """
    run() -> first(a).
    first(a) -> helper(fun() -> ok end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    unused(F) -> helper(F).
    helper(F) -> F().
    """

    assert unsafe?(private_erlang(context, body))
  end

  test "C15 named captures do not become anonymous closure identities", context do
    for target <- ["lists:reverse/1", "ssl:connect/3"] do
      body = """
      run() -> first(a).
      first(a) -> helper(fun #{target}), second(b);
      first(_) -> ok.
      second(X) -> first(X).
      helper(F) -> erlang:apply(F,[]).
      """

      assert unsafe?(private_erlang(context, body)), target
    end
  end

  test "C16 unknown wrapper default does not join a proven callback alternative", context do
    body = """
    run(X) -> first(a), helper(X).
    first(a) -> helper(fun() -> ok end), second(b);
    first(_) -> ok.
    second(X) -> first(X).
    helper(F) -> guarded(F,nil).
    guarded(F,_Context) -> F().
    """

    assert unsafe?(private_erlang(context, body, "run/1"))
  end

  defp unsafe?(result),
    do: result.unresolved_dispatch != [] or result.otp_ssl_imports != []

  defp erlang(context, body, extra \\ "") do
    source = "-module(no_otp_audit_fixture). -compile(export_all). " <> extra <> body
    compile_erlang(context, source, [])
  end

  test "B01 selected compiled producer bodies prove nine collector calls without invocation",
       context do
    fixture = b_fixture(context)
    result = b_run(context, fixture)
    assert result.unresolved_dispatch == []
    assert result.otp_ssl_imports == []
  end

  test "B02 current in-release unloaded producers remain usable without loading", context do
    fixture = b_fixture(context, load: false)
    assert b_run(context, fixture).unresolved_dispatch == []
    assert :code.is_loaded(fixture.protocol) == false
    assert :code.is_loaded(fixture.collector) == false
  end

  test "B03 producer module names carry no exemption", context do
    fixture = b_fixture(context, collector_body: "into(_) -> {[], external:callback()}.")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B04 every collector branch retains direct unsafe calls", context do
    for stage <- [:cont, :done, :halt] do
      fixture = b_fixture(context, unsafe_stage: stage)
      assert b_open_count(b_run(context, fixture)) == 9
      b_remove(fixture)
    end
  end

  test "B05 nested anonymous collector bodies retain unsafe calls", context do
    fixture = b_fixture(context, cont_body: "fun() -> ssl:connect(localhost,443,[]) end, [X|L]")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B06 callable collector input remains unknown", context do
    fixture = b_fixture(context, cont_body: "X()")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B07 an earlier matching protocol clause overrides the ordinary producer", context do
    fixture = b_fixture(context, prefix_clause: "impl(_) -> external; ")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B08 unknown earlier protocol guard cannot be ignored", context do
    fixture =
      b_fixture(context, prefix_clause: "impl(M) when erlang:map_size(M) > 0 -> external; ")

    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B09 changed implementation selection is rechecked on every audit", context do
    fixture = b_fixture(context, target: "unknown_b_producer")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B10 missing producer debug information is unproved", context do
    fixture = b_fixture(context, debug: false)
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B11 a missing selected file is unproved", context do
    fixture = b_fixture(context)
    File.rm!(fixture.collector_path)
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B12 changed loaded bytes cannot use stale debug forms", context do
    fixture = b_fixture(context)

    changed =
      b_compile(
        fixture.collector,
        "-export([into/1]). into(_) -> {[], fun(_,_) -> ssl:connect(localhost,443,[]) end}.",
        true
      )

    File.write!(fixture.collector_path, changed)
    assert :code.module_status(fixture.collector) == :modified
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B13 code path shadowing cannot substitute for the loaded path", context do
    fixture = b_fixture(context)
    shadow = Path.join(Path.dirname(fixture.directory), "shadow-ebin")
    File.mkdir_p!(shadow)

    File.cp!(
      fixture.collector_path,
      Path.join(shadow, Atom.to_string(fixture.collector) <> ".beam")
    )

    true = :code.add_patha(String.to_charlist(shadow))
    on_exit(fn -> :code.del_path(String.to_charlist(shadow)) end)
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B14 runtime selection reordering is rechecked after a successful audit", context do
    fixture = b_fixture(context)
    assert b_run(context, fixture).unresolved_dispatch == []
    shadow = Path.join(Path.dirname(fixture.directory), "reordered-ebin")
    File.mkdir_p!(shadow)

    File.cp!(
      fixture.protocol_path,
      Path.join(shadow, Atom.to_string(fixture.protocol) <> ".beam")
    )

    true = :code.add_patha(String.to_charlist(shadow))
    on_exit(fn -> :code.del_path(String.to_charlist(shadow)) end)
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B15 external loaded producer paths cannot borrow owned release bytes", context do
    fixture = b_fixture(context, external: true)
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B16 a symlinked producer path is noncanonical", context do
    fixture = b_fixture(context, load: false)
    link = fixture.directory <> "-link"
    File.ln_s!(fixture.directory, link)
    true = :code.add_patha(String.to_charlist(link))
    on_exit(fn -> :code.del_path(String.to_charlist(link)) end)
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B17 unknown collector seed is not a literal-map proof", context do
    fixture = b_fixture(context)
    assert b_open_count(b_run(context, fixture, "Input")) == 9
  end

  test "B18 recursive producer return never receives a proof", context do
    fixture = b_fixture(context, collector_body: "into(M) -> into(M).")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B19 collector local helpers cannot hide unscanned dispatch", context do
    for call <- ["hidden(), [X|L]", :remote_hidden] do
      fixture =
        b_fixture(context,
          cont_body: call,
          extra: "hidden() -> M=ssl, M:connect(localhost,443,[])."
        )

      assert b_open_count(b_run(context, fixture)) == 9
      b_remove(fixture)
    end
  end

  test "B20 a safe returned tuple does not erase unsafe producer statements", context do
    fixture = b_fixture(context, producer_prefix: "ssl:connect(localhost,443,[]), ")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B21 an unsafe unselected producer body remains an obligation", context do
    fixture = b_fixture(context, fallback: "ssl:connect(localhost,443,[])")
    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B22 skipped protocol alternatives may not supply a collector", context do
    fixture =
      b_fixture(context,
        prefix_clause: "impl(\#{'__struct__' := missing_b_struct}) -> external; "
      )

    assert b_run(context, fixture).unresolved_dispatch == []
  end

  test "B23 unknown struct implementation and missing map fields fail closed", context do
    fixture = b_fixture(context)

    for input <- [
          "\#{'__struct__' => other_b_struct, map => \#{}}",
          "\#{'__struct__' => b_struct}"
        ] do
      assert b_open_count(b_run(context, fixture, input)) == 9
    end
  end

  test "B24 collector construction never executes the returned function", context do
    fixture = b_fixture(context, cont_body: "erlang:error(audit_must_not_execute)")
    assert b_run(context, fixture).unresolved_dispatch == []
  end

  # Only generated trusted fixture modules may be loaded. No production module
  # is loaded, replaced, invoked or evaluated by these helpers or by the auditor.
  defp b_fixture(context, options \\ []) do
    suffix = Integer.to_string(System.unique_integer([:positive]))
    protocol = String.to_atom("no_otp_b_protocol_" <> suffix)
    collector = String.to_atom("no_otp_b_collector_" <> suffix)
    release = context.ebin |> Path.dirname() |> Path.dirname() |> Path.dirname() |> b_physical()
    System.put_env("NO_OTP_RELEASE", release)
    System.put_env("NO_OTP_PROJECT", release)
    directory = Path.join(release, "lib/elixir-b-" <> suffix <> "/ebin")
    File.mkdir_p!(directory)

    File.write!(
      Path.join(directory, "elixir.app"),
      "{application,elixir,[{vsn,\"b\"},{applications,[]}]}."
    )

    selected =
      if options[:external],
        do: Path.join(System.tmp_dir!(), "no-otp-b-external-" <> suffix),
        else: directory

    File.mkdir_p!(selected)
    fallback = Keyword.get(options, :fallback, "nil")
    target = Keyword.get(options, :target, Atom.to_string(collector))

    protocol_source = """
    -export([into/1]).
    into(M) -> (selected(M)):into(M).
    selected(M) -> case impl(M) of I when I =:= false orelse I =:= nil -> erlang:error(no_impl); I -> I end.
    #{Keyword.get(options, :prefix_clause, "")}
    impl(\#{'__struct__' := S}) when erlang:is_atom(S) -> struct_impl(S);
    impl(_) -> #{fallback}.
    struct_impl(b_struct) -> #{target};
    struct_impl(_) -> nil.
    """

    cont = Keyword.get(options, :cont_body, "[X|L]")
    remote_hidden? = cont == :remote_hidden
    cont = if remote_hidden?, do: Atom.to_string(collector) <> ":hidden(), [X|L]", else: cont
    done = "M\#{map := sets:union(S,sets:from_list(L,[{version,2}]))}"
    halt = "ok"
    unsafe = "ssl:connect(localhost,443,[])"
    cont = if options[:unsafe_stage] == :cont, do: unsafe, else: cont
    done = if options[:unsafe_stage] == :done, do: unsafe, else: done
    halt = if options[:unsafe_stage] == :halt, do: unsafe, else: halt

    default_body = """
    into(\#{'__struct__' := b_struct, map := S}=M) ->
      #{Keyword.get(options, :producer_prefix, "")}
      F=fun(L,{cont,X}) -> #{cont}; (L,done) -> #{done}; (_,halt) -> #{halt} end,
      {[],F}.
    #{Keyword.get(options, :extra, "")}
    """

    exports = if remote_hidden?, do: "-export([into/1,hidden/0]). ", else: "-export([into/1]). "
    collector_source = exports <> Keyword.get(options, :collector_body, default_body)
    debug = Keyword.get(options, :debug, true)
    entries = [{protocol, protocol_source}, {collector, collector_source}]

    fixture = %{
      protocol: protocol,
      collector: collector,
      directory: selected,
      protocol_path: Path.join(selected, Atom.to_string(protocol) <> ".beam"),
      collector_path: Path.join(selected, Atom.to_string(collector) <> ".beam")
    }

    on_exit(fn ->
      b_remove(fixture)
      if selected != directory, do: File.rm_rf!(selected)
    end)

    true = :code.add_patha(String.to_charlist(selected))

    for {module, source} <- entries do
      assert :code.is_loaded(module) == false
      bytes = b_compile(module, source, debug)
      path = Path.join(selected, Atom.to_string(module) <> ".beam")
      File.write!(path, bytes)

      if selected != directory,
        do: File.write!(Path.join(directory, Atom.to_string(module) <> ".beam"), bytes)

      if Keyword.get(options, :load, true),
        do:
          assert({:module, ^module} = :code.load_binary(module, String.to_charlist(path), bytes))
    end

    fixture
  end

  defp b_remove(fixture) do
    for module <- [fixture.protocol, fixture.collector] do
      :code.purge(module)
      :code.delete(module)
      :code.purge(module)
    end

    :code.del_path(String.to_charlist(fixture.directory))
  end

  defp b_compile(module, body, debug) do
    source = "-module(" <> Atom.to_string(module) <> "). " <> body
    {:ok, tokens, _} = :erl_scan.string(String.to_charlist(source))

    forms =
      tokens
      |> Enum.chunk_by(&match?({:dot, _}, &1))
      |> Enum.chunk_every(2)
      |> Enum.map(fn [form, dot] ->
        {:ok, parsed} = :erl_parse.parse_form(form ++ dot)
        parsed
      end)

    refute Enum.any?(forms, &match?({:attribute, _, :on_load, _}, &1))

    options =
      [:binary, :return_errors, :return_warnings] ++ if(debug, do: [:debug_info], else: [])

    assert {:ok, ^module, bytes, _warnings} = :compile.forms(forms, options)
    bytes
  end

  defp b_run(context, fixture, input \\ "\#{'__struct__' => b_struct, map => \#{}}") do
    body =
      for name <- ["ledger", "scope_processes", "scope_sockets"] do
        "#{name}(Input) -> {A,F}=" <>
          Atom.to_string(fixture.protocol) <>
          ":into(" <>
          input <>
          "), F(A,{cont,x}), F(A,done), F(A,halt)."
      end

    private_erlang(context, Enum.join(body, "\n"), "ledger/1,scope_processes/1,scope_sockets/1")
  end

  defp b_open_count(result),
    do: Enum.count(result.unresolved_dispatch, &(&1.kind == "unresolved_fun_invocation"))

  # Resolve the trusted test-created directory so macOS /var and /tmp aliases
  # do not accidentally turn positive fixtures into noncanonical negatives.
  defp b_physical(path, remaining \\ 16)
  defp b_physical(_path, 0), do: raise("fixture symlink depth exceeded")

  defp b_physical(path, remaining) do
    Path.expand(path)
    |> Path.split()
    |> Enum.reduce("", fn part, parent ->
      candidate = if parent == "", do: part, else: Path.join(parent, part)

      case File.read_link(candidate) do
        {:ok, target} -> b_physical(Path.expand(target, Path.dirname(candidate)), remaining - 1)
        {:error, :einval} -> candidate
        other -> raise("fixture path cannot be resolved: #{inspect(other)}")
      end
    end)
  end

  test "B25 a proven bound map key cannot skip an actually matching unsafe branch", context do
    fixture =
      b_map_fixture(context, """
      into(M) -> K=map, case M of
        \#{K := _} -> __UNPROVED_HELPER__:into(M);
        _ -> {[], fun(_,_) -> ok end}
      end.
      """)

    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B26 repeated map bindings compare map contents independent of field order", context do
    for bound <- ["\#{a => 1, b => 2}", "{\#{a => 1, b => 2}, ok}"] do
      matched = String.replace(bound, "a => 1, b => 2", "b => 2, a => 1")

      body =
        "into(M) -> Bound=" <>
          bound <>
          ", case " <>
          matched <>
          " of Bound -> __UNPROVED_HELPER__:into(M); _ -> {[], fun(_,_) -> ok end} end."

      fixture = b_map_fixture(context, body)
      assert b_open_count(b_run(context, fixture)) == 9
      b_remove(fixture)
    end
  end

  test "B27 repeated map bindings ignore different debug source annotations", context do
    fixture =
      b_map_fixture(context, """
      into(M) ->
        Bound=\#{a => 1, b => 2},
        case \#{a => 1, b => 2} of
          Bound -> __UNPROVED_HELPER__:into(M);
          _ -> {[], fun(_,_) -> ok end}
        end.
      """)

    assert b_open_count(b_run(context, fixture)) == 9
  end

  test "B28 unsupported compound map key expressions remain unknown", context do
    fixture =
      b_map_fixture(context, """
      into(M) -> K=map, case M of
        \#{{K, tag} := _} -> __UNPROVED_HELPER__:into(M);
        _ -> {[], fun(_,_) -> ok end}
      end.
      """)

    input = "\#{'__struct__' => b_struct, map => \#{}, {map,tag} => present}"
    assert b_open_count(b_run(context, fixture, input)) == 9
  end

  test "B29 semantic duplicate map keys cannot select an overwritten first value", context do
    fixture =
      b_map_fixture(
        context,
        "into(M) -> case M of \#{\#{a => 1, b => 2} := unsafe} -> __UNPROVED_HELPER__:into(M); _ -> {[], fun(_,_) -> ok end} end."
      )

    input =
      "\#{'__struct__' => b_struct, map => \#{}, \#{a => 1, b => 2} => safe, \#{b => 2, a => 1} => unsafe}"

    assert b_open_count(b_run(context, fixture, input)) == 9
  end

  test "B30 map keys compare contents independent of key map field order", context do
    fixture =
      b_map_fixture(
        context,
        "into(M) -> case M of \#{\#{b => 2, a => 1} := unsafe} -> __UNPROVED_HELPER__:into(M); _ -> {[], fun(_,_) -> ok end} end."
      )

    input = "\#{'__struct__' => b_struct, map => \#{}, \#{a => 1, b => 2} => unsafe}"
    assert b_open_count(b_run(context, fixture, input)) == 9
  end

  test "B31 supported atom and integer map keys retain exact Erlang identity", context do
    fixture =
      b_map_fixture(
        context,
        "into(M) -> case M of \#{true := unsafe} -> __UNPROVED_HELPER__:into(M); _ -> {[], fun(_,_) -> ok end} end."
      )

    unsafe = "\#{'__struct__' => b_struct, map => \#{}, 1 => safe, true => unsafe}"
    safe = "\#{'__struct__' => b_struct, map => \#{}, 1 => unsafe, true => safe}"
    assert b_open_count(b_run(context, fixture, unsafe)) == 9
    assert b_run(context, fixture, safe).unresolved_dispatch == []
  end

  test "B32 unsupported float keys never collapse into numerically equal integer keys", context do
    fixture =
      b_map_fixture(
        context,
        "into(M) -> case M of \#{1.0 := unsafe} -> __UNPROVED_HELPER__:into(M); _ -> {[], fun(_,_) -> ok end} end."
      )

    input = "\#{'__struct__' => b_struct, map => \#{}, 1 => safe, 1.0 => unsafe}"
    assert b_open_count(b_run(context, fixture, input)) == 9
  end

  # Earlier matching branches call this actual generated auxiliary module. Its
  # returned closure is unsafe, but neither helper nor closure is ever invoked.
  # A buggy proof that skips that branch sees only the later safe literal fun.
  defp b_map_fixture(context, body) do
    fixture = b_fixture(context)
    helper = String.to_atom(Atom.to_string(fixture.collector) <> "_unproved")
    helper_path = Path.join(fixture.directory, Atom.to_string(helper) <> ".beam")
    assert :code.is_loaded(helper) == false

    on_exit(fn ->
      :code.purge(helper)
      :code.delete(helper)
      :code.purge(helper)
    end)

    helper_source =
      "-export([into/1]). into(_) -> {[], fun(_,_) -> ssl:connect(localhost,443,[]) end}."

    helper_bytes = b_compile(helper, helper_source, true)
    File.write!(helper_path, helper_bytes)

    assert {:module, ^helper} =
             :code.load_binary(helper, String.to_charlist(helper_path), helper_bytes)

    source =
      "-export([into/1]). " <>
        String.replace(body, "__UNPROVED_HELPER__", Atom.to_string(helper))

    bytes = b_compile(fixture.collector, source, true)
    :code.purge(fixture.collector)
    :code.delete(fixture.collector)
    :code.purge(fixture.collector)
    File.write!(fixture.collector_path, bytes)
    module = fixture.collector

    assert {:module, ^module} =
             :code.load_binary(module, String.to_charlist(fixture.collector_path), bytes)

    fixture
  end

  defp private_erlang(context, body, exports \\ "run/0", extra \\ "", options \\ []) do
    source = "-module(no_otp_audit_fixture). -export([" <> exports <> "]). " <> extra <> body
    compile_erlang(context, source, options)
  end

  defp compile_erlang(context, source, options) do
    {:ok, tokens, _} = :erl_scan.string(String.to_charlist(source))

    forms =
      tokens
      |> Enum.chunk_by(&match?({:dot, _}, &1))
      |> Enum.chunk_every(2)
      |> Enum.map(fn [form, dot] ->
        {:ok, parsed} = :erl_parse.parse_form(form ++ dot)
        parsed
      end)

    assert {:ok, module, bytes, _warnings} =
             :compile.forms(
               forms,
               [:binary, :debug_info, :return_errors, :return_warnings, :nowarn_export_all] ++
                 options
             )

    audit(context, module, bytes)
  end

  defp audit(context, module, bytes) do
    File.write!(Path.join(context.ebin, Atom.to_string(module) <> ".beam"), bytes)
    [result] = NoOTP.ReleaseAudit.artifacts().beam_inspections
    result
  end

  # R: finite same-module atom returns, with all original controls retained.
  test "R01 compiled SSE-shaped selector covers both literal module returns", context do
    source = """
    defmodule NoOTPAuditReturnSelectorFixture do
      def close(state), do: stream_module(state).close(:socket)
      def ack(state), do: stream_module(state).acknowledge(:stream, :ref)
      defp stream_module(%{options: %{http_version: :http3}}), do: SafeH3
      defp stream_module(_state), do: SafeH2
    end
    """

    [{module, bytes}] = Code.compile_string(source)

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
    end)

    assert audit(context, module, bytes).unresolved_dispatch == []
  end

  test "R02 one unknown normal return poisons all-input selector summaries", context do
    for body <- [
          "run(X) -> (pick(X)):f(). pick(a) -> lists; pick(M) -> M.",
          "run(X) -> (pick(X)):f(). pick(X) -> case X of a -> lists; M -> M end.",
          "run(X) -> (pick(a)):f(), X. pick(a) -> lists; pick(M) -> M."
        ] do
      assert unsafe?(private_erlang(context, body, "run/1")), body
    end
  end

  test "R03 unsafe atom returns remain unsafe at every selector consumer", context do
    body = "run(X) -> (pick(X)):f(). pick(a) -> lists; pick(_) -> ssl."
    result = private_erlang(context, body, "run/1")
    assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["literal_module_ssl"]
  end

  test "R04 nested unsafe producer bodies are scanned exactly once", context do
    body = """
    run(X) -> (pick(X)):f().
    pick(_) -> _F=fun() -> ssl:connect(localhost,443,[]) end, lists.
    """

    result = private_erlang(context, body, "run/1")

    assert Enum.map(result.unresolved_dispatch, &{&1.line, &1.kind}) ==
             [{2, "literal_module_ssl"}]
  end

  test "R05 producer arguments retain their nested unsafe occurrence once", context do
    body = """
    run() -> (pick(fun() -> ssl:connect(localhost,443,[]) end)):f().
    pick(_) -> lists.
    """

    result = private_erlang(context, body)

    assert Enum.map(result.unresolved_dispatch, &{&1.line, &1.kind}) ==
             [{1, "literal_module_ssl"}]
  end

  test "R06 unsafe captures and shadowed callbacks in producers remain obligations", context do
    capture = """
    run(X) -> (pick(X)):f().
    pick(_) -> _F=fun ssl:connect/3, lists.
    """

    shadow = """
    run(X) -> (pick(X)):f().
    pick(F) -> _G=fun(F) -> F() end, lists.
    """

    assert Enum.map(
             private_erlang(context, capture, "run/1").unresolved_dispatch,
             &{&1.line, &1.kind}
           ) ==
             [{2, "literal_fun_ssl"}]

    assert Enum.map(
             private_erlang(context, shadow, "run/1").unresolved_dispatch,
             &{&1.line, &1.kind}
           ) ==
             [{2, "unresolved_fun_invocation"}]
  end

  test "R07 a literal base clause cannot certify a self-recursive selector", context do
    for body <- [
          "run(X) -> (pick(X)):f(). pick(0) -> lists; pick(N) -> pick(N-1).",
          "run(X) -> (pick(X)):f(). pick(X) -> pick(X), lists."
        ] do
      assert unsafe?(private_erlang(context, body, "run/1")), body
    end
  end

  test "R08 mutual return cycles and dependent wrappers remain unknown", context do
    body = """
    run(X) -> (wrapper(X)):f().
    wrapper(X) -> first(X).
    first(0) -> lists; first(X) -> second(X).
    second(X) -> first(X).
    """

    assert unsafe?(private_erlang(context, body, "run/1"))

    captured = """
    run(X) -> (first(X)):f().
    first(X) -> F=fun second/1, F(X), lists.
    second(X) -> first(X).
    """

    assert unsafe?(private_erlang(context, captured, "run/1"))
  end

  test "R09 a compiled default wrapper inherits only the all-input return summary", context do
    source = """
    defmodule NoOTPAuditReturnDefaultFixture do
      def run(value), do: select(value).f()
      defp select(value, mode \\\\ :default)
      defp select(:first, _mode), do: SafeFirst
      defp select(_value, _mode), do: SafeSecond
    end
    """

    [{module, bytes}] = Code.compile_string(source)

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
    end)

    assert audit(context, module, bytes).unresolved_dispatch == []
  end

  test "R10 a returned atom binding never leaks through shadowed formals", context do
    body = "run(F) -> M=pick(F), (fun(M) -> M:f() end)(F). pick(_) -> lists."
    result = private_erlang(context, body, "run/1")
    assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["unresolved_module_dispatch"]
  end

  test "R11 local aliases and every case branch contribute their atom result", context do
    body = """
    run(X) -> (pick(X)):f().
    pick(X) -> M=case X of a -> lists; _ -> maps end, M.
    """

    assert private_erlang(context, body, "run/1").unresolved_dispatch == []
  end

  test "R12 unproved error try and external return branches stay unknown", context do
    for producer <- [
          "pick(X) -> case X of a -> lists; _ -> erlang:error(no_return_claim) end.",
          "pick(X) -> try X() of _ -> lists catch _:_ -> maps end.",
          "pick(X) -> case X of a -> lists; _ -> external:pick(X) end.",
          "pick(_) -> <<\"lists\">>."
        ] do
      body = "run(X) -> (pick(X)):f(). " <> producer
      assert unsafe?(private_erlang(context, body, "run/1")), producer
    end
  end

  test "R13 atom union and function byte bounds fail closed without truncation", context do
    for count <- [16, 17] do
      clauses = Enum.map_join(1..count, "; ", &"pick(#{&1}) -> m#{&1}")
      body = "run(X) -> (pick(X)):f(). " <> clauses <> "."
      result = private_erlang(context, body, "run/1")
      assert result.unresolved_dispatch == [] == (count == 16)
    end

    huge = Enum.map_join(1..9_000, ",", &Integer.to_string/1)
    body = "run(X) -> (pick(X)):f(). pick(_) -> {" <> huge <> "}, lists."
    assert unsafe?(private_erlang(context, body, "run/1"))
  end

  test "R14 module function call and node budgets retain selector findings", context do
    helpers = Enum.map_join(1..255, " ", &"unused#{&1}() -> ok.")
    body = "run(X) -> (pick(X)):f(). pick(_) -> lists. " <> helpers
    assert unsafe?(private_erlang(context, body, "run/1"))

    calls = Enum.map_join(1..4_097, ",", fn _ -> "pick(X)" end)
    body = "run(X) -> " <> calls <> ", (pick(X)):f(). pick(_) -> lists."
    assert unsafe?(private_erlang(context, body, "run/1"))

    literal = String.duplicate("x", 100_001)
    body = "run(X) -> \"" <> literal <> "\", (pick(X)):f(). pick(_) -> lists."
    assert unsafe?(private_erlang(context, body, "run/1"))
  end

  test "R15 a returned atom invoked as a fun is not a source-level local call", context do
    for body <- [
          "run(X) -> F=pick(X), F(). pick(_) -> lists.",
          "run(X) -> (pick(X))(). pick(_) -> lists."
        ] do
      result = private_erlang(context, body, "run/1")
      assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["unresolved_fun_invocation"]
    end
  end

  test "R16 return assignments and private argument propagation remain outside this slice",
       context do
    safe = """
    run(X) -> helper(pick(X)).
    pick(a) -> lists; pick(_) -> maps.
    helper(M) -> M:f().
    """

    assert unsafe?(private_erlang(context, safe, "run/1"))
    assigned = "run(X) -> M=pick(X), M:f(). pick(_) -> lists."
    assert unsafe?(private_erlang(context, assigned, "run/1"))

    changed =
      String.replace(safe, "run(X) -> helper(pick(X))", "run(X,M) -> helper(pick(X)), helper(M)")

    assert unsafe?(private_erlang(context, changed, "run/2"))
  end

  test "R17 returned metadispatch names and module captures retain unsafe checks", context do
    for body <- [
          "run(X) -> (pick(X)):apply(ssl,connect,[]). pick(_) -> erlang.",
          "run(X) -> M=pick(X), F=fun M:connect/3, F(localhost,443,[]). pick(_) -> ssl.",
          "run(X) -> M=pick(X), erlang:spawn(M,connect,[]). pick(_) -> ssl."
        ] do
      assert unsafe?(private_erlang(context, body, "run/1")), body
    end
  end

  test "R18 return summaries never execute producer side effects", context do
    Process.delete(:audit_return_producer_executed)

    body = """
    run(X) -> (pick(X)):f().
    pick(_) -> erlang:put(audit_return_producer_executed,true), lists.
    """

    assert private_erlang(context, body, "run/1").unresolved_dispatch == []
    assert Process.get(:audit_return_producer_executed) == nil
  end

  # R19-R24: immediate case wrappers retain the narrow receiver proof boundary.
  test "R19 immediate case receivers use every normal-return atom", context do
    body = """
    run(X) -> case wrapper(X) of M -> M:f() end.
    wrapper(X) -> pick(X).
    pick(first) -> lists; pick(_) -> maps.
    """

    assert private_erlang(context, body, "run/1").unresolved_dispatch == []
  end

  test "R20 immediate case summaries retain unknown cycle and union bounds", context do
    for producer <- [
          "pick(first) -> lists; pick(M) -> M.",
          "pick(0) -> lists; pick(N) -> pick(N-1).",
          "pick(X) -> other(X). other(X) -> pick(X).",
          "pick(X) -> external:pick(X)."
        ] do
      body = "run(X) -> case pick(X) of M -> M:f() end. " <> producer
      assert unsafe?(private_erlang(context, body, "run/1")), producer
    end

    for count <- [16, 17] do
      clauses = Enum.map_join(1..count, "; ", &"pick(#{&1}) -> m#{&1}")
      body = "run(X) -> case pick(X) of M -> M:f() end. " <> clauses <> "."
      result = private_erlang(context, body, "run/1")
      assert result.unresolved_dispatch == [] == (count == 16)
    end
  end

  test "R21 immediate case proof does not become general binding propagation", context do
    for body <- [
          "run(X) -> case pick(X) of M when is_atom(M) -> M:f() end. pick(_) -> lists.",
          "run(X) -> case pick(X) of M -> external:effect(), M:f() end. pick(_) -> lists.",
          "run(X,N) -> case pick(X) of _M -> N:f() end. pick(_) -> lists.",
          "run(X) -> M=case pick(X) of N -> N end, M:f(). pick(_) -> lists.",
          "run(X) -> case pick(X) of M -> helper(M) end. pick(_) -> lists. helper(M) -> M:f().",
          "run(X) -> case external:pick(X) of M -> M:f() end."
        ] do
      exports = if String.starts_with?(body, "run(X,N)"), do: "run/2", else: "run/1"
      assert unsafe?(private_erlang(context, body, exports)), body
    end
  end

  test "R22 case producer other branches and nested arguments are scanned once", context do
    body = """
    run(X) -> case pick(fun() -> ssl:connect(localhost,443,[]) end) of
      \#{f := _F} -> ssl:connect(localhost,443,[]);
      M -> M:f(fun() -> ssl:connect(localhost,443,[]) end)
    end.
    pick(_) -> _F=fun() -> ssl:connect(localhost,443,[]) end, lists.
    """

    result = private_erlang(context, body, "run/1")

    assert Enum.map(result.unresolved_dispatch, &{&1.line, &1.kind}) ==
             [
               {1, "literal_module_ssl"},
               {2, "literal_module_ssl"},
               {3, "literal_module_ssl"},
               {5, "literal_module_ssl"}
             ]
  end

  test "R23 immediate case receivers retain unsafe and dynamic function checks", context do
    body = "run(X) -> case pick(X) of M -> M:f() end. pick(_) -> ssl."
    result = private_erlang(context, body, "run/1")
    assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["literal_module_ssl"]

    metadispatch = """
    run(X) -> case pick(X) of M -> M:apply(ssl,connect,[]) end.
    pick(_) -> erlang.
    """

    assert unsafe?(private_erlang(context, metadispatch, "run/1"))

    dynamic = "run(X,F) -> case pick(X) of M -> M:F() end. pick(_) -> lists."
    result = private_erlang(context, dynamic, "run/2")
    assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["unresolved_function_dispatch"]
  end

  test "R24 case refinement respects nested shadowing and never executes producers", context do
    shadow = """
    run(X) -> case pick(X) of M -> M:f(fun(M) -> M:f() end) end.
    pick(_) -> lists.
    """

    result = private_erlang(context, shadow, "run/1")
    assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["unresolved_module_dispatch"]

    Process.delete(:audit_case_producer_executed)

    body = """
    run(X) -> case pick(X) of M -> M:f() end.
    pick(_) -> erlang:put(audit_case_producer_executed,true), lists.
    """

    assert private_erlang(context, body, "run/1").unresolved_dispatch == []
    assert Process.get(:audit_case_producer_executed) == nil
  end

  # I: explicit checked induction. Original controls never request this proof.
  test "I01 explicit identity SCC proof requires a finite seed", context do
    body = "run() -> first(lists). first(M) -> M:f(), second(M). second(M) -> first(M)."
    assert unsafe?(private_erlang(context, body))
    result = i_run(context, body, i_domains())
    assert result.unresolved_dispatch == []
    assert result.parameter_invariant_derivation.status == "checked"
    assert length(result.parameter_invariant_derivation.checked_slots) == 2
  end

  test "I02 renamed functions and modules use the same derivation", context do
    body = "run() -> alpha(maps). alpha(T) -> T:f(), beta(T). beta(T) -> alpha(T)."
    domains = [{{:alpha, 1}, 0, [:maps]}, {{:beta, 1}, 0, [:maps]}]
    assert i_run(context, body, domains).unresolved_dispatch == []
  end

  test "I03 Proxy shaped entry and two recursive helpers preserve unrelated unknowns", context do
    body = """
    run(X) -> entry(X,lists).
    entry(X,M) -> read(X,M).
    read(X,M) -> M:recv(X,0,1), case X of a -> read(b,M); _ -> next(X,M) end.
    next(X,M) -> read(X,M).
    """

    domains = for name <- [:entry, :read, :next], do: {{name, 2}, 1, [:lists]}
    assert i_run(context, body, domains, "run/1").unresolved_dispatch == []
  end

  test "I04 unsafe finite seeds remain unsafe even when included in the domain", context do
    body = "run() -> first(ssl). first(M) -> M:connect(a,1,[]), second(M). second(M) -> first(M)."
    result = i_run(context, body, i_domains([:ssl]))
    assert unsafe?(result)
    assert Enum.any?(result.unresolved_dispatch, &(&1.kind == "literal_module_ssl"))
  end

  test "I05 missing domain alternatives and unknown seeds invalidate the proof", context do
    for body <- [
          "run() -> first(ssl). first(M) -> M:f(), second(M). second(M) -> first(M).",
          "run(X) -> first(X). first(M) -> M:f(), second(M). second(M) -> first(M)."
        ] do
      exports = if String.starts_with?(body, "run(X)"), do: "run/1", else: "run/0"
      assert unsafe?(i_run(context, body, i_domains(), exports))
    end
  end

  test "I06 computed or replaced recursive arguments cannot assert identity", context do
    for argument <- ["external:value(M)", "ssl", "lists"] do
      body =
        "run() -> first(lists). first(M) -> M:f(), second(M). second(M) -> first(#{argument})."

      assert unsafe?(i_run(context, body, i_domains([:lists, :ssl])))
    end
  end

  test "I07 every alternate branch is checked", context do
    body = """
    run(X) -> first(X,lists).
    first(X,M) -> M:f(), second(X,M).
    second(X,M) -> case X of a -> first(X,M); _ -> first(X,X) end.
    """

    domains = for name <- [:first, :second], do: {{name, 2}, 1, [:lists]}
    assert unsafe?(i_run(context, body, domains, "run/1"))
  end

  test "I08 added unknown caller remains an obligation", context do
    body = """
    run(X) -> first(lists), extra(X).
    extra(X) -> first(X).
    first(M) -> M:f(), second(M).
    second(M) -> first(M).
    """

    assert unsafe?(i_run(context, body, i_domains(), "run/1"))
  end

  test "I09 returning passing or remote capturing a private target blocks induction", context do
    for escape <- ["fun first/1", "lists:map(fun first/1,[])", "fun no_otp_audit_fixture:first/1"] do
      body =
        "run() -> first(lists), #{escape}. first(M) -> M:f(), second(M). second(M) -> first(M)."

      assert unsafe?(i_run(context, body, i_domains()))
    end
  end

  test "I10 export metadata cannot be overridden by a certificate", context do
    body = "run() -> first(lists). first(M) -> M:f(), second(M). second(M) -> first(M)."
    assert unsafe?(i_run(context, body, i_domains(), "run/0,first/1"))
    assert unsafe?(i_run(context, body, i_domains(), "run/0", "-compile(export_all). "))
  end

  test "I11 anonymous named fun and comprehension shadowing stay unknown", context do
    for edge <- [
          "fun(M) -> first(M) end",
          "fun Again(M) -> first(M), Again(M) end",
          "[first(M) || M <- external:values()]"
        ] do
      body = "run() -> first(lists). first(M) -> M:f(), second(M). second(M) -> #{edge}."
      assert unsafe?(i_run(context, body, i_domains()))
    end
  end

  test "I12 an unseeded cycle cannot invent a finite parameter", context do
    body = "run() -> ok. first(M) -> M:f(), second(M). second(M) -> first(M)."
    assert unsafe?(i_run(context, body, i_domains()))
  end

  test "I13 missing debug data cannot be replaced with a certificate", context do
    body = "run() -> first(lists). first(M) -> M:f(), second(M). second(M) -> first(M)."
    private_erlang(context, body)
    path = Path.join(context.ebin, "no_otp_audit_fixture.beam")
    {:ok, {_, stripped}} = :beam_lib.strip(File.read!(path))
    File.write!(path, stripped)

    [result] =
      NoOTP.ReleaseAudit.artifacts(parameter_invariants: %{no_otp_audit_fixture: i_domains()}).beam_inspections

    assert result.missing_abstract_code
    assert result.parameter_invariant_derivation.status == "missing_debug"
  end

  test "I14 changed selected artifact must rederive every seed", context do
    body = "run(X) -> first(lists). first(M) -> M:f(), second(M). second(M) -> first(M)."
    safe = i_run(context, body, i_domains(), "run/1")
    assert safe.unresolved_dispatch == []

    changed =
      i_run(context, String.replace(body, "first(lists)", "first(X)"), i_domains(), "run/1")

    assert safe.sha256 != changed.sha256
    assert unsafe?(changed)
  end

  test "I15 malformed duplicate oversized and absent slots fail closed", context do
    body = "run() -> first(lists). first(M) -> M:f(), second(M). second(M) -> first(M)."
    wide = for n <- 1..17, do: String.to_atom("audit_invariant_target_#{n}")

    for domains <- [
          :invalid,
          [{{:first, 1}, 0, []}],
          [{{:first, 1}, 0, ["lists"]}],
          [{{:first, 1}, 1, [:lists]}],
          [{{:absent, 1}, 0, [:lists]}],
          i_domains() ++ i_domains(),
          i_domains(wide),
          List.duplicate({{:first, 1}, 0, [:lists]}, 257)
        ] do
      result = i_run(context, body, domains)
      assert unsafe?(result)
      assert result.parameter_invariant_derivation == %{status: "rejected", checked_slots: []}
    end
  end

  test "I16 proof never executes seeds backedges or scanned callback bodies", context do
    Process.delete(:audit_invariant_executed)

    body = """
    run() -> erlang:put(audit_invariant_executed,true), first(lists).
    first(M) -> M:f(), second(M), fun() -> erlang:put(audit_invariant_executed,true) end.
    second(M) -> erlang:put(audit_invariant_executed,true), first(M).
    """

    assert i_run(context, body, i_domains()).unresolved_dispatch == []
    assert Process.get(:audit_invariant_executed) == nil
  end

  test "I17 two finite seeds join without dropping an unsafe alternative", context do
    body =
      "run() -> first(lists), first(ssl). first(M) -> M:f(), second(M). second(M) -> first(M)."

    assert unsafe?(i_run(context, body, i_domains([:lists, :ssl])))
    assert unsafe?(i_run(context, body, i_domains([:lists])))

    assert i_run(context, String.replace(body, "ssl", "maps"), i_domains([:lists, :maps])).unresolved_dispatch ==
             []
  end

  test "I18 independent product components and unknown callable parameters stay unknown",
       context do
    body = """
    run(X) -> first(X,lists).
    first(X,M) -> {A,B}={X,M}, A:f(), B:f(), second(X,M).
    second(X,M) -> first(X,M).
    """

    domains = for name <- [:first, :second], do: {{name, 2}, 1, [:lists]}
    result = i_run(context, body, domains, "run/1")
    assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["unresolved_module_dispatch"]
  end

  test "I19 captured finite identity retains nested unsafe callback obligations", context do
    body = """
    run() -> first(lists).
    first(M) -> M:f(), second(M), fun() -> N=ssl, N:connect(a,1,[]) end.
    second(M) -> fun() -> first(M) end.
    """

    result = i_run(context, body, i_domains())
    assert Enum.map(result.unresolved_dispatch, & &1.kind) == ["literal_module_ssl"]
  end

  test "I20 partial certificates cannot assume an omitted forwarding function", context do
    body = "run() -> first(lists). first(M) -> M:f(), second(M). second(M) -> first(M)."
    assert unsafe?(i_run(context, body, [{{:first, 1}, 0, [:lists]}]))
  end

  defp i_domains(atoms \\ [:lists]),
    do: [{{:first, 1}, 0, atoms}, {{:second, 1}, 0, atoms}]

  defp i_run(context, body, entries, exports \\ "run/0", extra \\ "") do
    private_erlang(context, body, exports, extra)

    [result] =
      NoOTP.ReleaseAudit.artifacts(parameter_invariants: %{no_otp_audit_fixture: entries}).beam_inspections

    result
  end

  test "P01 incoming-only requests preserve every unresolved occurrence", context do
    {before, after_report} = p_run(context, "entry(F) -> F().", [{:p_input, :entry, 1}])
    refute Map.has_key?(before, :callable_provenance_preflight)
    assert before.unresolved_dispatch != []
    assert after_report.unresolved_dispatch == before.unresolved_dispatch
    assert after_report.beam_inspections == before.beam_inspections
    proof = after_report.callable_provenance_preflight
    assert proof.stage == "incoming_only"
    assert proof.external_callable_records == []
    assert proof.scan_complete
    assert Enum.all?(proof.snapshots, & &1.selected)
    assert [%{status: "no_syntactic_incoming_edges", incoming: []}] = proof.roots
  end

  test "P02 direct local callers and captures remain explicit obligations", context do
    for body <- [
          "entry(F) -> F(). caller() -> entry(fun() -> ok end).",
          "entry(F) -> F(). caller() -> fun entry/1.",
          "entry(F) -> F(). caller() -> fun p_input:entry/1."
        ] do
      {before, report} =
        p_run(context, body, [{:p_input, :entry, 1}], exports: "entry/1,caller/0")

      assert report.unresolved_dispatch == before.unresolved_dispatch

      assert [%{status: "unconfirmed", incoming: [_ | _]}] =
               report.callable_provenance_preflight.roots
    end
  end

  test "P03 renamed public roots do not gain origin from their names", context do
    {before, report} =
      p_run(context, "renamed(F) -> F().", [{:p_other, :renamed, 1}],
        module: :p_other,
        exports: "renamed/1"
      )

    assert before.unresolved_dispatch == report.unresolved_dispatch

    assert [%{root: %{module: ":p_other", function: "renamed", arity: 1}}] =
             report.callable_provenance_preflight.roots

    assert report.callable_provenance_preflight.external_callable_records == []
  end

  test "P04 dynamic callable and aliases cannot disappear from incoming evidence", context do
    for body <- [
          "entry(F) -> F(). caller(F) -> F(fun() -> ok end).",
          "entry(F) -> F(). caller(M) -> M:entry(fun() -> ok end).",
          "entry(F) -> F(). caller(_) -> M=p_input, F=entry, M:F(fun() -> ok end).",
          "entry(F) -> F(). caller(F) -> G=F, G(fun() -> ok end)."
        ] do
      {_, report} =
        p_run(context, body, [{:p_input, :entry, 1}], exports: "entry/1,caller/1")

      assert [%{status: "unconfirmed", incoming: [_ | _]}] =
               report.callable_provenance_preflight.roots
    end
  end

  test "P05 apply and metadispatch retain unknown argument spines and selectors", context do
    for call <- [
          "erlang:apply(p_input,entry,[F])",
          "erlang:apply(p_input,entry,F)",
          "erlang:apply(F,[fun() -> ok end])",
          "erlang:spawn(p_input,entry,[F])",
          "erlang:make_fun(p_input,entry,1)",
          "erlang:F(p_input,entry,[F])",
          "F(p_input,entry,[fun() -> ok end])"
        ] do
      {_, report} =
        p_run(context, "entry(F) -> F(). caller(F) -> " <> call <> ".", [{:p_input, :entry, 1}],
          exports: "entry/1,caller/1"
        )

      assert [%{status: "unconfirmed", incoming: [_ | _]}] =
               report.callable_provenance_preflight.roots
    end
  end

  test "P06 original paths distinguish repeated annotations and nested closures", context do
    body =
      "entry(F) -> F(). caller() -> entry(fun() -> ok end), fun() -> entry(fun() -> ok end) end."

    {_, report} = p_run(context, body, [{:p_input, :entry, 1}], exports: "entry/1,caller/0")
    [root] = report.callable_provenance_preflight.roots
    edges = Enum.filter(root.incoming, &(&1.kind == "direct_arguments_require_proof"))
    assert length(edges) == 2
    assert length(Enum.uniq(Enum.map(edges, & &1.line))) == 1
    assert length(Enum.uniq(Enum.map(edges, & &1.path))) == 2
    assert length(Enum.uniq(Enum.map(edges, & &1.ordinal))) == 2
    assert Enum.all?(edges, &(&1.owner == %{function: "caller", arity: 0}))
  end

  test "P07 malformed duplicate and oversized requests never classify a callback", context do
    for roots <- [
          :invalid,
          [{:p_input, :entry, -1}],
          [{"p_input", :entry, 1}],
          [{:p_input, :entry, 1}, {:p_input, :entry, 1}],
          List.duplicate({:p_input, :entry, 1}, 65)
        ] do
      {before, report} = p_run(context, "entry(F) -> F().", roots)
      assert report.unresolved_dispatch == before.unresolved_dispatch
      refute report.callable_provenance_preflight.requests_valid
      assert report.callable_provenance_preflight.roots == []
      assert report.callable_provenance_preflight.external_callable_records == []
    end
  end

  test "P08 a new selected module adds its real incoming edge", context do
    extra = {:p_caller, "-export([run/1]). run(F) -> p_input:entry(F).", true}
    {before, report} = p_run(context, "entry(F) -> F().", [{:p_input, :entry, 1}], extra: [extra])
    assert before.unresolved_dispatch == report.unresolved_dispatch
    assert length(report.callable_provenance_preflight.snapshots) == 2
    [root] = report.callable_provenance_preflight.roots

    assert Enum.any?(
             root.incoming,
             &(&1.module == ":p_caller" and &1.kind == "direct_arguments_require_proof")
           )

    assert root.status == "unconfirmed"
  end

  test "P09 missing debug in any audited module invalidates closed incoming evidence", context do
    extra = {:p_hidden, "-export([run/1]). run(F) -> p_input:entry(F).", false}
    {_, report} = p_run(context, "entry(F) -> F().", [{:p_input, :entry, 1}], extra: [extra])
    assert report.missing_abstract_code != []
    assert [%{status: "unconfirmed"}] = report.callable_provenance_preflight.roots
    assert Enum.any?(report.callable_provenance_preflight.snapshots, &(not &1.debug))
  end

  test "P10 absent or private roots are not exported contracts", context do
    {_, report} =
      p_run(context, "entry(F) -> F(), hidden(F). hidden(F) -> F().", [
        {:p_absent, :entry, 1},
        {:p_input, :hidden, 1}
      ])

    assert Enum.all?(
             report.callable_provenance_preflight.roots,
             &(not &1.exported and &1.status == "unconfirmed")
           )
  end

  test "P11 scans neither execute producers nor hide unsafe nested bodies", context do
    Process.delete(:p_audit_executed)

    body =
      "entry(F) -> erlang:put(p_audit_executed,true), F(), fun() -> M=ssl, M:connect(a,1,[]) end."

    {before, report} = p_run(context, body, [{:p_input, :entry, 1}])
    assert report.unresolved_dispatch == before.unresolved_dispatch
    assert Enum.any?(report.unresolved_dispatch, &(&1.kind == "literal_module_ssl"))
    assert Process.get(:p_audit_executed) == nil
  end

  test "P12 incompatible literal MFA calls are distinguished from unknown targets", context do
    body = "entry(F) -> F(). caller() -> lists:reverse([])."
    {_, report} = p_run(context, body, [{:p_input, :entry, 1}], exports: "entry/1,caller/0")
    assert [%{incoming: []}] = report.callable_provenance_preflight.roots
  end

  test "P13 compiled nested expressions retain raw call and capture preorder", context do
    body = """
    entry(F) -> F().
    caller(X) ->
      A = \#{value => entry(X)},
      B = [entry(Y) || Y <- [X]],
      C = <<(entry(X)):8>>,
      D = fun Again(Y) -> case Y of stop -> entry(X); _ -> Again(stop) end end,
      E = fun() -> entry(X) end,
      F = fun entry/1,
      G = fun p_input:entry/1,
      try entry(X) of V -> {A,B,C,D,E,F,G,V}
      catch _:_ -> entry(X)
      after receive done -> entry(X) after 0 -> entry(X) end end.
    """

    {before, report} =
      p_run(context, body, [{:p_input, :entry, 1}], exports: "entry/1,caller/1")

    [snapshot] = report.callable_provenance_preflight.snapshots

    {:ok, {:p_input, [abstract_code: {:raw_abstract_v1, forms}]}} =
      :beam_lib.chunks(String.to_charlist(snapshot.beam), [:abstract_code])

    p_assert_raw_sites(before, report, forms)
    assert report.callable_provenance_preflight.scanned_nodes < p_raw_node_count(forms)
  end

  test "P14 valid scalar annotation forms leave identical raw site identities", context do
    for annotation <- [
          0,
          {7, 3},
          [
            location: {7, 3},
            generated: true,
            record: true,
            end_location: {9, 4},
            file: ~c"fixture.erl",
            text: ~c"entry(F)"
          ],
          [location: 7, file: "fixture.erl"]
        ] do
      {before, report, forms} =
        p_mutated(context, fn body -> [{:block, annotation, [p_entry_call() | body]}] end)

      p_assert_raw_sites(before, report, forms)
      assert [%{incoming: [_]}] = report.callable_provenance_preflight.roots
    end
  end

  test "P15 executable terms in file annotations are not erased as strings", context do
    for nested <- [p_entry_call(), p_entry_capture()] do
      annotation = [location: 1, file: [102, nested, 111]]
      assert :erl_anno.is_anno(annotation)

      {before, report, forms} =
        p_mutated(context, fn body -> [{:block, annotation, body}] end)

      p_assert_raw_sites(before, report, forms)
      assert [%{incoming: [edge]}] = report.callable_provenance_preflight.roots
      assert Enum.slice(edge.path, 5, 3) == [1, 1, 1]
    end
  end

  test "P16 executable terms in text annotations are not erased as strings", context do
    for nested <- [p_entry_call(), p_entry_capture()] do
      annotation = [location: 1, text: [nested]]
      assert :erl_anno.is_anno(annotation)

      {before, report, forms} =
        p_mutated(context, fn body -> [{:block, annotation, body}] end)

      p_assert_raw_sites(before, report, forms)
      assert [%{incoming: [_]}] = report.callable_provenance_preflight.roots
    end
  end

  test "P17 unknown tags and malformed arities retain every raw child", context do
    for wrap <- [
          fn body -> {:unknown_ast_tag, p_entry_call(), body} end,
          fn body -> {:tuple, p_entry_capture(), body, :unexpected_fourth_field} end,
          fn body -> {:block, 0, body, p_entry_call()} end,
          fn body -> {:atom, 0, {p_entry_call(), body}} end,
          fn body -> {p_entry_capture(), 0, body} end
        ] do
      {before, report, forms} = p_mutated(context, fn body -> [wrap.(body)] end)
      p_assert_raw_sites(before, report, forms)
      assert [%{incoming: [_]}] = report.callable_provenance_preflight.roots
    end
  end

  test "P18 malformed and unknown annotation properties fall back without partial erasure",
       context do
    for annotation <- [
          [location: 1, unknown: p_entry_call()],
          [location: 1, generated: p_entry_capture()],
          [location: 1, file: ~c"valid-prefix", text: [p_entry_call()]],
          [location: 1, file: [p_entry_capture()], text: ~c"valid-suffix"],
          [location: p_entry_call()],
          [file: [p_entry_capture()]]
        ] do
      {before, report, forms} =
        p_mutated(context, fn body -> [{:tuple, annotation, body}] end)

      p_assert_raw_sites(before, report, forms)
      assert [%{incoming: [_]}] = report.callable_provenance_preflight.roots
    end
  end

  test "P19 annotation validation bounds cannot truncate hidden obligations", context do
    for annotation <- [
          [location: 1] ++ List.duplicate({:generated, true}, 16) ++ [text: [p_entry_call()]],
          [location: 1, file: List.duplicate(?x, 4_096) ++ [p_entry_capture()]],
          [location: 1, text: [0x110000, p_entry_call()]],
          [location: 1, text: [-1, p_entry_capture()]]
        ] do
      {before, report, forms} =
        p_mutated(context, fn body -> [{:block, annotation, body}] end)

      p_assert_raw_sites(before, report, forms)
      assert [%{incoming: [_]}] = report.callable_provenance_preflight.roots
    end
  end

  test "P20 counted nodes exclude only proven headers and retain body data", context do
    for annotation <- [0, [location: 1, file: List.duplicate(?x, 4_096)]] do
      literal = {:tuple, annotation, [{:atom, 0, :ok}, {:integer, 0, 1}]}
      {before, report, forms} = p_mutated(context, fn _body -> [literal] end)
      p_assert_raw_sites(before, report, forms)
      # One clause list, one clause, one pattern list, one var and its name,
      # one guard list, one body list, one tuple, one element list, and each
      # of the two literal nodes with its value: thirteen retained nodes.
      assert report.callable_provenance_preflight.scanned_nodes == 13
      assert report.callable_provenance_preflight.scanned_sites == 0

      for {malformed, expected} <- [
            {put_elem(literal, 0, :unknown_ast_tag), 14 + p_raw_count(annotation)},
            {Tuple.append(literal, :extra), 15 + p_raw_count(annotation)}
          ] do
        {before, report, forms} = p_mutated(context, fn _body -> [malformed] end)
        p_assert_raw_sites(before, report, forms)
        assert report.callable_provenance_preflight.scanned_nodes == expected
      end
    end
  end

  defp p_entry_call,
    do: {:call, 1, {:remote, 1, {:atom, 1, :p_input}, {:atom, 1, :entry}}, [{:atom, 1, :input}]}

  defp p_entry_capture,
    do: {:fun, 1, {:function, {:atom, 1, :p_input}, {:atom, 1, :entry}, {:integer, 1, 1}}}

  # Change only the debug chunk of a real compiled fixture. The auditor must
  # conservatively retain obligations even when debug annotations are malformed;
  # no producer or rewritten code is loaded or executed by these controls.
  defp p_mutated(context, rewrite_body) do
    ebin = b_physical(context.ebin)
    directory = ebin |> Path.dirname() |> Path.dirname() |> Path.dirname()
    System.put_env("NO_OTP_RELEASE", directory)
    System.put_env("NO_OTP_PROJECT", directory)
    bytes = b_compile(:p_input, "-export([entry/1]). entry(F) -> F().", true)
    {:ok, :p_input, chunks} = :beam_lib.all_chunks(bytes)
    {~c"Dbgi", debug} = List.keyfind(chunks, ~c"Dbgi", 0)
    {:debug_info_v1, :erl_abstract_code, {forms, options}} = :erlang.binary_to_term(debug)

    forms =
      Enum.map(forms, fn
        {:function, annotation, :entry, 1, clauses} ->
          clauses =
            Enum.map(clauses, fn {:clause, anno, args, guards, body} ->
              {:clause, anno, args, guards, rewrite_body.(body)}
            end)

          {:function, annotation, :entry, 1, clauses}

        other ->
          other
      end)

    debug =
      :erlang.term_to_binary({:debug_info_v1, :erl_abstract_code, {forms, options}}, [:compressed])

    {:ok, bytes} = :beam_lib.build_module(List.keyreplace(chunks, ~c"Dbgi", 0, {~c"Dbgi", debug}))
    File.write!(Path.join(ebin, "p_input.beam"), bytes)
    true = :code.add_patha(String.to_charlist(ebin))
    on_exit(fn -> :code.del_path(String.to_charlist(ebin)) end)
    before = NoOTP.ReleaseAudit.artifacts()
    report = NoOTP.ReleaseAudit.artifacts(public_callable_roots: [{:p_input, :entry, 1}])
    {before, report, forms}
  end

  defp p_assert_raw_sites(before, report, forms) do
    assert Map.delete(report, :callable_provenance_preflight) == before
    proof = report.callable_provenance_preflight
    assert proof.scan_complete
    assert proof.external_callable_records == []
    sites = p_raw_sites(forms)
    assert proof.scanned_sites == length(sites)
    [root] = proof.roots

    expected =
      sites
      |> Enum.with_index()
      |> Enum.flat_map(fn {{path, term}, ordinal} ->
        if p_root_site?(term), do: [{path, ordinal}], else: []
      end)

    for edge <- root.incoming do
      {path, _term} = Enum.fetch!(sites, edge.ordinal)
      assert edge.path == path
    end

    actual =
      root.incoming
      |> Enum.filter(
        &(&1.kind in ["direct_arguments_require_proof", "capture", "capture_invocation"])
      )
      |> Enum.map(&{&1.path, &1.ordinal})

    assert actual == expected
  end

  # Independent full raw preorder, with no annotation/header filtering. This
  # checks both original tuple/list paths and ordinals across all call/capture
  # nodes, including nodes that do not contribute an incoming root edge.
  defp p_raw_sites(forms) do
    forms
    |> Enum.with_index()
    |> Enum.flat_map(fn
      {{:function, _, _, _, clauses}, index} -> p_raw_sites(clauses, [index, 4])
      _ -> []
    end)
  end

  defp p_raw_sites(term, path) do
    site =
      if match?({:call, _, _, _}, term) or
           match?({:fun, _, {:function, _, _}}, term) or
           match?({:fun, _, {:function, _, _, _}}, term),
         do: [{path, term}],
         else: []

    children =
      cond do
        is_tuple(term) -> Tuple.to_list(term)
        is_list(term) -> term
        true -> []
      end

    site ++
      (children
       |> Enum.with_index()
       |> Enum.flat_map(fn {child, index} ->
         p_raw_sites(child, path ++ [index])
       end))
  end

  defp p_root_site?({:call, _, {:atom, _, :entry}, [_]}), do: true

  defp p_root_site?({:call, _, {:remote, _, {:atom, _, :p_input}, {:atom, _, :entry}}, [_]}),
    do: true

  defp p_root_site?({:fun, _, {:function, :entry, 1}}), do: true

  defp p_root_site?(
         {:fun, _, {:function, {:atom, _, :p_input}, {:atom, _, :entry}, {:integer, _, 1}}}
       ),
       do: true

  defp p_root_site?(_other), do: false

  defp p_raw_node_count(forms) do
    forms
    |> Enum.reduce(0, fn
      {:function, _, _, _, clauses}, total -> total + p_raw_count(clauses)
      _, total -> total
    end)
  end

  defp p_raw_count(term) when is_tuple(term), do: 1 + p_raw_count_children(Tuple.to_list(term))
  defp p_raw_count(term) when is_list(term), do: 1 + p_raw_count_children(term)
  defp p_raw_count(_term), do: 1
  defp p_raw_count_children(children), do: Enum.reduce(children, 0, &(&2 + p_raw_count(&1)))

  defp p_run(context, body, roots, options \\ []) do
    ebin = b_physical(context.ebin)
    directory = ebin |> Path.dirname() |> Path.dirname() |> Path.dirname()
    System.put_env("NO_OTP_RELEASE", directory)
    System.put_env("NO_OTP_PROJECT", directory)
    module = Keyword.get(options, :module, :p_input)
    source = "-export([" <> Keyword.get(options, :exports, "entry/1") <> "]). " <> body
    entries = [{module, source, true} | Keyword.get(options, :extra, [])]

    for {module, source, debug?} <- entries do
      bytes = b_compile(module, source, debug?)
      File.write!(Path.join(ebin, Atom.to_string(module) <> ".beam"), bytes)
    end

    true = :code.add_patha(String.to_charlist(ebin))
    on_exit(fn -> :code.del_path(String.to_charlist(ebin)) end)
    {NoOTP.ReleaseAudit.artifacts(), NoOTP.ReleaseAudit.artifacts(public_callable_roots: roots)}
  end

  test "S01 tuple seeds preserve unknown payloads and exact forwarding occurrence", context do
    result = s_run(context, s_body())
    assert result.record.status == "checked"
    assert length(result.record.callers) == 2
    assert [observation] = result.record.observations
    assert observation.source == %{function: "deliver", arity: 2, parameter_index: 1}
    assert observation.callee == %{function: "notify", arity: 2, argument_index: 1}
    assert Enum.sort(observation.shapes) == Enum.sort(hd(result.record.slots).shapes)

    {:ok, {_, [{:abstract_code, {:raw_abstract_v1, forms}}]}} =
      :beam_lib.chunks(String.to_charlist(result.path), [:abstract_code])

    assert {:call, _, {:atom, _, :notify}, [_, {:var, _, :E}]} =
             s_at(forms, observation.site.path)

    assert Enum.at(p_raw_sites(forms), observation.site.ordinal) ==
             {observation.site.path, s_at(forms, observation.site.path)}
  end

  test "S02 renamed module functions variables and tags need no name exemption", context do
    body =
      "run(X) -> pass(X,{alpha,X}), pass(X,{beta,0,X}). pass(A,B) -> out(A,B). out(_,E) -> E."

    requests = [
      {:s_renamed, [{{:pass, 2}, 1, [{:tuple, :alpha, 2}, {:tuple, :beta, 3}]}],
       [{{:pass, 2}, 1, {:out, 2}, 1, :discover}]}
    ]

    assert s_run(context, body, requests, module: :s_renamed).record.status == "checked"
  end

  test "S03 private identity forwarding composes checked parameter dependencies", context do
    body =
      "run(X) -> wrap(X,{informational,200,X}), wrap(X,{trailers,X}). wrap(S,E) -> deliver(S,E). deliver(S,E) -> notify(S,E). notify(_,E) -> E."

    [{module, entries, observations}] = s_requests()
    entries = [{{:wrap, 2}, 1, s_shapes()} | entries]
    result = s_run(context, body, [{module, entries, observations}])
    assert result.record.status == "checked"
    assert Enum.any?(result.record.callers, &(&1.origin.kind == "parameter"))
  end

  test "S04 unrelated recursive callers do not poison independently seeded shapes", context do
    body =
      "run(X) -> first(X). first(X) -> deliver(X,{informational,200,X}), second(X). second(X) -> deliver(X,{trailers,X}), first(X). deliver(S,E) -> notify(S,E). notify(_,E) -> E."

    assert s_run(context, body).record.status == "checked"
  end

  test "S05 all branch callers contribute to the finite union", context do
    body =
      "run(X) -> case X of a -> deliver(X,{informational,200,X}); _ -> deliver(X,{trailers,X}) end. deliver(S,E) -> notify(S,E). notify(_,E) -> E."

    assert s_run(context, body).record.status == "checked"
    changed = String.replace(body, "deliver(X,{trailers,X})", "deliver(X,X)")
    assert s_run(context, changed).record.status == "unconfirmed"
  end

  test "S06 an added unknown or callable caller invalidates the entire theorem", context do
    for argument <- ["X", "fun() -> ok end", "external:produce(X)"] do
      body = String.replace(s_body(), "run(X) ->", "run(X) -> deliver(X,#{argument}),")
      result = s_run(context, body)
      assert result.record.status == "unconfirmed"
      assert result.record.slots == []
    end
  end

  test "S07 private function exports and export_all cannot establish a closed domain", context do
    for opts <- [[exports: "run/1,deliver/2"], [extra: "-compile(export_all). "]] do
      assert s_run(context, s_body(), s_requests(), opts).record.status == "unconfirmed"
    end
  end

  test "S08 returned passed and remote captures block private caller completeness", context do
    for capture <- ["fun deliver/2", "lists:map(fun deliver/2,[])", "fun s_input:deliver/2"] do
      body = String.replace(s_body(), "run(X) ->", "run(X) -> #{capture},")
      assert s_run(context, body).record.status == "unconfirmed"
    end
  end

  test "S09 closure and comprehension shadowing cannot borrow an outer parameter", context do
    for expression <- [
          "fun(E) -> deliver(S,E) end",
          "fun Again(E) -> deliver(S,E), Again(E) end",
          "[deliver(S,E) || E <- external:values()]"
        ] do
      body = String.replace(s_body(), "notify(S,E).", "notify(S,E), #{expression}.")
      assert s_run(context, body).record.status == "unconfirmed"
    end
  end

  test "S10 captured nonshadowed parameter forwarding retains its source slot", context do
    body = String.replace(s_body(), "notify(S,E).", "fun() -> notify(S,E) end.")
    assert s_run(context, body).record.status == "checked"
  end

  test "S11 unseeded cycles and omitted forwarding slots remain unknown", context do
    body =
      "run(_) -> ok. wrap(S,E) -> deliver(S,E). deliver(S,E) -> notify(S,E), wrap(S,E). notify(_,E) -> E."

    [{module, entries, observations}] = s_requests()
    requests = [{module, [{{:wrap, 2}, 1, s_shapes()} | entries], observations}]
    assert s_run(context, body, requests).record.status == "unconfirmed"
    seeded = String.replace(body, "run(_) -> ok.", "run(X) -> wrap(X,{trailers,X}).")
    assert s_run(context, seeded, requests).record.status == "checked"
    assert s_run(context, seeded).record.status == "unconfirmed"
  end

  test "S12 incorrect tag arity slot and observation operand cannot be asserted", context do
    [{module, entries, observations}] = s_requests()

    for requests <- [
          [{module, [{{:deliver, 2}, 1, [{:tuple, :wrong, 3}]}], observations}],
          [
            {module, [{{:deliver, 2}, 1, [{:tuple, :informational, 2}, {:tuple, :trailers, 2}]}],
             observations}
          ],
          [
            {module, [{{:deliver, 2}, 0, s_shapes()}],
             [{{:deliver, 2}, 0, {:notify, 2}, 0, :discover}]}
          ],
          [{module, entries, [{{:deliver, 2}, 1, {:notify, 2}, 0, :discover}]}]
        ] do
      assert s_run(context, s_body(), requests).record.status == "unconfirmed"
    end
  end

  test "S13 explicit original paths are checked against the actual compiled occurrence",
       context do
    result = s_run(context, s_body())
    [observation] = result.record.observations
    [{module, entries, _}] = s_requests()
    requests = [{module, entries, [{{:deliver, 2}, 1, {:notify, 2}, 1, observation.site.path}]}]
    assert s_report(context, :s_input, requests).record.status == "checked"

    wrong = [
      {module, entries, [{{:deliver, 2}, 1, {:notify, 2}, 1, observation.site.path ++ [0]}]}
    ]

    assert s_report(context, :s_input, wrong).record.status == "unconfirmed"

    moved =
      s_run(
        context,
        String.replace(s_body(), "notify(S,E).", "erlang:self(), notify(S,E)."),
        requests
      )

    assert moved.record.status == "unconfirmed"
  end

  test "S14 missing debug cannot be replaced by a requested shape", context do
    result = s_run(context, s_body())
    {:ok, {_, stripped}} = :beam_lib.strip(File.read!(result.path))
    File.write!(result.path, stripped)
    assert s_report(context, :s_input, s_requests()).record.status == "unconfirmed"
  end

  test "S15 different first selected artifact prevents a local certificate", context do
    result = s_run(context, s_body())
    shadow = Path.join(Path.dirname(context.ebin), "shape-shadow")
    File.mkdir_p!(shadow)
    shadow = b_physical(shadow)
    File.write!(Path.join(shadow, "s_input.beam"), File.read!(result.path))
    true = :code.add_patha(String.to_charlist(shadow))
    on_exit(fn -> :code.del_path(String.to_charlist(shadow)) end)
    assert s_report(context, :s_input, s_requests()).record.status == "unconfirmed"
  end

  test "S16 changed artifacts must rederive all shape seeds", context do
    before = s_run(context, s_body())
    after_result = s_run(context, String.replace(s_body(), "{trailers,X}", "X"))
    assert before.record.sha256 != after_result.record.sha256
    assert after_result.record.status == "unconfirmed"
  end

  test "S17 malformed duplicate oversized requests and absent modules fail closed", context do
    [{module, entries, observations}] = s_requests()

    for requests <- [
          :invalid,
          s_requests() ++ s_requests(),
          [{module, entries ++ entries, observations}],
          [{module, entries, observations ++ observations}],
          [{module, [{{:deliver, 2}, 2, s_shapes()}], observations}],
          [{module, [{{:deliver, 2}, 1, List.duplicate({:atom, :ok}, 17)}], observations}],
          List.duplicate(hd(s_requests()), 65)
        ] do
      result = s_run(context, s_body(), requests)
      refute Enum.any?(result.proof.modules, &(&1.status == "checked"))
    end

    result = s_run(context, s_body(), [{:absent_shape_module, entries, observations}])
    assert result.record.status == "unconfirmed"
    assert result.record.beam == nil
  end

  test "S18 node call and definition bounds cannot be overridden by shape requests", context do
    for kind <- [:nodes, :calls, :definitions] do
      result = s_run(context, s_body())

      s_rewrite(result.path, fn forms ->
        case kind do
          :definitions ->
            forms ++
              for n <- 1..257,
                  do:
                    {:function, 1, String.to_atom("shape_extra_#{n}"), 0,
                     [{:clause, 1, [], [], [{:atom, 1, :ok}]}]}

          _ ->
            Enum.map(forms, fn
              {:function, anno, :run, 1, [{:clause, line, args, guards, body}]} ->
                additions =
                  if kind == :nodes,
                    do: List.duplicate({:atom, 1, :ok}, 100_001),
                    else: List.duplicate(hd(body), 4_097)

                {:function, anno, :run, 1, [{:clause, line, args, guards, additions ++ body}]}

              other ->
                other
            end)
        end
      end)

      assert s_report(context, :s_input, s_requests()).record.status == "unconfirmed"
    end
  end

  test "S19 unsupported AST and ambiguous forwarding occurrences remain unknown", context do
    duplicate = String.replace(s_body(), "notify(S,E).", "notify(S,E), notify(S,E).")
    assert s_run(context, duplicate).record.status == "unconfirmed"
    result = s_run(context, s_body())

    s_rewrite(result.path, fn forms ->
      Enum.map(forms, fn
        {:function, anno, :run, arity, [{:clause, line, args, guards, body}]} ->
          {:function, anno, :run, arity,
           [{:clause, line, args, guards, [{:unrecognized_shape_expression, 1, []} | body]}]}

        other ->
          other
      end)
    end)

    assert s_report(context, :s_input, s_requests()).record.status == "unconfirmed"
  end

  test "S20 outer-shape proof neither executes nor hides nested unsafe code", context do
    Process.delete(:shape_producer_executed)

    body =
      String.replace(s_body(), "run(X) ->", "run(X) -> erlang:put(shape_producer_executed,true),")

    body =
      String.replace(
        body,
        "{informational,200,X}",
        "{informational,200,fun(M) -> M:connect(a,1,[]) end}"
      )

    result = s_run(context, body)
    assert result.record.status == "checked"
    assert result.report.unresolved_dispatch != []
    assert Process.get(:shape_producer_executed) == nil
    assert :code.is_loaded(:s_input) == false
    assert result.report.callable_provenance_preflight.external_callable_records == []
  end

  test "S21 full actual H3 source proves only the deliver event forwarding slice", context do
    root = System.get_env("NO_OTP_AUDIT_SOURCE_ROOT") || Path.expand("../..", __DIR__)
    source = File.read!(Path.join(root, "apps/http_runtime/lib/http/http3/connection_owner.ex"))

    source =
      String.replace(
        source,
        "defmodule HTTP.HTTP3.ConnectionOwner do",
        "defmodule NoOTPActualShapeOwner do",
        global: false
      )

    [{module, bytes}] = Code.compile_string(source)
    :code.purge(module)
    :code.delete(module)

    on_exit(fn ->
      :code.purge(module)
      :code.delete(module)
    end)

    requests = [
      {module, [{{:deliver, 3}, 2, [{:tuple, :informational, 3}, {:tuple, :trailers, 2}]}],
       [{{:deliver, 3}, 2, {:notify, 3}, 2, :discover}]}
    ]

    result = s_install(context, module, bytes, requests)
    assert result.record.status == "checked"
    assert length(result.record.callers) == 2
    assert [observation] = result.record.observations
    assert observation.site.owner == %{function: "deliver", arity: 3}
    assert Enum.all?(result.record.callers, &(&1.site.owner.function == "dispatch_event"))
    # This standalone owner already has no ordinary unresolved dispatches.
    # Bind that baseline to this exact compiled artifact, then compare all
    # ordinary fields so adding shape evidence cannot erase any finding.
    assert result.baseline.checked_beams == 1
    assert [baseline_beam] = result.baseline.beam_inspections
    assert baseline_beam.module == inspect(module)

    assert {baseline_beam.beam, baseline_beam.sha256} ==
             {result.record.beam, result.record.sha256}

    assert result.baseline.unresolved_dispatch == []

    assert Map.delete(result.report, :callable_provenance_preflight) ==
             Map.delete(result.baseline, :callable_provenance_preflight)

    refute NoOTP.ReleaseAudit.clean?(result.report, %{})
  end

  test "S22 requested shape facts cannot close unrelated exported callable inputs", context do
    body = s_body() <> " generic(F) -> F()."
    result = s_run(context, body, s_requests(), exports: "run/1,generic/1")
    assert result.record.status == "checked"
    assert Enum.any?(result.report.unresolved_dispatch, &(&1.kind == "unresolved_fun_invocation"))
    assert result.report.callable_provenance_preflight.external_callable_records == []
  end

  test "S23 literal atom seeds are distinct from tagged tuple seeds", context do
    body = "run(X) -> deliver(X,done). deliver(S,E) -> notify(S,E). notify(_,E) -> E."

    requests = [
      {:s_input, [{{:deliver, 2}, 1, [{:atom, :done}]}],
       [{{:deliver, 2}, 1, {:notify, 2}, 1, :discover}]}
    ]

    assert s_run(context, body, requests).record.status == "checked"

    assert s_run(context, String.replace(body, "deliver(X,done)", "deliver(X,{done})"), requests).record.status ==
             "unconfirmed"
  end

  test "S24 computed or aliased seed expressions require a separate derivation", context do
    for expression <- ["case X of a -> {trailers,X}; _ -> X end", "Y"] do
      body =
        "run(X) -> Y={trailers,X}, deliver(X,#{expression}). deliver(S,E) -> notify(S,E). notify(_,E) -> E."

      assert s_run(context, body).record.status == "unconfirmed"
    end
  end

  defp s_shapes, do: [{:tuple, :informational, 3}, {:tuple, :trailers, 2}]

  defp s_requests,
    do: [
      {:s_input, [{{:deliver, 2}, 1, s_shapes()}],
       [{{:deliver, 2}, 1, {:notify, 2}, 1, :discover}]}
    ]

  defp s_body,
    do:
      "run(X) -> deliver(X,{informational,200,X}), deliver(X,{trailers,X}). deliver(S,E) -> notify(S,E). notify(_,E) -> E."

  defp s_run(context, body, requests \\ s_requests(), options \\ []) do
    module = Keyword.get(options, :module, :s_input)

    source =
      "-export([" <>
        Keyword.get(options, :exports, "run/1") <>
        "]). " <>
        Keyword.get(options, :extra, "") <> body

    s_install(context, module, b_compile(module, source, true), requests)
  end

  defp s_install(context, module, bytes, requests) do
    ebin = b_physical(context.ebin)
    directory = ebin |> Path.dirname() |> Path.dirname() |> Path.dirname()
    System.put_env("NO_OTP_RELEASE", directory)
    System.put_env("NO_OTP_PROJECT", directory)
    File.write!(Path.join(ebin, Atom.to_string(module) <> ".beam"), bytes)
    true = :code.add_patha(String.to_charlist(ebin))
    on_exit(fn -> :code.del_path(String.to_charlist(ebin)) end)
    s_report(context, module, requests)
  end

  defp s_report(context, module, requests) do
    before = NoOTP.ReleaseAudit.artifacts(public_callable_roots: [])

    report =
      NoOTP.ReleaseAudit.artifacts(public_callable_roots: [], private_shape_invariants: requests)

    assert Map.delete(report, :callable_provenance_preflight) ==
             Map.delete(before, :callable_provenance_preflight)

    assert Map.delete(report.callable_provenance_preflight, :private_shape_derivations) ==
             before.callable_provenance_preflight

    proof = report.callable_provenance_preflight.private_shape_derivations

    %{
      baseline: before,
      report: report,
      proof: proof,
      record: List.first(proof.modules),
      path: Path.join(b_physical(context.ebin), Atom.to_string(module) <> ".beam")
    }
  end

  defp s_at(term, []), do: term
  defp s_at(term, [index | rest]) when is_tuple(term), do: s_at(elem(term, index), rest)
  defp s_at(term, [index | rest]) when is_list(term), do: s_at(Enum.fetch!(term, index), rest)

  defp s_rewrite(path, rewrite) do
    {:ok, module, chunks} = :beam_lib.all_chunks(File.read!(path))
    {~c"Dbgi", debug} = List.keyfind(chunks, ~c"Dbgi", 0)
    {:debug_info_v1, :erl_abstract_code, {forms, options}} = :erlang.binary_to_term(debug)

    debug =
      :erlang.term_to_binary(
        {:debug_info_v1, :erl_abstract_code, {rewrite.(forms), options}},
        [:compressed]
      )

    {:ok, bytes} = :beam_lib.build_module(List.keyreplace(chunks, ~c"Dbgi", 0, {~c"Dbgi", debug}))
    File.write!(path, bytes)
    assert :code.is_loaded(module) == false
  end
end
