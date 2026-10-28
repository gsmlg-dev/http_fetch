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
end
