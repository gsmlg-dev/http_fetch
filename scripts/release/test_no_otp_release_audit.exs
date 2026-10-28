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
          "run(X,F) -> G=case X of a -> fun() -> ok end; _ -> F end, G().",
          "run(X) -> M=case X of a -> lists; _ -> maps end, M:reverse([])."
        ] do
      result = erlang(context, body)
      assert result.unresolved_dispatch != [], body
      assert Enum.all?(result.unresolved_dispatch, &(&1.resolution == "unconfirmed"))
    end
  end

  test "fun parameters and named recursive funs cannot inherit outer target bindings", context do
    for body <- [
          "run() -> F=fun() -> ok end, G=fun(F) -> F() end, G(fun() -> ssl:connect(localhost,443,[]) end).",
          "run() -> M=lists, F=fun(M) -> M:connect(localhost,443,[]) end, F(ssl).",
          "run() -> F=fun Loop(N) -> case N of 0 -> ok; _ -> Loop(N-1) end end, F(1)."
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

  defp unsafe?(result),
    do: result.unresolved_dispatch != [] or result.otp_ssl_imports != []

  defp erlang(context, body, extra \\ "") do
    source = "-module(no_otp_audit_fixture). -compile(export_all). " <> extra <> body
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
               [:binary, :debug_info, :return_errors, :return_warnings, :nowarn_export_all]
             )

    audit(context, module, bytes)
  end

  defp audit(context, module, bytes) do
    File.write!(Path.join(context.ebin, Atom.to_string(module) <> ".beam"), bytes)
    [result] = NoOTP.ReleaseAudit.artifacts().beam_inspections
    result
  end
end
