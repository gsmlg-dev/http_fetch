# The Python wrapper owns one deadline/process group for bootstrap and execution.
# A real private release supplies selected library sources without OTP SSL.
if System.argv() == ["--bootstrap"] do
  owner = System.fetch_env!("NO_OTP_STATE_EQUATION_ROOT")
  owner = File.cd!(owner, &File.cwd!/0)
  true = owner == File.cd!(System.tmp_dir!(), &File.cwd!/0)
  project = Path.join(owner, "project")
  release = Path.join(owner, "release")
  File.mkdir_p!(Path.join(project, "lib"))
  File.mkdir_p!(Path.join(project, "priv/fixtures"))

  File.write!(Path.join(project, "mix.exs"), """
  defmodule NoOTP.StateEquationFixtureProject do
    use Mix.Project
    def project do
      [app: :no_otp_state_equation, version: "0.0.0", deps: [],
       consolidate_protocols: false,
       elixirc_options: [debug_info: true, warnings_as_errors: true],
       releases: [no_otp_state_equation: [include_erts: true, strip_beams: false]]]
    end
    def application, do: [extra_applications: [:crypto, :compiler, :ex_unit]]
  end
  """)

  File.cp!(
    Path.join(__DIR__, "no_otp_release_audit.exs"),
    Path.join(project, "lib/no_otp_release_audit.ex")
  )

  File.cp!(__ENV__.file, Path.join(project, "priv/test_no_otp_state_equation.exs"))

  File.cp!(
    Path.join(__DIR__, "fixtures/no_otp_state_equation.json"),
    Path.join(project, "priv/fixtures/no_otp_state_equation.json")
  )

  environment = [
    {"MIX_ENV", "prod"},
    {"MIX_BUILD_PATH", Path.join(project, "_build")},
    {"MIX_DEPS_PATH", Path.join(project, "deps")},
    {"MIX_HOME", Path.join(owner, "mix")},
    {"MIX_ARCHIVES", Path.join(owner, "archives")},
    {"HEX_HOME", Path.join(owner, "hex")},
    {"MIX_PATH", nil},
    {"ERL_LIBS", nil},
    {"ERL_FLAGS", nil},
    {"ERL_AFLAGS", nil},
    {"ERL_ZFLAGS", nil},
    {"ELIXIR_ERL_OPTIONS", nil},
    {"NO_OTP_STATE_EQUATION_RELEASE", release},
    {"NO_OTP_RELEASE", release},
    {"NO_OTP_PROJECT", project}
  ]

  {_, status} =
    System.cmd("mix", ["release", "no_otp_state_equation", "--path", release],
      cd: project,
      env: environment,
      into: IO.stream(:stdio, :line),
      stderr_to_stdout: true
    )

  if status != 0, do: System.halt(status)

  evaluation = """
  {_, diagnostics} = Code.with_diagnostics(fn ->
    Code.eval_file(Path.join(to_string(:code.priv_dir(:no_otp_state_equation)),
      "test_no_otp_state_equation.exs"))
  end)
  if diagnostics != [], do: raise("unexpected harness diagnostics: " <> inspect(diagnostics))
  """

  {_, status} =
    System.cmd(Path.join(release, "bin/no_otp_state_equation"), ["eval", evaluation],
      cd: release,
      env: environment,
      into: IO.stream(:stdio, :line),
      stderr_to_stdout: true
    )

  if status != 0, do: System.halt(status)
else
  {:ok, _} = Application.ensure_all_started(:crypto)
  {:ok, _} = Application.ensure_all_started(:ex_unit)
  ExUnit.start(autorun: false)

  defmodule NoOTP.StateEquationTest do
    # These tests deliberately inspect and change VM-wide selected code paths.
    use ExUnit.Case, async: false

    @inventory JSON.decode!(File.read!(Path.join(__DIR__, "fixtures/no_otp_state_equation.json")))
    @cases @inventory["conditional"] ++ @inventory["guards"] ++ @inventory["bifs"]
    @limits %{alternatives: 16, bytes: 65_536, functions: 256, calls: 4_096, nodes: 100_000}
    @selection_module :c44_selection_fixture

    setup_all do
      assert [25, 10, 8, 8] ==
               Enum.map(["conditional", "guards", "bifs", "selection"], &length(@inventory[&1]))

      assert length(Enum.uniq_by(@cases ++ @inventory["selection"], & &1["id"])) == 51
      root = File.cd!(System.fetch_env!("NO_OTP_STATE_EQUATION_RELEASE"), &File.cwd!/0)
      original_paths = :code.get_path()

      paths =
        Enum.filter(original_paths, &String.starts_with?(Path.expand(to_string(&1)), root <> "/"))

      assert paths != []
      assert :code.set_path(paths)
      assert_ssl_absent()
      assert Path.wildcard(Path.join(root, "lib/ssl*")) == []

      for module <- [:lists, :maps, Enum] do
        path = to_string(:code.which(module))
        assert String.starts_with?(path, root <> "/")
        assert {:ok, %File.Stat{type: :regular}} = File.lstat(path)

        assert {:ok, {^module, [abstract_code: {:raw_abstract_v1, [_ | _]}]}} =
                 :beam_lib.chunks(String.to_charlist(path), [:abstract_code])

        assert :code.module_status(module) in [:loaded, :not_loaded]
      end

      ebin = Path.join(root, "lib/state_equation_fixture-0/ebin")
      sources = Path.join(root, "control-sources")
      File.mkdir_p!(ebin)
      File.mkdir_p!(sources)

      File.write!(
        Path.join(ebin, "state_equation_fixture.app"),
        "{application,state_equation_fixture,[{vsn,\"0\"},{applications,[kernel,stdlib]}]}."
      )

      assert :code.add_patha(String.to_charlist(ebin))
      options = Code.compiler_options()
      Code.compiler_options(debug_info: true)

      rows =
        Map.new(@cases, fn row ->
          module = String.to_atom(row["module"])
          assert :code.is_loaded(module) == false
          bytes = compile_source(row, sources)
          verify_raw(row, module, bytes)
          File.write!(Path.join(ebin, row["module"] <> ".beam"), bytes)
          {row["id"], bytes}
        end)

      selection =
        Map.new(@inventory["selection_sources"], fn {key, source} ->
          module =
            case key do
              "ssl_import" -> :c44_selection_ssl_import
              "onload" -> :c44_selection_onload
              _ -> @selection_module
            end

          directory = Path.join(sources, key)
          File.mkdir_p!(directory)

          row = %{
            "id" => key,
            "module" => to_string(module),
            "language" => "erlang",
            "source" => source,
            "expected_warnings" => 0
          }

          bytes = compile_source(row, directory)

          if key != "replacement",
            do: File.write!(Path.join(ebin, to_string(module) <> ".beam"), bytes)

          {key, bytes}
        end)

      Code.compiler_options(debug_info: options.debug_info)
      assert_ssl_absent()
      final_paths = :code.get_path()
      pins = Map.new(Path.wildcard(Path.join(ebin, "*.beam")), &{&1, File.read!(&1)})

      on_exit(fn ->
        Enum.each(@cases, &unload(String.to_atom(&1["module"])))

        Enum.each(
          [
            @selection_module,
            :c44_selection_ssl_import,
            :c44_selection_onload,
            :c49_nonconsumption_fixture
          ],
          &unload/1
        )

        assert :code.set_path(original_paths)
        File.rm_rf!(Path.dirname(ebin))
        File.rm_rf!(sources)
      end)

      {:ok,
       root: root,
       ebin: ebin,
       sources: sources,
       rows: rows,
       selection: selection,
       paths: final_paths,
       pins: pins}
    end

    setup context do
      assert :code.get_path() == context.paths
      assert :code.is_loaded(@selection_module) == false
      assert_ssl_absent()
      saved = Map.new(["NO_OTP_RELEASE", "NO_OTP_PROJECT"], &{&1, System.get_env(&1)})

      on_exit(fn ->
        unload(@selection_module)
        unload(:c49_nonconsumption_fixture)
        assert :code.set_path(context.paths)

        Enum.each(saved, fn {key, value} ->
          if value, do: System.put_env(key, value), else: System.delete_env(key)
        end)

        Enum.each(context.pins, fn {path, bytes} -> assert File.read!(path) == bytes end)
        assert_ssl_absent()
      end)

      :ok
    end

    for row <- @cases do
      test row["id"], context do
        row = unquote(Macro.escape(row))
        module = String.to_atom(row["module"])
        assert :code.is_loaded(module) == false
        result = prove(context, module, row["expected_status"])
        assert :code.is_loaded(module) == false

        assert File.read!(Path.join(context.ebin, row["module"] <> ".beam")) ==
                 context.rows[row["id"]]

        verify_dependencies(result, context)

        if row["id"] == "source_list_fold_preserves" do
          assert Enum.any?(
                   result.dependencies,
                   &(&1.module == ":lists" and &1.function == "foldl")
                 )
        end

        if row["id"] == "map_fold_preserves" do
          assert Enum.any?(result.dependencies, &(&1.module == ":maps" and &1.function == "fold"))
        end

        if row["id"] == "unchanged_state_baseline", do: nonconsumption(context)
      end
    end

    for row <- @inventory["selection"] do
      test row["id"], context do
        row = unquote(Macro.escape(row))
        path = Path.join(context.ebin, "c44_selection_fixture.beam")
        original = context.selection["original"]
        replacement = context.selection["replacement"]
        assert original != replacement
        assert File.read!(path) == original

        module =
          case row["id"] do
            "current_unloaded_source" ->
              @selection_module

            "loaded_bytes_differ_from_selected_disk" ->
              assert {:module, @selection_module} =
                       :code.load_binary(@selection_module, String.to_charlist(path), replacement)

              assert :code.module_status(@selection_module) == :modified
              @selection_module

            "unloaded_source_restored" ->
              assert {:module, @selection_module} =
                       :code.load_binary(@selection_module, String.to_charlist(path), replacement)

              prove(context, @selection_module, "unconfirmed")
              unload(@selection_module)
              assert :code.is_loaded(@selection_module) == false
              @selection_module

            "loaded_path_differs_from_first_selected_source" ->
              alternate = Path.join(context.sources, "replacement/c44_selection_fixture.beam")
              File.write!(alternate, replacement)

              assert {:module, @selection_module} =
                       :code.load_binary(
                         @selection_module,
                         String.to_charlist(alternate),
                         replacement
                       )

              assert to_string(:code.which(@selection_module)) == alternate
              @selection_module

            "loaded_bytes_and_path_match" ->
              assert {:module, @selection_module} =
                       :code.load_binary(@selection_module, String.to_charlist(path), original)

              assert :code.module_status(@selection_module) == :loaded
              @selection_module

            "selected_source_has_literal_otp_ssl_import" ->
              bytes = context.selection["ssl_import"]

              assert {:ok, {:c44_selection_ssl_import, [imports: imports]}} =
                       :beam_lib.chunks(bytes, [:imports])

              assert {:ssl, :connect, 3} in imports
              :c44_selection_ssl_import

            "selected_source_has_on_load_body" ->
              assert {:ok, {:c44_selection_onload, [abstract_code: {:raw_abstract_v1, forms}]}} =
                       :beam_lib.chunks(context.selection["onload"], [:abstract_code])

              assert Enum.any?(forms, &match?({:attribute, _, :on_load, _}, &1))
              :c44_selection_onload

            "selected_source_is_missing" ->
              assert :code.which(:c44_selection_absent) == :non_existing
              :c44_selection_absent
          end

        before_loaded = :code.is_loaded(module)
        prove(context, module, row["expected_status"])
        assert :code.is_loaded(module) == before_loaded
        assert File.read!(path) == original
        assert_ssl_absent()
      end
    end

    defp prove(context, module, expected) do
      selected = %{
        release: %{resolved: context.root, error: nil},
        paths: Enum.map(:code.get_path(), &to_string/1)
      }

      before_paths = :code.get_path()
      assert :code.is_loaded(:c48_unloaded_fixture_target) == false

      result =
        NoOTP.ReleaseAudit.StateEquation.prove(
          selected,
          module,
          {:handle_call, 3},
          2,
          :transport,
          [:c43_allowed_transport],
          @limits
        )

      assert result.status == expected, inspect(result)
      assert result.scope == "callback_result_and_throw_only"
      assert result.entry_origins_proved == false
      assert result.ordinary_findings_removed == 0
      assert result.entry == %{function: "handle_call", arity: 3, parameter_index: 2}
      assert result.field == "transport"
      assert result.targets == ["c43_allowed_transport"]
      if expected == "checked_conditional", do: assert(result.complete)
      assert :code.get_path() == before_paths
      assert :code.is_loaded(:c48_unloaded_fixture_target) == false
      assert_ssl_absent()
      result
    end

    defp compile_source(row, directory) do
      module = String.to_atom(row["module"])
      extension = if row["language"] == "elixir", do: ".ex", else: ".erl"
      path = Path.join(directory, row["module"] <> extension)
      File.write!(path, row["source"])

      case row["language"] do
        "elixir" ->
          {compiled, diagnostics} =
            Code.with_diagnostics(fn -> Code.compile_string(row["source"], path) end)

          assert diagnostics == []
          assert [{^module, bytes}] = compiled
          unload(module)
          assert :code.is_loaded(module) == false
          bytes

        "erlang" ->
          assert {:ok, ^module, bytes, warnings} =
                   :compile.file(
                     String.to_charlist(path),
                     [:binary, :debug_info, :return_errors, :return_warnings]
                   )

          details = Enum.flat_map(warnings, fn {_file, entries} -> entries end)

          assert length(details) == row["expected_warnings"],
                 "unexpected fixture warnings for #{row["id"]}: #{inspect(warnings)}"

          if details != [],
            do: IO.puts("intentional fixture warning #{row["id"]}: #{inspect(details)}")

          assert :code.is_loaded(module) == false
          bytes
      end
    end

    defp verify_raw(row, module, bytes) do
      assert {:ok, {^module, chunks}} =
               :beam_lib.chunks(bytes, [:exports, :imports, :abstract_code])

      assert {:handle_call, 3} in Keyword.fetch!(chunks, :exports)
      refute Enum.any?(Keyword.fetch!(chunks, :imports), &match?({:ssl, _, _}, &1))
      assert {:raw_abstract_v1, forms} = Keyword.fetch!(chunks, :abstract_code)
      refute Enum.any?(forms, &match?({:attribute, _, :on_load, _}, &1))
      ops = Enum.map(guard_ops(forms), &to_string/1)
      for required <- row["required_raw_ops"], do: assert(required in ops)
      calls = raw_calls(forms)

      for required <- row["required_calls"] do
        assert {String.to_atom(required["module"]), String.to_atom(required["function"]),
                required["arity"]} in calls
      end

      if row["id"] == "raw_import_bindings" do
        assert {:fixture_decoy, :throw, 1} in Keyword.fetch!(chunks, :imports)
        assert {:local, :throw, 1} in calls
      end
    end

    defp verify_dependencies(result, context) do
      for dependency <- result.dependencies do
        module =
          if String.starts_with?(dependency.module, ":"),
            do: dependency.module |> String.trim_leading(":") |> String.to_existing_atom(),
            else: String.to_existing_atom("Elixir." <> dependency.module)

        path = to_string(:code.which(module))
        assert String.starts_with?(path, context.root <> "/")

        assert {:ok, {^module, [abstract_code: {:raw_abstract_v1, forms}]}} =
                 :beam_lib.chunks(String.to_charlist(path), [:abstract_code])

        function = String.to_existing_atom(dependency.function)
        arity = dependency.arity

        assert [{:function, _, ^function, ^arity, _} = form] =
                 Enum.filter(forms, &match?({:function, _, ^function, ^arity, _}, &1))

        assert dependency.form_sha256 ==
                 Base.encode16(:crypto.hash(:sha256, :erlang.term_to_binary(form)), case: :lower)
      end
    end

    defp nonconsumption(context) do
      root = Path.join(context.root, "ordinary-view")
      ebin = Path.join(root, "lib/nonconsumption_fixture-0/ebin")
      File.mkdir_p!(ebin)
      module = :c49_nonconsumption_fixture

      row = %{
        "id" => "nonconsumption",
        "module" => to_string(module),
        "language" => "erlang",
        "expected_warnings" => 0,
        "source" => """
        -module(c49_nonconsumption_fixture).
        -export([handle_call/3,out/1]).
        handle_call(_,_,State) -> {noreply,State}.
        out(Target) -> Target:send(data).
        """
      }

      bytes = compile_source(row, context.sources)
      File.write!(Path.join(ebin, to_string(module) <> ".beam"), bytes)

      File.write!(
        Path.join(ebin, "nonconsumption_fixture.app"),
        "{application,nonconsumption_fixture,[{vsn,\"0\"},{applications,[kernel,stdlib]}]}."
      )

      assert :code.add_patha(String.to_charlist(ebin))
      System.put_env("NO_OTP_RELEASE", root)
      System.put_env("NO_OTP_PROJECT", root)
      before = NoOTP.ReleaseAudit.artifacts()
      assert before.checked_beams == 1
      assert before.unresolved_dispatch != []
      result = prove(context, module, "checked_conditional")
      assert result.entry_origins_proved == false
      assert NoOTP.ReleaseAudit.artifacts() === before
      assert File.read!(Path.join(ebin, to_string(module) <> ".beam")) == bytes
      assert :code.is_loaded(module) == false
    end

    defp guard_ops({:clause, _, patterns, guards, body}),
      do: ops(guards) ++ Enum.flat_map(patterns ++ body, &guard_ops/1)

    defp guard_ops(tuple) when is_tuple(tuple),
      do: tuple |> Tuple.to_list() |> Enum.flat_map(&guard_ops/1)

    defp guard_ops(list) when is_list(list), do: Enum.flat_map(list, &guard_ops/1)
    defp guard_ops(_), do: []

    defp ops(tuple) when is_tuple(tuple) do
      current =
        if tuple_size(tuple) >= 3 and elem(tuple, 0) == :op, do: [elem(tuple, 2)], else: []

      current ++ (tuple |> Tuple.to_list() |> Enum.flat_map(&ops/1))
    end

    defp ops(list) when is_list(list), do: Enum.flat_map(list, &ops/1)
    defp ops(_), do: []

    defp raw_calls({:call, _, {:remote, _, {:atom, _, module}, {:atom, _, function}}, arguments}),
      do: [{module, function, length(arguments)} | Enum.flat_map(arguments, &raw_calls/1)]

    defp raw_calls({:call, _, {:atom, _, function}, arguments}),
      do: [{:local, function, length(arguments)} | Enum.flat_map(arguments, &raw_calls/1)]

    defp raw_calls(tuple) when is_tuple(tuple),
      do: tuple |> Tuple.to_list() |> Enum.flat_map(&raw_calls/1)

    defp raw_calls(list) when is_list(list), do: Enum.flat_map(list, &raw_calls/1)
    defp raw_calls(_), do: []

    defp unload(module) do
      :code.purge(module)
      :code.delete(module)
    end

    defp assert_ssl_absent do
      assert :code.which(:ssl) == :non_existing
      assert :code.is_loaded(:ssl) == false
      refute Enum.any?(Application.started_applications(), &(elem(&1, 0) == :ssl))
    end
  end

  result = ExUnit.run()

  if result.total != 51 or result.failures != 0 or result.excluded != 0 or result.skipped != 0,
    do: System.halt(1)
end
