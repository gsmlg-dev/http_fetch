defmodule NoOTP.DirectedReview do
  @moduledoc false
  @scope "supported_public_api_and_approved_callbacks"

  # This binds a finite, human-reviewed release proof. It does not infer targets,
  # execute a provider, or remove findings from the generic audit.
  def bind(artifacts, bundle, project, release) do
    try do
      check(bundle["schema"] == 1 and bundle["scope"] == @scope, "review scope")
      sources = source_snapshot(bundle, project)
      check(sources == bundle["sources"], "reviewed source census changed")

      bindings =
        Enum.map(artifacts.beam_inspections, &bind_beam(&1, bundle, project, release))

      expected = bundle["occurrences"]
      check(is_list(expected) and expected != [], "reviewed occurrences missing")
      check(length(Enum.uniq(expected)) == length(expected), "duplicate reviewed occurrence")

      actual =
        Enum.flat_map(artifacts.beam_inspections, fn inspection ->
          Enum.map(inspection.unresolved_dispatch, fn finding ->
            {inspection.module, finding.line, finding.kind}
          end)
        end)

      wanted = Enum.map(expected, &{&1["module"], &1["line"], &1["kind"]})
      check(Enum.sort(actual) == Enum.sort(wanted), "unreviewed or missing compiled dispatch")

      reviewed =
        Enum.map(expected, fn occurrence ->
          binding = Enum.find(bindings, &(&1.module == occurrence["module"]))
          check(binding != nil, "reviewed module missing")
          check(binding.source == occurrence["source"], "dispatch source changed")

          check(
            occurrence["line"] in Map.get(binding.function_call_lines, occurrence["mfa"], []),
            "dispatch owning function changed"
          )

          %{
            module: binding.module,
            beam: binding.beam,
            beam_sha256: binding.sha256,
            line: occurrence["line"],
            kind: occurrence["kind"],
            mfa: occurrence["mfa"],
            source: binding.source,
            proof: occurrence["proof"]
          }
        end)

      %{
        status: "PASS",
        scope: @scope,
        reviews: bundle["reviews"],
        sources: sources,
        beam_bindings: Enum.map(bindings, &Map.delete(&1, :function_call_lines)),
        raw_dispatch_count: length(artifacts.unresolved_dispatch),
        reviewed_dispatches: reviewed,
        remaining_dispatches: []
      }
    rescue
      error ->
        %{
          status: "FAIL",
          scope: @scope,
          error: Exception.message(error),
          raw_dispatch_count: length(artifacts.unresolved_dispatch),
          reviewed_dispatches: [],
          remaining_dispatches: artifacts.unresolved_dispatch
        }
    end
  end

  def accepted?(artifacts) do
    case Map.get(artifacts, :directed_review) do
      %{
        status: "PASS",
        scope: @scope,
        remaining_dispatches: [],
        raw_dispatch_count: count,
        reviewed_dispatches: reviewed
      } ->
        count == length(artifacts.unresolved_dispatch) and length(reviewed) == count

      _ ->
        false
    end
  end

  defp source_snapshot(bundle, project) do
    Enum.reduce(bundle["versions"], %{}, fn {package, _version}, sources ->
      root =
        if package == "no_otp_consumer",
          do: project,
          else: Path.join([project, "deps", package])

      directory = if package == "telemetry", do: "src", else: "lib"
      {:ok, %{type: :directory}} = File.lstat(Path.join(root, directory))

      files =
        root
        |> Path.join(directory <> "/**/*")
        |> Path.wildcard()
        |> Enum.reject(&File.dir?/1)

      Enum.reduce(files, sources, fn file, acc ->
        {:ok, %{type: :regular}} = File.lstat(file)
        Map.put(acc, package <> "/" <> Path.relative_to(file, root), digest(file))
      end)
    end)
  end

  defp bind_beam(inspection, bundle, project, release) do
    {:ok, {module, chunks}} =
      :beam_lib.chunks(String.to_charlist(inspection.beam), [:compile_info, :abstract_code])

    check(inspect(module) == inspection.module, "compiled module identity changed")
    {:raw_abstract_v1, forms} = Keyword.fetch!(chunks, :abstract_code)

    source =
      chunks
      |> Keyword.fetch!(:compile_info)
      |> Keyword.fetch!(:source)
      |> to_string()
      |> Path.expand()

    relative =
      if String.starts_with?(source, Path.join(project, "lib") <> "/") do
        "no_otp_consumer/" <> Path.relative_to(source, project)
      else
        Path.relative_to(source, Path.join(project, "deps"))
      end

    check(Map.has_key?(bundle["sources"], relative), "compiled source is outside reviewed inputs")
    check(digest(source) == bundle["sources"][relative], "compiled source bytes changed")
    [package | _rest] = Path.split(relative)
    version = Map.fetch!(bundle["versions"], package)
    filename = Atom.to_string(module) <> ".beam"
    beam = Path.join([release, "lib", package <> "-" <> version, "ebin", filename])
    check(Path.expand(inspection.beam) == beam, "release BEAM escaped its package")
    built = Path.join([project, "build", "lib", package, "ebin", filename])
    sha256 = digest(beam)
    check(sha256 == inspection.sha256 and sha256 == digest(built), "release/build BEAM differs")

    calls =
      for {:function, _line, name, arity, clauses} <- forms, into: %{} do
        {Atom.to_string(name) <> "/" <> Integer.to_string(arity), call_lines(clauses)}
      end

    %{
      module: inspection.module,
      beam: beam,
      sha256: sha256,
      build_beam: built,
      build_sha256: sha256,
      compile_source: source,
      source: relative,
      source_sha256: bundle["sources"][relative],
      function_call_lines: calls
    }
  end

  # Only locate the already reported site inside its raw compiled function.
  # No expression is evaluated and no callable-origin analysis is performed.
  defp call_lines({:call, annotation, callee, arguments}) do
    [:erl_anno.line(annotation) | call_lines(callee) ++ call_lines(arguments)]
  end

  defp call_lines(tuple) when is_tuple(tuple), do: tuple |> Tuple.to_list() |> call_lines()
  defp call_lines(list) when is_list(list), do: Enum.flat_map(list, &call_lines/1)
  defp call_lines(_literal), do: []

  defp digest(path), do: :crypto.hash(:sha256, File.read!(path)) |> Base.encode16(case: :lower)
  defp check(true, _message), do: :ok
  defp check(false, message), do: raise("directed release proof: " <> message)
end
