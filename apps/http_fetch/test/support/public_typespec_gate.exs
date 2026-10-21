# Run from an isolated consumer after `mix deps.get`, strict compilation, and
# `mix dialyzer --plt` have prepared its dependency PLT:
# mix run --no-start /path/to/http_fetch/apps/http_fetch/test/support/public_typespec_gate.exs /path/to/consumer.plt
# Only compiles/analyzes public API calls; no HTTP requests execute.
[plt] = System.argv()
true = File.regular?(plt)

for module <- [HTTP, HTTP.Promise, HTTP.RequestCompletion], do: Code.ensure_loaded!(module)

source = """
defmodule HTTPFetch.PublicTypespecConsumer do
  def await_one(url), do: url |> HTTP.fetch() |> HTTP.Promise.await()
  def await_two(url, options), do: url |> HTTP.fetch(options) |> HTTP.Promise.await(1_000)

  def completion(url) do
    case url |> HTTP.fetch(redirect: :manual) |> HTTP.Promise.completion() do
      nil -> :no_completion
      handle -> HTTP.RequestCompletion.await(handle, 1_000)
    end
  end

  def abort_completion(url) do
    case url |> HTTP.fetch(redirect: :manual) |> HTTP.Promise.completion() do
      nil -> :no_completion
      handle -> HTTP.RequestCompletion.abort_and_await(handle, 1_000)
    end
  end
end
"""

forged = """
defmodule HTTPFetch.ForgedCompletionConsumer do
  def forged, do: HTTP.RequestCompletion.await(%HTTP.RequestCompletion{}, 0)
end
"""

directory =
  Path.join(
    System.tmp_dir!(),
    "http-fetch-typespec-#{System.pid()}-#{System.unique_integer([:positive])}"
  )

File.mkdir_p!(directory)

try do
  warnings =
    for {name, code} <- [{"public", source}, {"forged", forged}], into: %{} do
      path = Path.join(directory, name <> ".ex")
      File.write!(path, code)

      {:ok, modules, diagnostics} =
        Kernel.ParallelCompiler.compile_to_path([path], directory, return_diagnostics: true)

      case diagnostics do
        [] -> :ok
        %{compile_warnings: [], runtime_warnings: []} -> :ok
      end

      beams =
        Enum.map(
          modules,
          &String.to_charlist(Path.join(directory, Atom.to_string(&1) <> ".beam"))
        )

      result =
        :dialyzer.run(
          analysis_type: :succ_typings,
          files: beams,
          init_plt: String.to_charlist(plt)
        )

      Enum.each(result, &IO.write(:dialyzer.format_warning(&1)))
      {name, result}
    end

  unless warnings["public"] == [],
    do: raise("public fetch/promise/completion composition failed Dialyzer")

  unless match?([{:warn_opaque, _, {:call_without_opaque, _}}], warnings["forged"]),
    do: raise("forged completion must retain exactly one call_without_opaque warning")

  IO.puts("PASS: public fetch/await/completion types; forged completion remains opaque")
after
  File.rm_rf!(directory)
end
