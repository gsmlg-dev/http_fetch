# Run from either independent QUIC example with `mix run --no-start`.
deps = Mix.Dep.load_and_cache()
lock = Mix.Dep.Lock.read()

for {app, version, module, outer_checksum} <- [
      {:elixir_quic, "0.21.17", Quic,
       "08b37301829efc5b94919a7cc55670596cf1fc641dcc7e3a42589714b9dab65c"},
      {:ex_ssl, "0.21.17", SSL.QUIC,
       "5eefa5ad6825a0d59b6036cf075d8ddacefe2e29ab0bb084b1c0e915b660aa6b"}
    ] do
  dep = Enum.find(deps, &(&1.app == app)) || raise("missing #{app} dependency")
  true = dep.scm == Hex.SCM
  true = dep.opts[:hex] == Atom.to_string(app)
  true = Path.expand(dep.opts[:dest]) == Path.expand("deps/#{app}")

  {:hex, ^app, ^version, _checksum, _managers, _dependencies, "hexpm", ^outer_checksum} =
    Map.fetch!(lock, app)

  true = Code.ensure_loaded?(module)
  true = to_string(Application.spec(app, :vsn)) == version
  app_dir = Path.expand(Path.join([Mix.Project.build_path(), "lib", Atom.to_string(app)]))
  true = Path.expand(Application.app_dir(app)) == app_dir
  true = Path.expand(Path.dirname(to_string(:code.which(module)))) == Path.join(app_dir, "ebin")
end

false = Code.ensure_loaded?(QUIC)
false = Map.has_key?(lock, :ex_quic)
IO.puts("PUBLISHED_QUIC_PROVENANCE_PASS elixir_quic=0.21.17 ex_ssl=0.21.17")
