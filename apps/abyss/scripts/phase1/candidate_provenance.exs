# Exact Hex dependencies in an isolated candidate consumer.
deps = Mix.Dep.load_and_cache()
lock = Mix.Dep.Lock.read()
version = System.fetch_env!("ABYSS_ENGINE_VERSION")

for {app, module} <- [{:elixir_quic, Quic}, {:ex_ssl, SSL.QUIC}] do
  dep = Enum.find(deps, &(&1.app == app)) || raise("missing #{app} dependency")
  true = dep.scm == Hex.SCM
  true = Path.expand(dep.opts[:dest]) == Path.expand("deps/#{app}")
  {:hex, ^app, ^version, _, _, _, _, _} = Map.fetch!(lock, app)
  true = Code.ensure_loaded?(module)
  true = to_string(Application.spec(app, :vsn)) == version
  app_dir = Path.expand(Path.join([Mix.Project.build_path(), "lib", Atom.to_string(app)]))
  true = Path.expand(Application.app_dir(app)) == app_dir
  true = Path.expand(Path.dirname(to_string(:code.which(module)))) == Path.join(app_dir, "ebin")
end

false = Code.ensure_loaded?(QUIC)
false = Map.has_key?(lock, :ex_quic)
IO.puts("CANDIDATE_HEX_QUIC_PROVENANCE_PASS #{version}")
