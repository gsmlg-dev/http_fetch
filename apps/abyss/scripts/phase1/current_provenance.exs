# Current staged engine paths are explicit consumer dependencies, outside the umbrella.
deps = Mix.Dep.load_and_cache()

for {app, module, variable} <- [
      {:elixir_quic, Quic, "ELIXIR_QUIC_PATH"},
      {:ex_ssl, SSL.QUIC, "EX_SSL_PATH"}
    ] do
  dep = Enum.find(deps, &(&1.app == app)) || raise("missing #{app} dependency")
  true = dep.scm == Mix.SCM.Path
  true = Path.expand(dep.opts[:dest]) == Path.expand(System.fetch_env!(variable))
  true = Code.ensure_loaded?(module)
  app_dir = Path.expand(Path.join([Mix.Project.build_path(), "lib", Atom.to_string(app)]))
  true = Path.expand(Application.app_dir(app)) == app_dir
  true = Path.expand(Path.dirname(to_string(:code.which(module)))) == Path.join(app_dir, "ebin")
end

false = Code.ensure_loaded?(QUIC)
IO.puts("CURRENT_QUIC_PROVENANCE_PASS")
