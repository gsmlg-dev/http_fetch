expected = System.fetch_env!("HTTP3_CONSUMER_VERSION")
project = System.fetch_env!("HTTP3_CONSUMER_PROJECT") |> Path.expand()
source = System.fetch_env!("HTTP3_CONSUMER_SOURCE")

packages =
  ~w(ex_ssl elixir_quic http_core elixir_quic_http3 http_runtime http_fetch http_web_socket http_event_source http_web_transport)a

dependencies = Mix.Dep.cached()

for app <- packages do
  dep = Enum.find(dependencies, &(&1.app == app)) || raise("missing coordinated package #{app}")

  unless dep.scm == Hex.SCM and dep.opts[:hex] == Atom.to_string(app) and
           dep.status == {:ok, expected},
         do: raise("invalid Hex resolution for #{app}: #{inspect(dep.status)}")

  unless Path.expand(dep.opts[:dest]) == Path.join([project, "deps", Atom.to_string(app)]),
    do: raise("dependency #{app} escaped isolated consumer")

  {:ok, _} = Application.ensure_all_started(app)

  unless to_string(Application.spec(app, :vsn)) == expected,
    do: raise("loaded #{app} version differs from coordinated release")
end

for module <- [
      SSL.Connection,
      Quic.Connection,
      QuicHttp3.Session,
      HTTP.Headers,
      HTTPRuntime.Application,
      HTTP,
      HTTP.WebSocket,
      HTTP.EventSource,
      HTTP.WebTransport
    ] do
  Code.ensure_loaded!(module)
  beam = :code.which(module) |> to_string() |> Path.expand()

  unless String.starts_with?(beam, Path.join(project, "build") <> "/"),
    do: raise("#{inspect(module)} did not load from the isolated Hex build: #{beam}")

  IO.puts("HTTP3 consumer loaded #{inspect(module)}=#{beam}")
end

IO.puts("HTTP3 consumer provenance: #{source}, nine Hex packages == #{expected}: PASS")
