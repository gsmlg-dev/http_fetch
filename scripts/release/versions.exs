defmodule ReleaseVersions do
  @apps ~w(ex_ssl elixir_quic http_core http_runtime elixir_quic_http3 http_fetch http_web_socket http_event_source http_web_transport)
  @internal MapSet.new(@apps)
  @graph %{
    "ex_ssl" => [],
    "elixir_quic" => ~w(ex_ssl),
    "http_core" => ~w(ex_ssl elixir_quic),
    "http_runtime" => ~w(http_core),
    "elixir_quic_http3" => ~w(http_core elixir_quic),
    "http_fetch" => ~w(http_core http_runtime),
    "http_web_socket" => ~w(http_core http_runtime),
    "http_event_source" => ~w(http_core http_runtime),
    "http_web_transport" => ~w(http_core)
  }

  def run([mode, version]) when mode in ["prepare", "validate"] do
    unless Regex.match?(~r/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/, version),
      do: raise("release version must be stable major.minor.patch")

    paths = ["mix.exs" | Enum.map(@apps, &"apps/#{&1}/mix.exs")]

    contents =
      Map.new(paths, fn path ->
        source = File.read!(path)

        version_regex =
          if Regex.match?(~r/@version "[^"]+"/, source),
            do: ~r/(?<=@version ")[^"]+(?=")/,
            else: ~r/(?<=      version: ")[^"]+(?=",)/

        updated = replace_one!(source, version_regex, version, mode, path)

        if path != "mix.exs" do
          declared =
            Regex.scan(
              ~r/\{:([a-z_]+), "[^"]+", in_umbrella: true, hex: :([a-z_]+)\}/,
              updated,
              capture: :all_but_first
            )
            |> Enum.map(fn [app, hex] ->
              unless app == hex, do: raise("invalid internal Hex identity in #{path}: #{app}")
              app
            end)

          expected = Map.fetch!(@graph, Path.basename(Path.dirname(path)))

          unless Enum.sort(declared) == Enum.sort(expected),
            do: raise("internal dependency graph mismatch in #{path}")
        end

        updated =
          Regex.replace(
            ~r/\{:([a-z_]+), "[^"]+", in_umbrella: true, hex: :([a-z_]+)\}/,
            updated,
            fn full, app, hex ->
              unless app == hex and MapSet.member?(@internal, app),
                do: raise("invalid internal Hex identity in #{path}: #{full}")

              wanted = "{:#{app}, \"== #{version}\", in_umbrella: true, hex: :#{app}}"

              if mode == "validate" and full != wanted,
                do: raise("release identity mismatch in #{path}: #{app}")

              wanted
            end
          )

        {path, updated}
      end)

    verify_locked_dependencies!(version)

    if mode == "prepare",
      do: Enum.each(contents, fn {path, source} -> File.write!(path, source) end)

    IO.puts("release sources and locked external requirements validated for #{version}")
  end

  def run(_), do: raise("usage: elixir scripts/release/versions.exs prepare|validate VERSION")

  defp replace_one!(source, regex, wanted, mode, path) do
    matches = Regex.scan(regex, source)
    unless length(matches) == 1, do: raise("expected exactly one release field in #{path}")

    if mode == "validate" and matches != [[wanted]],
      do: raise("release identity mismatch in #{path}")

    if mode == "prepare", do: Regex.replace(regex, source, wanted), else: source
  end

  defp verify_locked_dependencies!(version) do
    Mix.start()
    lock = Mix.Dep.Lock.read("mix.lock")

    Enum.each(lock, fn {package, entry} ->
      if MapSet.member?(@internal, to_string(package)),
        do: raise("internal package #{package} must not be locked externally")

      case entry do
        {:hex, _, _, _, _, dependencies, _, _} ->
          Enum.each(dependencies, fn {name, requirement, _options} ->
            if MapSet.member?(@internal, to_string(name)) and
                 not Version.match?(version, requirement) do
              raise "#{package} requires #{name} #{requirement}, incompatible with #{version}; see https://github.com/gsmlg-dev/http_fetch/issues/16"
            end
          end)

        _ ->
          :ok
      end
    end)
  end
end

ReleaseVersions.run(System.argv())
