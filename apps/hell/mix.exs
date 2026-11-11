defmodule Hell.MixProject do
  use Mix.Project

  def project do
    [
      app: :hell,
      version: "1.0.0-rc.12",
      build_path: "../../_build",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: ">= 1.18.0",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: dialyzer(),
      name: "Hell",
      description: "A simple & modern pure Elixir socket server",
      source_url: "https://github.com/gsmlg-dev/http_fetch",
      package: [
        name: "hell",
        licenses: ["MIT"],
        links: %{
          "GitHub" => "https://github.com/gsmlg-dev/http_fetch",
          "Changelog" =>
            "https://github.com/gsmlg-dev/http_fetch/blob/main/apps/hell/CHANGELOG.md"
        },
        files: [
          "lib",
          "mix.exs",
          "README*",
          "LICENSE*",
          "CHANGELOG*",
          "MIGRATION.md",
          "RELEASE.md"
        ]
      ],
      docs: docs()
    ]
  end

  def application do
    [extra_applications: [:logger] ++ if(Mix.env() == :test, do: [:ssl], else: [])]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps() do
    [
      {:ex_ssl, "== 1.0.0-rc.12", in_umbrella: true, hex: :ex_ssl},
      {:telemetry, "~> 0.4 or ~> 1.0"},
      {:machete, ">= 0.0.0", only: [:dev, :test]},
      {:ex_doc, "~> 0.25", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.0", only: [:dev, :test], runtime: false},
      {:credo, "~> 1.5", only: [:dev, :test], runtime: false}
    ]
  end

  defp dialyzer do
    [
      plt_core_path: "priv/plts",
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
      plt_add_deps: :apps_direct,
      plt_add_apps: [:public_key],
      flags: [
        "-Werror_handling",
        "-Wextra_return",
        "-Wmissing_return",
        "-Wunknown",
        "-Wunmatched_returns",
        "-Wunderspecs"
      ]
    ]
  end

  defp docs do
    [
      main: "Hell",
      source_url: "https://github.com/gsmlg-dev/http_fetch",
      source_ref: "main",
      source_url_pattern:
        "https://github.com/gsmlg-dev/http_fetch/blob/main/apps/hell/%{path}#L%{line}",
      extras: ["MIGRATION.md", "CHANGELOG.md"],
      groups_for_extras: [
        Changelog: ~r/CHANGELOG\.md/
      ],
      groups_for_modules: [
        Transport: [
          Hell.Transport,
          Hell.Transports.TCP,
          Hell.Transports.SSL
        ]
      ]
    ]
  end
end
