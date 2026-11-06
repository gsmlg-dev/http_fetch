defmodule Abyss.MixProject do
  use Mix.Project

  @source_url "https://github.com/gsmlg-dev/http_fetch"
  @version "1.0.0-rc.3"

  def project do
    [
      app: :abyss,
      version: @version,
      build_path: "../../_build",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      name: "Abyss",
      description: "Abyss is a pure Elixir UDP server",
      source_url: @source_url,
      dialyzer: dialyzer(),
      aliases: aliases(),
      package: package(),
      deps: deps(),
      docs: docs(),
      test_coverage: [
        ignore_modules: [
          ~r[Abyss.Test.*]
        ],
        summary: [threshold: 40]
      ]
    ]
  end

  def application do
    [
      mod: {Abyss.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps() do
    [
      {:telemetry, "~> 1.0"},
      {:telemetry_metrics, "~> 1.0"},
      {:mox, "~> 1.0", only: :test},
      {:ex_dns, "~> 0.3", only: [:dev, :test], runtime: false, optional: true},
      {:dhcp_ex, "~> 0.3", only: [:dev, :test], runtime: false, optional: true},
      {:machete, ">= 0.0.0", only: [:dev, :test]},
      {:ex_doc, ">= 0.0.0", only: [:dev, :test], runtime: false},
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

  defp package do
    [
      maintainers: ["Jonathan Gao"],
      licenses: ["MIT"],
      files:
        ~w(lib LICENSE mix.exs README.md docs/README.md docs/architecture.md docs/operations.md docs/releases.md docs/monorepo.md
           docs/dispatcher.md docs/quic-service.md docs/udp-broadcast-multicast.md
           docs/udp-runtime/design.md docs/udp-runtime/migration.md),
      links: %{
        Github: @source_url,
        Changelog: "https://hexdocs.pm/abyss/changelog.html"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        {"docs/README.md", filename: "documentation", title: "Documentation guide"},
        "docs/architecture.md",
        "docs/operations.md",
        "docs/releases.md",
        "docs/monorepo.md",
        "docs/dispatcher.md",
        "docs/quic-service.md",
        "docs/udp-broadcast-multicast.md",
        "docs/udp-runtime/design.md",
        "docs/udp-runtime/migration.md"
      ],
      groups_for_extras: [
        Overview: ["README.md", "docs/README.md", "docs/architecture.md"],
        Guides: [
          "docs/udp-runtime/migration.md",
          "docs/udp-runtime/design.md",
          "docs/udp-broadcast-multicast.md",
          "docs/dispatcher.md",
          "docs/quic-service.md"
        ],
        Operations: ["docs/operations.md", "docs/releases.md"]
      ],
      source_url: @source_url,
      source_ref: "main",
      source_url_pattern: "#{@source_url}/blob/main/apps/abyss/%{path}#L%{line}"
    ]
  end

  defp aliases do
    [
      "test.coverage": ["test --cover --include integration --include slow"],
      "test.all": ["test --include integration --include slow"],
      "test.unit": ["test --exclude integration --exclude slow"],
      "test.integration": ["test --include integration"],
      ci: [
        "format --check-formatted",
        "credo --strict",
        "test --cover --include integration"
      ]
    ]
  end
end
