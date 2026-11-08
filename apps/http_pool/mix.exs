defmodule HttpPool.MixProject do
  use Mix.Project
  @version "1.0.0-rc.10"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :http_pool,
      version: @version,
      build_path: "../../_build",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Bounded HTTP/1 idle and HTTP/2 reservation pools",
      package: [
        files: ["lib", "mix.exs", "README.md", "CHANGELOG.md", "LICENSE"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url}
      ],
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"],
        source_ref: "v#{@version}",
        source_url: @source_url
      ]
    ]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [
      {:http_core, "== 1.0.0-rc.10", in_umbrella: true, hex: :http_core},
      {:telemetry, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
