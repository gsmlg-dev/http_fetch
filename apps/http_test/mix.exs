defmodule HttpTest.MixProject do
  use Mix.Project

  @version "1.0.0-rc.12"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :http_test,
      version: @version,
      build_path: "../../_build",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Owner-isolated HTTP Family fixtures and acknowledged stream testing",
      package: [
        files: ["lib", "mix.exs", "README.md", "CHANGELOG.md", "LICENSE"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url}
      ],
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"],
        source_url: @source_url,
        source_ref: "v#{@version}"
      ]
    ]
  end

  def application, do: [extra_applications: [:logger], mod: {HTTP.Test.Application, []}]

  defp deps do
    [
      {:http_fetch, "== 1.0.0-rc.12", in_umbrella: true, hex: :http_fetch},
      {:plug, "~> 1.16", optional: true},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
