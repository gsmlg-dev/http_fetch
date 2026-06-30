defmodule HttpCore.MixProject do
  use Mix.Project

  @version "0.10.0"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :http_core,
      version: @version,
      build_path: "../../_build",
      deps_path: "../../deps",
      elixir: "~> 1.18",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Shared HTTP primitives for browser-like protocol clients",
      package: [
        files: ["lib", "mix.exs"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url}
      ],
      docs: [
        main: "HTTP.Headers",
        source_ref: "v#{@version}",
        source_url: @source_url
      ]
    ]
  end

  def application do
    [
      extra_applications: [:public_key, :ssl]
    ]
  end

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
