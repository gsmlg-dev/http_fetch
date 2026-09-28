defmodule HttpCore.MixProject do
  use Mix.Project

  @version "0.13.0"
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
      # TODO(upstream): gsmlg-dev/ex_quic#4 - replace both Git sources with verified Hex releases.
      {:ex_ssl,
       git: "https://github.com/gsmlg-dev/ex_ssl.git",
       ref: "f1327e0bb7fb2093b8dc2b07e72b26233a739963"},
      {:ex_quic,
       git: "https://github.com/gsmlg-dev/ex_quic.git",
       ref: "5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb"},
      {:quic, "~> 1.6", runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
