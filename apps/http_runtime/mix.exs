defmodule HttpRuntime.MixProject do
  use Mix.Project

  @version "0.21.1"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :http_runtime,
      version: @version,
      build_path: "../../_build",
      deps_path: "../../deps",
      elixir: "~> 1.18",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Shared pooled HTTP/2 runtime for HTTP stream clients",
      package: [
        files: ["lib", "mix.exs", "LICENSE"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url}
      ],
      docs: [
        main: "HTTP.Runtime.Stream",
        source_ref: "v#{@version}",
        source_url: @source_url
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {HTTPRuntime.Application, []}
    ]
  end

  defp deps do
    [
      {:http_core, "== 0.21.1", in_umbrella: true, hex: :http_core},
      {:elixir_quic_http3, "== 0.21.1", in_umbrella: true, hex: :elixir_quic_http3},
      {:telemetry, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
