defmodule QuicHttp3.MixProject do
  use Mix.Project

  @version "0.17.1"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :elixir_quic_http3,
      version: @version,
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      elixir: "~> 1.18",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "HTTP/3 application protocol layer for Elixir QUIC transports",
      package: [
        files: ["lib", "mix.exs", "README.md", "LICENSE"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => "#{@source_url}/tree/main/apps/elixir_quic_http3"}
      ],
      docs: [
        main: "QuicHttp3",
        source_ref: "v#{@version}",
        source_url: @source_url
      ]
    ]
  end

  def application do
    [
      mod: {QuicHttp3.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      # TODO(upstream): gsmlg-dev/http_fetch#16
      {:http_core, "== 0.17.1", in_umbrella: true, hex: :http_core},
      {:elixir_quic, "== 0.17.1", in_umbrella: true, hex: :elixir_quic},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
