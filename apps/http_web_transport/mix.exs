defmodule HttpWebTransport.MixProject do
  use Mix.Project

  @version "0.9.1"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :http_web_transport,
      version: @version,
      build_path: "../../_build",
      deps_path: "../../deps",
      elixir: "~> 1.18",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      aliases: aliases(),
      description: "A browser-like WebTransport client API for Elixir",
      package: [
        files: ["lib", "mix.exs"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url}
      ],
      docs: [
        main: "HTTP.WebTransport",
        source_ref: "v#{@version}",
        source_url: @source_url
      ]
    ]
  end

  def cli do
    [
      preferred_envs: ["test.e2e": :test]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  def application do
    [
      extra_applications: [:logger, :public_key, :ssl],
      mod: {HTTPWebTransport.Application, []}
    ]
  end

  defp deps do
    [
      {:http_core, "~> 0.9.1", in_umbrella: true, hex: :http_core},
      {:telemetry, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      "test.e2e": [&run_e2e_tests/1]
    ]
  end

  defp run_e2e_tests(args) do
    if Enum.any?(args) do
      Mix.Task.run("test", args)
    else
      Mix.Task.run("test", ["e2e/"])
    end
  end
end
