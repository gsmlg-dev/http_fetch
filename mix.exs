defmodule HttpFetch.MixProject do
  use Mix.Project

  @version "0.9.1"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :http_fetch,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps(),
      dialyzer: dialyzer(),
      aliases: aliases(),
      description:
        "A browser-like HTTP fetch API for Elixir using Erlang's built-in socket modules",
      package: [
        files: ["lib", "mix.exs", "README*", "LICENSE*", "CHANGELOG*"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url}
      ]
    ]
  end

  # Specifies which paths to compile per environment.
  # `e2e/support` is added so the helpers (Server, ResponseView, SSE) are
  # available to e2e tests under `e2e/`.
  defp elixirc_paths(:test), do: ["lib", "test/support", "e2e/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :public_key, :ssl],
      mod: {HTTPFetch.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:telemetry, "~> 1.0"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:briefly, "~> 0.4", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp dialyzer do
    [
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"},
      plt_add_apps: [:ex_unit, :mix],
      flags: [:unmatched_returns, :error_handling, :underspecs],
      ignore_warnings: ".dialyzer_ignore.exs"
    ]
  end

  defp aliases do
    [
      # `mix test.e2e [path]` runs the e2e test files (optionally filtered
      # to a single file or line range).
      "test.e2e": [&run_e2e_tests/1]
    ]
  end

  defp run_e2e_tests(args) do
    # If the user passed file paths or line refs, run only those.
    # Otherwise, run everything under `e2e/`.
    if Enum.any?(args) do
      Mix.Task.run("test", args)
    else
      Mix.Task.run("test", ["e2e/"])
    end
  end
end
