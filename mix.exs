defmodule HttpFetch.MixProject do
  use Mix.Project

  @version "0.4.0"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

  def project do
    [
      app: :http_fetch,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "A browser-like HTTP fetch API for Elixir using Erlang's built-in :httpc module",
      package: [
        files: ["lib", "mix.exs", "README*", "LICENSE*", "CHANGELOG*"],
        maintainers: ["Jonathan Gao"],
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url}
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :inets, :public_key, :ssl],
      mod: {HTTPFetch.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:briefly, "~> 0.4", only: :test}
    ]
  end
end
