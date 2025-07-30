defmodule HttpFetch.MixProject do
  use Mix.Project

  def project do
    [
      app: :http_fetch,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "A browser-like HTTP fetch API for Elixir using Erlang's built-in :httpc module",
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/gsmlg-dev/http_fetch"
      }
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
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
