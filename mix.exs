defmodule HttpFetch.Umbrella.MixProject do
  use Mix.Project

  @version "0.10.0"
  @source_url "https://github.com/gsmlg-dev/http_fetch"
  @e2e_apps ~w(http_fetch http_event_source http_web_transport http_web_socket)

  def project do
    [
      apps_path: "apps",
      version: @version,
      elixir: "~> 1.18",
      name: "HTTP Fetch",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: dialyzer(),
      aliases: aliases(),
      docs: [
        main: "readme",
        extras: ["README.md", "CHANGELOG.md"],
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

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp dialyzer do
    [
      plt_file: {:no_warn, "apps/http_fetch/priv/plts/dialyzer.plt"},
      plt_add_apps: [:ex_unit, :mix],
      flags: [:unmatched_returns, :error_handling, :underspecs],
      ignore_warnings: ".dialyzer_ignore.exs"
    ]
  end

  defp aliases do
    [
      "test.e2e": [&run_e2e_tests/1]
    ]
  end

  defp run_e2e_tests([]) do
    args = Enum.flat_map(@e2e_apps, &["--app", &1]) ++ ["cmd", "mix", "test.e2e"]

    Mix.Task.run("do", args)
  end

  defp run_e2e_tests(args) do
    Mix.Task.run("test", args)
  end
end
