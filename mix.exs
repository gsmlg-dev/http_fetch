defmodule HttpFetch.Umbrella.MixProject do
  use Mix.Project

  @version "0.9.1"
  @source_url "https://github.com/gsmlg-dev/http_fetch"

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
    run_child_e2e(:http_fetch, "apps/http_fetch", [])
    run_child_e2e(:http_event_source, "apps/http_event_source", [])
    run_child_e2e(:http_web_transport, "apps/http_web_transport", [])
    run_child_e2e(:http_web_socket, "apps/http_web_socket", [])
  end

  defp run_e2e_tests(args) do
    Mix.Task.run("test", args)
  end

  defp run_child_e2e(app, path, args) do
    Mix.Project.in_project(app, path, fn _module ->
      Mix.Task.run("test.e2e", args)
      Mix.Task.reenable("test.e2e")
      Mix.Task.reenable("test")
    end)
  end
end
