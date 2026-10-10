defmodule HttpFetch.Umbrella.MixProject do
  use Mix.Project

  @version "0.21.2"
  @source_url "https://github.com/gsmlg-dev/http_fetch"
  @e2e_apps ~w(http_fetch http_event_source http_web_transport http_web_socket)

  def project do
    [
      apps_path: "apps",
      apps: ci_apps(),
      version: @version,
      elixir: "~> 1.18",
      name: "HTTP Fetch",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: dialyzer(),
      aliases: aliases(),
      docs: [
        main: "readme",
        extras: [
          "README.md",
          "CHANGELOG.md",
          "docs/managed-transports.md",
          "docs/migration-provenance.md",
          "docs/migration-validation.md",
          "docs/ex-ssl-consumer-contract.md",
          "docs/ex-quic-consumer-contract.md",
          "docs/quic_http3_design.md",
          "docs/http3-fetch-contract.md",
          "docs/http3-wp5-acceptance.md",
          "docs/http3-implementation-audit.md",
          "apps/http_event_source/docs/http3-validation.md",
          "docs/pr-14-validation.md"
        ],
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

  # CI compiles the selected package and the siblings required by that package.
  # A normal invocation leaves app selection to Mix and includes the full umbrella.
  defp ci_apps do
    case System.get_env("HTTP_FETCH_CI_APP") do
      nil ->
        nil

      "ex_ssl" ->
        [:ex_ssl]

      "elixir_quic" ->
        [:ex_ssl, :elixir_quic]

      "http_core" ->
        [:ex_ssl, :elixir_quic, :http_core]

      "elixir_quic_http3" ->
        [:ex_ssl, :elixir_quic, :http_core, :elixir_quic_http3]

      "http_runtime" ->
        [:ex_ssl, :elixir_quic, :http_core, :elixir_quic_http3, :http_runtime]

      "http_fetch" ->
        [:ex_ssl, :elixir_quic, :http_core, :elixir_quic_http3, :http_runtime, :http_fetch]

      "http_event_source" ->
        test_consumer_apps(:http_event_source)

      "http_web_socket" ->
        test_consumer_apps(:http_web_socket)

      "http_web_transport" ->
        [:ex_ssl, :elixir_quic, :http_core, :http_web_transport]

      other ->
        raise "invalid HTTP_FETCH_CI_APP: #{inspect(other)}"
    end
  end

  # Shared-connection tests call HTTP.fetch/2; this is not a production dependency.
  defp test_consumer_apps(app) do
    runtime = [:ex_ssl, :elixir_quic, :http_core, :elixir_quic_http3, :http_runtime]
    runtime ++ if(Mix.env() == :test, do: [:http_fetch, app], else: [app])
  end

  defp dialyzer do
    [
      paths: ci_dialyzer_paths(),
      plt_file: {:no_warn, "apps/http_fetch/priv/plts/dialyzer.plt"},
      plt_add_apps: [:ex_unit, :mix],
      flags: [:unmatched_returns, :error_handling, :underspecs],
      ignore_warnings: ".dialyzer_ignore.exs"
    ]
  end

  defp ci_dialyzer_paths do
    case System.get_env("HTTP_FETCH_CI_APP") do
      nil ->
        nil

      app ->
        build = Mix.Project.build_path(build_path: "_build", build_per_environment: true)
        [Path.join([build, "lib", app, "ebin"])]
    end
  end

  defp aliases do
    [
      "test.e2e": [&run_e2e_tests/1]
    ]
  end

  defp run_e2e_tests([]) do
    Mix.Task.run("test", Enum.map(@e2e_apps, &"apps/#{&1}/e2e"))
  end

  defp run_e2e_tests(args) do
    Mix.Task.run("test", args)
  end
end
