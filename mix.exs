defmodule HttpFetch.Umbrella.MixProject do
  use Mix.Project

  @version "0.16.5"
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
          "docs/migration-provenance.md",
          "docs/migration-validation.md",
          "docs/ex-ssl-consumer-contract.md",
          "docs/ex-quic-consumer-contract.md",
          "docs/quic_http3_design.md",
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

  # CI compiles the selected package and the siblings required by its tests.
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
        [
          :ex_ssl,
          :elixir_quic,
          :http_core,
          :elixir_quic_http3,
          :http_runtime,
          :http_fetch,
          :http_event_source
        ]

      "http_web_socket" ->
        [
          :ex_ssl,
          :elixir_quic,
          :http_core,
          :elixir_quic_http3,
          :http_runtime,
          :http_fetch,
          :http_web_socket
        ]

      "http_web_transport" ->
        [:ex_ssl, :elixir_quic, :http_core, :http_web_transport]

      other ->
        raise "invalid HTTP_FETCH_CI_APP: #{inspect(other)}"
    end
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
    Mix.Task.run("test", Enum.map(@e2e_apps, &"apps/#{&1}/e2e"))
  end

  defp run_e2e_tests(args) do
    Mix.Task.run("test", args)
  end
end
