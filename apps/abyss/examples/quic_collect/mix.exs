defmodule AbyssCollectExample.MixProject do
  use Mix.Project

  def project do
    [
      app: :abyss_quic_collect_example,
      version: "0.1.0",
      elixir: "~> 1.18",
      deps: deps()
    ]
  end

  defp deps do
    engine =
      case System.get_env("ELIXIR_QUIC_PATH") do
        nil ->
          [{:elixir_quic, "== 0.21.17"}]

        path ->
          [
            {:elixir_quic, path: path},
            {:ex_ssl, path: System.fetch_env!("EX_SSL_PATH"), override: true}
          ]
      end

    [{:abyss, path: System.get_env("ABYSS_PATH", "../..")} | engine]
  end

  def application,
    do: [extra_applications: [:logger, :public_key], mod: {AbyssCollectExample.Application, []}]
end
