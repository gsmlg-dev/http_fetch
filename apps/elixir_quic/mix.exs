defmodule Quic.MixProject do
  use Mix.Project

  def project do
    [
      app: :elixir_quic,
      version: "0.19.1",
      description:
        "Experimental QUIC v1 transport, Initial fingerprint observation and client profiles",
      package: package(),
      elixir: "~> 1.18",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      warnings_as_errors: true
    ]
  end

  def application do
    [extra_applications: [:crypto, :logger]]
  end

  def cli do
    [preferred_envs: ["test.watch": :test]]
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/gsmlg-dev/http_fetch/tree/main/apps/elixir_quic"}
    ]
  end

  defp deps do
    [{:ex_ssl, "== 0.19.1", in_umbrella: true, hex: :ex_ssl}]
  end
end
