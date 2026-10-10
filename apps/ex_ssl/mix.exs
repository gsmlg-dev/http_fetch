defmodule SSL.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_ssl,
      version: "0.21.2",
      elixir: "~> 1.18",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      description: description(),
      package: package(),
      source_url: "https://github.com/gsmlg-dev/http_fetch",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:crypto, :public_key] ++ if(Mix.env() == :test, do: [:ssl], else: []),
      mod: {SSL.Application, []}
    ]
  end

  defp deps do
    [
      {:stream_data, "~> 1.1", only: :test}
    ]
  end

  defp description do
    "An independent Elixir/OTP TLS stack with programmable ClientHello wire profiles"
  end

  defp package do
    [
      name: "ex_ssl",
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/gsmlg-dev/http_fetch/tree/main/apps/ex_ssl"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]
end
