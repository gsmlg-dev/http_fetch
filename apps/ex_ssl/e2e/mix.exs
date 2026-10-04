defmodule ExSslE2E.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_ssl_e2e,
      version: "0.1.0",
      elixir: "~> 1.18",
      elixirc_paths: ["lib"],
      deps: [{:ex_ssl, path: ".."}]
    ]
  end

  def application do
    [extra_applications: [:crypto, :public_key]]
  end
end
