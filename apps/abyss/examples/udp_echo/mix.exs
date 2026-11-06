defmodule AbyssUDPExample.MixProject do
  use Mix.Project

  def project do
    [
      app: :abyss_udp_example,
      version: "0.1.0",
      elixir: "~> 1.18",
      deps: [{:abyss, path: System.get_env("ABYSS_PATH", "../..")}]
    ]
  end

  def application, do: [extra_applications: [:logger], mod: {AbyssUDPExample, []}]
end
