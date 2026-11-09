defmodule AbyssRaw.MixProject do
  use Mix.Project

  @version "1.0.0-rc.11"

  def project do
    [
      app: :abyss_raw,
      version: @version,
      name: "Abyss Raw",
      elixir: "~> 1.18",
      description: "Optional interface-bound DHCP and raw ARP sockets for Abyss",
      deps: [
        {:rustler, "~> 0.34", runtime: false},
        {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
      ],
      docs: [
        main: "readme",
        extras: ["README.md"],
        source_url: "https://github.com/gsmlg-dev/http_fetch",
        source_ref: "main",
        source_url_pattern:
          "https://github.com/gsmlg-dev/http_fetch/blob/main/packages/abyss_raw/%{path}#L%{line}"
      ],
      package: [
        name: "abyss_raw",
        licenses: ["MIT"],
        files: ~w(lib mix.exs README.md LICENSE native/dhcp_socket/src
                  native/dhcp_socket/Cargo.toml native/dhcp_socket/Cargo.lock
                  native/dhcp_socket/.cargo),
        links: %{"GitHub" => "https://github.com/gsmlg-dev/http_fetch"}
      ]
    ]
  end

  def application, do: [extra_applications: [:logger]]
end
