defmodule ExSslFeatureConsumer.MixProject do
  use Mix.Project

  def project do
    packages = System.fetch_env!("HTTP_FETCH_PACKAGE_DIR")

    ex_ssl =
      case System.fetch_env!("EX_SSL_DEP_MODE") do
        "published" -> {:ex_ssl, "~> 0.7.2"}
        "source" -> {:ex_ssl, path: System.fetch_env!("EX_SSL_SOURCE_DIR"), override: true}
      end

    [
      app: :ex_ssl_feature_consumer,
      version: "0.0.0",
      deps: [
        {:http_core, path: Path.join(packages, "http_core")},
        {:elixir_quic_http3, path: Path.join(packages, "elixir_quic_http3")},
        {:http_fetch, path: Path.join(packages, "http_fetch")},
        {:http_web_socket, path: Path.join(packages, "http_web_socket")},
        {:http_event_source, path: Path.join(packages, "http_event_source")},
        {:http_web_transport, path: Path.join(packages, "http_web_transport")},
        ex_ssl
      ]
    ]
  end

  def application, do: [extra_applications: [:logger, :ssl, :public_key]]
end
