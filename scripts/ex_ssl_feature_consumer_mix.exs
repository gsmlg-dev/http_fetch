defmodule ExSslFeatureConsumer.MixProject do
  use Mix.Project

  def project do
    mode = System.fetch_env!("EX_SSL_DEP_MODE")
    version = System.get_env("HTTP_FETCH_RELEASE_VERSION")

    deps =
      if mode == "candidate" do
        for app <- [
              :http_fetch,
              :http_web_socket,
              :http_event_source,
              :http_web_transport,
              :ex_ssl
            ],
            do: {app, "== " <> version}
      else
        packages = System.fetch_env!("HTTP_FETCH_PACKAGE_DIR")

        ex_ssl =
          case mode do
            "published" -> {:ex_ssl, "~> 0.7.2"}
            "source" -> {:ex_ssl, path: System.fetch_env!("EX_SSL_SOURCE_DIR"), override: true}
          end

        [
          {:http_core, path: Path.join(packages, "http_core"), override: true},
          {:http_runtime, path: Path.join(packages, "http_runtime"), override: true},
          {:http_fetch, path: Path.join(packages, "http_fetch")},
          {:http_web_socket, path: Path.join(packages, "http_web_socket")},
          {:http_event_source, path: Path.join(packages, "http_event_source")},
          {:http_web_transport, path: Path.join(packages, "http_web_transport")},
          ex_ssl
        ]
      end

    [
      app: :ex_ssl_feature_consumer,
      version: "0.0.0",
      deps: deps
    ]
  end

  def application, do: [extra_applications: [:logger, :ssl, :public_key]]
end
