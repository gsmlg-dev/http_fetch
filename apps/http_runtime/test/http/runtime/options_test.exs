defmodule HTTP.Runtime.OptionsTest do
  use ExUnit.Case, async: true
  alias HTTP.Runtime.Options

  test "stream clients reject explicit proxy endpoints instead of ignoring the route" do
    for init <- [
          [proxy: "http://proxy.example.test:8080"],
          %{"proxy" => "http://proxy.example.test:8080"}
        ] do
      assert {:error, :proxy_not_supported} =
               Options.validate(URI.parse("https://example.test/"), init)
    end

    assert {:ok, _} = Options.validate(URI.parse("https://example.test/"), proxy: nil)
  end

  test "secure Unix routes reject before networking while plain schemes retain H1" do
    path = "/unused-secure-unix.sock"

    for scheme <- ["https", "wss"], version <- [:http1, :auto, :http2] do
      assert {:error, :tls_over_unix_socket_not_supported} =
               Options.validate(URI.parse("#{scheme}://example.test/"),
                 unix_socket: path,
                 http_version: version
               )
    end

    for scheme <- ["http", "ws"] do
      assert {:ok, _} =
               Options.validate(URI.parse("#{scheme}://example.test/"), unix_socket: path)
    end
  end

  test "defaults preserve HTTP1 and aliases normalize explicit transport identity" do
    assert {:ok, options} = Options.validate(URI.parse("https://example.test/"), [])
    assert options[:http_version] == :http1
    assert options[:delivery] == :legacy
    assert options[:tls_backend] == :ex_ssl

    assert {:ok, h2} =
             Options.validate(URI.parse("wss://example.test/"), %{
               "httpVersion" => "http2",
               "http2Profile" => :native_v1,
               "http2Scope" => "tenant",
               "http2Reuse" => true,
               "delivery" => "ack"
             })

    assert h2[:http_version] == :http2
    assert h2[:delivery] == :ack
    assert h2[:http2_scope] == "tenant"
    assert %URI{scheme: "https", port: 443} = Options.origin_uri(URI.parse("wss://example.test/"))
  end

  test "route and profile contradictions fail before networking" do
    for {url, options, reason} <- [
          {"http://example.test/", [http_version: :http2], :http2_requires_tls},
          {"https://example.test/", [http_version: :h2c], :h2c_requires_cleartext},
          {"http://example.test/", [http_version: :auto, http2_profile: :native_v1],
           :http2_options_require_http2},
          {"https://example.test/", [http_version: :http1, http2_reuse: false],
           :http2_options_require_http2},
          {"https://example.test/", [http_version: :auto, http2_scope: :private],
           :http2_options_require_http2},
          {"http://example.test/",
           [http_version: :h2c, unix_socket: "/tmp/unopened-http-stream.sock"],
           {:unsupported_http_version_for_unix_socket, :h2c}}
        ] do
      assert {:error, ^reason} = Options.validate(URI.parse(url), options)
    end
  end

  test "TLS backend stays explicit and incompatible ALPN never gets silently overwritten" do
    assert {:ok, options} =
             Options.validate(URI.parse("https://example.test/"),
               http_version: :http2,
               tls_backend: :ex_ssl
             )

    assert options[:tls_backend] == :ex_ssl

    for {version, alpn} <- [{:http1, ["h2"]}, {:http2, ["http/1.1"]}, {:auto, ["h2"]}] do
      assert {:error, :incompatible_alpn} =
               Options.validate(URI.parse("https://example.test/"),
                 http_version: version,
                 ssl: [alpn_advertised_protocols: alpn]
               )
    end

    assert {:ok, _} =
             Options.validate(URI.parse("https://example.test/"),
               http_version: :auto,
               ssl: [alpn_advertised_protocols: ["http/1.1", "h2"]]
             )

    assert {:ok, options} =
             Options.validate(URI.parse("https://example.test/"),
               http_version: :auto,
               http2_profile: :native_v1
             )

    assert options[:http2_profile].id == "native_v1"
  end

  test "pseudo headers, controls, H2 connection fields and invalid finite delivery budgets fail" do
    for header <- [
          {":protocol", "websocket"},
          {"x-secret", "value\r\ninjected: yes"},
          {"connection", "upgrade"},
          {"x-padding", " value"}
        ] do
      assert {:error, :invalid_headers} =
               Options.validate(URI.parse("http://example.test/"),
                 http_version: :h2c,
                 headers: [header]
               )
    end

    for {key, value, reason} <- [
          {:delivery, :pull, :invalid_delivery},
          {:max_queue_bytes, 0, :invalid_max_queue_bytes},
          {:max_queue_events, :infinity, :invalid_max_queue_events},
          {:http2_reuse, "yes", :invalid_http2_reuse},
          {:http2_scope, make_ref(), :invalid_http2_scope},
          {:http_version, :http3, :invalid_http_version}
        ] do
      assert {:error, ^reason} =
               Options.validate(URI.parse("https://example.test/"), [{key, value}])
    end
  end
end
