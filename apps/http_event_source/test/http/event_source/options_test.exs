defmodule HTTP.EventSource.OptionsTest do
  use ExUnit.Case, async: false

  alias HTTP.EventSource.Options

  @h3_ca Path.expand("../../../../elixir_quic/test/fixtures/tls/root.pem", __DIR__)

  test "HTTP3 is explicit, HTTPS-only and preserves QUIC profile and trust options" do
    ssl = [cacertfile: @h3_ca, reference_identity: {:dns_id, "example.test"}]

    assert {:ok, options} =
             Options.new("https://example.test/events", %{
               "httpVersion" => "h3",
               "http3Profile" => :compact,
               "http3Reuse" => false,
               "ssl" => ssl
             })

    assert options.http_version == :http3
    assert options.http3_profile == :compact
    assert options.http3_reuse == false
    assert options.tls_backend == nil
    assert options.ssl == ssl
    transport = HTTP.Runtime.Options.transport_options(options)
    assert transport[:http3_profile] == :compact
    assert transport[:http3_reuse] == false
    refute Keyword.has_key?(transport, :tls_backend)

    assert {:error, :invalid_http_version} =
             HTTP.Runtime.Options.validate(URI.parse("https://example.test/events"),
               http_version: :http3
             )
  end

  test "HTTP3 rejects contradictory routes, TLS options and connection headers before networking" do
    for {url, init, reason} <- [
          {"http://example.test/events", [], :http3_requires_https},
          {"https://example.test/events", [tls_backend: :ssl],
           :tls_backend_not_supported_for_quic},
          {"https://example.test/events", [unix_socket: "/tmp/h3-sse.sock"],
           :unix_socket_not_supported_for_quic},
          {"https://example.test/events", [proxy: "http://proxy.test:8080"],
           :proxy_not_supported_for_quic},
          {"https://example.test/events", [http2_profile: :native_v1],
           :http2_options_require_http2},
          {"https://example.test/events", [socket_opts: [nodelay: true]],
           :socket_options_not_supported_for_quic},
          {"https://example.test/events", [connect_timeout: :infinity], :invalid_connect_timeout},
          {"https://example.test/events", [ssl: [verify: :verify_none]],
           :verify_none_not_supported}
        ] do
      assert {:error, ^reason} = Options.new(url, [http_version: :http3] ++ init)
    end

    for header <- [{"Connection", "keep-alive"}, {"TE", "gzip"}, {":path", "/injected"}] do
      assert {:error, :invalid_headers} =
               Options.new("https://example.test/events",
                 http_version: :http3,
                 ssl: [cacertfile: @h3_ca],
                 headers: [header]
               )
    end

    assert {:error, :invalid_http3_reuse} =
             Options.new("https://example.test/events",
               http_version: :http3,
               ssl: [cacertfile: @h3_ca],
               http3_reuse: :sometimes
             )

    assert {:error, {:invalid_profile, :browser}} =
             Options.new("https://example.test/events",
               http_version: :http3,
               ssl: [cacertfile: @h3_ca],
               http3_profile: :browser
             )
  end

  test "normalizes supported URL schemes" do
    assert {:ok, %{uri: %{scheme: "http"}, url: "http://example.com/events"}} =
             Options.new("http://example.com/events")

    assert {:ok, %{uri: %{scheme: "https"}, url: "https://example.com/events"}} =
             Options.new("https://example.com/events")
  end

  test "rejects unsupported URLs" do
    assert {:error, {:unsupported_scheme, "ftp"}} = Options.new("ftp://example.com/events")
    assert {:error, {:unsupported_scheme, nil}} = Options.new("/events")
  end

  test "normalizes flat init options" do
    assert {:ok, options} =
             Options.new("http://example.com/events",
               owner: self(),
               with_credentials: true,
               headers: %{"x-token" => "abc"},
               last_event_id: "42",
               reconnect_time: 10,
               max_reconnect_time: 20,
               connect_timeout: 30,
               idle_timeout: 40,
               ssl: [verify: :verify_none],
               socket_opts: [nodelay: true],
               unix_socket: "/tmp/events.sock",
               max_line_size: 50
             )

    assert options.owner == self()
    assert options.with_credentials == true
    assert {"X-Token", "abc"} in options.headers
    assert options.last_event_id == "42"
    assert options.reconnect_time == 10
    assert options.max_reconnect_time == 20
    assert options.connect_timeout == 30
    assert options.idle_timeout == 40
    assert options.ssl == [verify: :verify_none]
    assert options.socket_opts == [nodelay: true]
    assert options.unix_socket == "/tmp/events.sock"
    assert options.max_line_size == 50
  end

  test "normalizes string init keys" do
    assert {:ok, %{with_credentials: true, last_event_id: "abc"}} =
             Options.new("http://example.com/events", %{
               "withCredentials" => true,
               "lastEventId" => "abc"
             })
  end

  test "selects TLS backends from atom and string map options" do
    assert {:ok, %{tls_backend: :ssl}} =
             Options.new("https://example.com/events", tls_backend: :ssl)

    assert {:ok, %{tls_backend: :ex_ssl}} =
             Options.new("https://example.com/events", %{"tlsBackend" => "ex_ssl"})

    assert {:ok, %{tls_backend: :ssl}} =
             Options.new("https://example.com/events", %{"tls_backend" => "ssl"})
  end

  test "pins the configured TLS backend when options are constructed" do
    previous = Application.get_env(:http_core, :tls_backend)
    on_exit(fn -> restore_tls_backend(previous) end)

    Application.put_env(:http_core, :tls_backend, :ex_ssl)
    assert {:ok, options} = Options.new("https://example.com/events")
    assert options.tls_backend == :ex_ssl

    assert {:ok, %{tls_backend: :ssl}} =
             Options.new("https://example.com/events", tls_backend: :ssl)

    Application.put_env(:http_core, :tls_backend, :ssl)
    assert options.tls_backend == :ex_ssl
    assert {:ok, %{tls_backend: :ssl}} = Options.new("https://example.com/events")
  end

  test "rejects invalid init options" do
    assert {:error, :invalid_owner} = Options.new("http://example.com/events", owner: :bad)

    assert {:error, :invalid_last_event_id} =
             Options.new("http://example.com/events", last_event_id: "bad\nid")

    assert {:error, :invalid_reconnect_time} =
             Options.new("http://example.com/events", reconnect_time: -1)

    assert {:error, :invalid_tls_backend} =
             Options.new("https://example.com/events", tls_backend: :unknown)
  end

  test "defaults keep HTTP1 and finite parser and delivery bounds" do
    assert {:ok, options} = Options.new("http://example.com/events")
    assert options.http_version == :http1
    assert options.delivery == :legacy
    assert options.http2_profile == nil
    assert options.http2_scope == nil
    assert options.http2_reuse == true

    for value <- [
          options.max_event_size,
          options.max_event_parts,
          options.max_queue_bytes,
          options.max_queue_events
        ] do
      assert is_integer(value) and value > 0
    end
  end

  test "normalizes camelCase shared runtime and event bound aliases" do
    assert {:ok, options} =
             Options.new("https://example.com/events", %{
               "httpVersion" => "http2",
               "http2Profile" => :native_v1,
               "http2Scope" => "tenant-a",
               "http2Reuse" => false,
               "delivery" => "ack",
               "maxQueueBytes" => 1024,
               "maxQueueEvents" => 3,
               "maxEventSize" => 512,
               "maxEventParts" => 8,
               "maxRedirects" => 2
             })

    assert options.http_version == :http2
    assert options.http2_profile.id == "native_v1"
    assert options.http2_scope == "tenant-a"
    assert options.http2_reuse == false
    assert options.delivery == :ack
    assert options.max_queue_bytes == 1024
    assert options.max_queue_events == 3
    assert options.max_event_size == 512
    assert options.max_event_parts == 8
    assert options.max_redirects == 2
  end

  test "rejects route, profile and ALPN contradictions before a connection exists" do
    for {url, init, reason} <- [
          {"http://example.com/events", [http_version: :http2], :http2_requires_tls},
          {"https://example.com/events", [http_version: :h2c], :h2c_requires_cleartext},
          {"http://example.com/events", [http_version: :auto, http2_profile: :native_v1],
           :http2_options_require_http2},
          {"https://example.com/events", [http_version: :http1, http2_reuse: false],
           :http2_options_require_http2},
          {"http://example.com/events",
           [http_version: :h2c, unix_socket: "/tmp/unused-sse-options.sock"],
           {:unsupported_http_version_for_unix_socket, :h2c}},
          {"https://example.com/events",
           [http_version: :http2, ssl: [alpn_advertised_protocols: ["http/1.1"]]],
           :incompatible_alpn}
        ] do
      assert {:error, ^reason} = Options.new(url, init)
    end
  end

  test "event and acknowledged delivery budgets must be finite and positive" do
    for {key, reason} <- [
          {:max_event_size, {:invalid_option, :max_event_size}},
          {:max_event_parts, {:invalid_option, :max_event_parts}},
          {:max_queue_bytes, :invalid_max_queue_bytes},
          {:max_queue_events, :invalid_max_queue_events}
        ],
        value <- [0, -1, :infinity, 1.5] do
      assert {:error, ^reason} = Options.new("http://example.com/events", [{key, value}])
    end

    assert {:error, :event_limit_exceeds_delivery_limit} =
             Options.new("http://example.com/events",
               delivery: :ack,
               max_event_size: 32,
               max_queue_bytes: 38
             )

    assert {:ok, _} =
             Options.new("http://example.com/events",
               delivery: :ack,
               max_event_size: 32,
               max_queue_bytes: 39,
               max_queue_events: 1
             )

    assert {:ok, %{max_redirects: 0}} =
             Options.new("http://example.com/events", max_redirects: 0)

    assert {:error, {:invalid_option, :max_redirects}} =
             Options.new("http://example.com/events", max_redirects: :infinity)
  end

  test "cursor constructor rejects every header control byte and invalid UTF8" do
    for byte <- Enum.to_list(0..31) ++ [127] do
      assert {:error, :invalid_last_event_id} =
               Options.new("http://example.com/events", last_event_id: "a" <> <<byte>> <> "b")
    end

    assert {:error, :invalid_last_event_id} =
             Options.new("http://example.com/events", last_event_id: <<255>>)

    assert {:ok, %{last_event_id: "λ 7"}} =
             Options.new("http://example.com/events", last_event_id: "λ 7")
  end

  test "caller headers cannot inject cursor lines or HTTP2 connection fields" do
    for headers <- [
          [{"Last-Event-ID", "7\r\nx-secret: injected"}],
          [{":method", "POST"}],
          [{"Connection", "keep-alive"}],
          [{"Upgrade", "h2c"}]
        ] do
      assert {:error, :invalid_headers} =
               Options.new("http://example.com/events", http_version: :h2c, headers: headers)
    end
  end

  defp restore_tls_backend(nil), do: Application.delete_env(:http_core, :tls_backend)
  defp restore_tls_backend(value), do: Application.put_env(:http_core, :tls_backend, value)
end
