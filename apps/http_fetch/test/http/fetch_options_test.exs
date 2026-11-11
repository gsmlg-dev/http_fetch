defmodule HTTP.FetchOptionsTest do
  use ExUnit.Case

  describe "new/1" do
    test "validates proxy request mode in flat init options" do
      assert Map.get(HTTP.FetchOptions.new([]), :request_mode) == :fetch

      for input <- [
            [request_mode: :proxy],
            %{"request_mode" => "proxy"},
            %{"requestMode" => "proxy"}
          ] do
        assert Map.get(HTTP.FetchOptions.new(input), :request_mode) == :proxy
      end

      assert_raise ArgumentError, ~r/unsupported request_mode/, fn ->
        HTTP.FetchOptions.new(request_mode: :invalid)
      end
    end

    test "normalizes request-local header budgets and IPv6 preference in flat options" do
      for input <- [
            [response_header_limits: [max_fields: 10], prefer_ipv6: true],
            %{"response_header_limits" => %{max_fields: 10}, "prefer_ipv6" => true},
            %{"responseHeaderLimits" => %{max_fields: 10}, "preferIPv6" => true}
          ] do
        options = HTTP.FetchOptions.new(input)
        assert options.response_header_limits.max_fields == 10
        assert options.response_header_limits.max_head_bytes == 65_540
        assert options.prefer_ipv6
        transport = HTTP.FetchOptions.to_transport_options(options)
        assert transport[:response_header_limits] == options.response_header_limits
        assert transport[:prefer_ipv6]
      end

      assert HTTP.FetchOptions.new([]).response_header_limits == nil
      refute HTTP.FetchOptions.new([]).prefer_ipv6
      assert_raise ArgumentError, fn -> HTTP.FetchOptions.new(prefer_ipv6: :yes) end

      for version <- [:http2, :h2c, :http3, :auto] do
        assert_raise ArgumentError, fn ->
          HTTP.FetchOptions.new(http_version: version, response_header_limits: [max_fields: 1])
        end
      end
    end

    test "creates from keyword list" do
      options = HTTP.FetchOptions.new(method: "GET", timeout: 5_000)
      assert %HTTP.FetchOptions{method: :get, timeout: 5_000} = options
    end

    test "creates from atom-keyed map" do
      options =
        HTTP.FetchOptions.new(%{method: "POST", headers: %{"Content-Type" => "application/json"}})

      assert %HTTP.FetchOptions{method: :post} = options
      assert %HTTP.Headers{headers: [{"Content-Type", "application/json"}]} = options.headers
    end

    test "creates from browser-style string-keyed map" do
      options =
        HTTP.FetchOptions.new(%{
          "method" => "POST",
          "redirect" => "manual",
          "httpVersion" => "h2",
          "tlsBackend" => "ex_ssl",
          "connectTimeout" => 2_000
        })

      assert %HTTP.FetchOptions{
               method: :post,
               redirect: :manual,
               http_version: :http2,
               tls_backend: :ex_ssl,
               connect_timeout: 2_000
             } =
               options
    end

    test "creates from existing FetchOptions" do
      original = HTTP.FetchOptions.new(method: "GET")
      options = HTTP.FetchOptions.new(original)
      assert %HTTP.FetchOptions{method: :get} = options
    end

    test "normalizes method to atom" do
      assert %HTTP.FetchOptions{method: :get} = HTTP.FetchOptions.new(method: "GET")
      assert %HTTP.FetchOptions{method: :post} = HTTP.FetchOptions.new(method: "POST")
      assert %HTTP.FetchOptions{method: :get} = HTTP.FetchOptions.new(method: :get)
    end

    test "preserves extension method case without interning caller strings" do
      for method <- ["PROPFIND", "REPORT", "MiXeD", "propfind", "!token~"] do
        assert HTTP.FetchOptions.new(method: method).method == method
        assert HTTP.FetchOptions.new(%{"method" => method}).method == method
        assert HTTP.FetchOptions.new(%HTTP.FetchOptions{method: method}).method == method
      end

      method = "X-Unique-Method-#{System.unique_integer([:positive])}"
      assert HTTP.FetchOptions.new(method: method).method == method

      for token <- [method, String.downcase(method)] do
        assert_raise ArgumentError, fn -> String.to_existing_atom(token) end
      end
    end

    test "retains conventional method normalization and rejects malformed tokens" do
      assert HTTP.FetchOptions.new(method: "gEt").method == :get
      assert HTTP.FetchOptions.new(method: :POST).method == :post
      assert HTTP.FetchOptions.new(method: :propfind).method == :propfind

      for method <- [
            "",
            "BAD METHOD",
            "BAD\tMETHOD",
            "BAD\r\nMETHOD",
            "BAD/METHOD",
            "BAD:METHOD",
            "BAD\0METHOD",
            "BAD\x7fMETHOD",
            "ß",
            :ß,
            <<255>>,
            123
          ] do
        assert_raise ArgumentError, ~r/unsupported HTTP method/, fn ->
          HTTP.FetchOptions.new(method: method)
        end
      end
    end

    test "normalizes redirect mode" do
      assert %HTTP.FetchOptions{redirect: :follow} = HTTP.FetchOptions.new([])
      assert %HTTP.FetchOptions{redirect: :follow} = HTTP.FetchOptions.new(redirect: "follow")
      assert %HTTP.FetchOptions{redirect: :manual} = HTTP.FetchOptions.new(redirect: "manual")
      assert %HTTP.FetchOptions{redirect: :error} = HTTP.FetchOptions.new(redirect: :error)
    end

    test "normalizes duplex mode" do
      assert %HTTP.FetchOptions{duplex: nil} = HTTP.FetchOptions.new([])
      assert %HTTP.FetchOptions{duplex: :half} = HTTP.FetchOptions.new(duplex: "half")
      assert %HTTP.FetchOptions{duplex: :half} = HTTP.FetchOptions.new(%{"duplex" => "half"})
    end

    test "raw response decoding option supports flat forms and requires a boolean" do
      assert HTTP.FetchOptions.new([]).decode_body

      for input <- [[decode_body: false], %{"decode_body" => false}, %{"decodeBody" => false}] do
        options = HTTP.FetchOptions.new(input)
        refute options.decode_body
        assert HTTP.FetchOptions.to_transport_options(options)[:decode_body] == false
      end

      assert_raise ArgumentError, ~r/invalid decode_body/, fn ->
        HTTP.FetchOptions.new(decode_body: :raw)
      end
    end

    test "telemetry opt-out supports flat forms and requires boolean" do
      assert HTTP.FetchOptions.new([]).telemetry

      for input <- [[telemetry: false], %{"telemetry" => false}] do
        options = HTTP.FetchOptions.new(input)
        refute options.telemetry
        assert HTTP.FetchOptions.to_transport_options(options)[:telemetry] == false
      end

      assert_raise ArgumentError, ~r/invalid telemetry/, fn ->
        HTTP.FetchOptions.new(telemetry: :disabled)
      end
    end

    test "request and connection timeouts accept non-negative milliseconds or infinity" do
      for key <- [:timeout, :connect_timeout], value <- [0, 1, 30_000, :infinity] do
        options = HTTP.FetchOptions.new([{key, value}])
        assert Map.fetch!(options, key) == value
        assert HTTP.FetchOptions.to_transport_options(options)[key] == value
      end

      assert %HTTP.FetchOptions{connect_timeout: :infinity} =
               HTTP.FetchOptions.new(%{"connectTimeout" => :infinity})

      for key <- [:timeout, :connect_timeout], value <- [-1, "5", 1.5, :never, true] do
        assert_raise ArgumentError,
                     ~r/#{key} must be non-negative milliseconds or :infinity/,
                     fn ->
                       HTTP.FetchOptions.new([{key, value}])
                     end
      end
    end

    test "decoded-size limit accepts positive bytes or infinity" do
      assert HTTP.FetchOptions.new([]).max_decoded_body_size == nil

      refute Keyword.has_key?(
               HTTP.FetchOptions.to_transport_options(HTTP.FetchOptions.new([])),
               :max_decoded_body_size
             )

      for input <- [
            [max_decoded_body_size: 1_024],
            %{"max_decoded_body_size" => 1_024},
            %{"maxDecodedBodySize" => 1_024}
          ] do
        options = HTTP.FetchOptions.new(input)
        assert options.max_decoded_body_size == 1_024
        assert HTTP.FetchOptions.to_transport_options(options)[:max_decoded_body_size] == 1_024
      end

      assert HTTP.FetchOptions.new(max_decoded_body_size: :infinity).max_decoded_body_size ==
               :infinity

      for value <- [0, -1, "1024", 1.5, :none] do
        assert_raise ArgumentError, ~r/max_decoded_body_size must be/, fn ->
          HTTP.FetchOptions.new(max_decoded_body_size: value)
        end
      end
    end

    test "rejects invalid duplex mode" do
      assert_raise ArgumentError, ~r/unsupported duplex mode/, fn ->
        HTTP.FetchOptions.new(duplex: :full)
      end
    end

    test "rejects invalid redirect mode" do
      assert_raise ArgumentError, ~r/unsupported redirect mode/, fn ->
        HTTP.FetchOptions.new(redirect: :invalid)
      end
    end

    test "normalizes http version selection" do
      assert %HTTP.FetchOptions{http_version: :http1} = HTTP.FetchOptions.new([])

      assert %HTTP.FetchOptions{http_version: :http1} =
               HTTP.FetchOptions.new(http_version: "http/1.1")

      assert %HTTP.FetchOptions{http_version: :http2} = HTTP.FetchOptions.new(http_version: "h2")
      assert %HTTP.FetchOptions{http_version: :http3} = HTTP.FetchOptions.new(http_version: "h3")

      assert %HTTP.FetchOptions{http_version: :http3} =
               HTTP.FetchOptions.new(http_version: :http3)

      assert %HTTP.FetchOptions{http_version: :h2c} = HTTP.FetchOptions.new(http_version: :h2c)
      assert %HTTP.FetchOptions{http_version: :auto} = HTTP.FetchOptions.new(http_version: "auto")
    end

    test "rejects invalid http version selection" do
      assert_raise ArgumentError, ~r/unsupported http_version/, fn ->
        HTTP.FetchOptions.new(http_version: :spdy)
      end
    end

    test "normalizes TLS backend selection" do
      assert %HTTP.FetchOptions{tls_backend: :ex_ssl} = HTTP.FetchOptions.new([])

      for backend <- [:ssl, "ssl"] do
        assert_raise ArgumentError, ~r/unsupported tls_backend.*expected :ex_ssl/, fn ->
          HTTP.FetchOptions.new(tls_backend: backend)
        end
      end

      assert %HTTP.FetchOptions{tls_backend: :ex_ssl} =
               HTTP.FetchOptions.new(%{"tlsBackend" => "ex_ssl"})
    end

    test "rejects invalid TLS backend selection" do
      assert_raise ArgumentError, ~r/unsupported tls_backend/, fn ->
        HTTP.FetchOptions.new(tls_backend: :invalid)
      end

      assert_raise ArgumentError, ~r/unsupported tls_backend/, fn ->
        HTTP.FetchOptions.new(tls_backend: "SSL")
      end
    end

    test "normalizes HTTP/2 options and preserves them for transport" do
      options =
        HTTP.FetchOptions.new(
          http2_profile: "native-v1",
          http2_reuse: false,
          http2_scope: "tenant-a",
          http2_priority: %{urgency: 2}
        )

      assert options.http2_profile == "native-v1"
      assert options.http2_reuse == false
      assert options.http2_scope == "tenant-a"
      assert options.http2_priority == %{urgency: 2}

      transport_options = HTTP.FetchOptions.to_transport_options(options)
      assert transport_options[:http2_profile] == "native-v1"
      assert transport_options[:http2_reuse] == false
      assert transport_options[:http2_scope] == "tenant-a"
      assert transport_options[:http2_priority] == %{urgency: 2}
    end

    test "rejects unknown HTTP/2 options" do
      assert_raise ArgumentError, ~r/unsupported HTTP\/2 option/, fn ->
        HTTP.FetchOptions.new(http2_unknown: true)
      end
    end

    test "does not resolve a nil TLS backend for HTTP/3" do
      assert %HTTP.FetchOptions{http_version: :http3, tls_backend: nil} =
               HTTP.FetchOptions.new(http_version: :http3)
    end

    test "preserves explicit TLS backend markers for HTTP/3" do
      assert %HTTP.FetchOptions{tls_backend: false} =
               HTTP.FetchOptions.new(http_version: :http3, tls_backend: false)

      assert %HTTP.FetchOptions{tls_backend: :unknown} =
               HTTP.FetchOptions.new(http_version: :http3, tls_backend: :unknown)
    end
  end

  describe "to_transport_options/1" do
    test "converts socket transport options" do
      options =
        HTTP.FetchOptions.new(
          timeout: 5_000,
          connect_timeout: 2_000,
          redirect: :manual,
          http_version: :http2,
          tls_backend: :ex_ssl,
          ssl: [verify: :verify_none],
          socket_opts: [:inet6]
        )

      transport_options = HTTP.FetchOptions.to_transport_options(options)
      assert transport_options[:timeout] == 5_000
      assert transport_options[:connect_timeout] == 2_000
      assert transport_options[:redirect] == :manual
      assert transport_options[:http_version] == :http2
      assert transport_options[:tls_backend] == :ex_ssl
      assert transport_options[:ssl] == [verify: :verify_none]
      assert transport_options[:socket_opts] == [:inet6]
    end

    test "filters out fetch request options" do
      options =
        HTTP.FetchOptions.new(
          method: "GET",
          headers: %{"Accept" => "application/json"},
          body: "payload"
        )

      transport_options = HTTP.FetchOptions.to_transport_options(options)
      refute Keyword.has_key?(transport_options, :method)
      refute Keyword.has_key?(transport_options, :headers)
      refute Keyword.has_key?(transport_options, :body)
    end
  end

  describe "getter methods" do
    test "get_method/1" do
      options = HTTP.FetchOptions.new(method: "POST")
      assert HTTP.FetchOptions.get_method(options) == :post
    end

    test "get_headers/1" do
      options = HTTP.FetchOptions.new(headers: %{"Accept" => "application/json"})
      headers = HTTP.FetchOptions.get_headers(options)
      assert %HTTP.Headers{} = headers
    end

    test "get_body/1" do
      options = HTTP.FetchOptions.new(body: "test data")
      assert HTTP.FetchOptions.get_body(options) == "test data"
    end

    test "get_duplex/1" do
      options = HTTP.FetchOptions.new(duplex: "half")
      assert HTTP.FetchOptions.get_duplex(options) == :half
    end

    test "get_content_type/1" do
      options = HTTP.FetchOptions.new(content_type: "application/json")
      assert HTTP.FetchOptions.get_content_type(options) == "application/json"
    end
  end

  describe "alt_svc" do
    test "defaults to false and is omitted from transport options" do
      options = HTTP.FetchOptions.new(http_version: :auto)
      assert options.alt_svc == false
      refute Keyword.has_key?(HTTP.FetchOptions.to_transport_options(options), :alt_svc)
      assert options.tls_backend == :ex_ssl
    end

    test "requires http_version :auto and defers the default TLS backend" do
      for init <- [
            [http_version: :auto, alt_svc: true],
            %{"httpVersion" => "auto", "altSvc" => true},
            %{"http_version" => :auto, "alt_svc" => true}
          ] do
        options = HTTP.FetchOptions.new(init)
        transport = HTTP.FetchOptions.to_transport_options(options)
        assert transport[:alt_svc] == true
        assert options.tls_backend == nil
      end

      explicit = HTTP.FetchOptions.new(http_version: :auto, alt_svc: true, tls_backend: :ex_ssl)
      assert explicit.tls_backend == :ex_ssl
    end

    test "rejects other versions and non-boolean values" do
      for version <- [nil, :http1, :http2, :http3, :h2c] do
        assert_raise ArgumentError, ~r/alt_svc requires http_version: :auto/, fn ->
          HTTP.FetchOptions.new(http_version: version, alt_svc: true)
        end
      end

      assert_raise ArgumentError, ~r/invalid alt_svc/, fn ->
        HTTP.FetchOptions.new(http_version: :auto, alt_svc: "yes")
      end

      assert_raise ArgumentError, fn -> HTTP.fetch("https://example.test", alt_svc: true) end
    end
  end

  describe "http3_resumption and early_data" do
    test "default off and map to transport options when enabled" do
      default = HTTP.FetchOptions.new([])
      refute default.http3_resumption or default.early_data
      transport = HTTP.FetchOptions.to_transport_options(default)
      refute Keyword.has_key?(transport, :http3_resumption)
      refute Keyword.has_key?(transport, :early_data)

      options = HTTP.FetchOptions.new(%{"http3Resumption" => true, "earlyData" => true})
      transport = HTTP.FetchOptions.to_transport_options(options)
      assert transport[:http3_resumption] == true
      assert transport[:early_data] == true
    end

    test "early_data is limited to safe methods without a body" do
      for method <- [:get, "HEAD", "options"] do
        assert %{early_data: true} = HTTP.FetchOptions.new(method: method, early_data: true)
      end

      for method <- [:post, "PUT", :delete, :patch, "CONNECT"] do
        assert_raise ArgumentError, ~r/early_data requires GET, HEAD or OPTIONS/, fn ->
          HTTP.FetchOptions.new(method: method, early_data: true)
        end
      end

      assert_raise ArgumentError, ~r/without a body/, fn ->
        HTTP.FetchOptions.new(early_data: true, body: "payload")
      end

      assert %{early_data: false} = HTTP.FetchOptions.new(method: :post, early_data: false)
    end

    test "rejects non-boolean values" do
      assert_raise ArgumentError, ~r/invalid http3_resumption/, fn ->
        HTTP.FetchOptions.new(http3_resumption: "yes")
      end

      assert_raise ArgumentError, ~r/invalid early_data/, fn ->
        HTTP.FetchOptions.new(early_data: 1)
      end
    end
  end

  describe "edge cases" do
    test "handles empty options" do
      options = HTTP.FetchOptions.new([])
      assert %HTTP.FetchOptions{} = options
    end

    test "rejects unknown options" do
      assert_raise ArgumentError, ~r/unknown fetch option: :custom_option/, fn ->
        HTTP.FetchOptions.new(custom_option: "value")
      end

      assert_raise ArgumentError, ~r/unknown fetch option: "custom"/, fn ->
        HTTP.FetchOptions.new(%{"custom" => "value"})
      end

      assert_raise ArgumentError, ~r/unknown fetch option/, fn ->
        HTTP.fetch("http://127.0.0.1:1/", metohd: "POST")
      end
    end

    test "rejects non-pair entries" do
      assert_raise ArgumentError, ~r/key, value/, fn -> HTTP.FetchOptions.new([:method]) end
    end

    test "validates signal" do
      controller = HTTP.AbortController.new()
      assert HTTP.FetchOptions.new(signal: controller).signal == controller
      assert HTTP.FetchOptions.new(signal: nil).signal == nil

      for bad <- ["abort", :controller, make_ref(), %{}] do
        assert_raise ArgumentError, ~r/invalid signal/, fn ->
          HTTP.FetchOptions.new(signal: bad)
        end

        assert_raise ArgumentError, ~r/invalid signal/, fn ->
          HTTP.fetch("http://127.0.0.1:1/", signal: bad)
        end
      end
    end
  end
end
