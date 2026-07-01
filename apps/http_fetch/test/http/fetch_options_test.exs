defmodule HTTP.FetchOptionsTest do
  use ExUnit.Case

  describe "new/1" do
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
          "connectTimeout" => 2_000
        })

      assert %HTTP.FetchOptions{
               method: :post,
               redirect: :manual,
               http_version: :http2,
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

    test "normalizes redirect mode" do
      assert %HTTP.FetchOptions{redirect: :follow} = HTTP.FetchOptions.new([])
      assert %HTTP.FetchOptions{redirect: :follow} = HTTP.FetchOptions.new(redirect: "follow")
      assert %HTTP.FetchOptions{redirect: :manual} = HTTP.FetchOptions.new(redirect: "manual")
      assert %HTTP.FetchOptions{redirect: :error} = HTTP.FetchOptions.new(redirect: :error)
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
  end

  describe "to_transport_options/1" do
    test "converts socket transport options" do
      options =
        HTTP.FetchOptions.new(
          timeout: 5_000,
          connect_timeout: 2_000,
          redirect: :manual,
          http_version: :http2,
          ssl: [verify: :verify_none],
          socket_opts: [:inet6]
        )

      transport_options = HTTP.FetchOptions.to_transport_options(options)
      assert transport_options[:timeout] == 5_000
      assert transport_options[:connect_timeout] == 2_000
      assert transport_options[:redirect] == :manual
      assert transport_options[:http_version] == :http2
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

    test "get_content_type/1" do
      options = HTTP.FetchOptions.new(content_type: "application/json")
      assert HTTP.FetchOptions.get_content_type(options) == "application/json"
    end
  end

  describe "edge cases" do
    test "handles empty options" do
      options = HTTP.FetchOptions.new([])
      assert %HTTP.FetchOptions{} = options
    end

    test "ignores unknown options" do
      options = HTTP.FetchOptions.new(custom_option: "value")
      assert %HTTP.FetchOptions{} = options
      refute Map.has_key?(options, :custom_option)
    end
  end
end
