defmodule HTTP.FetchOptionsTest do
  use ExUnit.Case

  describe "new/1" do
    test "creates from keyword list" do
      options = HTTP.FetchOptions.new(method: "GET", timeout: 5000)
      assert %HTTP.FetchOptions{method: :get, timeout: 5000} = options
    end

    test "creates from map" do
      options =
        HTTP.FetchOptions.new(%{method: "POST", headers: %{"Content-Type" => "application/json"}})

      assert %HTTP.FetchOptions{method: :post} = options
      assert %HTTP.Headers{headers: [{"Content-Type", "application/json"}]} = options.headers
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
  end

  describe "to_http_options/1" do
    test "converts HTTP-specific options" do
      options =
        HTTP.FetchOptions.new(
          timeout: 5000,
          connect_timeout: 2000,
          autoredirect: true,
          ssl: [verify: :verify_none]
        )

      http_options = HTTP.FetchOptions.to_http_options(options)
      assert http_options[:timeout] == 5000
      assert http_options[:connect_timeout] == 2000
      assert http_options[:autoredirect] == true
      assert http_options[:ssl] == [verify: :verify_none]
    end

    test "filters out non-HTTP options" do
      options =
        HTTP.FetchOptions.new(
          method: "GET",
          headers: %{"Accept" => "application/json"},
          sync: false
        )

      http_options = HTTP.FetchOptions.to_http_options(options)
      refute Keyword.has_key?(http_options, :sync)
      refute Keyword.has_key?(http_options, :headers)
    end
  end

  describe "to_options/1" do
    test "converts client options" do
      options =
        HTTP.FetchOptions.new(opts: [sync: false, body_format: :binary, full_result: false])

      opts = HTTP.FetchOptions.to_options(options)
      assert opts[:sync] == false
      assert opts[:body_format] == :binary
      assert opts[:full_result] == false
    end

    test "handles streaming options" do
      options = HTTP.FetchOptions.new(stream: :self)
      opts = HTTP.FetchOptions.to_options(options)
      assert opts[:stream] == :self
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

    test "handles unknown options gracefully" do
      options = HTTP.FetchOptions.new(custom_option: "value")
      assert %HTTP.FetchOptions{} = options
    end

    test "merges nested options" do
      options =
        HTTP.FetchOptions.new(
          timeout: 5000,
          opts: [sync: true]
        )

      http_options = HTTP.FetchOptions.to_http_options(options)
      assert http_options[:timeout] == 5000

      opts = HTTP.FetchOptions.to_options(options)
      assert opts[:sync] == true
    end
  end
end
