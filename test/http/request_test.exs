defmodule HTTP.RequestTest do
  use ExUnit.Case
  doctest HTTP.Request

  describe "Request struct" do
    test "create request with defaults" do
      request = %HTTP.Request{}
      assert request.method == :get
      assert %HTTP.Headers{headers: []} = request.headers
      assert request.http_options == []
      assert request.options == [sync: false]
    end

    test "create request with custom values" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("http://example.com"),
        headers: HTTP.Headers.new([{"Content-Type", "application/json"}]),
        body: "test",
        content_type: "application/json"
      }

      assert request.method == :post
      assert %URI{} = request.url
      assert request.url.host == "example.com"
      assert %HTTP.Headers{headers: [{"Content-Type", "application/json"}]} = request.headers
      assert request.body == "test"
      assert request.content_type == "application/json"
    end

    test "convert to httpc args" do
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("http://example.com"),
        headers: HTTP.Headers.new([{"Accept", "application/json"}])
      }

      [method, request_tuple, _http_options, _options] = HTTP.Request.to_httpc_args(request)
      assert method == :get
      assert {~c"http://example.com", headers} = request_tuple

      assert Enum.any?(headers, fn {name, value} ->
               to_string(name) == "User-Agent" and to_string(value) =~ "Mozilla/5.0"
             end)

      assert Enum.any?(headers, fn {name, value} ->
               to_string(name) == "Accept" and to_string(value) == "application/json"
             end)
    end

    test "does not override provided user agent" do
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("http://example.com"),
        headers: HTTP.Headers.new([{"User-Agent", "CustomAgent/1.0"}])
      }

      [method, request_tuple, _http_options, _options] = HTTP.Request.to_httpc_args(request)
      assert method == :get
      assert {~c"http://example.com", headers} = request_tuple

      assert Enum.any?(headers, fn {name, value} ->
               to_string(name) == "User-Agent" and to_string(value) == "CustomAgent/1.0"
             end)

      # Should not have the default user agent
      refute Enum.any?(headers, fn {name, value} ->
               to_string(name) == "User-Agent" and to_string(value) =~ "http_fetch"
             end)
    end
  end
end
