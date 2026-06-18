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

    test "convert to HTTP/1.1 wire request" do
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("http://example.com"),
        headers: HTTP.Headers.new([{"Accept", "application/json"}])
      }

      wire = request |> HTTP.Request.to_iodata() |> IO.iodata_to_binary()

      assert wire =~ "GET / HTTP/1.1\r\n"
      assert wire =~ "Host: example.com\r\n"
      assert wire =~ "Connection: close\r\n"
      assert wire =~ "User-Agent: Mozilla/5.0"
      assert wire =~ "Accept: application/json\r\n"
    end

    test "does not override provided user agent" do
      request = %HTTP.Request{
        method: :get,
        url: URI.parse("http://example.com"),
        headers: HTTP.Headers.new([{"User-Agent", "CustomAgent/1.0"}])
      }

      wire = request |> HTTP.Request.to_iodata() |> IO.iodata_to_binary()

      assert wire =~ "GET / HTTP/1.1\r\n"
      assert wire =~ "User-Agent: CustomAgent/1.0\r\n"
      refute wire =~ "http_fetch/"
    end

    test "convert to legacy httpc args" do
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

    test "convert body requests to legacy httpc args" do
      request = %HTTP.Request{
        method: :post,
        url: URI.parse("http://example.com/widgets"),
        headers: HTTP.Headers.new([{"Authorization", "Bearer token"}]),
        body: "payload",
        content_type: "text/plain",
        http_options: [timeout: 1_000],
        options: [sync: false]
      }

      assert [
               :post,
               {~c"http://example.com/widgets", headers, ~c"text/plain", ~c"payload"},
               [timeout: 1_000],
               [sync: false]
             ] = HTTP.Request.to_httpc_args(request)

      assert {~c"Authorization", ~c"Bearer token"} in headers
    end

    test "convert multipart form data to legacy httpc body request tuple" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("name", "value")
        |> HTTP.FormData.append_file("upload", "test.txt", "content")

      request = %HTTP.Request{
        method: :post,
        url: URI.parse("http://example.com/upload"),
        headers: HTTP.Headers.new([{"Authorization", "Bearer token"}]),
        body: form
      }

      assert [
               :post,
               {~c"http://example.com/upload", headers, content_type, body},
               [],
               [sync: false]
             ] = HTTP.Request.to_httpc_args(request)

      assert {~c"Authorization", ~c"Bearer token"} in headers
      refute Enum.any?(headers, fn {name, _value} -> name == ~c"Content-Type" end)
      assert to_string(content_type) =~ "multipart/form-data; boundary="
      assert to_string(body) =~ "name=\"upload\"; filename=\"test.txt\""
    end
  end
end
