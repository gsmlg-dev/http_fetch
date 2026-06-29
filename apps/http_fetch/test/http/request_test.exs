defmodule HTTP.RequestTest do
  use ExUnit.Case
  doctest HTTP.Request

  describe "Request struct" do
    test "create request with defaults" do
      request = %HTTP.Request{}
      assert request.method == :get
      assert %HTTP.Headers{headers: []} = request.headers
      assert request.transport_options == []
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

    test "serializes multipart form data to HTTP/1.1 wire request" do
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

      wire = request |> HTTP.Request.to_iodata() |> IO.iodata_to_binary()

      assert wire =~ "POST /upload HTTP/1.1\r\n"
      assert wire =~ "Authorization: Bearer token\r\n"
      assert wire =~ "Content-Type: multipart/form-data; boundary="
      assert wire =~ "name=\"upload\"; filename=\"test.txt\""
    end
  end
end
