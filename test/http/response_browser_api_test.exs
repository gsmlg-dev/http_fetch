defmodule HTTP.ResponseBrowserAPITest do
  use ExUnit.Case, async: true

  alias HTTP.Response
  alias HTTP.Headers
  alias HTTP.Blob

  describe "Browser Fetch API properties" do
    test "ok is true for 200-299 status codes" do
      for status <- 200..299 do
        response = Response.new(status: status)
        assert response.ok == true, "Status #{status} should have ok=true"
      end
    end

    test "ok is false for non-2xx status codes" do
      non_success_statuses = [100, 199, 300, 301, 400, 404, 500, 503]

      for status <- non_success_statuses do
        response = Response.new(status: status)
        assert response.ok == false, "Status #{status} should have ok=false"
      end
    end

    test "status_text is correctly set for common status codes" do
      test_cases = [
        {200, "OK"},
        {201, "Created"},
        {204, "No Content"},
        {301, "Moved Permanently"},
        {302, "Found"},
        {304, "Not Modified"},
        {400, "Bad Request"},
        {401, "Unauthorized"},
        {403, "Forbidden"},
        {404, "Not Found"},
        {500, "Internal Server Error"},
        {502, "Bad Gateway"},
        {503, "Service Unavailable"}
      ]

      for {status, expected_text} <- test_cases do
        response = Response.new(status: status)
        assert response.status_text == expected_text,
               "Status #{status} should have status_text='#{expected_text}', got '#{response.status_text}'"
      end
    end

    test "status_text is empty for unknown status codes" do
      response = Response.new(status: 999)
      assert response.status_text == ""
    end

    test "body_used is false initially" do
      response = Response.new(status: 200, body: "test")
      assert response.body_used == false
    end

    test "redirected is false by default" do
      response = Response.new(status: 200)
      assert response.redirected == false
    end

    test "redirected can be set to true" do
      response = Response.new(status: 302, redirected: true)
      assert response.redirected == true
    end

    test "type defaults to :basic" do
      response = Response.new(status: 200)
      assert response.type == :basic
    end

    test "type can be set to other values" do
      types = [:basic, :cors, :error, :opaque]

      for type <- types do
        response = Response.new(status: 200, type: type)
        assert response.type == type
      end
    end
  end

  describe "body_used tracking" do
    test "body_used is checked but due to immutability, multiple reads work" do
      # Note: In Elixir, due to immutability, body_used doesn't persist across
      # function calls like it does in JavaScript. The check exists for
      # documentation and API compatibility, but doesn't prevent multiple reads
      # of the same immutable response value.

      response = Response.new(status: 200, body: "Hello")

      # Multiple reads work because response is immutable
      assert Response.text(response) == "Hello"
      assert Response.text(response) == "Hello"  # Works in Elixir
    end

    test "body_used flag can be manually checked" do
      response = Response.new(status: 200, body: "test")
      assert response.body_used == false

      # In a mutable language, this would be true after reading
      # In Elixir, response is immutable so flag doesn't change
    end

    test "clone resets body_used flag" do
      # Manually create a response with body_used: true for testing
      base_response = Response.new(status: 200, body: "test")
      response = %{base_response | body_used: true}

      clone = Response.clone(response)
      assert clone.body_used == false
    end

    test "reading methods don't mutate original response" do
      response = Response.new(status: 200, body: ~s({"key": "value"}))

      # Read with json
      assert {:ok, _} = Response.json(response)

      # Original response unchanged (Elixir immutability)
      assert response.body_used == false

      # Can read with text too
      assert is_binary(Response.text(response))
    end
  end

  describe "Response.clone/1" do
    test "clones buffered response allowing multiple reads" do
      response = Response.new(status: 200, body: "Hello World")
      clone = Response.clone(response)

      # Read original
      text1 = Response.text(response)
      assert text1 == "Hello World"

      # Read clone
      text2 = Response.text(clone)
      assert text2 == "Hello World"

      # Both have same content
      assert text1 == text2
    end

    test "clone resets body_used to false" do
      response = Response.new(status: 200, body: "test")
      clone = Response.clone(response)

      assert clone.body_used == false
    end

    test "clone preserves all response properties" do
      headers = Headers.new([{"content-type", "application/json"}])
      url = URI.parse("https://example.com")

      response =
        Response.new(
          status: 201,
          headers: headers,
          body: "data",
          url: url,
          redirected: true,
          type: :cors
        )

      clone = Response.clone(response)

      assert clone.status == 201
      assert clone.status_text == "Created"
      assert clone.ok == true
      assert clone.headers == headers
      assert clone.body == "data"
      assert clone.url == url
      assert clone.redirected == true
      assert clone.type == :cors
    end

    test "clone with empty body" do
      response = Response.new(status: 204, body: nil)
      clone = Response.clone(response)

      assert clone.body == nil
      assert clone.body_used == false
    end
  end

  describe "Response.arrayBuffer/1" do
    test "returns binary data" do
      binary = <<1, 2, 3, 4, 5>>
      response = Response.new(status: 200, body: binary)

      result = Response.arrayBuffer(response)
      assert result == binary
      assert is_binary(result)
    end

    test "array_buffer/1 alias works" do
      binary = <<1, 2, 3, 4>>
      response = Response.new(status: 200, body: binary)

      result1 = Response.arrayBuffer(response)
      clone = Response.clone(response)
      result2 = Response.array_buffer(clone)

      assert result1 == result2
    end

    test "works with empty body" do
      response = Response.new(status: 200, body: "")
      result = Response.arrayBuffer(response)
      assert result == ""
    end
  end

  describe "HTTP.Blob" do
    test "new/2 creates blob with data, type, and size" do
      data = <<1, 2, 3, 4, 5>>
      blob = Blob.new(data, "image/png")

      assert blob.data == data
      assert blob.type == "image/png"
      assert blob.size == 5
    end

    test "new/1 uses default type" do
      blob = Blob.new(<<1, 2, 3>>)
      assert blob.type == "application/octet-stream"
    end

    test "to_binary/1 extracts data" do
      data = <<1, 2, 3, 4>>
      blob = Blob.new(data, "image/jpeg")
      assert Blob.to_binary(blob) == data
    end

    test "type/1 returns MIME type" do
      blob = Blob.new(<<>>, "text/plain")
      assert Blob.type(blob) == "text/plain"
    end

    test "size/1 returns byte size" do
      blob = Blob.new(<<1, 2, 3, 4, 5, 6, 7, 8>>, "application/octet-stream")
      assert Blob.size(blob) == 8
    end

    test "size is 0 for empty blob" do
      blob = Blob.new(<<>>, "text/plain")
      assert Blob.size(blob) == 0
    end
  end

  describe "Response.blob/1" do
    test "returns blob with correct data and type" do
      headers = Headers.new([{"content-type", "image/png"}])
      data = <<137, 80, 78, 71>>  # PNG magic bytes
      response = Response.new(status: 200, body: data, headers: headers)

      blob = Response.blob(response)

      assert blob.data == data
      assert blob.type == "image/png"
      assert blob.size == 4
    end

    test "extracts content type from response headers" do
      headers = Headers.new([{"content-type", "application/json; charset=utf-8"}])
      response = Response.new(status: 200, body: ~s({"key":"value"}), headers: headers)

      blob = Response.blob(response)
      assert blob.type == "application/json"
    end

    test "uses default type when no Content-Type header" do
      response = Response.new(status: 200, body: "data")

      blob = Response.blob(response)
      assert blob.type == "text/plain"
    end

    test "calculates correct size" do
      data = String.duplicate("a", 1000)
      response = Response.new(status: 200, body: data)

      blob = Response.blob(response)
      assert blob.size == 1000
    end
  end

  describe "HTTP.StatusText" do
    test "get/1 returns correct text for 1xx codes" do
      assert HTTP.StatusText.get(100) == "Continue"
      assert HTTP.StatusText.get(101) == "Switching Protocols"
      assert HTTP.StatusText.get(103) == "Early Hints"
    end

    test "get/1 returns correct text for 2xx codes" do
      assert HTTP.StatusText.get(200) == "OK"
      assert HTTP.StatusText.get(201) == "Created"
      assert HTTP.StatusText.get(204) == "No Content"
      assert HTTP.StatusText.get(206) == "Partial Content"
    end

    test "get/1 returns correct text for 3xx codes" do
      assert HTTP.StatusText.get(301) == "Moved Permanently"
      assert HTTP.StatusText.get(302) == "Found"
      assert HTTP.StatusText.get(304) == "Not Modified"
      assert HTTP.StatusText.get(307) == "Temporary Redirect"
    end

    test "get/1 returns correct text for 4xx codes" do
      assert HTTP.StatusText.get(400) == "Bad Request"
      assert HTTP.StatusText.get(401) == "Unauthorized"
      assert HTTP.StatusText.get(404) == "Not Found"
      assert HTTP.StatusText.get(418) == "I'm a teapot"
      assert HTTP.StatusText.get(429) == "Too Many Requests"
    end

    test "get/1 returns correct text for 5xx codes" do
      assert HTTP.StatusText.get(500) == "Internal Server Error"
      assert HTTP.StatusText.get(502) == "Bad Gateway"
      assert HTTP.StatusText.get(503) == "Service Unavailable"
      assert HTTP.StatusText.get(504) == "Gateway Timeout"
    end

    test "get/1 returns empty string for unknown codes" do
      assert HTTP.StatusText.get(999) == ""
      assert HTTP.StatusText.get(0) == ""
      assert HTTP.StatusText.get(600) == ""
    end
  end

  describe "Response.new/1 constructor" do
    test "automatically sets status_text from status code" do
      response = Response.new(status: 404)
      assert response.status_text == "Not Found"
    end

    test "automatically sets ok based on status code" do
      response_success = Response.new(status: 200)
      assert response_success.ok == true

      response_error = Response.new(status: 404)
      assert response_error.ok == false
    end

    test "initializes body_used to false" do
      response = Response.new(status: 200, body: "test")
      assert response.body_used == false
    end

    test "accepts all Browser API fields" do
      headers = Headers.new([{"content-type", "text/html"}])
      url = URI.parse("https://example.com/page")

      response =
        Response.new(
          status: 302,
          headers: headers,
          body: "Redirect",
          url: url,
          redirected: true,
          type: :basic
        )

      assert response.status == 302
      assert response.status_text == "Found"
      assert response.ok == false
      assert response.headers == headers
      assert response.body == "Redirect"
      assert response.body_used == false
      assert response.url == url
      assert response.redirected == true
      assert response.type == :basic
      assert response.stream == nil
    end

    test "works with minimal parameters" do
      response = Response.new(status: 200)

      assert response.status == 200
      assert response.status_text == "OK"
      assert response.ok == true
      assert response.body == nil
      assert response.body_used == false
      assert response.redirected == false
      assert response.type == :basic
    end
  end
end
