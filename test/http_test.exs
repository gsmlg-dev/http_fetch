defmodule HTTPTest do
  use ExUnit.Case
  doctest HTTP

  @base_url "http://httpbin.org"

  describe "basic HTTP requests" do
    test "fetch returns HTTP.Response struct" do
      resp =
        HTTP.fetch("#{@base_url}/status/200")
        |> HTTP.Promise.await()

      assert %HTTP.Response{} = resp
    end

    test "fetch handles HTTP error status" do
      resp =
        HTTP.fetch("#{@base_url}/status/404")
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 404} = resp
    end

    test "fetch handles different status codes" do
      statuses = [200, 201, 400, 404, 500]

      for status <- statuses do
        resp =
          HTTP.fetch("#{@base_url}/status/#{status}")
          |> HTTP.Promise.await()

        assert %HTTP.Response{status: ^status} = resp
      end
    end
  end

  describe "HTTP methods" do
    test "GET request" do
      resp =
        HTTP.fetch("#{@base_url}/get", method: "GET")
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end

    test "POST request" do
      resp =
        HTTP.fetch("#{@base_url}/post",
          method: "POST",
          body: "test data"
        )
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end

    test "PUT request" do
      resp =
        HTTP.fetch("#{@base_url}/put",
          method: "PUT",
          body: "test data"
        )
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end

    test "DELETE request" do
      resp =
        HTTP.fetch("#{@base_url}/delete", method: "DELETE")
        |> HTTP.Promise.await()

      # Allow 200 or 502 status codes (httpbin.org can be flaky)
      assert %HTTP.Response{status: status} = resp
      assert status in [200, 502]
    end

    test "PATCH request" do
      resp =
        HTTP.fetch("#{@base_url}/patch",
          method: "PATCH",
          body: "test data"
        )
        |> HTTP.Promise.await()

      # Allow 200 or 502 status codes (httpbin.org can be flaky)
      assert %HTTP.Response{status: status} = resp
      assert status in [200, 502]
    end
  end

  describe "request headers" do
    test "custom headers" do
      headers = %{"User-Agent" => "HTTP-Fetch-Test", "X-Test-Header" => "test-value"}

      resp =
        HTTP.fetch("#{@base_url}/headers", headers: headers)
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end

    test "content-type header" do
      resp =
        HTTP.fetch("#{@base_url}/post",
          method: "POST",
          content_type: "application/json",
          body: "{\"test\": \"data\"}"
        )
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end
  end

  describe "request body" do
    test "string body" do
      body = "test body content"

      resp =
        HTTP.fetch("#{@base_url}/post",
          method: "POST",
          body: body
        )
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end

    test "empty body" do
      resp =
        HTTP.fetch("#{@base_url}/post",
          method: "POST"
        )
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end
  end

  describe "response parsing" do
    test "JSON response parsing" do
      resp =
        HTTP.fetch("#{@base_url}/json")
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp

      case HTTP.Response.json(resp) do
        {:ok, json} -> assert is_map(json)
        {:error, reason} -> flunk("JSON parsing failed: #{inspect(reason)}")
      end
    end

    test "text response" do
      resp =
        HTTP.fetch("#{@base_url}/robots.txt")
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp

      text = HTTP.Response.text(resp)
      assert is_binary(text)
    end
  end

  describe "error handling" do
    test "invalid URL" do
      resp =
        HTTP.fetch("not-a-valid-url")
        |> HTTP.Promise.await()

      assert {:error, _reason} = resp
    end

    test "non-existent domain" do
      resp =
        HTTP.fetch("http://this-domain-does-not-exist-12345.com")
        |> HTTP.Promise.await()

      assert {:error, _reason} = resp
    end

    test "malformed URL" do
      resp =
        HTTP.fetch("http://")
        |> HTTP.Promise.await()

      assert {:error, _reason} = resp
    end
  end

  describe "request options" do
    test "timeout option" do
      resp =
        HTTP.fetch("#{@base_url}/delay/1", options: [timeout: 5000])
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end

    test "connect timeout" do
      resp =
        HTTP.fetch("#{@base_url}/get", options: [connect_timeout: 5000])
        |> HTTP.Promise.await()

      assert %HTTP.Response{status: 200} = resp
    end
  end
end
