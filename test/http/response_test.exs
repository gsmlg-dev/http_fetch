defmodule HTTP.ResponseTest do
  use ExUnit.Case
  doctest HTTP.Response

  describe "Response struct" do
    test "create response" do
      response = %HTTP.Response{
        status: 200,
        headers: HTTP.Headers.new([{"Content-Type", "application/json"}]),
        body: "{\"test\": \"data\"}",
        url: "http://example.com"
      }

      assert response.status == 200
      assert %HTTP.Headers{} = response.headers
      assert response.body == "{\"test\": \"data\"}"
      assert response.url == "http://example.com"
    end

    test "response text" do
      response = %HTTP.Response{body: "test content"}
      assert HTTP.Response.text(response) == "test content"
    end

    test "response json - valid" do
      response = %HTTP.Response{body: "{\"key\": \"value\"}"}
      assert {:ok, %{"key" => "value"}} = HTTP.Response.json(response)
    end

    test "response json - invalid" do
      response = %HTTP.Response{body: "invalid json"}
      assert {:error, _reason} = HTTP.Response.json(response)
    end

    test "read_all - non-streaming response" do
      response = %HTTP.Response{body: "test content", stream: nil}
      assert HTTP.Response.read_all(response) == "test content"
    end

    test "read_all - empty body" do
      response = %HTTP.Response{body: nil, stream: nil}
      assert HTTP.Response.read_all(response) == ""
    end

    test "read_as_json - valid" do
      response = %HTTP.Response{body: ~s({"key": "value"}), stream: nil}
      assert {:ok, %{"key" => "value"}} = HTTP.Response.read_as_json(response)
    end

    test "read_as_json - invalid" do
      response = %HTTP.Response{body: "invalid json", stream: nil}
      assert {:error, _reason} = HTTP.Response.read_as_json(response)
    end

    test "get_header" do
      response = %HTTP.Response{headers: HTTP.Headers.new([{"Content-Type", "application/json"}])}
      assert HTTP.Response.get_header(response, "content-type") == "application/json"
      assert HTTP.Response.get_header(response, "missing") == nil
    end

    test "content_type" do
      response = %HTTP.Response{
        headers: HTTP.Headers.new([{"Content-Type", "application/json; charset=utf-8"}])
      }

      assert HTTP.Response.content_type(response) == {"application/json", %{"charset" => "utf-8"}}
    end
  end
end
