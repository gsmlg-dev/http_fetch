defmodule HTTP.ResponseTest do
  use ExUnit.Case
  doctest HTTP.Response

  describe "Response struct" do
    test "create response" do
      response = %HTTP.Response{
        status: 200,
        headers: %{"content-type" => "application/json"},
        body: "{\"test\": \"data\"}",
        url: "http://example.com"
      }

      assert response.status == 200
      assert response.headers == %{"content-type" => "application/json"}
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
  end
end