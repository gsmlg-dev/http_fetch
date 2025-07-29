defmodule HTTP.RequestTest do
  use ExUnit.Case
  doctest HTTP.Request

  describe "Request struct" do
    test "create request with defaults" do
      request = %HTTP.Request{}
      assert request.method == :get
      assert request.headers == []
      assert request.options == []
    end

    test "create request with custom values" do
      request = %HTTP.Request{
        method: :post,
        url: "http://example.com",
        headers: [{"Content-Type", "application/json"}],
        body: "test",
        content_type: "application/json"
      }

      assert request.method == :post
      assert request.url == "http://example.com"
      assert request.headers == [{"Content-Type", "application/json"}]
      assert request.body == "test"
      assert request.content_type == "application/json"
    end

    test "convert to httpc args" do
      request = %HTTP.Request{
        method: :get,
        url: "http://example.com",
        headers: [{"Accept", "application/json"}]
      }

      [method, request_tuple, _options, _opts] = HTTP.Request.to_httpc_args(request)
      assert method == :get
      assert request_tuple == {~c"http://example.com", [{~c"Accept", ~c"application/json"}]}
    end
  end
end