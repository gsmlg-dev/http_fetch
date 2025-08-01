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

    test "fetch and read data by `read_all/1`" do
      resp =
        HTTP.fetch("https://www.internic.net/domain/root.zone",
          headers: [{"user-agent", "Elixir http_fetch 0.4.1"}],
          timeout: 30_000,
          connect_timeout: 15_000
        )
        |> HTTP.Promise.await()

      assert resp.status == 200

      content_length = resp.headers |> HTTP.Headers.get("content-length") |> String.to_integer()

      body = resp |> HTTP.Response.read_all()
      assert byte_size(body) == content_length
    end
  end

  describe "write_to/2" do
    test "write non-streaming response to file" do
      temp_path = Path.join(System.tmp_dir!(), "http_response_test.txt")
      
      response = %HTTP.Response{
        status: 200,
        headers: %HTTP.Headers{},
        body: "test content",
        url: "http://example.com",
        stream: nil
      }

      assert :ok = HTTP.Response.write_to(response, temp_path)
      assert File.read!(temp_path) == "test content"
      
      # Cleanup
      File.rm!(temp_path)
    end

    test "write empty response to file" do
      temp_path = Path.join(System.tmp_dir!(), "empty_response_test.txt")
      
      response = %HTTP.Response{
        status: 200,
        headers: %HTTP.Headers{},
        body: nil,
        url: "http://example.com",
        stream: nil
      }

      assert :ok = HTTP.Response.write_to(response, temp_path)
      assert File.read!(temp_path) == ""
      
      # Cleanup
      File.rm!(temp_path)
    end

    test "write iodata response to file" do
      temp_path = Path.join(System.tmp_dir!(), "iodata_response_test.txt")
      
      response = %HTTP.Response{
        status: 200,
        headers: %HTTP.Headers{},
        body: ["hello", " ", "world"],
        url: "http://example.com",
        stream: nil
      }

      assert :ok = HTTP.Response.write_to(response, temp_path)
      assert File.read!(temp_path) == "hello world"
      
      # Cleanup
      File.rm!(temp_path)
    end

    test "write creates directory if needed" do
      temp_dir = Path.join(System.tmp_dir!(), "nested_test_dir")
      temp_path = Path.join(temp_dir, "test_file.txt")
      
      response = %HTTP.Response{
        status: 200,
        headers: %HTTP.Headers{},
        body: "nested directory content",
        url: "http://example.com",
        stream: nil
      }

      assert :ok = HTTP.Response.write_to(response, temp_path)
      assert File.read!(temp_path) == "nested directory content"
      
      # Cleanup
      File.rm_rf!(temp_dir)
    end

    test "write_to with actual HTTP response" do
      temp_path = Path.join(System.tmp_dir!(), "actual_response_test.txt")
      
      resp =
        HTTP.fetch("https://httpbin.org/json",
          headers: [{"user-agent", "Elixir http_fetch 0.4.1"}],
          timeout: 30_000
        )
        |> HTTP.Promise.await()

      assert resp.status == 200
      assert :ok = HTTP.Response.write_to(resp, temp_path)
      
      # Verify file was written
      assert File.exists?(temp_path)
      content = File.read!(temp_path)
      assert byte_size(content) > 0
      assert content =~ "slideshow"
      
      # Cleanup
      File.rm!(temp_path)
    end
  end
end
