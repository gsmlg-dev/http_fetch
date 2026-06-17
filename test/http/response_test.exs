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
      body = String.duplicate("root-zone-line\n", 100)
      url = start_local_http_server!(body)
      resp = url |> HTTP.fetch(timeout: 5_000, connect_timeout: 1_000) |> HTTP.Promise.await()

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
      body = ~s({"slideshow":{"title":"Sample Slide Show"}})
      url = start_local_http_server!(body, [{"Content-Type", "application/json"}])

      resp = url |> HTTP.fetch(timeout: 5_000, connect_timeout: 1_000) |> HTTP.Promise.await()

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

  defp start_local_http_server!(body, headers \\ [{"Content-Type", "text/plain"}]) do
    {:ok, listen_socket} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {127, 0, 0, 1},
        reuseaddr: true
      ])

    {:ok, port} = :inet.port(listen_socket)

    pid =
      spawn_link(fn ->
        {:ok, socket} = :gen_tcp.accept(listen_socket)
        _ = recv_headers(socket, <<>>)

        response_headers =
          headers
          |> Enum.concat([
            {"Content-Length", to_string(byte_size(body))},
            {"Connection", "close"}
          ])
          |> Enum.map(fn {name, value} -> [name, ": ", value, "\r\n"] end)

        :ok = :gen_tcp.send(socket, ["HTTP/1.1 200 OK\r\n", response_headers, "\r\n", body])
        :gen_tcp.close(socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp recv_headers(socket, acc) do
    if String.contains?(acc, "\r\n\r\n") do
      :ok
    else
      case :gen_tcp.recv(socket, 0, 5_000) do
        {:ok, data} -> recv_headers(socket, acc <> data)
        {:error, reason} -> {:error, reason}
      end
    end
  end
end
