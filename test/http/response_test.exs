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

    test "read_all raises on streaming errors instead of returning a partial body" do
      {:ok, stream} = HTTP.Stream.start_link(0)

      producer =
        Task.async(fn ->
          :ok = HTTP.Stream.chunk(stream, "partial", 1_000)
          HTTP.Stream.error(stream, :closed)
        end)

      response = %HTTP.Response{body: nil, stream: stream}

      assert_raise RuntimeError, ~r/stream read failed: :closed/, fn ->
        HTTP.Response.read_all(response)
      end

      Task.await(producer)
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

    test "write streaming response directly to a file" do
      temp_path = Path.join(System.tmp_dir!(), "stream_response_test.txt")
      {:ok, stream} = HTTP.Stream.start_link(0)

      producer =
        Task.async(fn ->
          :ok = HTTP.Stream.chunk(stream, "hello", 1_000)
          :ok = HTTP.Stream.chunk(stream, " world", 1_000)
          HTTP.Stream.finish(stream)
        end)

      response = %HTTP.Response{body: nil, stream: stream}

      assert :ok = HTTP.Response.write_to(response, temp_path)
      assert File.read!(temp_path) == "hello world"
      Task.await(producer)

      File.rm!(temp_path)
    end

    test "write streaming response returns stream errors" do
      temp_path = Path.join(System.tmp_dir!(), "stream_response_error_test.txt")
      {:ok, stream} = HTTP.Stream.start_link(0)

      producer =
        Task.async(fn ->
          :ok = HTTP.Stream.chunk(stream, "partial", 1_000)
          HTTP.Stream.error(stream, :closed)
        end)

      response = %HTTP.Response{body: nil, stream: stream}

      assert {:error, :closed} = HTTP.Response.write_to(response, temp_path)
      assert File.read!(temp_path) == "partial"
      Task.await(producer)

      File.rm!(temp_path)
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

    test "streams large redirect bodies when autoredirect is false" do
      body = String.duplicate("x", HTTP.Config.streaming_threshold() + 1)

      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)

          send_raw_response(socket, [
            "HTTP/1.1 302 Found\r\n",
            "Location: /next\r\n",
            "Content-Length: ",
            Integer.to_string(byte_size(body)),
            "\r\n",
            "Connection: close\r\n",
            "\r\n",
            body
          ])
        end)

      response =
        url
        |> HTTP.fetch(options: [autoredirect: false])
        |> HTTP.Promise.await()

      assert response.status == 302
      assert response.body == nil
      assert is_pid(response.stream)
      assert HTTP.Response.read_all(response) == body
    end

    test "follows redirects after headers without buffering large redirect bodies" do
      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, first} = :gen_tcp.accept(listen_socket)

          send_raw_response(first, [
            "HTTP/1.1 302 Found\r\n",
            "Location: /final\r\n",
            "Content-Length: ",
            Integer.to_string(HTTP.Config.streaming_threshold() + 1),
            "\r\n",
            "Connection: close\r\n",
            "\r\n"
          ])

          {:ok, second} = :gen_tcp.accept(listen_socket)

          send_response(second, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])
        end)

      response =
        url
        |> HTTP.fetch(options: [autoredirect: true])
        |> HTTP.Promise.await()

      assert response.status == 200
      assert response.redirected == true
      assert HTTP.Response.read_all(response) == "ok"
    end

    test "follows redirects by default" do
      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, first} = :gen_tcp.accept(listen_socket)

          send_raw_response(first, [
            "HTTP/1.1 302 Found\r\n",
            "Location: /final\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n",
            "\r\n"
          ])

          {:ok, second} = :gen_tcp.accept(listen_socket)

          send_response(second, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])
        end)

      response = url |> HTTP.fetch() |> HTTP.Promise.await()

      assert response.status == 200
      assert response.redirected == true
      assert HTTP.Response.read_all(response) == "ok"
    end

    test "returns invalid content-length errors for comma-joined response framing" do
      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)

          send_raw_response(socket, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: ",
            Integer.to_string(HTTP.Config.streaming_threshold() + 1),
            ", ",
            Integer.to_string(HTTP.Config.streaming_threshold() + 1),
            "\r\n",
            "Connection: close\r\n",
            "\r\n"
          ])
        end)

      assert {:error, :invalid_content_length} =
               url |> HTTP.fetch() |> HTTP.Promise.await()
    end

    test "closes sockets when waiting for response headers times out" do
      test_pid = self()

      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          _ = recv_headers(socket, <<>>)
          send(test_pid, :request_received)
          send(test_pid, {:server_recv_after_timeout, :gen_tcp.recv(socket, 0, 5_000)})
          :gen_tcp.close(socket)
        end)

      assert {:error, :request_timeout} =
               url |> HTTP.fetch(timeout: 100) |> HTTP.Promise.await(2_000)

      assert_receive :request_received
      assert_receive {:server_recv_after_timeout, {:error, :closed}}, 2_000
    end

    test "streams chunked responses even when content-length is small" do
      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)

          send_raw_response(socket, [
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 1\r\n",
            "Connection: close\r\n",
            "\r\n",
            "5\r\nhello\r\n0\r\n\r\n"
          ])
        end)

      response = url |> HTTP.fetch() |> HTTP.Promise.await()

      assert response.status == 200
      assert response.body == nil
      assert is_pid(response.stream)
      assert HTTP.Response.read_all(response) == "hello"
    end

    test "rewrites POST 302 redirects to GET and strips entity headers" do
      test_pid = self()

      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, first} = :gen_tcp.accept(listen_socket)

          send_raw_response(first, [
            "HTTP/1.1 302 Found\r\n",
            "Location: /final\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n",
            "\r\n"
          ])

          {:ok, second} = :gen_tcp.accept(listen_socket)
          request = recv_request(second)
          send(test_pid, {:redirect_request, request})

          send_response(second, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])
        end)

      response =
        url
        |> HTTP.fetch(
          method: :post,
          body: "payload",
          headers: %{
            "Content-Type" => "text/plain",
            "Content-Length" => "999"
          },
          options: [autoredirect: true]
        )
        |> HTTP.Promise.await()

      assert response.status == 200

      assert_receive {:redirect_request,
                      %{request_line: "GET /final HTTP/1.1", body: ""} = request}

      refute Map.has_key?(request.headers, "content-type")
      refute Map.has_key?(request.headers, "content-length")
    end

    test "preserves non-POST methods on 302 redirects" do
      test_pid = self()

      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, first} = :gen_tcp.accept(listen_socket)

          send_raw_response(first, [
            "HTTP/1.1 302 Found\r\n",
            "Location: /final\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n",
            "\r\n"
          ])

          {:ok, second} = :gen_tcp.accept(listen_socket)
          request = recv_request(second)
          send(test_pid, {:redirect_request, request})

          send_raw_response(second, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])
        end)

      response =
        url
        |> HTTP.fetch(
          method: :put,
          body: "payload",
          content_type: "text/plain",
          options: [autoredirect: true]
        )
        |> HTTP.Promise.await()

      assert response.status == 200

      assert_receive {:redirect_request,
                      %{request_line: "PUT /final HTTP/1.1", body: "payload", headers: headers}}

      assert headers["content-type"] == "text/plain"
      assert headers["content-length"] == "7"
    end

    test "rewrites 303 redirects to GET and strips representation headers" do
      test_pid = self()

      url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, first} = :gen_tcp.accept(listen_socket)

          send_raw_response(first, [
            "HTTP/1.1 303 See Other\r\n",
            "Location: /final\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n",
            "\r\n"
          ])

          {:ok, second} = :gen_tcp.accept(listen_socket)
          request = recv_request(second)
          send(test_pid, {:redirect_request, request})

          send_response(second, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])
        end)

      response =
        url
        |> HTTP.fetch(
          method: :put,
          body: "payload",
          headers: %{
            "Content-Encoding" => "gzip",
            "Content-Language" => "en",
            "Content-Location" => "/payload",
            "Content-Type" => "text/plain",
            "Content-Length" => "999"
          },
          options: [autoredirect: true]
        )
        |> HTTP.Promise.await()

      assert response.status == 200

      assert_receive {:redirect_request,
                      %{request_line: "GET /final HTTP/1.1", body: "", headers: headers}}

      refute Map.has_key?(headers, "content-encoding")
      refute Map.has_key?(headers, "content-language")
      refute Map.has_key?(headers, "content-location")
      refute Map.has_key?(headers, "content-type")
      refute Map.has_key?(headers, "content-length")
    end

    test "strips credentials on cross-origin redirects" do
      test_pid = self()

      target_url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)
          request = recv_request(socket)
          send(test_pid, {:redirect_request, request})

          send_response(socket, [
            "HTTP/1.1 200 OK\r\n",
            "Content-Length: 2\r\n",
            "Connection: close\r\n",
            "\r\n",
            "ok"
          ])
        end)

      source_url =
        start_raw_http_server!(fn listen_socket ->
          {:ok, socket} = :gen_tcp.accept(listen_socket)

          send_raw_response(socket, [
            "HTTP/1.1 302 Found\r\n",
            "Location: ",
            target_url,
            "\r\n",
            "Content-Length: 0\r\n",
            "Connection: close\r\n",
            "\r\n"
          ])
        end)

      response =
        source_url
        |> HTTP.fetch(
          headers: %{
            "Authorization" => "Bearer token",
            "Proxy-Authorization" => "Basic proxy",
            "Cookie" => "session=secret",
            "X-Keep" => "yes"
          }
        )
        |> HTTP.Promise.await()

      assert response.status == 200

      assert_receive {:redirect_request, %{headers: headers}}

      refute Map.has_key?(headers, "authorization")
      refute Map.has_key?(headers, "proxy-authorization")
      refute Map.has_key?(headers, "cookie")
      assert headers["x-keep"] == "yes"
    end
  end

  defp start_local_http_server!(body, headers \\ [{"Content-Type", "text/plain"}]) do
    start_raw_http_server!(fn listen_socket ->
      {:ok, socket} = :gen_tcp.accept(listen_socket)

      response_headers =
        headers
        |> Enum.concat([
          {"Content-Length", to_string(byte_size(body))},
          {"Connection", "close"}
        ])
        |> Enum.map(fn {name, value} -> [name, ": ", value, "\r\n"] end)

      send_raw_response(socket, ["HTTP/1.1 200 OK\r\n", response_headers, "\r\n", body])
    end)
  end

  defp start_raw_http_server!(handler) when is_function(handler, 1) do
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
        handler.(listen_socket)
        :gen_tcp.close(listen_socket)
      end)

    on_exit(fn ->
      if Process.alive?(pid), do: Process.exit(pid, :kill)
      :gen_tcp.close(listen_socket)
    end)

    "http://127.0.0.1:#{port}/test"
  end

  defp send_raw_response(socket, response) do
    _ = recv_headers(socket, <<>>)
    send_response(socket, response)
  end

  defp send_response(socket, response) do
    :ok = :gen_tcp.send(socket, response)
    :gen_tcp.close(socket)
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

  defp recv_request(socket) do
    {head, rest} = recv_header_block(socket, <<>>)
    [request_line | header_lines] = String.split(head, "\r\n")

    headers =
      header_lines
      |> Enum.flat_map(fn line ->
        case String.split(line, ":", parts: 2) do
          [name, value] -> [{String.downcase(name), String.trim(value)}]
          _ -> []
        end
      end)
      |> Map.new()

    content_length =
      headers
      |> Map.get("content-length", "0")
      |> String.to_integer()

    body = recv_body(socket, rest, content_length)

    %{request_line: request_line, headers: headers, body: body}
  end

  defp recv_header_block(socket, acc) do
    case :binary.match(acc, "\r\n\r\n") do
      {index, 4} ->
        head = binary_part(acc, 0, index)
        rest = binary_part(acc, index + 4, byte_size(acc) - index - 4)
        {head, rest}

      :nomatch ->
        {:ok, data} = :gen_tcp.recv(socket, 0, 5_000)
        recv_header_block(socket, acc <> data)
    end
  end

  defp recv_body(_socket, data, content_length) when byte_size(data) >= content_length do
    binary_part(data, 0, content_length)
  end

  defp recv_body(socket, data, content_length) do
    {:ok, more} = :gen_tcp.recv(socket, content_length - byte_size(data), 5_000)
    recv_body(socket, data <> more, content_length)
  end
end
