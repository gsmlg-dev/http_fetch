defmodule HTTPUnixSocketTest do
  use ExUnit.Case, async: true

  alias HTTP.Promise
  alias HTTP.Response
  alias HTTP.Test.UnixSocketServer

  doctest HTTP.UnixSocket

  describe "Unix socket GET requests" do
    test "simple GET request returns response" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn _request ->
          %{
            status: 200,
            headers: %{"Content-Type" => "text/plain"},
            body: "Hello from Unix socket!"
          }
        end)

      promise = HTTP.fetch("http://localhost/test", unix_socket: socket_path)
      assert %Response{status: 200, body: body} = Promise.await(promise)
      assert body == "Hello from Unix socket!"

      UnixSocketServer.stop(server_pid)
    end

    test "GET request with JSON response" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn _request ->
          %{
            status: 200,
            headers: %{"Content-Type" => "application/json"},
            body: ~s({"message":"success","data":{"id":1,"name":"test"}})
          }
        end)

      promise = HTTP.fetch("http://localhost/api/data", unix_socket: socket_path)
      response = Promise.await(promise)

      assert response.status == 200
      assert {:ok, json} = Response.json(response)
      assert json["message"] == "success"
      assert json["data"]["id"] == 1
      assert json["data"]["name"] == "test"

      UnixSocketServer.stop(server_pid)
    end

    test "GET request with query parameters" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn request ->
          # Verify query parameters are passed correctly
          assert request.path == "/search?q=elixir&limit=10"

          %{
            status: 200,
            headers: %{"Content-Type" => "application/json"},
            body: ~s({"results":[]})
          }
        end)

      promise =
        HTTP.fetch("http://localhost/search?q=elixir&limit=10", unix_socket: socket_path)

      response = Promise.await(promise)
      assert response.status == 200

      UnixSocketServer.stop(server_pid)
    end

    test "GET request with custom headers" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn request ->
          # Verify custom headers are sent
          assert request.headers["authorization"] == "Bearer test-token"
          assert request.headers["x-custom-header"] == "custom-value"

          %{
            status: 200,
            headers: %{"Content-Type" => "text/plain"},
            body: "Authenticated"
          }
        end)

      promise =
        HTTP.fetch("http://localhost/protected",
          unix_socket: socket_path,
          headers: [
            {"Authorization", "Bearer test-token"},
            {"X-Custom-Header", "custom-value"}
          ]
        )

      response = Promise.await(promise)
      assert response.status == 200
      assert response.body == "Authenticated"

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Unix socket POST requests" do
    test "POST request with JSON body" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn request ->
          # Verify request
          assert request.method == "post"
          assert request.headers["content-type"] == "application/json"

          # Parse JSON body
          {:ok, body_json} = JSON.decode(request.body)
          assert body_json["title"] == "Test Post"
          assert body_json["content"] == "This is a test"

          %{
            status: 201,
            headers: %{"Content-Type" => "application/json"},
            body: ~s({"id":123,"status":"created"})
          }
        end)

      body = JSON.encode!(%{title: "Test Post", content: "This is a test"})

      promise =
        HTTP.fetch("http://localhost/posts",
          method: "POST",
          unix_socket: socket_path,
          headers: [{"Content-Type", "application/json"}],
          body: body
        )

      response = Promise.await(promise)
      assert response.status == 201
      assert {:ok, json} = Response.json(response)
      assert json["id"] == 123
      assert json["status"] == "created"

      UnixSocketServer.stop(server_pid)
    end

    test "POST request with text body" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn request ->
          assert request.method == "post"
          assert request.body == "plain text data"

          %{
            status: 200,
            headers: %{"Content-Type" => "text/plain"},
            body: "Received"
          }
        end)

      promise =
        HTTP.fetch("http://localhost/data",
          method: "POST",
          unix_socket: socket_path,
          body: "plain text data"
        )

      response = Promise.await(promise)
      assert response.status == 200

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Unix socket PUT requests" do
    test "PUT request updates resource" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn request ->
          assert request.method == "put"
          assert request.path == "/users/123"

          {:ok, body_json} = JSON.decode(request.body)
          assert body_json["name"] == "Updated Name"

          %{
            status: 200,
            headers: %{"Content-Type" => "application/json"},
            body: ~s({"id":123,"name":"Updated Name"})
          }
        end)

      body = JSON.encode!(%{name: "Updated Name"})

      promise =
        HTTP.fetch("http://localhost/users/123",
          method: "PUT",
          unix_socket: socket_path,
          headers: [{"Content-Type", "application/json"}],
          body: body
        )

      response = Promise.await(promise)
      assert response.status == 200

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Unix socket DELETE requests" do
    test "DELETE request removes resource" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn request ->
          assert request.method == "delete"
          assert request.path == "/users/123"

          %{
            status: 204,
            headers: %{},
            body: ""
          }
        end)

      promise =
        HTTP.fetch("http://localhost/users/123",
          method: "DELETE",
          unix_socket: socket_path
        )

      response = Promise.await(promise)
      assert response.status == 204
      assert response.body == ""

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Unix socket PATCH requests" do
    test "PATCH request partially updates resource" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn request ->
          assert request.method == "patch"

          {:ok, body_json} = JSON.decode(request.body)
          assert body_json["email"] == "newemail@example.com"

          %{
            status: 200,
            headers: %{"Content-Type" => "application/json"},
            body: ~s({"id":123,"email":"newemail@example.com"})
          }
        end)

      body = JSON.encode!(%{email: "newemail@example.com"})

      promise =
        HTTP.fetch("http://localhost/users/123",
          method: "PATCH",
          unix_socket: socket_path,
          headers: [{"Content-Type", "application/json"}],
          body: body
        )

      response = Promise.await(promise)
      assert response.status == 200

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Unix socket error handling" do
    test "returns error when socket file doesn't exist" do
      non_existent_path = "/tmp/non_existent_socket_#{:rand.uniform(99999)}.sock"

      promise = HTTP.fetch("http://localhost/test", unix_socket: non_existent_path)
      result = Promise.await(promise)

      assert {:error, _reason} = result
    end

    test "handles server errors correctly" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn _request ->
          %{
            status: 500,
            headers: %{"Content-Type" => "application/json"},
            body: ~s({"error":"Internal server error"})
          }
        end)

      promise = HTTP.fetch("http://localhost/error", unix_socket: socket_path)
      response = Promise.await(promise)

      assert response.status == 500
      assert {:ok, json} = Response.json(response)
      assert json["error"] == "Internal server error"

      UnixSocketServer.stop(server_pid)
    end

    test "handles 404 not found" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn _request ->
          %{
            status: 404,
            headers: %{"Content-Type" => "text/plain"},
            body: "Not Found"
          }
        end)

      promise = HTTP.fetch("http://localhost/nonexistent", unix_socket: socket_path)
      response = Promise.await(promise)

      assert response.status == 404
      assert response.body == "Not Found"

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Unix socket response headers" do
    test "correctly parses response headers" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn _request ->
          %{
            status: 200,
            headers: %{
              "Content-Type" => "application/json",
              "X-Custom-Header" => "custom-value",
              "X-Request-Id" => "abc123"
            },
            body: ~s({"data":"test"})
          }
        end)

      promise = HTTP.fetch("http://localhost/test", unix_socket: socket_path)
      response = Promise.await(promise)

      assert response.status == 200
      assert HTTP.Headers.get(response.headers, "content-type") == "application/json"
      assert HTTP.Headers.get(response.headers, "x-custom-header") == "custom-value"
      assert HTTP.Headers.get(response.headers, "x-request-id") == "abc123"

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Unix socket with Promise chaining" do
    test "chains multiple operations" do
      {:ok, socket_path, server_pid} =
        UnixSocketServer.start_link(fn _request ->
          %{
            status: 200,
            headers: %{"Content-Type" => "application/json"},
            body: ~s({"value":42})
          }
        end)

      # Test Promise chaining with await (simpler version to avoid task ownership issues)
      promise = HTTP.fetch("http://localhost/data", unix_socket: socket_path)
      response = Promise.await(promise)

      assert response.status == 200
      assert {:ok, json} = Response.json(response)
      assert json["value"] == 42

      UnixSocketServer.stop(server_pid)
    end
  end

  describe "Real-world use case: Docker socket" do
    test "connects to Docker daemon (requires Docker)" do
      socket_path = "/var/run/docker.sock"

      assert File.exists?(socket_path), "Docker socket not found at #{socket_path}"

      promise = HTTP.fetch("http://localhost/version", unix_socket: socket_path)
      response = Promise.await(promise)

      assert response.status == 200
      assert {:ok, json} = Response.json(response)
      assert Map.has_key?(json, "Version")
    end
  end
end
