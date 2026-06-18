defmodule E2E.DockerSocketTest do
  use ExUnit.Case, async: true

  alias HTTP.Test.UnixSocketServer

  @moduletag :e2e
  @moduletag timeout: 30_000

  test "connects to Docker daemon over a Unix socket" do
    {:ok, socket_path, server_pid} =
      UnixSocketServer.start_link(fn request ->
        assert request.method == "get"
        assert request.path == "/version"

        %{
          status: 200,
          headers: %{"Content-Type" => "application/json"},
          body: ~s({"Version":"test-docker","ApiVersion":"1.44"})
        }
      end)

    response =
      "http://localhost/version"
      |> HTTP.fetch(unix_socket: socket_path)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert {:ok, json} = HTTP.Response.json(response)
    assert Map.has_key?(json, "Version")

    UnixSocketServer.stop(server_pid)
  end
end
