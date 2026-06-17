defmodule E2E.DockerSocketTest do
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  test "connects to Docker daemon over a Unix socket" do
    socket_path = "/var/run/docker.sock"

    assert File.exists?(socket_path), "Docker socket not found at #{socket_path}"

    response =
      "http://localhost/version"
      |> HTTP.fetch(unix_socket: socket_path)
      |> HTTP.Promise.await()

    assert response.status == 200
    assert {:ok, json} = HTTP.Response.json(response)
    assert Map.has_key?(json, "Version")
  end
end
