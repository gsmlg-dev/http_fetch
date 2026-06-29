defmodule E2E.MethodsTest do
  @moduledoc """
  Exercises the seven HTTP verbs (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD)
  end-to-end against the vendored test server.
  """
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias E2E.ResponseView

  defp get(path, opts \\ []) do
    path |> E2E.Server.url() |> HTTP.fetch([method: "GET"] ++ opts) |> HTTP.Promise.await()
  end

  defp send_with(method, path, body) do
    path
    |> E2E.Server.url()
    |> HTTP.fetch(method: method, body: body, content_type: "text/plain")
    |> HTTP.Promise.await()
  end

  describe "GET" do
    test "returns 200 with the request echo as JSON" do
      view = get("/get?q=1") |> E2E.ResponseView.from()
      assert view.status == 200
      assert %{"method" => "GET", "query" => %{"q" => ["1"]}} = E2E.ResponseView.json!(view)
    end
  end

  describe "POST" do
    test "echoes the request body" do
      view = send_with("POST", "/post", "hello world") |> E2E.ResponseView.from()
      assert view.status == 200
      assert %{"method" => "POST", "body" => "hello world"} = E2E.ResponseView.json!(view)
    end
  end

  describe "PUT" do
    test "echoes the request body" do
      view = send_with("PUT", "/put", "put-body") |> E2E.ResponseView.from()
      assert view.status == 200
      assert %{"method" => "PUT", "body" => "put-body"} = E2E.ResponseView.json!(view)
    end
  end

  describe "PATCH" do
    test "echoes the request body" do
      view = send_with("PATCH", "/patch", "patch-body") |> E2E.ResponseView.from()
      assert view.status == 200
      assert %{"method" => "PATCH", "body" => "patch-body"} = E2E.ResponseView.json!(view)
    end
  end

  describe "DELETE" do
    test "returns 204 with no body" do
      resp =
        E2E.Server.url("/delete")
        |> HTTP.fetch(method: "DELETE")
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 204
      assert E2E.ResponseView.text(view) == ""
    end
  end

  describe "OPTIONS" do
    test "returns the Allow header listing supported methods" do
      resp =
        E2E.Server.url("/options")
        |> HTTP.fetch(method: "OPTIONS")
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 204
      allow = E2E.ResponseView.get_header(view, "allow")
      assert allow =~ "GET"
      assert allow =~ "POST"
      assert allow =~ "PUT"
      assert allow =~ "PATCH"
      assert allow =~ "DELETE"
      assert allow =~ "OPTIONS"
      assert allow =~ "HEAD"
    end
  end

  describe "HEAD" do
    test "returns 200 with headers and no body" do
      resp =
        E2E.Server.url("/head")
        |> HTTP.fetch(method: "HEAD")
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      # HEAD responses must not include a body.
      assert E2E.ResponseView.text(view) == ""
    end
  end
end
