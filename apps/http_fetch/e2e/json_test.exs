defmodule E2E.JSONTest do
  @moduledoc """
  JSON request and response round-trips.
  """
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias E2E.ResponseView

  describe "JSON responses" do
    test "decodes application/json response body" do
      resp = E2E.Server.url("/json") |> HTTP.fetch() |> HTTP.Promise.await()
      view = E2E.ResponseView.from(resp)
      assert view.status == 200

      assert E2E.ResponseView.json!(view) == %{
               "ok" => true,
               "n" => 42,
               "message" => "hello from test server"
             }
    end
  end

  describe "JSON requests" do
    test "POST application/json round-trips through the server" do
      body = JSON.encode!(%{"user" => "alice", "tags" => ["a", "b"]})

      resp =
        E2E.Server.url("/post")
        |> HTTP.fetch(
          method: "POST",
          body: body,
          content_type: "application/json"
        )
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      assert %{"body" => echoed} = E2E.ResponseView.json!(view)
      # Server echoes the raw body string.
      assert echoed == body
    end

    test "charset parameter is tolerated by the server" do
      body = ~s({"hello":"world"})

      resp =
        E2E.Server.url("/post")
        |> HTTP.fetch(
          method: "POST",
          body: body,
          content_type: "application/json; charset=utf-8"
        )
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      assert %{"body" => ^body} = E2E.ResponseView.json!(view)
    end

    test "Accept: application/json is honored" do
      resp =
        E2E.Server.url("/json")
        |> HTTP.fetch(headers: %{"Accept" => "application/json"})
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      assert %{"ok" => true} = E2E.ResponseView.json!(view)
    end
  end
end
