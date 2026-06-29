defmodule E2E.URLEncodedTest do
  @moduledoc """
  application/x-www-form-urlencoded request bodies, both raw and built via
  `HTTP.FormData` (which auto-selects urlencoded when no files are present).
  """
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias E2E.ResponseView

  describe "raw urlencoded body" do
    test "posts a simple key/value pair" do
      resp =
        E2E.Server.url("/urlencoded")
        |> HTTP.fetch(
          method: "POST",
          body: "name=alice&color=blue",
          content_type: "application/x-www-form-urlencoded"
        )
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200

      assert %{"form" => %{"name" => ["alice"], "color" => ["blue"]}} =
               E2E.ResponseView.json!(view)
    end

    test "preserves percent-encoded special characters" do
      resp =
        E2E.Server.url("/urlencoded")
        |> HTTP.fetch(
          method: "POST",
          body: "greeting=hello%20world&symbols=a%26b%3Dc",
          content_type: "application/x-www-form-urlencoded"
        )
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)

      assert %{"form" => %{"greeting" => ["hello world"], "symbols" => ["a&b=c"]}} =
               E2E.ResponseView.json!(view)
    end
  end

  describe "HTTP.FormData text-only form" do
    test "is auto-encoded as urlencoded" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("name", "bob")
        |> HTTP.FormData.append_field("lang", "elixir")

      resp =
        E2E.Server.url("/urlencoded")
        |> HTTP.fetch(method: "POST", body: form)
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200

      assert %{"form" => %{"name" => ["bob"], "lang" => ["elixir"]}} =
               E2E.ResponseView.json!(view)
    end

    test "handles unicode values" do
      form =
        HTTP.FormData.new()
        |> HTTP.FormData.append_field("msg", "héllo 🌍")

      resp =
        E2E.Server.url("/urlencoded")
        |> HTTP.fetch(method: "POST", body: form)
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert %{"form" => %{"msg" => ["héllo 🌍"]}} = E2E.ResponseView.json!(view)
    end
  end
end
