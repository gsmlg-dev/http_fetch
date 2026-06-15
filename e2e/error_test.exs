defmodule E2E.ErrorTest do
  @moduledoc """
  Non-2xx status codes, redirects, and abort/timeout behaviour.
  """
  use ExUnit.Case, async: true

  @moduletag :e2e
  @moduletag timeout: 30_000

  alias E2E.ResponseView

  describe "status codes" do
    test "404 returns a 404 Response (not an error tuple)" do
      resp = E2E.Server.url("/status/404") |> HTTP.fetch() |> HTTP.Promise.await()
      view = E2E.ResponseView.from(resp)
      assert view.status == 404
    end

    test "500 returns a 500 Response" do
      resp = E2E.Server.url("/status/500") |> HTTP.fetch() |> HTTP.Promise.await()
      view = E2E.ResponseView.from(resp)
      assert view.status == 500
    end
  end

  describe "redirects" do
    test "autoredirect: true follows a 302 chain" do
      resp =
        E2E.Server.url("/redirect/2")
        |> HTTP.fetch(options: [autoredirect: true])
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 200
      assert E2E.ResponseView.json!(view) == %{"ok" => true, "redirects" => 0}
    end

    test "autoredirect: false returns the 302" do
      resp =
        E2E.Server.url("/redirect/2")
        |> HTTP.fetch(options: [autoredirect: false])
        |> HTTP.Promise.await()

      view = E2E.ResponseView.from(resp)
      assert view.status == 302
    end
  end

  describe "aborts" do
    # TODO(upstream): gsmlg-dev/http_fetch#6
    test "aborting an in-flight request returns an error tuple" do
      controller = HTTP.AbortController.new()

      promise =
        E2E.Server.url("/delay/2000")
        |> HTTP.fetch(
          signal: controller,
          options: [timeout: 10_000]
        )

      Process.sleep(100)
      :ok = HTTP.AbortController.abort(controller)

      result = HTTP.Promise.await(promise, 10_000)
      assert match?({:error, _}, result)
    end
  end
end
