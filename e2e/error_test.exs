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
      view = ResponseView.from(resp)
      assert view.status == 404
    end

    test "500 returns a 500 Response" do
      resp = E2E.Server.url("/status/500") |> HTTP.fetch() |> HTTP.Promise.await()
      view = ResponseView.from(resp)
      assert view.status == 500
    end
  end

  describe "redirects" do
    test "follows a 302 chain by default" do
      resp =
        E2E.Server.url("/redirect/2")
        |> HTTP.fetch()
        |> HTTP.Promise.await()

      view = ResponseView.from(resp)
      assert view.status == 200
      assert ResponseView.json!(view) == %{"ok" => true, "redirects" => 0}
    end

    test "redirect: :follow follows a 302 chain" do
      resp =
        E2E.Server.url("/redirect/2")
        |> HTTP.fetch(redirect: :follow)
        |> HTTP.Promise.await()

      view = ResponseView.from(resp)
      assert view.status == 200
      assert ResponseView.json!(view) == %{"ok" => true, "redirects" => 0}
    end

    test "redirect: :manual returns the 302" do
      resp =
        E2E.Server.url("/redirect/2")
        |> HTTP.fetch(redirect: :manual)
        |> HTTP.Promise.await()

      view = ResponseView.from(resp)
      assert view.status == 302
    end

    test "redirect: :error rejects a 302" do
      result =
        E2E.Server.url("/redirect/2")
        |> HTTP.fetch(redirect: :error)
        |> HTTP.Promise.await()

      assert {:error, :redirect} = result
    end
  end

  describe "aborts" do
    test "aborting an in-flight request returns an error tuple" do
      controller = HTTP.AbortController.new()

      promise =
        E2E.Server.url("/delay/2000")
        |> HTTP.fetch(
          signal: controller,
          timeout: 10_000
        )

      Process.sleep(100)
      :ok = HTTP.AbortController.abort(controller)

      result = HTTP.Promise.await(promise, 10_000)
      assert match?({:error, _}, result)
    end
  end
end
