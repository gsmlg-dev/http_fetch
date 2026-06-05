defmodule HTTPFetch.E2ETest do
  @moduledoc """
  End-to-end tests that exercise the full HTTP fetch pipeline against real
  network endpoints.

  These tests are slow and require internet access. They are NOT part of the
  default `mix test` run; invoke them with:

      mix test.e2e

  Add new e2e tests under `e2e/` and tag with `@moduletag :e2e`.
  """

  use ExUnit.Case, async: false

  @moduletag :e2e
  @moduletag timeout: 60_000

  alias HTTP.Promise
  alias HTTP.Response

  @base_url "http://httpbin.org"

  describe "real HTTP round-trips" do
    test "GET /status/200 returns a 200 Response" do
      resp = HTTP.fetch("#{@base_url}/status/200") |> Promise.await()
      assert %Response{status: 200} = resp
    end

    test "GET /json returns a parseable JSON body" do
      resp = HTTP.fetch("#{@base_url}/json") |> Promise.await()
      assert resp.status == 200
      assert {:ok, decoded} = JSON.decode(resp.body)
      assert is_map(decoded)
    end

    test "GET /get echoes query params in the response body" do
      resp =
        HTTP.fetch("#{@base_url}/get", query: %{"q" => "http_fetch"})
        |> Promise.await()

      assert resp.status == 200
      assert {:ok, %{"args" => %{"q" => "http_fetch"}}} = JSON.decode(resp.body)
    end
  end
end
