defmodule E2E.Server do
  @moduledoc """
  Resolves the base URL of the running e2e test server.

  The server is started outside of the ExUnit process by the CI workflow (or
  by a developer running `apps/http_fetch/priv/test_server/server` locally) and its URL is
  exported as the `E2E_BASE_URL` environment variable.

  ## Usage

      base = E2E.Server.base_url!()
      HTTP.fetch("\#{base}/json") |> HTTP.Promise.await()
  """

  @doc """
  Returns the base URL of the e2e test server (e.g. `"http://127.0.0.1:54321"`).

  Reads the `E2E_BASE_URL` environment variable. Raises a clear error if it
  is not set, which usually means the test server was not started before
  `mix test.e2e` was invoked.
  """
  @spec base_url!() :: String.t()
  def base_url! do
    case System.get_env("E2E_BASE_URL") do
      nil ->
        raise """
        E2E_BASE_URL is not set. The e2e test server must be started before
        running `mix test.e2e`. Either:

          1. Run the CI workflow which exports E2E_BASE_URL for you, OR
          2. Locally:
               go build -o apps/http_fetch/priv/test_server/server ./apps/http_fetch/priv/test_server
               apps/http_fetch/priv/test_server/server &
               export E2E_BASE_URL=http://127.0.0.1:$(grep ^PORT= <log>)
        """

      url ->
        String.trim_trailing(url, "/")
    end
  end

  @doc """
  Joins the base URL with a path, handling slashes correctly.

      iex> E2E.Server.url("/json")
      "http://127.0.0.1:54321/json"
  """
  @spec url(String.t()) :: String.t()
  def url(path) do
    base = base_url!()
    if String.starts_with?(path, "/"), do: base <> path, else: base <> "/" <> path
  end
end
