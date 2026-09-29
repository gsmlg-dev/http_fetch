defmodule E2E.HTTP3Test do
  use ExUnit.Case, async: true

  @moduletag :e2e

  test "reports the HTTP/3 backend capability boundary" do
    assert {:error, :http3_not_supported_by_elixir_quic_http3} =
             "https://example.com/"
             |> HTTP.fetch(http_version: :http3, timeout: 1_000)
             |> HTTP.Promise.await()
  end
end
