defmodule E2E.WebTransportQUICE2ETest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport

  @moduletag :e2e

  test "reports the WebTransport backend capability boundary" do
    transport = WebTransport.new("https://example.com/transport", connect_timeout: 1_000)

    assert {:error, :webtransport_not_supported_by_elixir_quic_http3} =
             WebTransport.await_ready(transport, 1_000)

    assert WebTransport.state(transport) == :failed
  end
end
