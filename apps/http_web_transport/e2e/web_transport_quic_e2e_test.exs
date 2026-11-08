defmodule E2E.WebTransportQUICE2ETest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport

  @moduletag :e2e

  test "the live backend refuses without explicit QUIC trust and never falls back" do
    transport = WebTransport.new("https://example.com/transport", connect_timeout: 1_000)

    assert {:error, {:http3_not_established, _}} = WebTransport.await_ready(transport, 2_000)

    assert WebTransport.state(transport) == :failed
  end
end
