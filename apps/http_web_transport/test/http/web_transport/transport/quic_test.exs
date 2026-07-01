defmodule HTTP.WebTransport.Transport.QUICTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.Transport.QUIC

  test "validates H3 WebTransport metadata before reporting unavailable backend" do
    assert {:ok, options} = Options.new("https://example.com/transport")
    assert {:error, :quic_backend_unavailable} = QUIC.connect(options.uri, options)
  end

  test "rejects invalid H3 WebTransport CONNECT targets before backend setup" do
    assert {:ok, options} = Options.new("https://example.com/transport")

    assert {:error, {:unsupported_scheme, "http"}} =
             QUIC.connect(URI.parse("http://example.com/transport"), options)

    assert {:error, :fragment_not_allowed} =
             QUIC.connect(URI.parse("https://example.com/transport#frag"), options)
  end

  test "rejects non-normalized backend inputs" do
    assert {:error, :invalid_quic_connect_options} =
             QUIC.connect(URI.parse("https://example.com/"), [])
  end
end
