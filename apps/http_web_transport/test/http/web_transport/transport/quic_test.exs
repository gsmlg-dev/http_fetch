defmodule HTTP.WebTransport.Transport.QUICTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport.Options
  alias HTTP.WebTransport.Transport.QUIC

  test "default backend module exposes the QUIC transport contract" do
    assert {:ok, options} = Options.new("https://example.com/transport")
    assert options.backend == QUIC
    assert Code.ensure_loaded?(QUIC)
    assert function_exported?(QUIC, :connect, 2)
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
