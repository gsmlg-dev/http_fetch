defmodule HTTP.WebTransport.Transport.QUICTest do
  use ExUnit.Case, async: true

  alias HTTP.WebTransport.{Options, Profile}
  alias HTTP.WebTransport.Transport.QUIC

  test "default backend module exposes the QUIC transport contract" do
    assert {:ok, options} = Options.new("https://example.com/transport")
    assert options.backend == QUIC
    assert Code.ensure_loaded?(QUIC)
    assert function_exported?(QUIC, :connect, 2)
    assert function_exported?(QUIC, :handle_message, 2)
    assert function_exported?(QUIC, :acknowledge, 2)
    refute Profile.supported?()
  end

  test "rejects invalid H3 WebTransport CONNECT targets before backend setup" do
    assert {:ok, options} = Options.new("https://example.com/transport")

    assert {:error, :invalid_webtransport_url} =
             QUIC.connect(URI.parse("http://example.com/transport"), options)

    assert {:error, :invalid_webtransport_url} =
             QUIC.connect(URI.parse("https://example.com/transport#frag"), options)
  end

  test "rejects non-normalized backend inputs" do
    assert {:error, :invalid_webtransport_options} =
             QUIC.connect(URI.parse("https://example.com/"), [])
  end

  test "trust failure before CONNECT reports no session and leaves no owner" do
    assert {:ok, options} = Options.new("https://example.com/transport", connect_timeout: 2_000)
    before = DynamicSupervisor.count_children(:http_fetch_http3_connection_supervisor).active

    assert {:error, {:http3_not_established, _}} =
             QUIC.connect(URI.parse("https://example.com/transport"), options)

    assert DynamicSupervisor.count_children(:http_fetch_http3_connection_supervisor).active ==
             before
  end

  test "owner messages of other sessions and unknown messages are ignored" do
    ref = %QUIC.Ref{owner: self(), ref: make_ref(), generation: make_ref(), monitor: make_ref()}
    assert :ignore = QUIC.handle_message(ref, {:http3, make_ref(), ref.ref, :done})
    assert :ignore = QUIC.handle_message(ref, :unrelated)

    assert {:ok, [{:webtransport_closed, ^ref, %{close_code: 7, reason: "bye"}}]} =
             QUIC.handle_message(
               ref,
               {:http3, ref.generation, ref.ref, {:wt, {:close, 7, "bye"}}}
             )
  end
end
