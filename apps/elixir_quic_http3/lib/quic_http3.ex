defmodule QuicHttp3 do
  @moduledoc """
  HTTP/3 application protocol boundary for QUIC transports.

  This package owns HTTP/3 semantics above QUIC. It deliberately does not
  implement QUIC packet handling or expose the legacy `:quic_h3` API. The
  transport-agnostic session is available through `QuicHttp3.Session`.

  The HTTP/3 client profile is beta. The QPACK decoder supports the dynamic
  table; the local encoder stays static/literal with Huffman strings. 0-RTT for
  safe requests, exclusive-session migration and WebSocket over HTTP/3 are
  beta; WebTransport is not reported as supported. `capabilities/0` describes
  this implemented subset; independent acceptance and publication are recorded
  separately.
  """

  @http3_alpn "h3"

  @type alpn :: binary()

  @type capabilities :: %{
          required(:alpn) => alpn(),
          required(:status) => :beta,
          required(:http3) => true,
          required(:qpack) => true,
          required(:qpack_profile) => :static_literal,
          required(:qpack_huffman) => true,
          required(:dynamic_qpack) => true,
          required(:zero_rtt) => true,
          required(:connection_migration) => true,
          required(:websocket_over_http3) => true,
          required(:webtransport) => false
        }

  @doc "Return the protocol capabilities currently implemented by this app."
  def capabilities do
    %{
      alpn: @http3_alpn,
      status: :beta,
      http3: true,
      qpack: true,
      qpack_profile: :static_literal,
      qpack_huffman: true,
      # Dynamic-table QPACK decoding (RFC 9204); the encoder stays
      # `qpack_profile: :static_literal`.
      dynamic_qpack: true,
      zero_rtt: true,
      # Exclusive-session migrate/2 only; pooled connections are not migratable.
      connection_migration: true,
      websocket_over_http3: true,
      webtransport: false
    }
  end

  @doc "The HTTP/3 ALPN identifier used by the QUIC transport adapter."
  def alpn, do: @http3_alpn
end
