defmodule QuicHttp3 do
  @moduledoc """
  HTTP/3 application protocol boundary for QUIC transports.

  This package owns HTTP/3 semantics above QUIC. It deliberately does not
  implement QUIC packet handling or expose the legacy `:quic_h3` API. The
  transport-agnostic session is available through `QuicHttp3.Session`.

  The initial HTTP/3 client profile is beta, with static/literal QPACK and
  Huffman strings. Capability reporting describes this implemented subset;
  independent acceptance and publication are recorded separately.
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
          required(:dynamic_qpack) => false,
          required(:zero_rtt) => false,
          required(:connection_migration) => false,
          required(:websocket_over_http3) => false,
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
      dynamic_qpack: false,
      zero_rtt: false,
      connection_migration: false,
      websocket_over_http3: false,
      webtransport: false
    }
  end

  @doc "The HTTP/3 ALPN identifier used by the QUIC transport adapter."
  def alpn, do: @http3_alpn
end
