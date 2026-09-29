defmodule QuicHttp3 do
  @moduledoc """
  HTTP/3 application protocol boundary for QUIC transports.

  This package owns HTTP/3 semantics above QUIC. It deliberately does not
  implement QUIC packet handling or expose the legacy `:quic_h3` API.
  """

  @http3_alpn "h3"

  @type alpn :: binary()

  @type capabilities :: %{
          required(:alpn) => alpn(),
          required(:http3) => false,
          required(:qpack) => false,
          required(:webtransport) => false
        }

  @doc "Return the protocol capabilities currently implemented by this app."
  def capabilities do
    %{
      alpn: @http3_alpn,
      http3: false,
      qpack: false,
      webtransport: false
    }
  end

  @doc "The HTTP/3 ALPN identifier used by the future QUIC transport adapter."
  def alpn, do: @http3_alpn
end
