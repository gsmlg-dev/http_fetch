# QUIC HTTP/3 Application Boundary

`apps/elixir_quic_http3` is the HTTP/3 application layer for this umbrella.
Its OTP application name is `:elixir_quic_http3`, and its public Elixir
namespace is `QuicHttp3`.

## Ownership

- `elixir_quic` owns QUIC v1 transport, TLS/ALPN negotiation, stream lifecycle,
  flow control, and QUIC datagrams.
- `elixir_quic_http3` owns HTTP/3 control/request streams, SETTINGS, frames,
  QPACK, HTTP/3 errors, and session lifecycle.
- `http_fetch` maps `HTTP.Request` and response events to an HTTP/3 session.
- `http_web_transport` maps extended CONNECT and WebTransport stream/datagram
  semantics to the same HTTP/3 layer.

The HTTP/3 layer must not import the legacy `:quic_h3` API. The existing
`HTTP.HTTP3` and `HTTP.WebTransport.Transport.QUIC` implementations remain the
compatibility backend until the new stack has independent interoperability
evidence.

## Current Slice

The first slice establishes the application boundary and transport contract.
`QuicHttp3.Frame`, `QuicHttp3.Settings`, and `QuicHttp3.Varint` delegate to the
existing `http_core` codecs so there is one wire implementation during the
migration. `QuicHttp3.Stream` classifies QUIC stream identifiers and incremental
unidirectional stream type prefixes. `QuicHttp3.Control` validates local and
peer control-stream ownership, buffers split prefixes/frames, requires SETTINGS
as the first frame, rejects duplicate or forbidden frames, and emits SETTINGS
and GOAWAY events. `QuicHttp3.capabilities/0` still intentionally reports
HTTP/3, QPACK, and WebTransport as unavailable until their session
implementations exist.

The next implementation slices are:

1. QUIC transport capabilities required by H3: `h3` ALPN, peer-initiated
   unidirectional stream events, bounded stream operations, and QUIC DATAGRAM.
2. QPACK static/dynamic table state and header block encoding/decoding.
3. HTTP request/response sessions with flow control and cancellation.
4. WebTransport extended CONNECT, session demultiplexing, and datagrams.
5. Interoperability validation, production selector integration, and only then
   removal of the legacy `quic` dependencies.
