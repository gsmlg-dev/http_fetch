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

The current implementation establishes the application boundary and transport contract.
`QuicHttp3.Frame`, `QuicHttp3.Settings`, and `QuicHttp3.Varint` delegate to the
existing `http_core` codecs so there is one wire implementation during the
migration. `QuicHttp3.Stream` classifies QUIC stream identifiers and incremental
unidirectional stream type prefixes. `QuicHttp3.Control` validates local and
peer control-stream ownership, buffers split prefixes/frames, requires SETTINGS
as the first frame, rejects duplicate or forbidden frames, and emits SETTINGS
and GOAWAY events. `QuicHttp3.Qpack` provides RFC 9204 static-table
indexed/name-reference fields, RFC 7541 Huffman strings, bounded dynamic-table
state, and zero-dynamic-table header blocks. `QuicHttp3.Session` drives the
control and request streams through the transport behaviour, handles bounded
writes, incremental response parsing, peer SETTINGS/GOAWAY, cancellation, and
explicit transport failures. The session keeps QPACK dynamic capacity at zero
until encoder/decoder stream synchronization is added.

`QuicHttp3.capabilities/0` still intentionally reports HTTP/3, QPACK, and
WebTransport as unavailable. The new stack has deterministic fake-transport
coverage but no independent HTTP/3 peer interoperability evidence yet, so
the `http_fetch` HTTP/3 selector currently returns an explicit unsupported
result while the stateful session is adapted to the fetch callback contract.
The legacy `quic` and `quic_h3` dependencies are no longer used.

The next implementation slices are:

1. The `QuicHttp3.Transport.Quic` adapter now owns an explicit
   `elixir_quic` endpoint/connection handle, configures `h3` ALPN by default,
   delegates bounded stream operations, and exposes QUIC DATAGRAM send/read
   with the upstream v0.3.0 capability boundary. Endpoint shutdown remains an
   explicit caller operation.
2. QPACK encoder/decoder stream synchronization and dynamic-table wire state.
3. WebTransport extended CONNECT, session demultiplexing, and datagrams.
4. Adapt the stateful session to the fetch callback contract, then perform
   independent HTTP/3 interoperability validation before enabling the
   production selector.
