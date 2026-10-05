# TLS, QUIC, and HTTP/3 application boundaries

The TLS provider, QUIC transport, and HTTP/3 application are separate umbrella
packages. Their imported source is recorded in
[migration provenance](migration-provenance.md).

| Layer | Package / app | Public namespace | Owns |
| --- | --- | --- | --- |
| TLS | `ex_ssl` / `:ex_ssl` | `SSL` | TLS handshake, transcript, peer authentication, traffic secrets, and ClientHello serialization/observation |
| Transport | `elixir_quic` / `:elixir_quic` | `Quic` | QUIC packet protection, connection state, streams, transport parameters, and datagrams |
| HTTP/3 application | `elixir_quic_http3` / `:elixir_quic_http3` | `QuicHttp3` | HTTP/3 control/request streams, frames, settings, QPACK, and session boundary |
| HTTP clients | `http_fetch`, `http_event_source`, `http_web_socket`, `http_web_transport` | `HTTP` | Consumer adapters and public request/session behavior |

Fetch, EventSource and WebSocket depend on `http_core` and `http_runtime`.
WebTransport depends on `http_core`. The shared runtime owns HTTP/2 and HTTP/3
connections and depends on `http_core` and `elixir_quic_http3`; the companion
depends on `http_core` and `elixir_quic`. Shared primitives depend on `ex_ssl`
and `elixir_quic`; the QUIC transport depends on `ex_ssl`.

`elixir_quic` uses only the public `SSL.QUIC` and `SSL.Fingerprint` interfaces.
TLS returns ordered actions; QUIC processes them in order and retains emitted
CRYPTO bytes for retransmission without another TLS call. TLS authentication,
transcript, and secret derivation remain owned by `ex_ssl`; QUIC Initial and
packet/header protection remain owned by `elixir_quic`. TLS protocol work does
not call OTP `:ssl`; the existing OTP backend remains the default for TCP TLS.
See the imported [QUIC architecture](quic/architecture.md),
[TLS contract](quic/ex-ssl-quic-contract.md), and
[consumer contract](ex-quic-consumer-contract.md) for detailed limits and
ownership rules.

## Current capability boundary

`QuicHttp3.capabilities/0` reports the implemented initial client profile:
`status: :beta`, `http3: true`, `qpack: true`,
`qpack_profile: :static_literal` and `qpack_huffman: true`. HTTP/3 control and
request streams use static/literal QPACK, including Huffman strings, with zero
dynamic-table capacity and zero blocked streams.

Fetch and EventSource select verified HTTPS HTTP/3 explicitly with
`http_version: :http3`; protocol failures do not downgrade. Dynamic QPACK,
0-RTT, connection migration, WebSocket over HTTP/3 and WebTransport remain
unsupported. `Quic.capabilities/0` continues reporting `http3: false`: raw QUIC
owns transport, while the companion owns HTTP/3. Negotiated `h3` alone is not
proof of authenticated application readiness.

See the [Fetch contract](http3-fetch-contract.md) for public behavior and the
[acceptance record](http3-wp5-acceptance.md) for independent peer, artifact, load
and canary results. Beta capability reporting does not claim those gates have
completed or establish full conformance or production readiness.

The `tls_backend` setting selects TCP TLS only. Passing a non-`nil` backend to
a QUIC-backed API returns `:tls_backend_not_supported_for_quic`; QUIC uses the
separate `SSL.QUIC` interface. There is no fallback to OTP `:ssl`, the legacy
`:quic` implementation, or a native QUIC library.

## Release state

The nine packages share a coordinated version and exact internal dependency
requirements. The original `0.16.1` migration inventory and validation are
historical snapshots; they do not describe current package availability.
Current candidate and published artifact evidence is recorded separately in the
[implementation audit](http3-implementation-audit.md). Public HTTP/3 activation
and beta acceptance are separate from installing the companion package.
