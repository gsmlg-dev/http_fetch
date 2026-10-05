# QUIC consumer contract

This document maps the imported public QUIC and TLS interfaces to the HTTP
umbrella. It is not a full QUIC conformance claim. The supported HTTP/3 beta
profile is described below. Source
identity and license records are in
[migration provenance](migration-provenance.md); implementation evidence and
limits are in [`docs/quic/`](quic/consumer-contract.md).

## Packages and authority

| Package | OTP app / public namespace | Dependency role |
| --- | --- | --- |
| `ex_ssl` | `:ex_ssl` / `SSL` | TLS provider; no internal runtime dependency |
| `elixir_quic` | `:elixir_quic` / `Quic` | QUIC v1 transport; depends on `ex_ssl` |
| `http_core` | `:http_core` / `HTTP.*` | Shared HTTP and TLS/QUIC integration; depends on `ex_ssl` and `elixir_quic` |
| `http_runtime` | `:http_runtime` / `HTTP.Runtime.*`, `HTTP.HTTP3.*` | Shared HTTP/2 and HTTP/3 owners; depends on `http_core` and `elixir_quic_http3` |
| `elixir_quic_http3` | `:elixir_quic_http3` / `QuicHttp3` | HTTP/3 beta application; depends on `http_core` and `elixir_quic` |
| `http_fetch` | `:http_fetch` / `HTTP` | Fetch consumer; depends on `http_core` and `http_runtime` |
| `http_event_source` | `:http_event_source` / `HTTP.EventSource` | EventSource consumer; depends on `http_core` and `http_runtime` |
| `http_web_socket` | `:http_web_socket` / `HTTP.WebSocket` | WebSocket consumer; depends on `http_core` and `http_runtime` |
| `http_web_transport` | `:http_web_transport` / `HTTP.WebTransport` | WebTransport application boundary; depends on `http_core` |

Internal dependencies use the exact coordinated umbrella version,
`in_umbrella: true`, and the corresponding Hex identity. The original `0.16.1`
inventory is preserved as a historical migration snapshot. Current candidate
and published artifact evidence is recorded in the
[implementation audit](http3-implementation-audit.md).

## TLS to QUIC boundary

Production QUIC code calls public `SSL.QUIC` and `SSL.Fingerprint` functions.
It does not import private TLS handshake, transcript, PKIX, or traffic-state
modules. `SSL.QUIC` owns certificate authentication and the TLS transcript/key
schedule. Its input levels are `:initial`, `:handshake`, and `:application`;
the QUIC connection reassembles CRYPTO stream offsets and supplies contiguous
handshake bytes. Process the returned TLS action list in order. Retain each
emitted byte range once and retransmit it without advancing TLS again.

The QUIC transport owns Initial and packet/header-protection keys, packet-number
spaces, stream state, transport-parameter semantics, and packet lifecycle.
Authenticated transport parameters and TLS handshake completion are separate
facts. Do not infer peer authentication or application readiness from ALPN or
fingerprint matches. QUIC endpoints and all peer-driven parser/buffer paths keep
the documented bounds; see the source [QUIC architecture](quic/architecture.md)
and [testing requirements](quic/testing.md).

`ex_ssl` implements TLS through its own engine with OTP crypto and public-key
primitives. It does not use OTP `:ssl` to perform production TLS handshakes.
The shared TCP clients still default to OTP `:ssl`; selecting ex_ssl for TCP
does not change the QUIC TLS path. A non-`nil` TCP `tls_backend` supplied to
the QUIC API is rejected explicitly.

## Application and selector boundary

`Quic` provides raw QUIC streams and optional unreliable DATAGRAMs. Application
ALPN is opaque metadata; the transport does not dispatch HTTP/3 from `h3`.
`QuicHttp3` is a separate HTTP/3 application package with independent
capability reporting:

- `Quic.capabilities().http3` is `false`.
- `QuicHttp3.capabilities()` reports HTTP/3 beta, `http3: true`, `qpack: true`,
  `qpack_profile: :static_literal` and Huffman support.
- Fetch and EventSource support explicit verified HTTPS `http_version: :http3`
  through the supervised runtime, without protocol fallback.
- Dynamic QPACK, 0-RTT, migration, WebSocket over HTTP/3 and WebTransport remain
  unsupported. The profile advertises zero dynamic capacity and blocked streams.

The [Fetch contract](http3-fetch-contract.md) defines upload acknowledgements,
unknown-operation handling, redirects, deadlines, trailers and cancellation.
Beta status describes the implemented subset; final peer, artifact, load and
canary acceptance is tracked separately in the
[acceptance record](http3-wp5-acceptance.md).

The internal `HTTP.QUIC.ExQuic` adapter, where used directly, accepts a TLS
keyword list plus bounded endpoint settings, normalizes verification before
starting a connection, and forwards opaque QUIC handles and operation results.
It does not retry unknown operations or reinterpret raw stream success as an
HTTP/3 session. Its optional driver argument is a test seam; production uses
`Quic`. There is no legacy transport or native-library fallback.

See [the HTTP/3 boundary](quic_http3_design.md) for the protocol split and
[TLS consumer contract](ex-ssl-consumer-contract.md) for TCP-specific behavior.
