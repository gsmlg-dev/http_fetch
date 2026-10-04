# TLS, QUIC, and HTTP/3 application boundaries

The TLS provider, QUIC transport, and HTTP/3 application are separate umbrella
packages. Their imported source is recorded in
[migration provenance](migration-provenance.md).

| Layer | Package / app | Public namespace | Owns |
| --- | --- | --- | --- |
| TLS | `ex_ssl` / `:ex_ssl` | `SSL` | TLS handshake, transcript, peer authentication, traffic secrets, and ClientHello serialization/observation |
| Transport | `elixir_quic` / `:elixir_quic` | `Quic` | QUIC packet protection, connection state, streams, transport parameters, and datagrams |
| HTTP/3 application | `elixir_quic_http3` / `:elixir_quic_http3` | `QuicHttp3` | HTTP/3 control/request streams, frames, settings, QPACK, and session boundary |
| HTTP clients | `http_fetch`, `http_web_transport` | `HTTP` | Consumer adapters and public request/session behavior |

The runtime dependency direction is `http_fetch/http_web_transport ->
http_core -> {ex_ssl, elixir_quic}`; HTTP/3 also depends on `http_core` and
`elixir_quic`. The independent shared HTTP/2 owner is `http_runtime`, used by
`http_fetch`, EventSource, and WebSocket through `http_core`.

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

The imported source does not enable production HTTP/3 or WebTransport. At this
revision, `QuicHttp3.capabilities/0` reports `http3: false`, `qpack: false`, and
`webtransport: false`; `Quic.capabilities/0` reports `http3: false`. The Fetch
HTTP/3 route returns `:http3_not_supported_by_elixir_quic_http3`, and the
WebTransport QUIC selector remains unsupported. Offering or negotiating `h3`
ALPN does not implement HTTP/3 framing or make either selector available.

The `tls_backend` setting selects TCP TLS only. Passing a non-`nil` backend to
a QUIC-backed API returns `:tls_backend_not_supported_for_quic`; QUIC uses the
separate `SSL.QUIC` interface. There is no fallback to OTP `:ssl`, the legacy
`:quic` implementation, or a native QUIC library.

## Release state

The nine-package dependency declarations use the local source candidate at
`0.16.1`. Six packages had already been published at that version with the old
dependency metadata, so the complete TLS/QUIC graph is not available as a
nine-package Hex release. Do not republish or describe those immutable package
versions as updated. See [migration validation](migration-validation.md) for
pending integration checks and the next-release safeguards.
