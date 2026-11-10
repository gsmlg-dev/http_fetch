# elixir_quic_http3

Beta HTTP/3 client application protocol for the `elixir_quic` transport.

The source was imported from
`gsmlg-dev/ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6` and extended in
the `http_fetch` umbrella. `QuicHttp3.Session` owns HTTP/3 control/request streams,
settings, response framing and QPACK; `QuicHttp3.Transport.Quic` supplies the
native transport. The shared runtime owns pooling and application delivery.

`QuicHttp3.capabilities/0` reports `status: :beta`, `http3: true`, `qpack: true`,
`qpack_profile: :static_literal` (the encoder) and `qpack_huffman: true`. It also
reports `dynamic_qpack: true` (the decoder advertises a 4096-byte dynamic table and
16 blocked streams by default; `0`/`0` restores the static-only profile),
`zero_rtt: true` (opt-in, safe requests only), `connection_migration: true`
(exclusive sessions only) and `websocket_over_http3: true`. `webtransport` stays
`false` until a draft-17 peer can verify it. Raw `Quic.capabilities().http3`
remains `false`.

Fetch and EventSource select this runtime explicitly with
`http_version: :http3`. HTTPS and verified peer identity are required; there is
no protocol fallback. See the [Fetch contract](../../docs/http3-fetch-contract.md)
for bodies, deadlines, cancellation, redirects, trailers and telemetry.

Beta capability reporting does not establish complete protocol conformance,
production readiness or publication. Independent peer, artifact, load and canary
results are tracked separately in the
[implementation audit](../../docs/http3-implementation-audit.md) and
[acceptance record](../../docs/http3-wp5-acceptance.md); final acceptance remains
subject to those gates.
