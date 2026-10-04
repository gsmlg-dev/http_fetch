# TLS and QUIC source migration provenance

This record identifies the TLS, QUIC, and HTTP/3 sources integrated into this
umbrella and the boundary they preserve. It does not claim that the imported
packages have been published or that HTTP/3/WebTransport are enabled.

## Source inventory

| Package | Umbrella path | OTP app / public namespace | Imported source and origin | License |
| --- | --- | --- | --- | --- |
| `ex_ssl` | `apps/ex_ssl` | `:ex_ssl` / `SSL` | `gsmlg-dev/ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6`; historical upstream TLS source `gsmlg-dev/ex_ssl@fb47051355c9d0a29caee046fa060a745ad0ce5b` (`v0.7.2`) | Apache-2.0 |
| `elixir_quic` | `apps/elixir_quic` | `:elixir_quic` / `Quic` | `gsmlg-dev/ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6` | MIT |
| `elixir_quic_http3` | `apps/elixir_quic_http3` | `:elixir_quic_http3` / `QuicHttp3` | `gsmlg-dev/ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6` | MIT |

The destination baseline before these imports is
`http_fetch@e844ce03067fedac82c079f21c47810e671be0bb` (`v0.16.1`). The three
destination app trees correspond to `apps/ex_ssl`, `apps/elixir_quic`, and
`apps/elixir_quic_http3` in the source revision above.

The imported `ex_ssl` source is the reviewed sibling carried by that exact
`ex_quic` tree. `fb470513...` records its earlier standalone upstream origin;
it is historical provenance, not the destination dependency version or a
separate source checkout used by the umbrella. The old ex_ssl 0.7.2 Hex package
and its consumer results remain historical evidence only. The source contracts
and implementation ledgers under [`docs/quic/`](quic/architecture.md) and
`apps/ex_ssl/docs/` describe the current imported behavior. Copied fixtures
retain their upstream license notices and stay outside package archives where
the source manifest excludes them.

## Destination adaptation inventory

All 390 tracked source-app files from the reviewed `ex_quic` revision are
present in this destination. A blob comparison against that revision finds 58
intentional differences in those imported files. Mix manifests carry the
destination version, exact internal Hex identities, portable package file
lists and build configuration; app READMEs describe the destination. The
listed implementation/test files contain destination lint, type-check, and
regression repairs. The complete task diff remains the authority for exact
code changes; these are source-provenance exceptions, not a claim that
imported files are byte-identical.

`apps/ex_ssl` (39):

```text
README.md
e2e/README.md
lib/ssl.ex
lib/ssl/capabilities.ex
lib/ssl/client_hello/materializer.ex
lib/ssl/client_hello/profile.ex
lib/ssl/client_hello/serializer.ex
lib/ssl/client_identity.ex
lib/ssl/connection.ex
lib/ssl/crypto/finished.ex
lib/ssl/crypto/key_schedule.ex
lib/ssl/crypto/signature.ex
lib/ssl/crypto/tls12_key_schedule.ex
lib/ssl/crypto/traffic_state.ex
lib/ssl/diagnostics.ex
lib/ssl/options.ex
lib/ssl/pkix/pkix.ex
lib/ssl/protocol/client_offer.ex
lib/ssl/protocol/handshake_core.ex
lib/ssl/protocol/handshake_machine.ex
lib/ssl/protocol/inner_plaintext.ex
lib/ssl/protocol/resumption.ex
lib/ssl/protocol/server_flight.ex
lib/ssl/protocol/server_handshake.ex
lib/ssl/protocol/server_hello.ex
lib/ssl/protocol/tls12.ex
lib/ssl/protocol/tls12_codec.ex
lib/ssl/protocol/transcript.ex
lib/ssl/quic.ex
lib/ssl/quic/config.ex
lib/ssl/session_ticket.ex
lib/ssl/socket.ex
lib/ssl/ticket_cache.ex
mix.exs
test/ssl/fingerprint_test.exs
test/ssl/input_ordering_regression_test.exs
test/support/compatibility.ex
test/support/local_tls_peer.ex
test/support/openssl_peer.ex
```

`apps/elixir_quic` (18):

```text
README.md
lib/quic.ex
lib/quic/codec.ex
lib/quic/congestion/new_reno.ex
lib/quic/connection.ex
lib/quic/crypto_reassembly.ex
lib/quic/endpoint.ex
lib/quic/handshake_scheduler.ex
lib/quic/inspector.ex
lib/quic/io/endpoint.ex
lib/quic/protection.ex
lib/quic/recovery.ex
lib/quic/runtime.ex
lib/quic/streams.ex
lib/quic/transport_parameters.ex
mix.exs
test/quic/phase1_io_tls_test.exs
test/quic/retry_test.exs
```

`apps/elixir_quic_http3` (1):

```text
mix.exs
```

Two destination-only files supplement the 390 tracked imports: the new
`apps/ex_ssl/test/ssl/local_tls_peer_test.exs` regression test and
`apps/elixir_quic_http3/README.md` destination package documentation.

The round-four `Quic.Streams` change and round-five test-support contract
changes are all included in the imported-source comparison: 58 changed files
across all three apps, with no additional source files. The root
`.dialyzer_ignore.exs` adds one narrowly anchored exception for
`Quic.Streams.new/2` at `lib/quic/streams.ex:90`, where the declared
`MapSet.t()` field type meets Elixir's compiled literal opacity issue
([elixir-lang/elixir#15673](https://github.com/elixir-lang/elixir/issues/15673)).
Round four removed the separate unreachable private `valid_final_send/3`
guard, without adding an ignore for it.

The Caddy harness README names both destination CI workflows and retains its
explicit local Docker restriction.

## Package identities and dependency graph

The canonical umbrella contains nine packages. Internal dependency declarations
preserve the Hex package identities while Mix resolves the local sibling:

```elixir
{:dependency, "== 0.16.1", in_umbrella: true, hex: :dependency}
```

The graph is:

| Package | Internal runtime dependencies |
| --- | --- |
| `ex_ssl` | none |
| `elixir_quic` | `ex_ssl` |
| `http_core` | `ex_ssl`, `elixir_quic` |
| `http_runtime` | `http_core` |
| `elixir_quic_http3` | `http_core`, `elixir_quic` |
| `http_fetch`, `http_event_source`, `http_web_socket` | `http_core`, `http_runtime` |
| `http_web_transport` | `http_core` |

These `0.16.1` constraints describe the local candidate graph. Six packages
(`http_core`, `http_runtime`, Fetch, WebSocket, EventSource, and WebTransport)
were already published at 0.16.1 before this migration and cannot be republished
with new dependency metadata. The new TLS, QUIC, and HTTP/3 packages at this
version have not been published. Issue [#16](https://github.com/gsmlg-dev/http_fetch/issues/16)
remains open for the coordinated release work; a later authorized version is
required before the complete graph can be consumed from Hex. Do not describe
the local umbrella metadata as an available nine-package Hex release.

## Preserved boundaries

- `ex_ssl` implements TLS through its own `SSL` engine and OTP cryptographic
  primitives. Production TLS handshakes do not fall back to OTP `:ssl`; TCP
  `:ssl` remains the existing default backend in `http_core`.
- TLS parsing and handshake inputs remain bounded. The QUIC integration uses
  public `SSL.QUIC` and `SSL.Fingerprint` APIs, preserves TLS action order, and
  does not copy private TLS orchestration or PKIX internals.
- `elixir_quic` owns QUIC transport state and public `Quic` APIs. It does not
  imply HTTP/3 from negotiated ALPN, use a fake/native fallback, or own HTTP/3
  framing.
- `elixir_quic_http3` owns the separate HTTP/3 application boundary. Its
  current capabilities report `http3: false`, `qpack: false`, and
  `webtransport: false`. Fetch HTTP/3 and WebTransport production selectors
  remain explicitly unsupported.

See [the consumer contracts](ex-ssl-consumer-contract.md) for TLS call
constraints, [the QUIC consumer contract](ex-quic-consumer-contract.md) for
ownership and current selectors, and [migration validation](migration-validation.md)
for executed versus pending evidence.

## Standalone repository retirement guidance

This source consolidation does not authorize deleting, archiving, or changing
the standalone `ex_ssl` or `ex_quic` repositories. Consider redirects or
deprecation automation only after a coordinated release of all nine packages
and successful published-consumer evidence. Before any future retirement,
coordinate downstream maintainers, retain repository history and tags, and
preserve licensed fixtures and their provenance. Until those conditions are
met, keep standalone repositories and their histories intact.
