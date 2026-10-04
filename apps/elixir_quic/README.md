# elixir_quic — experimental QUIC v1 library

[![GitHub Release](https://img.shields.io/github/v/release/gsmlg-dev/http_fetch)](https://github.com/gsmlg-dev/http_fetch/releases)
[![Hex.pm](https://img.shields.io/hexpm/v/elixir_quic.svg)](https://hex.pm/packages/elixir_quic)
[![CI](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml)
[![Test](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml)
[![Release](https://github.com/gsmlg-dev/http_fetch/actions/workflows/release.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/release.yml)
[![E2E](https://github.com/gsmlg-dev/http_fetch/actions/workflows/e2e.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/e2e.yml)

This app is imported into the `http_fetch` umbrella from `gsmlg-dev/ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6`. Its current shared version is `0.16.1`, and the package requires the sibling `ex_ssl == 0.16.1`. The imported TLS source came from `gsmlg-dev/ex_ssl@fb47051355c9d0a29caee046fa060a745ad0ce5b`; historical package comparison remains recorded in the [TLS contract](../../docs/quic/ex-ssl-quic-contract.md). Independent certificate handshakes, Retry, single-fault packet impairment and certificate/ALPN rejection passed in the source repository against aioquic 1.2.0. Full protocol lifecycle and product acceptance remain incomplete. See the [Phase 1 acceptance record](../../docs/quic/phase1-acceptance.md) for source evidence and limitations.

The project has three mandatory goals: JA3/JA4 observation of visible QUIC ClientHello data, measured profile-controlled client behavior, and opt-in integration with the Abyss UDP server. It is not a client-only plan.

## Start here

Use [CODEX-START.md](../../docs/quic/CODEX-START.md) for the imported historical plan. The first execution slice implements M0–M1: engineering/dependency contracts, wire codecs and Initial/Retry protection with tests. It does not claim that UDP networking is complete.

| Document | Purpose |
|---|---|
| [Phase 1 plan](../../docs/quic/phase1-implement-plan.md) / [Consumer API](../../docs/quic/consumer-contract.md) / [I/O contract](../../docs/quic/io-contract.md) | Reliable streams, public handles, admission outcomes and integration ownership |
| [Implementation plan](../../docs/quic/implement-plan.md) | Ordered M0–M6 tasks, dependencies and concrete exit gates |
| [Architecture](../../docs/quic/architecture.md) / [Detailed design](../../docs/quic/design.md) | Functional core, runtime ownership, routing, sending and resource constraints |
| [Actual TLS contract](../../docs/quic/ex-ssl-quic-contract.md) | Existing public SSL.QUIC API, action order and limitations |
| [Fingerprint design](../../docs/quic/fingerprint-design.md) | Observation, matching, simulation and fidelity evidence |
| [Abyss integration](../../docs/quic/abyss-integration.md) | Opt-in pre-handler dispatch and shared-socket lifecycle |
| [Testing](../../docs/quic/testing.md) / [PRD](../../docs/quic/prd.md) | Requirements, independent oracles and experimental release acceptance |
| [ex_ssl review](../../docs/quic/ex-ssl-review.md) | F1 closure and honest scope of current verification |
| [Revision changes](../../docs/quic/revision-3.md) / [Sources](../../docs/quic/sources.md) | Supersession rules and pinned evidence |

## Dependency and status

`SSL.QUIC` and `SSL.Fingerprint` are real upstream APIs at the reviewed pin, not work to invent in ex_quic. The umbrella resolves `ex_ssl` from the local `apps/ex_ssl` sibling; its upstream source pin and historical Hex package comparison are recorded in the [TLS contract](../../docs/quic/ex-ssl-quic-contract.md). See [implementation progress](../../docs/quic/requirements-progress.md) and [runtime evidence](../../docs/quic/m3-runtime.md) and [independent peer evidence](../../docs/quic/m3-interop.md) and [M3-C through M3-E acceptance](../../docs/quic/m3-acceptance.md) for implemented surfaces and remaining gates; design documents also include future modules.

The upstream formatter finding is closed and the inspected supported-runtime compiler/test and TLS-reference jobs pass. Current known upstream limitations, historical macOS TCP integration failures and the absence of a whole-library security audit remain explicit in the review document.

## Adopting this package

The Hex package and OTP application are `elixir_quic` / `:elixir_quic`.
The canonical source repository is `gsmlg-dev/http_fetch`; the public module namespace is `Quic`.
After the shared `0.16.1` release is published, depend on:

```elixir
{:elixir_quic, "== 0.16.1"}
```

Consumers moving from the Git dependency must replace their `:ex_quic`
dependency/application entry with `:elixir_quic`, including application config
or release configuration that names the old app. Rename calls and aliases from
`QUIC` / `QUIC.*` to `Quic` / `Quic.*`; function names and arguments are unchanged.
The unrelated Hex package named `ex_quic` is not this library.

Local tests cover codecs, packet protection, inspection, recovery, and both-role UDP certificate handshakes. These self-connection tests are not independent interoperability or security certification. The full product gate requires observer + measured client profiles + Abyss termination; HTTP/3/QPACK and additional TLS features remain separate work.


## Application ALPN and unreliable datagrams

Profiles accept application ALPN, for example
`Quic.Profile.compile(:ordered, alpn: ["h3"])`; the default remains `ex-quic`.
Negotiating `h3` does not implement HTTP/3 or QPACK. Consumers own those protocols.

RFC 9221 DATAGRAM support is opt-in per endpoint with
`datagram: [max_frame_size: 1200, max_items: 64, max_buffer_bytes: 65_536]`.
Use `Quic.send_datagram/3` and `Quic.read_datagrams/3` with a public connection
handle. DATAGRAM payloads are unreliable, message-oriented, congestion-controlled,
and never retransmitted after loss. See the [consumer contract](../../docs/quic/consumer-contract.md)
for negotiation, size limits, bounded queues and admission semantics.

## Publishing

`elixir_quic` is one of nine packages released together from the `http_fetch` umbrella. See the root release workflow and contributor guidance for validation, dependency order, and publication. HexDocs publication is separate from package publication.

## License

MIT. See [LICENSE](LICENSE). Copied test-only TLS fixtures retain their upstream
Apache-2.0 license in `test/fixtures/tls/LICENSE` and are excluded from the Hex package.
