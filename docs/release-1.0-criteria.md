# 1.0.0 release criteria

Date: 2026-11-11. Baseline: 1.0.0-rc.13 (`5b1adbd`). Status: **approved 2026-11-11** (verdicts below are
the maintainer's rulings).

## What 1.0.0 promises

1.0.0 freezes the public API of all 14 coordinated packages under semver: no
breaking change to module names, function signatures, option names, return
shapes or documented error reasons before 2.0.

Two support tiers, stated in each package README:

| Tier | Scope | Promise |
| --- | --- | --- |
| Stable | HTTP/1.1 and HTTP/2 for Fetch, EventSource and WebSocket; `ex_ssl` TCP TLS client and server; `http_core`, `http_pool`, `http_runtime` (H1/H2), `http_test`; Abyss TCP/UDP; Hell | Semver; behaviour changes only as bug fixes with a CHANGELOG entry |
| Beta | Everything over QUIC: `elixir_quic`, `elixir_quic_http3`, HTTP/3 in all clients, Alt-Svc discovery, `http3_resumption`/`early_data`, `migrate/2`, WebTransport, Abyss QUIC listener | API kept, but behaviour and capability flags may change in a minor release; gaps are documented, not blocking |

Capability flags stay as they are: `Quic.capabilities().http3` false,
WebTransport `Profile.supported?/0` false until an independent draft-17 peer
exists.

## Known gaps and proposed verdicts

**Blocks 1.0** means it lands in rc.14. **Ship documented** means 1.0 ships
with the gap listed in the package docs.

### Stable tier

| # | Gap | Proposed verdict | Reason |
| --- | --- | --- | --- |
| S1 | Flaky test: ex_ssl TLS lifecycle `:timeout` variant | Blocks 1.0 | Root-cause it: either a real race in a stable-tier deadline or a test bug; no 1.0 with a known flake |
| S2 | Flaky test: OpenSSL peer teardown (`nested_tls_carrier`) | Blocks 1.0 | Same |
| S3 | Fetch accepts unknown option keys silently; `signal:` not validated as a pid | Blocks 1.0 | Rejecting them after 1.0 would be a breaking change; decide now |
| S4 | `HTTP.Response.write_to/2` raises `MatchError` when the file write fails | Blocks 1.0 | Contract is `{:error, reason}` for expected I/O failures |
| S5 | `body_used` is never set on `HTTP.Response` | Blocks 1.0 | Either implement browser semantics or remove the field before the API freezes |
| S6 | `json/1` doc says "deprecated" | Blocks 1.0 | Doc-only; fix wording so the frozen API is described accurately |
| S7 | H2 reused-owner `request_headers` hard match (unverified crash risk) | Blocks 1.0 | Verify with a test; fix if it can crash the socket owner |
| S8 | EventSource `origin/1` with IPv6 hosts untested | Blocks 1.0 | One test; fix if wrong |
| S9 | Public API freeze review for all 14 packages (exported modules, options, error reasons, `@moduledoc false` on internals) | Blocks 1.0 | The point of 1.0; renames are free now and breaking later |
| S10 | README / CLAUDE.md drift (streaming, telemetry, Credo, HTTP/3 bullets) | Blocks 1.0 | Docs must match the frozen API |
| S11 | ex_ssl server mTLS: no CRL/OCSP checking of client certificates | Ship documented | Documented in the ex_ssl consumer contract; a feature, not a defect |
| S12 | ex_ssl: no public-suffix list for wildcard checks | Ship documented | rc.13 rejects `*.tld` (at least two labels after `*`); a PSL is an enhancement |
| S13 | ex_ssl: residual buffered-data-at-unclean-close case left after the #158 fix | Blocks 1.0 (verify) | Sigma's streaming path; pin it with a test, then fix or document |
| S14 | HTTP pool connectors keyed per key; per-DATA-frame Task cost | Ship documented | Performance, not correctness; no API impact |

### Beta tier

| # | Gap | Proposed verdict | Reason |
| --- | --- | --- | --- |
| B1 | QUIC: Version Negotiation not sent or handled | Ship documented | Listed in `docs/quic/consumer-contract.md` "Not implemented" |
| B2 | QUIC: CONNECTION_CLOSE not resent while closing | Ship documented | Listed; peer falls back to idle timeout |
| B3 | QUIC: error handling for a later coalesced packet | Ship documented | Needs a Handshake-key coalescing harness to test |
| B4 | QUIC: RTT sample taken from largest-acked rule | Ship documented | Minor accuracy; no interop failure seen |
| B5 | QUIC: stateless reset, ECN, PMTUD, persistent congestion, pacing, local key update, AEAD limits, NEW_TOKEN issuance, delayed ACKs | Ship documented | All listed with consequences |
| B6 | HTTP/3 client does not send GOAWAY on shutdown | Ship documented | Optional in RFC 9114; connection close is correct |
| B7 | HTTP/3 grease/unknown uni-stream cap of 128 | Ship documented | Bounded; design change deferred |
| B8 | QPACK encoder is static/literal only | Ship documented | Interoperable; compression only |
| B9 | WebTransport: no independent draft-17 peer; IPv6 authority untested | Ship documented | `Profile.supported?/0` stays false |

## Exit conditions for 1.0.0

1. Every "Blocks 1.0" row is fixed with a regression test, or re-ruled.
2. rc.14 is published with those fixes; CI (all six workflows, the release-proof
   gate and the independent HTTP/3 and QUIC gates) is green on it.
3. Downstream consumers (gsmlg-opt/sigma, backplane, Singularity,
   ex_storage_service) compile and pass their suites on the candidate.
4. No new stable-tier bug reported against the final RC for 7 days.
5. 1.0.0 is cut from that RC's commit with no code changes, only the version bump
   and CHANGELOG.
