# ex_ssl / http_fetch readiness

Release authorization update: the user subsequently authorized commit/push and
the **0.5.0** minor release. The validation scope below describes the completed
implementation task before that authorization. No production TLS engine change
or backend default switch is included; human security review remains incomplete.

## Current validation candidate — 2026-09-22

The clean starting checkout matched reviewed baseline
`c93000d01c5321a6606092fb0113d8a56b9975b8`, version 0.4.0. This library-only
validation change preserves protocol engines, public API, mandatory verification,
TLS 1.3 defaults, and disabled-by-default resumption. It does not authorize a
release, tag, merge, dependency promotion, remote workflow dispatch or default switch.

The current work closes the continuous runtime-matrix integration gap and extends
existing deterministic resumption/transport coverage. The
[security review evidence map](SECURITY_REVIEW_EVIDENCE.md) links implementation,
tests, supported peers and limitations. Current executed commands/counts are in
the first section of the [progress ledger](EX_SSL_HTTP_FETCH_PROGRESS.md).

`scripts/downstream_candidate.sh` verifies the immutable consumer revision
`6a6c93e5c852e2e2bbffcc2186bef9bf34a79cac`, exercises its existing source smoke
interface, and verifies standalone package startup. Source-candidate results are
separate from published Hex dependency validation. Historical release results
below must not be mistaken for execution of this candidate's remote CI.

**HUMAN-SECURITY-REVIEW remains incomplete.** Other OS/provider combinations and
long-duration deployment remain unverified. Bounded resource tests do not prove
indefinite stability, security certification, full OTP parity or a speed advantage.
Keep OTP as the default and ex_ssl explicitly opt-in.

## Historical release and implementation snapshot

Release update, 2026-09-22: the user subsequently authorized worktree integration,
commit/push and minor releases. ex_ssl v0.4.0 (`5b0353e`) and http_fetch v0.12.0
(`90a0ca1`) are published on GitHub and Hex; all release workflows succeeded.
The remainder of this document preserves the earlier source-candidate evidence,
including its then-current worktree paths and no-publication scope. Those status
statements are historical. See the [progress ledger](EX_SSL_HTTP_FETCH_PROGRESS.md)
REL-1 through REL-3 for integration failures, corrections, final validation and
publication verification. Human security review remains incomplete; defaults and
compatibility limits remain unchanged.

Date: 2026-09-22. Recommendation: retain explicit opt-in use and the current
OTP backend default. The implementation plan's automated gates have been exercised
locally; independent human security review remains a separate, incomplete gate.
No merge, push, tag, publication, dependency upgrade or default switch occurred.

## Revisions and review scope

Both repositories use `codex/tls-backend-plan` in their own `.trees/tls-backend-plan`.
The ex_ssl implementation starts at remote release baseline `0f16c2c`; http_fetch
starts at PR #14 head `690258a`, which descends from inspection baseline `a1312cc`.
Implementation heads: ex_ssl `18b4f85` (runtime `c2d1d0c`, TLS1.2 `844d4a6`),
http_fetch `381f198`. The original ex_ssl checkout `99c09ec` and existing dirty worktrees were preserved.
The already-correct cross-record closure and early-response upload fixes in PR #14
were verified rather than replaced. See the [ledger](EX_SSL_HTTP_FETCH_PROGRESS.md)
for task IDs, failures, repairs, commands and per-phase commit references, and the
[change manifest](EX_SSL_HTTP_FETCH_CHANGES.md) for changed paths and commits.

## Delivered subset

- P0: deterministic closure/early-response regressions, bounded HTTP/2 frames and
  headers, strict Content-Length and exact response-completion accounting.
- P1: runtime-filtered capabilities; P384 ECDHE/ECDSA, Ed25519 and RSA-PSS-PSS
  with independent vectors, signature/key restrictions and HTTP interoperability.
- P2: bounded, redacted PEM/DER client identity loading, initial TLS client
  authentication, fragmented large identity flights, deterministic cancellation,
  exact peer-observed HTTP/WSS/SSE identities and credential-scoped redirects.
- P3: ordered cipher/group/signature/certificate policies with explicit profile
  conflicts; safe TCP options, local addressing, IPv6 and pre-I/O rejection.
  Advanced certificate callbacks/CRL/OCSP/trust policies have no production consumer
  in the audited contract and remain explicit option errors.
- P4: independent TLS 1.2 ECDHE/EMS/AES-GCM engine, four RSA/ECDSA suites, required
  secure-renegotiation indication, TLS 1.2/mixed opt-in negotiation, initial mTLS,
  transcript/Finished/AEAD/downgrade negatives and existing runtime lifecycle rules.
  Packaged HTTP/1.1, cross-window HTTP/2, WSS and EventSource exchanges pass.
- P5: disabled-by-default TLS 1.3 PSK_DHE resumption, authenticated bounded tickets,
  fresh shares and HRR binders, loaded-policy partitioning, current PKIX revalidation,
  atomic one-use cache, expiry and owned retained bytes; full authentication on
  server decline; bounded diagnostics and independently observed resumed HTTP/1.1.
- P6: fresh five-package source and published-dependency consumers, runtime matrix,
  configured static/E2E checks, reproducible fragmented mutations, repeated cleanup,
  concurrent reconnect batches and measured full/resumed handshake/transfer costs.

All TLS protocol operations use ex_ssl with OTP crypto/public_key primitives.
OTP SSL is used only by reference/test peers and the unchanged selectable OTP
consumer backend. There is no automatic TLS fallback, uncertain-byte replay,
0-RTT, weakened peer verification or modification of installed dependency sources.
HTTP/3 and WebTransport retain their existing QUIC implementation.

## Executed validation

All listed successful commands exited zero. Test exclusions are not counted.

| Gate | Result |
| --- | --- |
| Full ex_ssl, Elixir1.18.5 / OTP28, seed104 | 534 tests +19 properties, zero failures, no exclusions |
| Full ex_ssl, Elixir1.19.6 / OTP28, seed105 | 534 tests +19 properties, zero failures, no exclusions |
| Full ex_ssl, Elixir1.20.4 / OTP29.0.5, seed106 | 534 tests +19 properties, zero failures, no exclusions |
| ex_ssl formatting and dev/test warnings-as-errors compilation | Pass on the configured runtime tuples; no warning suppression |
| ex_ssl dependency graph | 52 modules, zero dependency cycles; compiler/xref checks, no additional analyzer dependency introduced |
| Caddy authenticated JA3/JA4 E2E | Pinned Docker build, deps, strict compile and one test pass; isolated container removed |
| Root-scoped five-app consumer regression, seed62 | 442 tests +20 doctests, zero failures |
| HTTP fetch after final validator style correction, seed99 | 174 tests +20 doctests, zero failures |
| Fresh five-package source consumer, seed36 | 47 tests, zero failures; source override only in temporary consumer |
| Packaged option gate after style correction, seed36 | 9 tests, zero failures |
| Fresh five-package published-dependency consumer | Pass, transitive released ex_ssl0.3.0, no direct ex_ssl declaration or umbrella lockfile |
| Consumer dev/test strict compile, formatting, configured Credo | Pass; Credo54 checks over116 files, no issues |
| Consumer configured Dialyzer | Pass; four existing warnings ignored, zero new warnings, zero unnecessary ignores |
| Consumer configured E2E from umbrella root | fetch50, WebSocket3, EventSource2, WebTransport3:58 tests, zero failures |
| Bounded malformed/fragmented campaign, seed95 | 3 properties ×200 runs +2 fragmentation tests, zero failures |
| Connection resource campaign, seed103 | 2 tests, zero failures:17 sequential full/resumed/failed/dead-owner connections plus warmup and24 connections in three barrier-released batches |

The three full library commands are `MIX_ENV=test mix test --include integration
--seed N`. The additional runtimes use Nix packages
`beam.packages.erlang_28.elixir_1_19` / `erlang_28` and
`beam.packages.erlang_29.elixir_1_20` / `beam.interpreters.erlang_29`, with distinct
`MIX_BUILD_PATH` and `TMPDIR` directories. Use a fresh `mktemp -d` directory for
each matrix process: fixture IDs are unique only within a VM. A shared-temporary-
root refresh produced fixture failures; the same seeds passed with isolation.
Test commands exited zero; a subsequent empty-directory cleanup failed on leftover
Mix/reference-fixture files, which were inspected and removed separately. Consumer tests run from the umbrella root.

Source packages: `EX_SSL_SOURCE_DIR=<ex_ssl-worktree> bash
scripts/ex_ssl_source_smoke.sh`. Published dependency metadata: `bash
scripts/external_consumer_smoke.sh`. The latter intentionally does not prove new
features absent from released ex_ssl0.3.0. Neither harness changes release metadata.

Resource checks prove owned connection/writer death, raw port closure, canceled or
absent pending state, bounded cache size and baseline supervisor children. Live
connection binary/monitor aggregates are sampled inside its sensitive process.
The plain sensitive writer has no sys callback: only aggregate live memory and
subsequent process death are measured, not its externally redacted binary/monitor
lists. Ambient VM process counts and long-duration production behavior are not
certified. Fuzzing is bounded reproducible sampling, not exhaustive protocol proof.

## Measurements and remaining gates

[Benchmark details](RESUMPTION_BENCHMARK.md) record identical local OpenSSL peers,
pinned AES128/X25519/RSA-PSS/ALPN/TCP nodelay, one warmup and five measured samples
per backend/mode, and exact1MiB echoes. Median handshake times (microseconds):
OTP full2874/resumed1568; ex_ssl full2921/resumed2658. These small local samples
show no transfer-speed advantage and do not justify a default change.

Known limitations and unverified work:

- The tested OTP28/OTP29 TLS1.2 reference-server configurations omit EMS and are
  explicitly rejected. Positive TLS1.2 interoperability uses OpenSSL3.6.3.
  CBC, static RSA, finite-field DHE, renegotiation and TLS1.2 resumption are unsupported.
- TLS1.3 auto resumption rejects mTLS, mixed/TLS1.2 version lists, manual tickets,
  persistence and early data. Packaged resumed HTTP1.1 is proven; HTTP2/WSS/SSE
  resumption is not separately exercised by that consumer gate.
- Only documented diagnostics/options and passive/raw/active-once delivery are
  supported. This is not full OTP parity or a whole-library replacement.
- These are local equivalents of configured workflows; remote GitHub Actions
  were not dispatched on the unpushed branches. Other OS/crypto-provider and
  long-duration production deployments remain unverified.
- Next incomplete gate: **HUMAN-SECURITY-REVIEW**, covering both TLS engines,
  resumption authentication/secret lifetime, certificate policies and concurrency.
  Automated tests and agent review do not certify security. Future publication or
  backend promotion requires a separate decision; neither is authorized here.
