# HTTP/2 production validation

**Production contract: NOT MET. Work stopped under AGENTS scope policy.**
The final full-suite attempt found two failures in the unchanged, out-of-scope
`HTTP.OwnerMonitorTest` (100 ms `:watching` assertions). No fix or retry of those
tests was attempted. The upload-admission cleanup fix is committed;
its focused tests and Dialyzer passed. The previous soak was stopped as obsolete
intermediate evidence; a full soak on the final source has **NOT RUN**.
Required root format/Credo checks also fail in unchanged HTTP/3 files.
The user subsequently authorized committing, merging to main and pushing.
This integration authorization does not establish production readiness; no
package release or deployment is included.

## Candidate and environment

- Current source candidate: `93b36e0bc3f990ac361a53c9091a52367428a702`.
- Earlier independent acceptance candidate: `2b462399a7611807eebd63331677044b0ba286c6`.
  Its results below are intermediate evidence, not acceptance of the current tree.
- Review baseline: `a2c508a48812556d43c85ba89654df3200e1551c`.
- Implementation baseline: `d095739c3310601c27252afe76255674906d6c78`.
- Implementation branch: `codex/http2-production`; integration target: `main`.
- Elixir 1.18.5; Erlang OTP 28 / ERTS 16.4.0.5.
- Linux 6.18.48 x86_64, glibc 2.42; Intel Core i5-9300H, 4 cores / 8 logical CPUs.
- Independent peers: Python hyper-h2 4.2.0, hpack 4.1.0, hyperframe 6.1.0;
  Node 24.19.0 with nghttp2 1.69.0.
- Seeded credit model: `{9113, 7541, 2026}`; independent workloads: seed 0.
- Acceptance runs share this host with other validation processes. Durations
  below are observed acceptance runtimes, not isolated throughput benchmarks.

Commands use `MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build`
unless noted. Default `_build` had stale http_core 0.11.0 metadata. A clean build
path resolved dependency preparation without changing source or the lockfile.

The plan/review files predated this work as user-owned untracked files and are
preserved. Protocol/runtime changes were committed in dependency groups: pure
core (`4f11419`), owner/flow/pool/fetch integration (`f00ad4f`), activation and
observability (`32fe273`), independent gates (`e0af3aa`), deterministic reset
barrier (`1b6449f`), and complete-response TCP close handling (`2b46239`).
P2–P5 runtime changes are grouped because the shared owner, consumption ACKs,
pool reservations, and public route migration depend on each other.

## Public configurations and contracts

Ordinary explicit `http_version: :http2` and h2c prior knowledge use the same
supervised ConnectionOwner as explicit wire profiles. HTTPS `:auto` uses it when
h2 is negotiated; existing strict-profile negotiation checks remain. The overall
default remains HTTP/1. TLS backends remain OTP `:ssl` and explicit `:ex_ssl`,
without backend fallback. No h2c Upgrade, proxy, CONNECT, push, HTTP/3 expansion,
or ex_ssl modification was added.

Pool identities retain origin, TLS, profile and caller scope separation. Opaque
TLS options, including structs, conservatively disable reuse. Owners are temporary
children of a dedicated supervisor, independent of the initiating request.
Automatic request replay is not implemented: ambiguous POSTs and consumed
producers are never silently retried.

Wire-profile revision 2 explicitly advertises ENABLE_PUSH=0. All three IDs
(`native_v1`, `synthetic_test_v1`, `synthetic_test_v2`) have cold/warm public-wire
coverage. Synthetic profiles do not claim browser fingerprint equivalence.
See `HTTP2_FINGERPRINTS.md` for the migration details.

## Finding-to-regression evidence

Paths below are relative to the repository. Test basenames live under
`apps/http_core/test/http/` or `apps/http_fetch/test/http/` as indicated.

| Finding / phase | Implementation | Executed regression and acceptance evidence |
|---|---|---|
| H2-01 / P1,P4 | core `http2/connection.ex`, owner stream release | core `http2_production_core_test.exs`, `http2_credit_invariant_test.exs`; public reuse gate at peer limits 1/2/100. Runtime and protocol maps are both measured. |
| H2-02 / P1,P3 | core prefix scheduler; owner fair drains; `body_bridge.ex` | `http2_production_flow_test.exs`, `http2_body_bridge_test.exs`, `http2_runtime_test.exs`; exact independent 10 MiB binary/streamed uploads with 1/16/64 KiB source chunks. |
| H2-03 / P1,P2 | separate peer send allowance and local receive accounting | core production tests, owner boundary tests, and seeded credit-conservation test with 10,000 interleaved receive/ACK operations. |
| H2-04 / P3 | consumption ACKs, finite owner admission, monitored delivery worker | `http2_slow_consumer_test.exs`; independent 100-request barrier with one paused 6 MiB stream and 99 completing siblings. |
| H2-05 / P1,P2 | `boundary.ex`, SETTINGS/owner dispatch, no-push policy | `http2_protocol_boundary_test.exs`, `http2_production_boundary_test.exs`; PING, reset, GOAWAY, continuation lock, padding/priority, frame limits, server ENABLE_PUSH=1 rejection. |
| H2-06 / P1,P5 | `stream_state.ex`, socket response phases, `stream.ex` | core response semantics, fetch production semantics/lifecycle, and stream tests: informational/final/trailer phases, CL/body rules, redirects, returned-stream errors. |
| H2-07 / P2,P5 | staged batch validation, terminal flags, bounded close drain, original deadlines | production lifecycle/boundary tests; 43 socket HTTP2 tests; actual blocked-writer and activation tests. TCP and OTP TLS peer-close tests also each passed 51 consecutive runs. |
| H2-08 / P4 | connection supervisor; caller/connector/subscriber monitors; bounded pool | production pool, route, pool-key and pool telemetry tests. Covers deadlines, cancellation, abandoned claims, owner death, capacity and opaque TLS structs. |
| H2-09 / P1 | connection-wide HPACK, ACK-sensitive decoder limits, bounded decode | core HPACK/settings production tests; independent hpack 4.1.0 shrink/grow/shared-state gate; fatal ambiguous header-write regression. |
| H2-10 / P5 | profile validation, order once, common public runtime | `http2_profile_wire_test.exs` checks every named profile on stream IDs 1 and 3: exact SETTINGS, raw header-name order, priority frames/header; route and profile-key tests. |

Actual early red evidence was retained, including owner boundary 5/5 failures
(`/tmp/http2-owner-red.log`), pure boundary 5/5 failures
(`/tmp/http2-boundary-red.log`), and public upload 1/2 failures
(`/tmp/http2-flow-red.log`). Later regressions reproduced activation failure,
opaque TLS struct pooling crashes, and peer-close races before their fixes.
No test was removed to conceal those failures. The returned-stream reset fixture
now explicitly waits for response delivery before sending reset, avoiding a race
that could legally reject the promise before any response had been returned.

Large ex_ssl fixture preparation uses explicit TCP_NODELAY to avoid hundreds of
serialized delayed-ACK round trips; request deadlines were not expanded.

## Latest verification and mandatory stop

- `mix test`: **FAIL**, 661 tests and 20 doctests, two failures, three gated QUIC
  skips. `/tmp/http2-final-tests.log`. Failures are
  `apps/http_core/test/http/owner_monitor_test.exs:4` and `:37`, both waiting
  for `{:watching, guardian}` within the existing 100 ms assertion timeout.
  Both test and implementation are unchanged from the implementation baseline.
- Focused failed-open cleanup plus real blocked-writer tests: **PASS**, 3 tests,
  zero failures, `/tmp/http2-final-cleanup.log`. Warm and cold admission failure
  release internal producers and preserve a reusable pooled owner; a required
  send timeout reaps the request tasks.
- `mix dialyzer`: **PASS**, four intentional ignores, no unnecessary ignores;
  `/tmp/http2-final-dialyzer.log`.
- `mix credo --all`: **FAIL**, only the same two excluded HTTP/3 findings;
  `/tmp/http2-final-credo.log` (before removal of an unreachable error branch).
- The full suite preceded the final removal of that unreachable branch. Focused
  tests and Dialyzer ran after it. Final independent
  matrix/reuse/package/30-minute soak acceptance is not claimed.

AGENTS requires stopping on out-of-scope test failures. Those tests were not
modified, and subsequent implementation/acceptance was stopped.

## Integration verification

Before committing the cleanup fix, its two focused test files were rerun:
3 tests, zero failures. Formatting passed for all four changed source/test files.
The required pre-push `mix credo` was rerun and failed only in the same unchanged
HTTP/3 files (`control.ex:230` and `transport/quic.ex:27`), recorded in
`/tmp/http2-prepush-credo.log`. The user-owned plan and review remain untracked
and are not included in these commits.

## Earlier candidate repository checks

| Command | Candidate outcome |
|---|---|
| `mix deps.get --check-locked` with isolated build | PASS |
| `mix compile --warnings-as-errors` | PASS |
| `mix test` | PASS: 658 tests, 20 doctests, 0 failures; 3 explicitly gated QUIC skips. `/tmp/http2-candidate-tests.log` |
| Changed HTTP2 source/test/script `mix format --check-formatted` | PASS |
| Root `mix format --check-formatted` | FAIL: unchanged `apps/elixir_quic_http3/lib/quic_http3/qpack.ex:700`; `/tmp/http2-candidate-format.log` |
| Root `mix credo --all` | FAIL: unchanged HTTP/3 `control.ex:230` single-clause with; `transport/quic.ex:27` redundant with clause. `/tmp/http2-candidate-credo.log` |
| `mix dialyzer` | PASS; four existing intentional ignores retained; `/tmp/http2-candidate-dialyzer.log` |
| `MIX_ENV=dev MIX_BUILD_PATH=/tmp/http-fetch-h2-production-docs mix docs` | PASS with existing documentation warnings; `/tmp/http2-candidate-docs.log` |
| `git diff --check` | PASS |

The three HTTP/3 files above are byte-for-byte unchanged from the implementation
baseline. The objective excludes HTTP/3 expansion and AGENTS requires surgical
scope. They were not edited to manufacture a green repository-wide gate.

## Earlier candidate independent acceptance workloads

The runner prints candidate SHA, tracked-tree dirtiness, peer versions, platform,
seed, actual resource samples and final outcome. The matrix uses a fresh peer and
VM per case. No production codec is used by either independent server.

| Gate | Candidate status |
|---|---|
| Smoke: two peers × h2c / TLS OTP ssl / TLS ex_ssl | PASS |
| 10 MiB binary and 1/16/64 KiB-chunked streaming uploads, plus 10 MiB download, all six peer/transport cases | PASS at `2b46239`; final tree NOT RUN |
| 100 simultaneous requests, differing sizes; one paused 6 MiB response while 99 finish | PASS at `2b46239` on hyper-h2 h2c and Node/nghttp2 TLS ex_ssl; final tree NOT RUN |
| 10,000 sequential requests at peer limits 1/2/100 | PASS at `2b46239`, all three limits; final tree NOT RUN |
| Independent HPACK decoder | PASS; `/tmp/http2-candidate-hpack.log` |
| Fresh consumers of six built packages, TLS OTP ssl and ex_ssl | PASS at `2b46239`, both consumers; final tree NOT RUN |
| 30-minute mixed TLS ex_ssl traffic against Node/nghttp2 | STOPPED intermediate run at `2b46239`; final full soak NOT RUN |

Matrix summary: `/tmp/http2-candidate-matrix-summary.log`. Per-case logs use
`/tmp/http2-candidate-<mode>-<peer>-<h2c|tls>-<backend>[-package].log`.
Reuse logs: `/tmp/http2-candidate-reuse{1,2,100}.log`.

The concurrent peers withhold all responses until 100 distinct requests have
arrived on one connection. The gate verifies their barrier header and body bytes,
holds a streamed response unread, waits for all 99 siblings, measures the paused
owner, then consumes the final stream. This proves overlap and sibling progress;
launching 100 tasks alone is not treated as proof.

The package gate uses `mix hex.build --unpack` for six applications, then creates
a separate consumer with unpacked package paths. It compiles with warnings as
errors and exercises public fetch without an explicit ex_ssl dependency.
It does not publish packages.

Reproduction examples (from repository root):

```sh
MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build \
  /tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py \
  --peer hyper-h2 --mode reuse --limit 1 --count 10000

MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build \
  /tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py \
  --peer node --tls --backend ex_ssl --mode concurrent

MIX_BUILD_PATH=/tmp/http-fetch-h2-production-build \
  /tmp/http2-production-peer-venv/bin/python scripts/http2_interop_gate.py \
  --peer node --tls --backend ex_ssl --mode soak --seconds 1800
```

Use `--mode transfer` for large transfers and `--package` for the external
consumer. Create the Python environment with pinned `h2==4.2.0`, `hpack==4.1.0`,
and `hyperframe==6.1.0`. Peers bind loopback and use existing test certificates.

## Bounds, observations and limits

- Receive admission has a 1 MiB connection budget and at most 128 unconsumed
  deliveries per stream. Stream credit returns only after consumption; connection
  credit may return on admission within the budget so siblings can progress.
- Producer source chunks are capped at 64 KiB and scheduled in at most 16 KiB
  quanta. A caller-supplied binary remains an original request allocation, not a
  claimed receive-buffer bound. HTTP/2 bridge status and telemetry report its
  bounded chunks and lifetime outcomes.
- Writes use a finite one-second send timeout. A real peer with small TCP buffers
  grants 64 MiB credit and stops reading; the request returns a transport timeout
  within five seconds, with owner death and pool removal asserted.
- Writer batch peak measures serialized batches, **not** queued mailbox bytes.
- Connection telemetry exposes active/protocol streams, receive/upload bytes,
  finite close categories, numeric peer error codes and flow-control stalls.
  Pool telemetry exposes aggregate reservations, waiters, connecting/draining
  counts and queue wait. It excludes raw keys, headers, bodies and TLS identities.
- A real paused consumer retained 65,535 wire bytes while its sibling and PING
  progressed. Its gate bounds each observed mailbox to 8 messages, process memory
  to 2 MB and binary references to 1 MiB. Independent 100-request gates also
  observed 65,535 buffered bytes and owner mailbox 0 while the last consumer paused.
- The soak uses 16 concurrent mixed requests per batch. Every quiescent batch
  checks zero pool reservations, runtime/protocol streams, pending upload and
  unconsumed receive bytes; at most one pool key/four owners; owner mailbox <=16,
  heap <=8 MiB and binary references <=2 MiB. Global tolerances are baseline
  +128 MiB BEAM memory and +64 processes. These are explicit acceptance budgets,
  not universal memory or throughput guarantees.

## Remaining blockers

1. Two unchanged, out-of-scope OwnerMonitor tests failed in the full suite.
   Work stopped per the explicit scope policy; the cause has not been established.
2. Upload-cleanup source and tests are committed. Final source acceptance,
   independent matrix/reuse/package gates and the complete soak remain NOT RUN.
3. Repository-wide format and Credo remain FAIL in the unchanged, excluded HTTP/3
   files. HTTP/2 tests passing does not make those required gates green.

The user authorized main-branch integration and remote push after reviewing the
blocked state. No package release or deployment is included. Production readiness
is not claimed while these blocking gates are incomplete or failing.
