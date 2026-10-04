# Phase 1 acceptance record

Date: 2026-09-28. **Q-01 through Q-06 and G-T: PASS for the scoped experimental
transport subset.** The publication follow-up also corrects the pre-existing
formatting-only issue in `lib/quic/inspector.ex`; repository-wide and script
formatting now pass. This is not full QUIC
conformance, a production security audit, or completed HTTP/3 migration.

## Candidate and environment

Repository: `gsmlg-dev/ex_quic`, branch `main`. Review baseline and the HEAD at the
implementation acceptance checkpoint were
`51e2dd72837fe15a23c1880bddd985096d221f49`. There were no tracked
initial differences. Initially untracked `02-ex_quic-plan.md` and
`02-ex_quic-prompt.md` were not edited by this task; the latter was absent in the
implementation inventory and was not deleted by this task. The initial acceptance
checkpoint left fixes uncommitted. The user subsequently authorized worktree
integration, committing and pushing; no additional `.trees/` worktrees existed.
The original `02-ex_quic-plan.md` remains outside these commits. Other repositories
were read-only; no tags or package releases are part of this publication.

Runtime: Elixir 1.18.5, Erlang/OTP 28.5.0.5, ERTS 16.4.0.5, Linux. Final ExUnit
seed: `28092026`. Independent peer: `aioquic==1.2.0`, run with Python 3.12 through
`uv`. The initial test attempt lacked fetched dependencies. An early 153-test /
7-failure run overlapped new regressions and is not a pristine baseline result.

## Verified dependency

`mix.exs` and `mix.lock` pin the actual G-S implementation:
`gsmlg-dev/ex_ssl@f1327e0bb7fb2093b8dc2b07e72b26233a739963`. The source and upstream
`docs/phase1-acceptance.md` were inspected; that record identifies this immutable
commit as G-S PASS. The runtime delta from review baseline
`02eb981f59d4e182d4473e264a9f8b093ec6bf3d` includes stricter IP reference-identity
validation. No guessed future tag or replacement TLS implementation is used.

Removed `runtime: false`. A fresh production release includes and normally starts
`:ex_ssl` and `:public_key`; `SSL.QUIC` is available and OTP `:ssl` is not running.
The release was started as a daemon, checked with RPC, then stopped successfully.
An initial relative `MIX_BUILD_PATH` attempt failed because dependency build paths
resolved differently; the successful clean check used an absolute new build path.
An initial `eval` invocation did not start release applications; the final check
uses actual release startup and RPC rather than treating that invocation as a
startup pass.

## Sub-gate decisions

| Gate | Status | Actual changes and evidence |
| --- | --- | --- |
| Q-01 streams | PASS | Correct initiator/direction bits (uni bit 0x02), monotonic class allocation, bounded sparse implicit opening, existing-stream preservation at limits, overlap/reordering/delivered-prefix handling, unique FIN/reset and final-size validation. Corrected the old uni=4 expectation. Stream regressions plus 100 seeded property trials over all role/direction classes pass. |
| Q-02 parameters/credit | PASS | Authenticated peer parameters installed into runtime; zero/default and directional windows preserved; highest-offset/reset accounting separated from delivery/consumption. Coalesced recoverable MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS, sustainable record/memory budgets, peer packet/ACK/idle parameters and send resumption verified. Independent transfers use 16 KiB connection/stream windows. |
| Q-03 packetization/recovery | PASS | 16 KiB writes split using protected size, new PNs for retries, final-range FIN, stable blocked/error shapes, partial scheduling rollback without PN reuse, duplicate receipt and ACK-before-receipt handling. Lost payload transfers to retained pending work before history pruning; a full two-record history test makes progress through 12 STREAM/control retry cycles. ACKs reclaim data and suppress equivalent retries. |
| Q-04 consumer/lifecycle | PASS | Public endpoint and generation handles; accept/ready/attach/info; bounded pull events and small reads; send/receive half-close, reset/STOP_SENDING, opaque application close. Ref/deadline/result caches cover connect/accept/open/send/read/events/reset/stop/close. Tests cover expired admission, already-admitted timeout, exact timed-out read recovery, process failure, consumer death, stale handles and route cleanup. ACK/credit events signal writable capacity. |
| Q-05 I/O/TLS | PASS | Retry uses the injected writer, including socket=nil endpoints; application CRYPTO enters bounded reassembly and public SSL.QUIC; unequal local/peer CID lengths decrypt correctly. Real independent server emits an 89-byte valid NewSessionTicket flight, accepted by the ex_quic client while transfers continue. G-S pin and clean release startup verified. |
| Q-06 independent acceptance | PASS | Both standalone roles and external server capability pass with the pinned peer, dedicated `phase1-streams` ALPN, integrity-checked concurrent streams, 2 MiB received application payload per arrangement, small windows/reads, seeded two-way impairment, admitted-stream cancellation, finite deadlines, measured resources and cleanup. Negative/Retry matrix passes in both roles. |
| G-T | PASS | Scoped reliable-stream transport acceptance, standalone plus fake/injected external sender; does not wait for Abyss. G-A/G-P1 remain separate and NOT RUN here. |

Focused regression-first checkpoints were run independently before the final
suite: initial streams (27 passing), expanded credit checks, runtime parameters
(12), initial combined packetization (55), ACK-before-receipt (12), and consumer
lifecycle (60). Later targeted regressions exposed durable-call process exits,
missing ACK-driven writable events, retained loss history at capacity and
transient I/O peak accounting. The initial Q-05 regression run failed four tests
before implementation; its integrated codec/TLS/external-I/O check then passed 21.
Some supplementary limit/authorization/diagnostic assertions were added after the
implementation; they are not presented as red-before-fix evidence.

The first publication rerun exposed a lifecycle-test race: `:quic_closed` is sent
from termination before the process necessarily exits. The test now explicitly
awaits its process-monitor `:DOWN` before checking that the process is gone,
retaining the cleanup assertion and finite deadline. No runtime behavior or
assertion was weakened, and no retry was used to hide the failure.


## Final commands and results

All commands ran at the repository root. Successful commands below exit 0.
Local disposable logs are under `/tmp/ex-quic-*`; compact network results are
preserved in [phase1-evidence](phase1-evidence/).

| Check | Command / result | Status |
| --- | --- | --- |
| Dependencies | `mix deps.get`; resolved exact G-S SHA above | PASS |
| Source and script format | `mix format --check-formatted` plus `mix format --check-formatted scripts/phase1/interop.exs scripts/phase1/release_check.exs` | PASS |
| Whole-repository format | Initial check exited 1 on pre-existing `lib/quic/inspector.ex:33`; formatting-only correction made during publication follow-up; final check exits 0 | PASS |
| Strict compilation | `mix compile --warnings-as-errors`; exit 0 | PASS |
| Unit/property/integration | `mix test --seed 28092026`; **206 tests, 0 failures**; rerun successfully during publication follow-up | PASS |
| Python syntax | `compile(open("scripts/phase1/peer.py").read(), "scripts/phase1/peer.py", "exec")`; no code execution or bytecode artifact | PASS |
| Independent client | `PHASE1_INTEROP_RUN=1 PHASE1_SCENARIO=impaired mix run scripts/phase1/interop.exs client` | PASS |
| Independent server | Same command with `server` | PASS |
| External server | `PHASE1_INTEROP_RUN=1 PHASE1_EXTERNAL=1 PHASE1_SCENARIO=impaired mix run scripts/phase1/interop.exs server` | PASS |
| CA/identity/ALPN/Retry controls | `INTEROP_SCENARIO=<scenario> mix run scripts/interop/run.exs <role> /tmp/ex-quic-phase1-<role>-<scenario>` for `wrong_ca`, `wrong_hostname`, `wrong_alpn`, `retry`, each in `client` and `server`; **8/8 exit 0** | PASS |
| Clean release build | `MIX_ENV=prod MIX_BUILD_PATH=/home/gao/Workspace/gsmlg-dev/ex_quic/_build/phase1-final-release-clean mix release --path /home/gao/Workspace/gsmlg-dev/ex_quic/_build/phase1-release --overwrite` | PASS |
| Release startup | `_build/phase1-release/bin/ex_quic daemon`; then `rpc 'Code.eval_file("/home/gao/Workspace/gsmlg-dev/ex_quic/scripts/phase1/release_check.exs")'`; `RELEASE_PASS`; then `stop`; all exit 0 | PASS |
| Whitespace integrity | `git diff --check` | PASS |
| Real Abyss shared-socket G-A/G-P1 | Other repository implementation/acceptance intentionally outside this task | NOT RUN |
| HTTP/3 migration / production security audit / full conformance | Outside agreed subset | NOT RUN |

## Independent workload and finite limits

Each endpoint opens four bidi streams carrying 256 KiB each in 16 KiB calls,
plus three uni streams. Both initiator roles are exercised in each arrangement.
Payload words encode stream ID and position, so order is checked as well as byte
count and FIN. Peer SHA-256 results and exact Elixir comparisons independently
verify payload integrity. Echo occurs only on the opposite initiator's bidi
streams; no unidirectional echo is attempted. Local bidi FIN is held until all
four have started. The three uni payloads remain open until the opposite peer's
three prefixes arrive, then FIN-only frames close them together. A fifth bidi
stream admits data and is reset while the other four continue.

The test uses 16,384-byte connection and stream windows, 1,024-byte reads with a
5 ms loop delay, and a 15-second transfer deadline. No window/MTU enlargement or
unbounded retries is used. Only definite `:blocked` admissions are retried;
unknown outcomes abort this network check and are exercised separately by runtime
tests. A seeded impairment wrapper drops, duplicates and reorders one large
protected application datagram in **each direction** (two of each action per
arrangement). Held reordering has a finite 500 ms deadline; timeout disqualifies
the run. It does not claim statistical loss-rate stress or exhaustive fault
schedules.

The external fixture owns its UDP socket and receive pump. Its injected sender
counts and forwards actual datagrams; ex_quic owns no socket in this mode.
Separate fake-sender tests cover Retry and invalid/failed local completions.
After close, the connection monitor fires, active CID routes are zero, endpoints
stop, and the external fixture closes its socket/pump. Connection-owned queues,
caches, stream/recovery records and monitors disappear with the process. Bounded
endpoint operation/retired-CID caches can remain until endpoint shutdown; they
are not falsely reported as zero immediately after connection close.

## Resource results

The following final-run figures are populated from the preserved JSON evidence.
Runtime counters observe mutations, including transient one-item I/O queue and
in-flight receipt states. Mailboxes are sampled at runtime/harness observation
points; these are not a VM-wide continuous profiler. Encoded operation-result
bytes are not total heap memory. The Python peer's older `highwater` field counts
cumulative received bytes, not retained memory; it is not used as a memory bound.

| Metric | ex_quic client | ex_quic server | external server |
| --- | ---: | ---: | ---: |
| Transfer duration (ms) | 7484 | 7245 | 6739 |
| Unread bytes | 16384 | 16384 | 16384 |
| Out-of-order retained bytes | 2301 | 1167 | 1167 |
| Queued STREAM bytes | 52084 | 37289 | 38607 |
| Pending datagrams | 18 | 13 | 13 |
| I/O queue entries / in-flight sends | 1 / 1 | 1 / 1 | 1 / 1 |
| I/O queued bytes | 1350 | 1350 | 1350 |
| Recovery records | 4096 | 4096 | 4096 |
| Stream records | 16 | 16 | 16 |
| Events | 19 | 18 | 18 |
| Operation results | 256 | 256 | 256 |
| Encoded operation-result bytes | 131107 | 126866 | 130747 |
| Tracked references | 261 | 261 | 261 |
| Runtime mailbox sample | 1 | 1 | 1 |
| Consumer mailbox sample | 10 | 1 | 1 |
| Accepted application CRYPTO bytes | 89 | 0 | 0 |
| Active routes after close | 0 | 0 | 0 |

Evidence: [client](phase1-evidence/client-final.json), [server](phase1-evidence/server-final.json), [external](phase1-evidence/external-final.json).
External callback: 9094 successful sends, 2414101 bytes; fixture cleanup passed. All three connection cleanup monitors completed.


## Handoff and remaining boundaries

Public entry points are `Quic.listen/1`, `client/1`, `local/1`, `connect/3`,
`accept/2`, `attach/3`, `ready/1`, `info/1`, `events/3`, `open_stream/3`,
`send_stream/4`, `read/3`, `reset_stream/3`, `stop_stream/3`, `close/4`,
`operation_status/2`, and `capabilities/0`, including documented default arities.
See [consumer-contract.md](consumer-contract.md), [io-contract.md](io-contract.md)
and [phase1-implement-plan.md](phase1-implement-plan.md).

Abyss can own listener I/O and attach independent application consumers using
these contracts. ALPN is negotiated metadata. DNS/DoQ and server HTTP/3/QPACK
belong to their application servers. No Abyss or http_fetch changes were made;
http_fetch client adapter/dependency preparation and subsequent HTTP/3 sessions
remain downstream work.

Terminal stream records are bounded tombstones (default 1024 records). Further
opening can exhaust a connection's lifetime record budget; MAX_STREAMS grants
respect that policy. The latest 256 operation results are retained by default;
eviction or process death yields an unresolved/unknown outcome and never licenses
a blind retry. Attach timeout can follow an attachment; retrying attachment to
the same consumer is idempotent with respect to ownership. Local consumers must
serialize requests through bounded work queues; arbitrary local callers can
otherwise fill ordinary BEAM mailboxes. No per-write peer-delivery receipt is
exposed. Pruned old loss records accept late ACKs as no-ops while retained logical
payload continues safely. Migration, resumption/0-RTT, QUIC DATAGRAM, HTTP/3,
QPACK and WebTransport are unsupported. The experimental subset and these
finite-lifetime policies must remain explicit in downstream products.

## Cumulative ACK correction — issue #2 (2026-09-28)

The v0.2.0 recovery implementation rejected valid cumulative ACK ranges wider
than 4,096 packet numbers. This imposed a connection-lifetime limit even when
all earlier packet records had already been acknowledged and pruned.

Recovery now checks range membership only for retained packet records. Work is
bounded by `max_sent_packets` and `max_ack_ranges`, independent of numeric range
width. The obsolete `max_ack_span` field/option is removed. Never-issued packet
numbers still fail before ACK processing; retained pending receipts, late ACKs
for lost packets, descending RTT sample selection and congestion accounting keep
their existing behavior.

Validation used Elixir 1.18.5 / OTP 28.5.0.5 (ERTS 16.4.0.5), the unchanged
`ex_ssl` pin above, and seed `28092026` in `.trees/issue-2`:

- Baseline: `mix deps.get` and `mix test test/quic/recovery_test.exs --seed 28092026`
  exited 0; 16 tests passed.
- Before the fix: recovery regressions exited 2 (20 tests, 3 failures), and the
  scheduler regression exited 2 (5 tests, 1 failure), all on the expected
  `:invalid_ack_ranges` rejection.
- After the fix: both focused files passed together (25 tests, exit 0).
  Coverage includes the default 4,098-packet history boundary, a 4,100-packet
  STREAM sequence with a four-record bound, a sparse range reaching `2^62 - 1`,
  delayed local receipts, late loss acknowledgments and invalid/range-count bounds.
- `MIX_ENV=test mix compile --warnings-as-errors`, both repository/script format
  checks, `mix test --seed 28092026` (211 tests, 0 failures), `git diff --check`,
  and `git diff --exit-code -- mix.lock` all exited 0.

The downstream http_fetch/Abyss joint workload remains a separate retest after
updating its immutable ex_quic revision. These deterministic regressions do not
claim that downstream G-P1 has passed or establish unrestricted lifetime readiness.

Independent pinned `aioquic==1.2.0` Phase 1 impaired-stream checks also passed
(exit 0) for client, server and external-server arrangements:
`PHASE1_INTEROP_RUN=1 PHASE1_SCENARIO=impaired mix run scripts/phase1/interop.exs <role>`
with `PHASE1_EXTERNAL=1` for the external server. Each reported payload integrity,
cleanup and zero remaining CID routes. These are the existing ex_quic fixtures,
not the downstream joint reproduction.

## Hex publication migration (2026-09-29)

The OTP application and Hex package are now `elixir_quic` / `:elixir_quic`;
the public namespace is renamed from `QUIC` / `QUIC.*` to `Quic` / `Quic.*`.
Function names and arguments are unchanged; consumers must update their aliases
and module references. The unused `ExQuic` placeholder module is removed.
The repository remains `gsmlg-dev/ex_quic`. The project is MIT licensed;
repository-owned test credentials retain their upstream Apache-2.0 attribution
and are excluded from the package. Existing source-only release tags are unchanged.

The exact Hex dependency `ex_ssl 0.7.2` replaces the G-S Git dependency. All 58
packaged production files matched the accepted source byte-for-byte; the package
checksum and source revision are recorded in `ex-ssl-quic-contract.md`. Tests and
interop scripts use attributed local test credentials, since Hex excludes the
upstream test directory.

Elixir 1.18.5 / OTP 28.5.0.5, seed `28092026`: strict compilation, formatting,
`mix test --seed 28092026` (211 tests), `mix hex.build`, package unpacking, YAML
and workflow shell syntax validation, and `git diff --check` passed. The renamed
production release started, passed `scripts/phase1/release_check.exs` through RPC,
and stopped. An initial immediate RPC preceded daemon readiness and returned
`:noconnection`; the RPC succeeded once the daemon was available. Three existing
impaired aioquic arrangements passed with the Hex dependency and local fixtures.
An earlier separate fixture-focused run observed the existing metrics-test race
(event count 1 after draining rather than 0); no assertion or runtime behavior
was changed to hide it. The complete final suite passed.

Local `mix hex.publish package --dry-run --yes` requested authentication and
exited without publishing; package validation uses `mix hex.build` instead.
Actual publication runs only in GitHub Actions. The workflow pushes verified
source/tag before Hex publication and supports retrying the same version, checking
an existing package's checksum before treating it as already published.

An isolated consumer of the unpacked package resolved `ex_ssl 0.7.2` from Hex,
compiled with warnings as errors, and started a real production release with
`:elixir_quic`, `:ex_ssl` and `:public_key`, without OTP `:ssl`. The public `Quic`
module and release check passed; the daemon was stopped afterward. This uses a
clean release rather than a Mix process, since Mix/Hex itself can start OTP `:ssl`.

After the explicit `Quic` namespace rename, strict compilation, formatting and
all 211 tests passed again (seed `28092026`). The package was rebuilt and unpacked
from renamed source. Existing impaired client/server/external-server network
checks all passed with cleanup and zero retained routes. No compatibility aliases
with Ex/Elixir prefixes or the old all-uppercase module namespace are shipped.

The first Hex-release run (`36512082713`) reproduced the metrics-test race and
stopped before tag creation or publication. The test now waits for the actual
seven-byte stream payload, suspends the ingress endpoint as a synchronous routing
barrier, drains the bounded event queue and reads metrics directly from the
connection before resuming ingress in `after`. The empty-queue and historical
high-water assertions remain in place; no runtime code or assertion was weakened.
The focused test and complete 211-test suite pass with seed `28092026`.
