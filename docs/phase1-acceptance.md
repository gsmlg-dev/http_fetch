# Phase 1 acceptance and handoff

Date: 2026-09-28. **G-F: PASS for the executed internal adapter subset.**
**Joint http_fetch/Abyss G-P1 item: PASS after upgrading to ex_quic v0.2.1.**
The previous blocker, [ex_quic issue #2](https://github.com/gsmlg-dev/ex_quic/issues/2),
is closed and the unchanged sustained joint workload now succeeds. This is not
completed HTTP/3 replacement, full QUIC conformance or a security certification.
G-F and the joint combination retain separate evidence below.

## Published dependency migration: BLOCKED (2026-09-29)

The maintainer requested published dependencies instead of Git pins before
worktree integration. Hex currently publishes `ex_ssl` 0.7.2, but Hex's
`ex_quic` 0.1.2 belongs to `mickel8/ex_quic`, an unrelated lsquic wrapper.
The required `gsmlg-dev/ex_quic` 0.2.1 still declares a Git-pinned TLS dependency.
`MIX_ENV=prod mix hex.build --unpack -o /tmp/http-fetch-phase1-package-preflight`
from `apps/http_core` fails because `ex_ssl` and `ex_quic` are Git dependencies.

[Upstream feature request #4](https://github.com/gsmlg-dev/ex_quic/issues/4)
tracks publication under an available Hex name with a compatible published
TLS dependency and source/acceptance provenance. No unrelated package, override,
or speculative dependency declaration was substituted. The existing Git sources
remain only in the unmerged worktree pending this migration. Merge and release
are BLOCKED; prior adapter evidence above applies only to the recorded sources,
not to a future Hex combination. No merge, push, or release was performed.

## Source identity and existing work

The reviewed baseline and this worktree's HEAD are
`3bf5ec6518f17800f95b54bb8c5dbda55386d44a`. The changes are **uncommitted worktree
artifacts**, not a new source revision, at
`/home/gao/Workspace/gsmlg-dev/http_fetch/.trees/codex/quic-phase1`, branch
`codex/quic-phase1`. Main and its untracked `04-http_fetch-plan.md` remain intact.
The earlier `.trees/codex/ex-ssl-consumer-validation` artifact was not merged,
overwritten or used as a runtime dependency. No commit, push, merge, tag, package
publication or remote workflow dispatch was performed.

| Component | Actual source |
| --- | --- |
| http_fetch/http_core | Baseline above plus this uncommitted artifact; application versions remain 0.13.0 |
| ex_quic G-T | Git `5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb`, version 0.2.1 |
| ex_ssl G-S | Git `f1327e0bb7fb2093b8dc2b07e72b26233a739963`, version field 0.7.1 |
| Legacy quic in umbrella | Existing locked Hex 1.6.5, unchanged |
| Legacy quic in cold standalone consumer | Fresh `~> 1.6` resolution: Hex 1.10.0; compiled but not started by standalone http_core |
| Optional Abyss joint host | Git `50e121fce66daeb9cb25a2f5dc93050ca37efc5d`; disposable fixture only |
| Independent peer | aioquic 1.2.0, Python 3.12.13; Python source from pinned ex_quic `scripts/phase1/peer.py`, temporary copy changes only ALPN to `ex-quic-phase1` |
| Runtime | Linux x86_64, Elixir 1.18.5, OTP 28.5.0.5 / ERTS 16.4.0.5 |

The independent virtual environment resolved attrs 26.1.0, certifi 2026.7.22,
cffi 2.1.1, cryptography 50.0.1, pycparser 3.0, pylsqpack 0.3.24,
pyOpenSSL 26.4.0, service-identity 26.1.0 and typing-extensions 4.16.0.
Only aioquic is constrained by the script; these transitive versions record this
run rather than claiming a fully locked Python environment. No QPACK API is used
by the raw-stream fixture despite aioquic's transitive pylsqpack dependency.

The upstream gate records and exact contract revisions are linked from
[the consumer mapping](ex-quic-consumer-contract.md). Remote revisions were
verified before dependency changes; the fetched dependency HEADs match both pins.
The v0.2.1 tag points at `5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb` and
includes the ACK correction merged in `4c60115a98ee38f75a38dc48d018a8fc465a781a`.
The update changes recovery code/tests and version/acceptance metadata, not the
public consumer/I/O/TLS interfaces or ex_ssl pin. No adapter API change or local
workaround was needed.

## Changes and gate decisions

| Item | Status | Evidence and boundary |
| --- | --- | --- |
| F-01 dependency audit/alignment | PASS | One matching ex_ssl Git URL/SHA in direct/transitive dependencies; no override; ex_quic is a normal http_core runtime dependency; old production quic declarations retained |
| F-01 compatibility | PASS | Root-scoped HTTP/1, HTTP/2, shared TLS, WebSocket, SSE and WebTransport regressions; existing E2E; OTP remains default |
| F-02 internal adapter | PASS | Public ex_quic calls only; opaque handles/options/results preserved; finite read/write/event bounds; strict scripted-driver tests prove no retry or connection close on stream cancellation |
| F-02 association/errors | PASS | Generation-sensitive notification filtering, exact operation references, blocked/unknown forwarding, destructive-read recovery forwarding; real expired operation rejection/status and owner-death cleanup |
| F-03 TLS normalization | PASS | Explicit trust, independent DNS/IP reference identity and SNI, raw ALPN, bounded file credentials, supported algorithms/profiles; public SSL.QUIC mapping check and real negative authentication tests |
| F-04 standalone UDP | PASS | Four bidi + two uni streams, 16 KiB calls, over 1 MiB cumulative, exact per-stream contents/FIN, peer reset and stop observation, another stream completes after cancellation, small windows, owner cleanup |
| F-04 pinned independent peer | PASS | 1 MiB local-initiated bidi plus 1 MiB remote-initiated bidi data, three uni streams in each direction, 16 KiB calls, 1 KiB reads with 5ms yields, exact payloads/FINs, peer checksum, reset in both directions, bounded resource observations; baseline and seeded two-way impairment both pass |
| Legacy backend boundary | PASS | Compiled adapter/TLS imports exclude legacy modules and private engine state; runtime call tracing during the independent exchange records **0** `:quic`/`:quic_h3` calls, including spawned descendants |
| Standalone consumer/release | PASS | Fresh copied http_core source, no umbrella lock/build or adjacent sources; ordinary startup includes ex_quic/ex_ssl; one resolved ex_ssl; actual UDP endpoint creation/cleanup in consumer VM and running release RPC |
| G-F | PASS | Scoped adapter/dependency gate above; production HTTP/3 remains on old library; repaired ACK regression and current limitations are recorded below |
| G-P1: ex_ssl + ex_quic + http_fetch, standalone/independent | PASS | This run's pinned combination and separate upstream G-S/G-T records |
| G-P1: Abyss-hosted raw-stream combination | PASS | Same public raw-handler workload: four bidi/two uni streams, 1,572,864 bytes, per-stream SHA-256 and FIN, four client acknowledgment FINs, worker/endpoint/listener cleanup |
| HTTP/3/QPACK client sessions and production cutover | NOT RUN | Subsequent phase; no selector, session layer or fallback added |
| Other OTP/Elixir tuples, remote CI, production security audit | NOT RUN | No evidence claimed |

The existing TCP-only HTTP/2 buffered-close regression contains a private probe
from the baseline. Its version guard was revalidated against pinned G-S's
`closed`, `size` and `active` fields and advanced from 0.4.0 to 0.7.1. No such
probe was introduced into the QUIC adapter or its network tests.

## Commands and observed results

Run commands at the worktree's umbrella root. All PASS entries exited zero.
These are fresh results on the v0.2.1 source combination. Seed: `28092026`. Normal unit runs intentionally skip the three real QUIC tests;
the final full run below explicitly enables them and has **zero skips**.

| Command | Status | Result |
| --- | --- | --- |
| `MIX_ENV=test mix deps.get` | PASS | Both exact Git pins fetched; unrelated umbrella lock entries unchanged |
| Baseline root tests across all five app test directories | PASS | 507 tests + 20 doctests, zero failures before changes |
| `mix compile --warnings-as-errors` | PASS | Development build |
| `MIX_ENV=test mix compile --warnings-as-errors` | PASS | Test build |
| `HTTP_QUIC_PHASE1_REAL=1 MIX_ENV=test mix test apps/http_core/test/http/quic --seed 28092026` | PASS | 18 tests, zero failures/skips: 8 adapter/import, 7 TLS normalization, 3 real integration/lifecycle tests |
| `HTTP_QUIC_PHASE1_REAL=1 MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test apps/http_web_socket/test apps/http_event_source/test apps/http_web_transport/test --seed 28092026` | PASS | 525 tests + 20 doctests, zero failures/skips |
| Existing Go fixture build/start, then `E2E_BASE_URL=http://127.0.0.1:<fixture-port> MIX_ENV=test mix test.e2e apps/http_fetch/e2e apps/http_web_socket/e2e apps/http_event_source/e2e apps/http_web_transport/e2e --seed 28092026` | PASS | 58 tests, zero failures; fixture stopped afterward |
| `MIX_ENV=test mix run scripts/phase1_quic_independent.exs` | PASS | Independent summary and local exact comparisons; 8,470ms transfer, zero legacy QUIC calls; public close notification, endpoint monitor cleanup and explicit Python peer termination/reaping |
| `timeout 180 bash scripts/phase1_consumer_release.sh` | PASS | `PHASE1_CONSUMER_RELEASE_PASS`; strict compile, fresh dependency tree and lock checks, real release start/RPC/stop |
| `PHASE1_SCENARIO=impaired MIX_ENV=test mix run scripts/phase1_quic_independent.exs` | PASS | 8,310ms transfer; two drops, two duplications, two reorderings across both directions; zero reorder timeouts and zero legacy calls; peer checksum and cleanup pass |
| `timeout 180 bash scripts/phase1_quic_abyss.sh` | PASS | `PHASE1_ABYSS_JOINT_PASS streams=6 bytes=1572864 client_ack_fins=4`; no transport-limit or assertion changes to evade the former failure |
| Recovery-only reproduction in issue #2 | PASS | Valid already-ACKed range 0..4097 now returns success with no new ACK/loss/RTT work; a range including never-issued packet 4098 still rejects as `:ack_never_issued` |
| `mix format --check-formatted` | FAIL | Two unchanged baseline files: `apps/http_core/lib/http/http2/wire_profile.ex:215` and `apps/http_core/lib/http/http2/stream_state.ex:85`; not changed outside this task's scope |
| Scoped format command below | PASS | All modified/new Elixir source, tests and scripts |
| `mix credo` | PASS | Configured checks, no issues |
| `mix dialyzer` | PASS | Four configured existing warnings skipped; zero unnecessary skips |
| `git diff --check`; `bash -n scripts/phase1_consumer_release.sh scripts/phase1_quic_abyss.sh` | PASS | Whitespace/shell integrity |

Scoped formatting command:

```sh
mix format --check-formatted apps/http_core/mix.exs \
  apps/http_core/lib/http/quic/*.ex apps/http_core/test/http/quic/*.exs \
  apps/http_fetch/test/http/socket_client_http2_test.exs scripts/phase1*.exs
```

The Go server preparation follows `.github/workflows/e2e.yml`: build from
`apps/http_fetch/priv/test_server`, start its executable, read its emitted `PORT`,
and set `E2E_BASE_URL` before running the root-scoped suites.

Current compact evidence:

- [Independent baseline](phase1-evidence/independent.json)
- [Independent impaired run](phase1-evidence/independent-impaired.json)
- [Abyss joint result](phase1-evidence/abyss.json)
- [ACK correction checks](phase1-evidence/ack-regression.txt)

The [v0.2.0 independent result](phase1-evidence/independent-v0.2.0.json) is retained
as historical evidence only. Fresh local logs use
`/tmp/http-fetch-phase1-update-{deps,compile,dev-compile,tests,e2e,independent,impaired,release,abyss,ack,format,credo,dialyzer}.log`.
These local logs are not remote CI evidence.

## Failed checkpoints and limitations

Initial harness failures were not counted as acceptance: the first E2E command
omitted its required Go server; the release checker initially indexed atom lock
keys as strings, then attempted RPC before node readiness; the final script has a
finite readiness barrier. An early TLS normalizer compile used a non-guard
function in a guard; an unmatched certificate decode return was later corrected
for Dialyzer. The exploratory `mix credo --strict` additionally reports existing
low-priority suggestions outside scope; configured `mix credo` passes.

The first independent fixture used the upstream peer's original ALPN and could
not become ready. A bespoke queue then let FIN overtake a blocked chunk, followed
by incorrect echo/lifecycle bookkeeping. Those failing fixture implementations
were replaced by the pinned upstream workload's scheduling/verification logic,
with this adapter as the sole client transport. The peer source is copied only
for its dedicated ALPN. A transient Python executable supplied by `uv run` was
not reusable after that command exited; the final fixture creates a disposable
venv and directly owns/reaps the Python peer. No engine source or assertion was
weakened to obtain the independent PASS.

The first joint fixture attempted repeated whole-window writes and stalled when
remaining credit was smaller than a whole window. Its consumer scheduling uses
one initial 16 KiB write and subsequent 1 KiB writes. On v0.2.0, that sustained
workload exposed the real upstream cumulative-ACK span defect and failed with
`{:invalid_ack, :invalid_ack_ranges}`. Work on the combination stopped under
issue #2, with no local engine workaround. The v0.2.1 update accepts valid wide
ranges by processing bounded retained packet records rather than expanding the
numeric span, while preserving never-issued rejection. The same joint script
now passes; its resolved TODO is a regression comment. G-A was available
throughout, and its source pin is unchanged.

Real CA/identity failures terminate without readiness. Wrong ALPN terminates at
the engine's handshake deadline; the test waits up to 12 seconds and requires an
actual close, not merely a still-pending handshake. Deterministic unknown-outcome
and late-generation checks use strict fakes; real tests cover expired admission,
owner death, close and cleanup, but do not claim exhaustive UDP late-packet fault
schedules. The pinned independent impairment schedule passed with seed 28092026; this is
one bounded schedule, not statistical loss-rate stress or exhaustive fault coverage. Resource highwaters are engine counters and mailbox samples,
not total VM memory profiling. No per-write peer delivery receipt exists.

Finite stream tombstones and operation-result caches remain upstream limits.
The reported cumulative-ACK defect is fixed and independently retested; passing
bounded workloads still does not certify arbitrary long-lived or production traffic.
No compatibility or security guarantee beyond the tested internal adapter subset
is asserted. The old HTTP/3/WebTransport implementations and their existing TLS
option semantics remain unchanged and retain their `quic` dependency.
