# HTTP/3 implementation audit

Plan: [2026-10-05 review](http_fetch_HTTP3_review_and_plan_2026-10-05.md).
Baseline: `6e33bcba7dae9acee1924af744c766b8e1d6147d`.
Implementation branch: `codex/http3-completion`.

The user authorized a commit, push, and patch release attempt after each work
package. Intermediate release failures are audit evidence; they do not authorize
weakening release checks. Existing 0.16.1 artifacts remain immutable. Final
completion requires all required gates and the final release to succeed.

| Package | Release target | State |
| --- | --- | --- |
| WP0: baseline | 0.16.2 | Commit pushed; release attempt failed at baseline Dialyzer |
| WP1: transport and resumable state | 0.16.3 | Commit pushed; release failed before publication: uv environment lacked pip |
| WP2: bounded HTTP/3 profile | 0.16.4 | Commit pushed; protocol gates PASS; release failed after publishing ex_ssl 0.16.4 |
| WP3: runtime and pooling | 0.16.5 | Independent review repaired three runtime gaps; audited commit ready |
| WP4: explicit Fetch integration | 0.16.6 | Pending |
| WP5: independent acceptance | 0.16.7 | Pending |

Local validation, remote workflow results, wire interoperability, artifact
consumers, and soak/canary evidence are recorded separately. Dynamic QPACK,
0-RTT, connection migration, Alt-Svc/racing, WebSocket over H3, and WebTransport
remain outside the initial HTTP/3 profile.

## WP0

Restored isolated CI test closure without modifying WS/SSE assertions or runtime
dependencies. Fresh red builds reproduced the historical five missing-Fetch
failures. Fresh green builds: WebSocket 82 tests and EventSource 64 tests, zero
failures (historical seeds, max-cases 8). See the baseline evidence document.

Root `MIX_ENV=test mix compile --warnings-as-errors`: PASS (Elixir 1.18.5/OTP 28).
Release automation tests initially failed 1/11: `archives.exs` incorrectly called
Hex's tarball unpacker with `:none`, interpreted as a filesystem output. Inspected
the installed Hex 2.4.0 implementation and changed the output to `:memory`.
This is a release-script defect, not a Hex defect. Rerun result recorded below.

Release automation rerun: **PASS**, 11 tests, exit 0. Manifest/harness formatting
and `git diff --check`: **PASS**.

Exact release tooling command: `python3 -m unittest discover -s scripts/release
-p 'test_*.py' -v` from the implementation worktree (default Mix environment).
WP0 commit: `bc63a24a1c93447efedf402e14fdbc71b680641d`.
Release attempt: [37269991020](https://github.com/gsmlg-dev/http_fetch/actions/runs/37269991020),
target `0.16.2`, workflow `release.yml`, `git_ref=codex/http3-completion`.
Remote nine-app unit tests and TLS integration tests passed; normal Credo passed.
Release failed before publication at Dialyzer on the pre-existing compiled
MapSet literal in `SSL.Protocol.ServerHello.grease?/1` (line 427).
No tag or package publication was reached. The narrow baseline repair is being
validated for the next audited step; the check is retained.

WP0 follow-up: the exact Dialyzer warning was reproduced and repaired by
representing the same fixed GREASE identifiers as a list (no ignore changes).
ServerHello 1 property and 16 tests passed; scoped Dialyzer had zero warnings.
Release tests reproduced two failures on a prepared 0.16.2 graph because their
fixtures assumed 0.16.1. Version-independent fixtures now pass 11/11 on both
graphs. Detailed commands and limits remain in the baseline evidence document.

## WP1

The adapter and Session now retain native generation identity, side-effect
references, allocated streams, admitted offsets, FIN, and destructively pulled
batches. Unknown admission is resolved from its original reference, never
replayed. Read demand can pause individual requests before QUIC grants receive
credit. Native attachment, authenticated H3 readiness, both cancellation halves,
and owned/shared endpoint cleanup have deterministic and native UDP coverage.
Review found four additional failure-transition defects; repairs and fresh
regressions are recorded in `http3-wp1-transport-session.md` before commit.

WP1 fresh root verification: `MIX_ENV=test mix test` with the four WP1 test
files and `--seed 0`: **41 tests, zero failures**. Spec and quality re-review:
**PASS**. Full native query/DNS wall-clock bounds remain a WP3 owner obligation.

WP1 commit: `ddcc053`. Release attempt:
[37272275808](https://github.com/gsmlg-dev/http_fetch/actions/runs/37272275808),
target `0.16.3`. Source validation, nine-app tests, TLS integration, Dialyzer,
transport impairment, Caddy fingerprint, aioquic, documentation, and independent
nine-archive consumers passed remotely. The next HTTP/2 package-traffic step
failed because setup-uv supplied a Python environment without `pip`. It reached
no tag or publication. The next audit uses `uv pip install` and the branch's
workflow definition; every traffic and publication gate remains required.

## WP2

Binary and demand-driven streamed uploads now emit DATA frames. Incremental
response parsing validates informational/final/trailer ordering and content
length, with independent field-count, encoded/decoded header, and session
retention limits. All 99 static QPACK entries follow RFC 9204, mixed encodings
preserve order, and malformed complete fields fail with explicit error scope.
Control/QPACK critical streams, unknown extensions, GOAWAY admission, retained
blocked continuations, and exactly-once completion are covered by regressions.

Root rerun: **103 companion tests, zero failures**, seed 0; compile with
warnings-as-errors **PASS**. Codec spec/quality re-review **PASS**. Native UDP
binary and streamed upload regressions **PASS**. Pinned independent aioquic
1.2.0 authenticated UDP POST echoed all 61,725 arbitrary bytes and retained
zero terminal requests: **PASS**. Reproduce with `uv run --python 3.12 --with
aioquic==1.2.0 python scripts/http3/session_gate.py`. This is companion evidence;
public Fetch acceptance remains a later gate. The uv release dependency install
was also verified in a fresh Python 3.12 virtual environment.

WP2 commit: `5cf3a4776158cf0ecb8833b894b354209e73f95f`. Release attempt
[37274530399](https://github.com/gsmlg-dev/http_fetch/actions/runs/37274530399)
passed every validation gate, created `v0.16.4` / release commit `5f801df`, and
published `ex_ssl 0.16.4`. Publication of `elixir_quic` then failed because the
portable staged package had no installed production dependencies. Remaining
packages were not published. Immutable artifacts are preserved; the next audit
uses a later version. The release repair installs production dependencies in
package order, rechecks byte-identical archives after preparation, and preserves
registry verification. Release automation regressions: 13 tests PASS. Actual
staged `elixir_quic` resolved published `ex_ssl == 0.16.4`; archive rebuild remained
byte-identical. `hex.publish package --dry-run --yes` reached package publication
checks with a dummy key (exit 0, no registry write); real auth is workflow-owned.

## WP3

Moved the still-unsupported HTTP/3 facade from core into runtime and added the
acyclic companion dependency to runtime, portable release order, isolated
consumers and CI closures. Added serialized owners, supervised request relays,
bounded upload/read delivery, monitored pool leases, finite opening/operation
watchdogs, no-replay unknown reconciliation, GOAWAY draining and rotation before
960 native stream allocations. Receive budgets are derived from admitted
concurrency; borrowed endpoint descriptors expose immutable budgets for validation.

Root independent rerun (Elixir 1.18.5/OTP 28, root MIX_ENV=test, seed 0): native
QUIC **235/0**, HTTP/3 companion **103/0**, runtime **78/0**. Owned compile,
format, normal Credo and Dialyzer **PASS** (existing intentional ignores retained).
Pinned aioquic **32 concurrent streamed uploads/downloads**, 61,725 bytes each,
single connection identity, zero leases after completion: **PASS**. A serial
consumer with 31 paused siblings also completed every response within the finite
2,293,760-byte native budget: **PASS**.

Stock pinned Caddy 2.8.4 exposed two native prerequisites: missing NEW_TOKEN
([#17](https://github.com/gsmlg-dev/http_fetch/issues/17)) and missing authenticated
peer key updates ([#18](https://github.com/gsmlg-dev/http_fetch/issues/18)). Both
now have deterministic regressions. Caddy's key-phase transition was independently
authenticated with the RFC 9001 next traffic secret before repair. The actual
61,725-byte POST now passes with complete byte integrity and no retained session
requests. See `apps/elixir_quic/docs/key-update-validation.md` and
`http3-wp3-runtime.md`. These gates do not claim public Fetch support or canary.

WP3 independent review reproduced and repaired deadline cleanup behind unacked
DATA, per-owner pool capacity, and custom native record-limit rotation. Root
fresh rerun after review: native **235/0**, companion **103/0**, runtime **82/0**,
seed 0. Root full test-environment Dialyzer **PASS** (five existing intentional
skips, zero new warnings). Native timeout releases requests/leases before the
subscriber ACK; only the bounded delivery relay waits for consumer settlement.
The supported Fetch facade is deliberately withheld from this checkpoint.
