# QUIC-TLS implementation ledger

## Phase-one consumer contract hardening — 2026-09-28

The current follow-up uses reviewed base
`02eb981f59d4e182d4473e264a9f8b093ec6bf3d` on Linux / Elixir 1.18.5 / OTP
28.5.0.5. Its scoped source changes, actual worktree identity and fresh validation
are recorded in [phase1-acceptance.md](phase1-acceptance.md), with sequencing in
[phase1-implement-plan.md](phase1-implement-plan.md). The only runtime change is
early QUIC IP-reference configuration validation; shared TLS/TCP code and public
function signatures are unchanged. Additional tests cover public action order,
authentication boundaries, terminal states, redaction, generic opaque ALPN,
profile freshness and bounded ignored tickets. The ordinary packaged-consumer
startup check is reproducible without modifying a downstream repository.

The sections below describe earlier implementation/release runs. Their source
SHAs, runtimes, full-suite failures and publication authorizations are historical;
they are not new results or authorization for this phase-one worktree delivery.

## Original implementation task

Task source: repository-root `CODEX-PROMPT.md`. Implementation and acceptance evidence are recorded below; the full integration
suite is not claimed green.
Starting branch: `main`; HEAD: `bcb946d40327c68f238df5fd66d945d90f251af4`.
The pre-existing untracked task prompt is preserved. No release/version change,
commit, push or changes to another repository are authorized by this work.

## Current implementation

`SSL.QUIC` now exposes `capabilities/0`, `new/2`, `feed/3`, `info/1`, and `abort/2`.
The client and server use actual fresh ECDHE, certificate signatures and Finished.
TCP and QUIC share `ClientHandshake` for ClientHello/HRR, `HandshakeCore` for
client authentication/secret derivation, and the existing codec/PKIX/crypto
primitives. `ServerFlightVerifier` owns TCP record adaptation; the new
`ServerHandshake` uses the same key-schedule derivation and signature primitives.

The public interface uses caller-owned opaque state and one ordered action list.
Secrets have explicit direction/level/suite/AEAD/hash and redacted inspection.
Transport parameters have separate unverified/authenticated events. Server
completion never claims a client certificate identity. Both input and emitted
handshake bytes consume a bounded cumulative budget. Record-free profiles require
empty session ID and `RecordPolicy.mode: :none`; TCP capabilities accept only the
existing default mode and cannot accidentally emit QUIC parameter extensions.

| Role / transport | Current status |
| --- | --- |
| TCP client, TLS 1.2 | Existing bounded engine retained |
| TCP client, TLS 1.3 | Shared ClientHello/HRR/authentication; existing mTLS/resumption retained |
| Record-free TLS 1.3 client | Real certificate/identity/CV/Finished validation, HRR, directional secrets; independent aioquic peer passed |
| Record-free TLS 1.3 server | Real negotiation/ECDHE/certificate/CV/Finished, HRR and CH2 constraints; no mTLS/resumption/0-RTT; independent aioquic peer passed |
| Record-free post-handshake | Client boundedly parses and discards NST; KeyUpdate/PHA reject in the RFC 9001 error domains |
| Fingerprint public API | `SSL.Fingerprint` direct and fragmented observation; JA3/JA4 from actual bytes, official/reference goldens |
| TCP server | Outside task scope |
| QUIC networking / HTTP/3 | Outside task scope |

## Evidence

Local runtime: Elixir 1.20.1 / OTP 29.0.2.

- Before edits, `mix format --check-formatted`,
  `mix compile --warnings-as-errors`, and `mix test` passed: 394 checks
  (19 properties, 375 tests); 177 integration tests excluded.
- The new raw-core fixture test failed before implementation with
  `UndefinedFunctionError` for `HandshakeCore.start_client/2` (expected red).
- A pre-production-edit `mix test --include integration` run included that
  newly added red test, so it is **not a clean baseline run**. It reported
  570/572 passing: the expected red plus an existing
  `input_ordering_regression_test.exs:325` reference-server failure (expected
  `{:error, :closed}`, got `{:ok, "pending-output"}`).
- Focused extraction tests passed: 71 checks (3 properties, 68 tests), covering
  server-flight verification, handshake machine, resumption verifier/HRR and
  client authentication. Two compile warnings found during extraction were
  corrected.
- Post-extraction `mix format --check-formatted` and
  `mix compile --warnings-as-errors` passed.
- Post-extraction `mix test --include integration`: 571/572 passed (19
  properties, 553 tests). The sole failure is the same pre-existing
  `input_ordering_regression_test.exs:325` peer assertion described above. This
  is a failed full-suite gate, not a passing integration claim.
- After adding two more raw-core authentication negative tests, `mix test`
  passed all 397 checks (19 properties, 378 tests); 177 integration tests
  excluded. Format and warnings-as-errors compile passed in the same command.
  `git diff --check` passed. The two additional tests are default tests and were
  not part of the preceding 572-check integration run.

The raw-core test uses the existing independently constructed SHA-384 fixture:
application key outputs, exact encrypted client Finished and final transcript
digest must match. It also checks that core secrets contain no record states and
ordinary result inspection does not disclose the application secret.
Additional raw-core tests reject wrong trust, wrong reference identity, altered
CertificateVerify and altered Finished, and check incremental-state inspection.

Focused command:

```sh
mix test test/ssl/protocol/server_flight_verifier_test.exs \
  test/ssl/protocol/handshake_machine_test.exs \
  test/ssl/protocol/resumption_verifier_test.exs \
  test/ssl/protocol/resumption_hrr_test.exs \
  test/ssl/protocol/client_authentication_test.exs
```

Local diagnostic logs (not release artifacts) are
`/tmp/ex_ssl-quic-baseline-integration.log`, `/tmp/ex_ssl-quic-core-red.log`,
`/tmp/ex_ssl-quic-core-green.log`, `/tmp/ex_ssl-quic-core-all.log`, and
`/tmp/ex_ssl-quic-core-default.log`. The integration failure existed before
production edits and was not weakened or removed. The new shared core has no
`Record`, `TrafficState`, socket, Logger or process calls; the TCP adapter still
owns the record epochs and the existing connection owns delivery barriers.

## Duplex API validation (second implementation slice)

- `mix format --check-formatted` and `mix compile --warnings-as-errors`: passed.
- `mix test`: **413 passed** (19 properties, 394 tests), 177 integration tests
  excluded. Log: `/tmp/ex_ssl-quic-phase2-default.log`.
- `mix test --include integration`: **588/590 passed** (19 properties, 571
  tests). Log: `/tmp/ex_ssl-quic-phase2-integration.log`. Failures:
  1. The previously observed `input_ordering_regression_test.exs:325` peer
     closure assertion (`pending-output`).
  2. `connection_backpressure_test.exs:9`: `KeyUpdate was not queued behind output`.
     A focused rerun reproduced this; a **clean detached HEAD** worktree at
     `.trees/quic-baseline-audit` also reproduced the same test/error, establishing
     a baseline failure rather than assuming it. Baseline command:
     `mix test --include integration test/ssl/connection_backpressure_test.exs:9`.
     Logs: `/tmp/ex_ssl-quic-backpressure-recheck.log` and
     `/tmp/ex_ssl-quic-clean-baseline-backpressure.log`.
- After the shared repeated-HRR classification correction, focused
  `mix test test/ssl/quic_test.exs test/ssl/protocol/handshake_machine_test.exs`
  passed 39 tests. Both later whole-suite commands include that correction.
- `git diff --check`: passed. No existing test was removed or weakened.

The 16 new public API tests execute full dual-endpoint handshakes, HRR,
all runtime-available suite/group combinations (three suites and three groups
on this runtime), paired read/write secrets, one-time actions, write-secret-before-
bytes ordering, single-byte fragmentation, same-level coalescing, wrong levels,
partial-message level changes, empty/missing/duplicate parameters, trust/identity
and CV/Finished failures, HRR immutable-field/repeat failures, no-common
algorithms/ALPN, declared and cumulative limits, configured certificate/extension
bounds, ignored legal PSK proposals/unknown modes, bounded NST, abort and terminal
calls. These are self-connection and negative tests, **not independent QUIC-TLS
interoperability evidence**. The existing raw-core fixture is separately checked.

## Fingerprint, independent-peer and boundary validation

- `mix format --check-formatted`: passed.
- `mix compile --warnings-as-errors`: passed.
- `mix test`: **423 passed** (20 properties, 403 tests), 177 integration tests
  excluded. Log: `/tmp/ex_ssl-quic-final-default.log`.
- `mix test test/ssl/quic_test.exs test/ssl/fingerprint_test.exs`: **26 passed**
  (1 property, 25 tests), including new bounded malformed-input, certificate,
  signature and cumulative-output limits, unoffered selections and RFC 9001
  error-domain checks. Expected red checks were run before their implementation;
  logs: `/tmp/ex_ssl-quic-boundaries-{red,green}.log`.
- The core drops its ephemeral private-key reference after derivation; the
  existing independent-fixture inspection check now also asserts this release.
- `QUIC_TLS_PYTHON=/tmp/ex_ssl-quic-reference-venv/bin/python mix run
  e2e/quic_tls/run.exs`: **13/13 passed**, repeated after final production changes.
  Log: `/tmp/ex_ssl-quic-final-independent.log`. Both roles, three suites,
  ECDSA/RSA identities, exact directional-secret digests, ALPN, parameters and
  completion match independent aioquic 1.2.0. The additional client-identity
  scenario checks CertificateRequest/CertificateVerify handling. Setup and pinned
  dependencies: [reference harness](../e2e/quic_tls/README.md).
- Fingerprints: official FoxIO JA4 worked example and independent Caddy JA3
  expected projection/digest pass; unknown IDs, GREASE, signature order, binary
  ALPN, q/t provenance and bytewise observation of an actual emitted ClientHello
  pass. [Definition/license](FINGERPRINTS.md).
- RFC 9846/9001 and their listed errata were reviewed; dispositions, error mapping
  and secret lifetimes are recorded in [QUIC_TLS_STANDARDS.md](QUIC_TLS_STANDARDS.md).

## Acceptance map

| Group | Evidence |
| --- | --- |
| A: TCP compatibility | Default suite, full integration runs below, existing golden/OTP/OpenSSL/TLS1.2/STARTTLS/mTLS/resumption scenarios retained; no tests deleted or weakened |
| B: framing/resources | QUIC bytewise/coalesced input, illegal level/type, cross-level partial, declared/inbound/outbound budget, certificate count/bytes, extension/signature limits, terminal/empty calls and arbitrary bounded-input property |
| C: handshake/authentication | Real dual-endpoint ECDHE/CV/Finished, HRR/CH2, no-common and unoffered selections, trust/identity/CV/Finished negatives; independent ECDSA/RSA/client-identity scenarios |
| D: boundary | Complementary local read/write secrets, one-time events, secret-before-output assertions, separate parameter versus identity authentication, redacted Inspect and released terminal references |
| E: fingerprints | Official/reference expected values, raw/hash, q/t, GREASE/unknown/order and emitted-byte fragmentation |
| F: independent QUIC-TLS | Pinned aioquic TLS Context in both roles, 13 scenarios; explicit separate CI workflow provided |

Full QUIC networking is out of scope and **not tested**. The new CI workflow has
not been dispatched; local execution is evidence only for the current runtime,
not all supported OS/OTP combinations. The implementation remains experimental,
without a production-security certification or an independent human audit.

## Final integration gate

`mix test --include integration` (seed 449482): **598/600 passed**, 2 failed:
previously evidenced input-ordering peer assertion and an intermittent lifecycle
supervisor-child-count assertion at `connection_lifecycle_test.exs:303`.
Log: `/tmp/ex_ssl-quic-final-integration.log`.
The lifecycle scenario's isolated cold-start command failed on both changed and
original HEAD trees at the earlier `:gen_tcp.accept` timeout; this is a different
symptom and does **not** prove the child-count failure is baseline. Running the
entire lifecycle module with seed 449482 passed **28/28 on both trees**.
Logs: `/tmp/ex_ssl-quic-lifecycle-{current,baseline}.log` and
`/tmp/ex_ssl-quic-lifecycle-{current,baseline}-module.log`.
Same-seed whole-suite recheck after those comparisons:

- Changed tree: **599/600 passed** (20 properties, 580 tests), with only the
  previously evidenced `input_ordering_regression_test.exs:325` failure.
  Lifecycle passed on this recheck. Log:
  `/tmp/ex_ssl-quic-final-integration-recheck.log`.
- Original HEAD: **568/571 passed** (19 properties, 552 tests), failing the same
  input-ordering scenario, the previously evidenced KeyUpdate/backpressure
  scenario, and `ResumptionBlockedWriteTest`'s blocked-write deadline assertion.
  Log: `/tmp/ex_ssl-quic-original-integration-recheck.log`.
- The transient child-count assertion did not recur; its specific cause is
  unconfirmed and it is not relabeled as a proven baseline failure. It remains
  recorded as an intermittent validation risk.
- `git diff --check` passed. No commit, push, release or version bump was made.

The requested public TLS/fingerprint implementation and independent harness are
present. The full integration gate remains **failed**, not silently converted to
passing by excluding the baseline test. Addressing the pre-existing runtime
backpressure/closure failures is separate work; no such test was modified here.


## Completion audit against the task sections

This audit uses the task's explicit distinction between preserving the existing
TCP support and fixing newly introduced regressions. Pre-existing failures are
reported, not excluded or repaired as unrelated work. A failed whole-suite run
is not represented as a passing gate.

| Task section | Authoritative implementation and verification |
| --- | --- |
| 1: scope | Only this repository changed; no runtime dependency added, QUIC packet layer, TCP server API, commit, push or version change |
| 2: baseline and sources | Original HEAD and pre-edit commands above; original-tree comparisons retained; standards/errata audit in `QUIC_TLS_STANDARDS.md` |
| 3: shared core | `HandshakeMachine` calls shared `ClientHandshake`; TCP `ServerFlightVerifier` adapts `HandshakeCore` into records; `SSL.QUIC` calls the same core without record wrapping; server uses shared derivation/signatures; existing TCP vectors/regressions run |
| 4: public contract | `SSL.QUIC` public types and five functions, caller-owned redacted state and ordered actions; `QUIC_TLS_INTERFACE.md` covers ownership, levels, reliable queue handoff, completion/authentication separation and errors |
| 5: QUIC constraints | Empty session ID/no records/no CCS, mandatory raw extension 57, configured/runtime capability separation, bounded buffers, no Initial or packet keys; public negative tests and parameter-placement audit |
| 6: real roles | Actual ECDHE, PKIX, role-bound CV and Finished, HRR/CH2; self-connection and independent aioquic secrets/identity checks; unsupported server mTLS/resumption/0-RTT explicitly documented |
| 7: fingerprints | `SSL.Fingerprint`, reused ClientOffer envelope, original IDs/order, explicit transport, emitted-byte/fragmentation tests, official JA4 and independent JA3 reference values plus license |
| 8: verification | Acceptance A-F map above; original TCP tests retained; offline defaults plus explicit pinned independent harness and CI workflow; complete QUIC networking expressly not claimed |
| 9: artifacts | README/AGENTS/architecture/design/PRD/plan/compatibility/CHANGELOG updated; ADR, interface, implementation, standards and fingerprint documents present |

The final audit added a public extension-placement test covering missing or
duplicate EncryptedExtensions parameters and forbidden parameters in ServerHello,
CertificateRequest, certificate entries and NewSessionTicket. It also found and
fixed malformed profile extension containers raising an Enumerable exception:
`nil`, integers, maps and improper lists now return a structured configuration
error. The regression test was observed red before this correction and green
afterward (`/tmp/ex_ssl-quic-config-{red,green}.log`).

The original lifecycle module was additionally run with
`--seed 449482 --repeat-until-failure 10`: the initial run and all ten repetitions
passed 28 tests each. This did not reproduce the earlier supervisor-count symptom
and is not asserted to establish its root cause. Log:
`/tmp/ex_ssl-quic-lifecycle-baseline-repeat.log`.

Final current-tree commands after the profile correction and placement tests:

| Command | Result |
| --- | --- |
| `mix format --check-formatted` | Passed |
| `mix compile --warnings-as-errors` | Passed |
| `mix test` | **425 passed**: 20 properties, 405 tests; 177 integration tests excluded |
| `mix test --include integration --seed 449482` | **601/602 passed**: only the original input-ordering closure assertion failed; lifecycle passed |
| `git diff --check` | Passed |

Logs: `/tmp/ex_ssl-quic-audit-final-default.log` and
`/tmp/ex_ssl-quic-audit-final-integration.log`. The independent 13-scenario
reference result above remains the executed interoperability evidence. The
last configuration-only correction does not change the valid configurations
used by that harness.

All requested implementation artifacts and requirement-specific evidence are
present. The existing TCP closure-test failure is explicitly left outside the
new-regression repair scope in task section 8A. Thus delivery of the requested
TLS/fingerprint boundary is complete, while the repository-wide integration
suite is **not green**. The transient lifecycle observation remains a documented
validation risk, not a resolved defect or a proven baseline defect.


## R1–R3 boundary repair — 2026-09-23

This section records the new repair, not a reinterpretation of the historical
runs above. Starting branch/HEAD: `main`,
`29907a396ef025532454dec13cd3a787b600e44e` (v0.6.0). The only pre-existing working
file was the untracked `CODEX-FIX-PROMPT.md`; it is preserved. The user subsequently
authorized conventional commits, push, and the next minor GitHub release (v0.7.0),
superseding the repair prompt's original no-publication instruction. No ex_quic
or Abyss files, production dependencies, or TCP runtime code are changed.
Runtime: Elixir 1.20.1, Erlang/OTP 29.0.2 (ERTS 17.0.2), macOS;
Python reference environment `/tmp/ex_ssl-quic-reference-venv` with pinned aioquic
1.2.0. `unbuffer` is unavailable; commands used ordinary `mix` with captured logs.

### Reproduction and correction

Before production edits, `mix test test/ssl/quic_test.exs
 test/ssl/fingerprint_test.exs` passed **28 checks** (exit 0;
`/tmp/ex_ssl-fix-baseline.log`). After adding R1–R3 regressions,
`mix test test/ssl/quic_test.exs` failed **7 of 31 checks** (exit 2, seed 287963;
`/tmp/ex_ssl-fix-red.log`):

| Item | Observed red behavior | Minimal correction and coverage |
| --- | --- | --- |
| R1 | Removing extension 51 emitted HRR | `ServerHandshake.validate_offer/1` requires key_share/supported_groups presence for certificate/ECDHE; the observer stays permissive. Whole/bytewise missing-extension failures emit only terminal error; present-empty produces a decoded valid HRR; duplicate/malformed/unrelated groups reject; normal duplex and legal declined PSK still pass. |
| R2 | 2048-byte cookie under a 1024-byte budget emitted CH2; 1025-byte vector was also accepted; low-budget SH exported secrets | `ServerHello` shares a declared-length check with QUIC's bounded (at most 76-byte) Initial prefix check; `ClientHandshake` accepts optional decoder limits while old arities retain defaults. Exact 1024-byte vector succeeds, 1025 fails; length/payload split and bytewise feeds reject before retry/secret output; ordinary SH, shared decoder defaults and TCP HRR remain tested. |
| R3 | Unoffered SNI EE and forbidden ticket extensions became decode_error | QUIC EE/NST pre-parsing reuses `HandshakeCore.decode_alert/1`. Tests compare actual core/TCP adapter/QUIC processing for unoffered, unsupported, forbidden and malformed EE; missing TP/unoffered ALPN retain their distinct errors. Coalesced failure discards earlier uncommitted parameter actions. |

The first green attempt exposed a test-helper assumption: a post-handshake ticket
failure retains the documented historical `handshake_complete: true` fact.
The helper now checks that historical value explicitly for tickets while checking
false for handshake failures. Production completion semantics were not changed.
An existing ticket test's generic decode_error expectation was replaced with the
specific illegal_parameter/forbidden_extension assertion required by R3; no
rejection assertion was removed or relaxed.

The public `SSL.QUIC` API needs no migration. The internal decoder adds optional
limits, and the existing core error mapping becomes reusable within the protocol
implementation. Exact transcript bytes, fresh keys, authentication checks,
ordered actions, both roles and fingerprint APIs are retained. The interface
now explicitly documents inbound vector budgeting versus the existing outbound
message/cumulative budgets, and the unsupported empty-share client profile.

### Executed validation

| Command | Result |
| --- | --- |
| `mix format --check-formatted` | Exit 0 |
| `mix compile --warnings-as-errors` | Exit 0 |
| `mix test test/ssl/quic_test.exs test/ssl/fingerprint_test.exs` | Exit 0; **37 passed**, 1 property and 36 tests |
| Focused protocol command below | Exit 0; **143 passed**, 6 properties and 137 tests (before the final empty-profile test and additional assertions) |
| `mix test` | Exit 0; **435 passed**, 20 properties and 415 tests; normal default excludes 177 integration tests |
| `mix test --include integration --seed 449482` | Exit 2; **610/612 passed**, precisely the two baseline TCP failures below |
| `git diff --check` | Exit 0 |
| `/tmp/ex_ssl-quic-reference-venv/bin/pip install -r e2e/quic_tls/requirements.txt` | Exit 0; pinned dependencies present |
| `QUIC_TLS_PYTHON=/tmp/ex_ssl-quic-reference-venv/bin/python mix run e2e/quic_tls/run.exs` | Exit 0; **13/13 PASS**, both roles, suites, ECDSA/RSA and client identity |

Focused command (includes ClientHandshake coverage through HandshakeMachine):

```sh
mix test test/ssl/quic_test.exs test/ssl/fingerprint_test.exs \
  test/ssl/protocol/server_hello_test.exs \
  test/ssl/protocol/handshake_machine_test.exs \
  test/ssl/protocol/server_flight_verifier_test.exs \
  test/ssl/protocol/server_flight_test.exs \
  test/ssl/protocol/resumption_hrr_test.exs \
  test/ssl/protocol/resumption_verifier_test.exs \
  test/ssl/protocol/client_authentication_test.exs
```

Local logs: `/tmp/ex_ssl-fix-focused.log`, `/tmp/ex_ssl-fix-independent.log`,
`/tmp/ex_ssl-fix-reference-install.log`, and
`/tmp/ex_ssl-fix-final-{format,compile,api,default,integration,diff}.log`.
Per-command exit codes are captured in `/tmp/ex_ssl-fix-final-results.json`.
The initial changed-tree full integration run was **609/611** before the final
empty-profile test; its failures were identical (`/tmp/ex_ssl-fix-integration.log`).

### Baseline attribution and acceptance

Created a clean detached worktree at `.trees/quic-fix-baseline`, exact commit
`29907a396ef025532454dec13cd3a787b600e44e`. Ran `mix deps.get` (exit 0), then the
same `mix test --include integration --seed 449482`, same host/runtime/default
24 max_cases, without filtering tests. Result: exit 2, **600/602 passed**;
`/tmp/ex_ssl-fix-clean-integration.log`. Its tracked working tree remained clean.
Both baseline and changed trees fail these exact assertions:

1. `input_ordering_regression_test.exs:325`: reference peer expects
   `{:error, :closed}`, receives `{:ok, "pending-output"}` at line 336.
2. `connection_backpressure_test.exs:9`: `KeyUpdate was not queued behind output`
   at line 49.

These are reproduced baseline defects, not passing checks, and were not repaired
by expanding the task into TCP runtime changes. No new TCP failure appeared in
these runs; lifecycle tests passed. Historical intermittent observations above
are not reclassified or claimed resolved. The full integration gate remains
**failed**, and no exclusion, timeout increase or retry was used to hide it.

The prior independent CI is verified successful: `gh run view 35819480101`
reports `success`, head `33a3637c9ec972dd1db9b173f38686286445c9a6`.
That supersedes the historical pre-dispatch wording above. The current local
13-scenario reference also passes. Pinned aioquic 1.2.0 cannot process/generate
HRR (see the harness README); no independent HRR pass is claimed.

R1–R3 and the existing independent reference pass, with no new observed TCP
regression. These three defects no longer block ex_quic from using the documented
experimental record-free API. The known TCP failures, inbound-only extension
budget scope, unavailable independent HRR coverage, and absence of production
security certification remain explicit limitations. This is not full QUIC
network interoperability or an assurance that all CI/runtime matrices pass.

Final decoder assertions additionally verify the default shared ClientHandshake
call accepts the large legal cookie while its limited call rejects the exact
2066-byte vector. `mix test test/ssl/quic_test.exs
 test/ssl/protocol/server_hello_test.exs`: exit 0, **49 passed** (2 properties,
47 tests); `/tmp/ex_ssl-fix-final-decoder.log`. No production code changed after
the full-suite/reference runs recorded above.


### v0.7.0 GitHub release preparation

Repair commit: `eea1621` (`fix(quic): enforce TLS negotiation and extension boundaries`).
Version-only release preparation updates `mix.exs` and dates the changelog.
`mix format --check-formatted`, `mix compile --warnings-as-errors`, and `mix test`
all exit 0 on v0.7.0; the latter again passes **435 checks**
(`/tmp/ex_ssl-v0.7.0-test.log`). `mix hex.build --output /tmp/ex_ssl-0.7.0.tar`
exits 0; this builds a GitHub release attachment and does not publish to Hex.
The package excludes the untracked repair prompt and test credentials. GitHub
release notes carry the same baseline-failure and independent-HRR limitations.

## F1 cross-version formatting — 2026-09-23

Baseline: `606087058e912b08ce20e145bcd8505744be8a78` (v0.7.0).
This follow-up changes only four expressions in three files: explicit `do/end`
for two config conditionals and the retry guard, plus a `chain` binding immediately
after successful secret derivation and before certificate encoding. Conditions,
short-circuiting, return values, field-access timing and handshake actions are
unchanged. Parsed ASTs for Config and ClientHandshake are identical after removing
source metadata; the new server binding is used only by the original next call.
No protocol tests, interfaces, dependencies, minimum Elixir requirement or CI
matrix/check names were changed. R1–R3 remain intact.

Elixir 1.18.5 reproduced the original four formatting differences (exit 1;
`/tmp/ex_ssl-f1-red.log`). After the edit, full-repository
`mix format --check-formatted` exits 0 on **1.18.5, 1.19.5 and 1.20.1**;
all three accept the same bytes without formatter rewrites. Local runtimes use
OTP 29.0.2; this is formatter evidence, not local OTP28 compatibility evidence.
The 1.18.5 distribution is built for OTP27, as in the original CI; an attempted
OTP28 distribution download returned 404 before the correct artifact was selected.
There is no need for a new format job or a branch-protection change.

Local Elixir 1.20.1 / OTP29.0.2 validation (all exit 0):

- `mix compile --warnings-as-errors`.
- `mix test test/ssl/quic_test.exs test/ssl/fingerprint_test.exs test/ssl/protocol/server_hello_test.exs`:
  **54 passed**, including 2 properties.
- `mix test`: **435 passed**, including 20 properties; 177 integration tests
  excluded by the unchanged default policy.
- `QUIC_TLS_PYTHON=/tmp/ex_ssl-quic-reference-venv/bin/python mix run e2e/quic_tls/run.exs`:
  **13/13 PASS**, unchanged pinned aioquic 1.2.0 scenarios.
- `git diff --check`.

Logs: `/tmp/ex_ssl-f1-{compile,focused,default,reference,diff}.log` and
`/tmp/ex_ssl-f1-results.json`. The Linux suite wrapper is not run locally because
`setsid` and `timeout` are unavailable. The existing GitHub `Test` matrix executes
`./scripts/ci_run_suite.sh --seed 101 test` for 1.18/28, 1.19/28 and 1.20/29;
release notes record the actual remote run/job results before publication.
The optional full local integration command is not rerun for this syntax-only
change. Earlier macOS TCP failures above remain historical evidence, not current
passes or formatter failures. The user's final instruction explicitly authorizes
commit/push and the v0.7.1 GitHub patch release.
