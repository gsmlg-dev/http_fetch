# QUIC Peer Migration (M1) Implementation Plan

> **For agentic workers:** Use `executing-plans` for the integrated runtime work and bounded independent workers for the pure CID and accounting tasks. Follow the approved design and current-checkout instruction; do not create branches or worktrees. The coordinator owns Git, shared builds, final review, and authorized RC delivery.

**Goal:** Preserve a ready Quic/Abyss server connection and its streams when its authenticated client changes address.

**Architecture:** The endpoint routes active CIDs independently of peer address, while the connection admits new paths only after authenticated 1-RTT packets. A bounded pure path state machine owns validation and selection; IO and recovery pin reservations, receipts and congestion to path identities. CID route registration precedes advertisement and remains asynchronous to avoid an endpoint/connection callback deadlock.

**Tech Stack:** Elixir/Mix umbrella, OTP crypto, pure ExUnit state tests, real UDP integration, pinned aioquic 1.2.0, existing GitHub/Hex unified release tooling.

Approved spec: `docs/superpowers/specs/2026-11-07-quic-migration-and-early-data-design.md`.
Baseline: `91c18288b86b86634890de36fc0ac929eab8b6fd`; only the design commit is ahead of remote main.

## Execution boundaries

Implement M1 only in this plan. M2, R1, and R2 retain their approved subsequent
milestones. Preserve optional Abyss engine loading, default TLS policy, all three
packet-number spaces, operation/handle identities, and ordinary DATAGRAM loss
semantics. Builds run from the umbrella root. Independent pure tests may use
separate Elixir VMs without writing the shared build directory.

## Task 1: characterize missing migration and implement bounded path state

**Create:** `apps/elixir_quic/lib/quic/paths.ex`,
`apps/elixir_quic/test/quic/paths_test.exs`.

- [x] Write failing pure tests for authenticated path admission, one alternate
  path, highest non-probing PN selection, probe-only non-selection, stale old PN,
  matching responses on another arrival path, challenge bounds, timeout fallback,
  and finite challenge/MTU validation state.
- [x] Run the test in an independent VM and retain its expected missing-function
  failure before implementing the state machine:

  ```bash
  elixir -r apps/elixir_quic/test/quic/paths_test.exs -e ''
  ```

- [x] Implement the pure state operations with explicit local/remote/path
  generations. Initial path id is `:default`; additional ids are monotonic integers
  within the connection generation. Caller-supplied eight-byte entropy is stored
  only for three outstanding challenges per path. `active` selection and
  `peer_address_validated` remain distinct from reachability/MTU validation.
- [x] Verify at most two live records, three challenges each, and fallback under
  signed monotonic timestamps. Re-run pure tests with source required first.

## Task 2: bounded local CID issuance

**Owner:** CID worker. **Create:** `apps/elixir_quic/lib/quic/local_cids.ex`,
`apps/elixir_quic/test/quic/local_cids_test.exs`.

- [x] Write and run red tests for target/capacity, one reserved registration,
  publication ordering, consecutive sent sequences, idempotent retired history,
  and retirement of unsent/current-packet CID.
- [x] Implement this agreed pure interface:

  ```elixir
  LocalCIDs.new(initial_cid, peer_limit)
  LocalCIDs.configure(state, peer_limit)
  LocalCIDs.refill?(state)
  LocalCIDs.reserve(state, cid, token, registration_id)
  LocalCIDs.registered(state, registration_id)
  LocalCIDs.published(state, sequence)
  LocalCIDs.retire(state, sequence, containing_dcid)
  LocalCIDs.active?(state, cid)
  ```

- [x] Verify with standalone ExUnit; retain red/green output. No root build or Git
  mutation by the worker. Parent integrates advertisement/recovery pruning below.

## Task 3: path-specific IO and recovery accounting

**Owner:** accounting worker. **Modify:**
`apps/elixir_quic/lib/quic/io/endpoint.ex`,
`apps/elixir_quic/lib/quic/recovery.ex`.
**Create:** `apps/elixir_quic/test/quic/io_endpoint_path_test.exs`,
`apps/elixir_quic/test/quic/recovery_path_test.exs`.

- [x] Write red tests for per-path amplification including queued bytes, global
  queue ceilings, zero new-path counters, pinned receipts, global PN monotonicity,
  independent congestion/RTT, cross-path ACK timing, and controller retirement.
- [x] Extend both pure structs with `active_path: :default` and at most one
  inactive controller. Preserve top-level selected RTT/congestion and aggregate IO
  byte counters for existing callers/tests. Implement these additive interfaces:

  ```elixir
  IOEndpoint.add_path(budget, id, validated)
  IOEndpoint.select_path(budget, id)
  IOEndpoint.receive_bytes(budget, bytes, id)
  IOEndpoint.validate_address(budget, id)
  IOEndpoint.enqueue(budget, bytes, remote, at, id)
  IOEndpoint.drop_path(budget, id)
  Recovery.add_path(recovery, id)
  Recovery.select_path(recovery, id)
  Recovery.receive_ack(recovery, space, ack, at, arrival_path)
  Recovery.drop_path(recovery, id)
  ```

- [x] Pin each packet and send receipt to `path_id`; terminal old history may
  retain immutable identity after controller retirement. Refuse controller removal
  while live reservations/queued/sent packets remain. Prospective unknown ACK
  arrival ids may suppress RTT sampling without allocating a path controller.
- [x] Run standalone old and new accounting tests; parent later runs the root
  integrated closure. Do not weaken legacy receipt/generation behavior.

## Task 4: authenticate path metadata and process path/CID frames

**Modify:** `apps/elixir_quic/lib/quic/handshake_scheduler.ex`,
`apps/elixir_quic/lib/quic/peer_cids.ex`, `apps/elixir_quic/lib/quic/codec.ex`.
**Tests:** new `apps/elixir_quic/test/quic/migration_scheduler_test.exs` plus
existing scheduler/levels/peer-CID suites.

- [x] Add and run red protected-packet tests before runtime changes. Preserve
  arrival DCID, authenticated PN/level/probing facts, arrival path and path frame
  events without adding application-visible effects for duplicates.
- [x] Accept metadata through an additive datagram API and keep old arities:

  ```elixir
  HandshakeScheduler.receive_datagram(state, bytes, at, path_id)
  HandshakeScheduler.send_path_frames(state, path_id, frames, padding_size)
  ```

- [x] Pass ACK arrival path to recovery. Pin sends to their reserved path and
  never retransmit PATH_RESPONSE/DATAGRAM frames blindly. Emit PATH_CHALLENGE/
  PATH_RESPONSE facts in both roles only at application encryption level.
- [x] Keep authenticated peer `disable_active_migration` and CID-limit policy;
  configure separate local/peer CID state from validated parameters. Accept local
  retirement only for previously sent sequences and not the packet's DCID. Prune
  retired issuance from pending and recovery control work; coalesce refill.
- [x] Run existing and new scheduler tests from the umbrella root after workers
  finish, using the task-owned build path. Require zero warnings.

## Task 5: route and validate migration in the runtime

**Modify:** `apps/elixir_quic/lib/quic/endpoint.ex`,
`apps/elixir_quic/lib/quic/connection.ex`.
**Tests:** endpoint/connection integration plus new migration runtime suite.

- [x] Characterize changed-source dropping with a real protected connection.
- [x] Carry local/remote/path generation with endpoint delivery. Route active CIDs
  from changed addresses to servers while client remote-address acceptance stays
  fixed. Preserve provisional Initial/Retry admission and unknown-CID dropping.
- [x] Create/credit candidate paths only after authenticated 1-RTT traffic on a
  confirmed connection. Allocate at most one candidate/previous record, select on
  the highest non-probing PN, and use path-specific budgets/send destinations.
- [x] Send fresh unpredictable path challenges, reply on arrival paths, and accept
  matching responses on any path. Probe old paths too. Enforce 1200-byte validation
  when amplification permits and separate reachability from MTU confirmation.
- [x] Add generation-checked finite validation timers based on three PTOs, retry
  at most three challenges, and restore a usable validated path on failure. Keep
  late receipts/ACKs pinned; retire obsolete controllers only after settlement.
- [x] Register/refill local CIDs through generation/ref-tagged async requests and
  acknowledgments. Install route before advertising. Immediately revoke retired
  routes/tokens and coalesce replacement under pressure.
- [x] Verify no endpoint callback deadlock, bounded paths/CIDs under churn, no
  forged-address allocation, no shared-listener disruption, and no stale timer
  selection. Add path/resource observations to `info/1` without exposing secrets.

## Task 6: independent address-change acceptance

**Create:** `scripts/migration/peer.py`, `scripts/migration/gate.exs`,
`scripts/migration/gate.py`, and focused harness controls.
**Modify:** Abyss QUIC tests/docs only where engine integration requires it.

- [x] Build a pinned aioquic client and owned relay with explicit phase controls.
  Switch relay source port, then loopback IP, during a single connection/stream.
  Exchange phase markers and require byte-equal ordered content plus one FIN.
- [x] Run against standalone Quic and an Abyss shared listener, keeping another
  connection active. Exchange DATAGRAM phase markers with ordinary loss semantics;
  never convert DATAGRAM into a reliable protocol support claim.
- [x] Capture immutable peer/tool/source identity, each transition's wire traffic,
  authentication/validation observations, finite deadlines, and process/socket
  cleanup. Controlled localhost address changes are the acceptance scope.
- [x] Add negative gates for forged/wrong response traffic, reorder, lost
  validation and fallback, reserved amplification, CID churn and same-CID rebinding.

## Task 7: integrated review, capability and gate wiring

**Modify:** `apps/elixir_quic/lib/quic.ex`, current QUIC/Abyss consumer docs,
`README.md`, `AGENTS.md` capability text, relevant CI/release script wiring and
candidate/published consumers.

- [x] Report `migration: %{peer: [:server], local: []}` only once real M1 gates
  pass. Explain both-role path-frame handling and M1's server remote-change scope.
  Keep resumption/early data unsupported and raw HTTP3 false.
- [x] Review each worker against spec first, then code quality; fix findings before
  declaring integration complete. Inspect the final combined diff for scope.
- [x] Run formatting, strict compile, Credo, affected unit/integration tests,
  Dialyzer and docs as required. Record failures before retries; do not skip
  failed requirements.
- [ ] Run full manual CI, Test, Integration and E2E regression for shared gate changes.

## Task 8: authorized RC publication and independent consumption

- [ ] Commit and push accepted M1 changes on current main. Inspect remote releases
  and choose the next unclaimed unified RC version. Dispatch the existing release
  with `version`, branch `git_ref=main`, `publish_docs`, and
  `defer_static_analysis=false`. Record the feature SHA, then verify the workflow's
  version-bump commit and immutable release tag against that source.
- [ ] Require full workflow success, immutable source/tag identity, eleven portable
  plus asynchronous native package results, GitHub/Hex byte equality, docs parity,
  no-OTP scope proof, and a fresh published-only migration consumer.
- [ ] Report PASS/FAIL/BLOCKED/NOT RUN evidence and final source/release links.
  Do not describe M2/R1/R2 as implemented by the M1 release.

## Verification commands

Local acceptance: both independent source migration modes and the fresh isolated
three-package server consumer pass. Full eleven-app source regression passes
7,762 tests, 23 doctests and 20 property checks with integration/slow enabled.
QUIC's final closure is 427 tests after 19 regressions for a pre-existing PTO
congestion-credit stall exposed by the server-package gate. The unchanged
concurrent 1 MiB/FIN UDP gate now passes under the reproducing CPU conditions,
normal load and deterministic loss. A rebuilt fresh three-package Hex candidate
passes provenance, idle/network/DATAGRAM and both migration modes. Strict
compilation, formatting, Credo, Dialyzer and docs pass; Python
release295/CI47/migration19 controls pass. The final full source rerun retains one
unchanged Hell 100ms TLS receipt failure; that exact case passes in isolation.
Core's three environment-gated raw QUIC cases also pass when explicitly enabled.
Earlier failures and repairs remain in
`/tmp/http-fetch-quic-m1-barBLX/verification.md`. Updated remote manual regression
and the complete RC workflow, artifacts and published consumers remain required
before delivery is complete.

Use a task-owned `MIX_BUILD_PATH`, retaining commands/output under a new `/tmp`
evidence directory. The existing idle `/tmp/http-fetch-quic-next-9g02lf9z/build`
may be reused without deleting its unrelated contents.

```bash
MIX_ENV=test mix deps.get --check-locked
MIX_ENV=test mix compile --warnings-as-errors
MIX_ENV=test mix test apps/elixir_quic/test
MIX_ENV=test mix test apps/elixir_quic/test --only integration
MIX_ENV=test mix test apps/abyss/test --include integration
mix format --check-formatted
mix credo
mix dialyzer
mix docs
git diff --check
```

Pure tests are state/vector evidence. The independent gate and fresh RC consumer
must additionally establish actual wire migration and resource retirement.
