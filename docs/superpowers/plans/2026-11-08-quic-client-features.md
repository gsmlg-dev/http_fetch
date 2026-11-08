# QUIC Client Features Implementation Plan

> **For agentic workers:** execute this plan inline with executing-plans and scoped-prd-execution. Current checkout only; no branch, worktree, commit or subagent is authorized.

**Goal:** Implement exclusive-client local migration and negotiated reliable reset, then integrate the real Task B TLS continuation contract for separately accepted R1/R2.

**Architecture:** Keep Endpoint as socket owner and Connection as serialized protocol owner. Allocate candidate IO asynchronously, pin writers to path IDs, retain global packet numbers, and join native socket lifetimes through Cleanup. Reliable reset extends the existing stream/recovery machinery; it never substitutes RESET_STREAM for RESET_STREAM_AT.

**Tech Stack:** Elixir umbrella, OTP UDP/crypto, ExUnit, QUIC v1, reliable-reset draft-11; independent pinned aioquic for M2.

## Execution and verification environment

Use `ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-quic-A-20261108/test` from the umbrella root. Dependencies and root build directories remain untouched. Format only explicit owned files. Preserve all other lanes' edits. Capability remains false until its complete independent acceptance passes.

## Task 1: Characterize and implement M2

Files: `apps/elixir_quic/lib/quic.ex`, `quic/{connection,endpoint,paths}.ex`, `quic/io/gen_udp.ex`; tests in `apps/elixir_quic/test/quic/client_migration*_test.exs`.

- [x] Add tests for local-path creation, zero-receive-credit probe, deadline fallback and two-path busy state. Require `Paths.start_local(paths, local, now, pto, deadline)` to retain old active and unchanged remote.
- [x] Add `Quic.migrate(handle, local: {ip, port}, ref: ref, deadline: bound)` through existing durable operation handling. Validate client/confirmed/policy/CID/path budget before asynchronous `{:quic_bind_path, pid, generation, ref, id, local, deadline}` admission.
- [x] Endpoint authenticates every ingress socket generation, checks exclusive standalone ownership, enrolls IO/Port before activation, and reports `{:quic_path_bound, generation, ref, id, result}`. Connection retains admission/final outcome under the same ref.
- [x] Probe using a fresh CID/controller/ledger; preserve server-address validation. On matched padded response select candidate and send PING. Retire obsolete writer only after pending effects and recovery settlement; failed bind/validation leaves old selected.
- [ ] Run root scoped tests for paths, migration runtime, scheduler, IO and cleanup. Run independent port then loopback-IP migration with exact stream bytes/FIN, DATAGRAM, failure/busy/dedup and cleanup receipts using owned scripts.

## Task 2: Reliable reset draft-11

Files: `quic/{codec,transport_parameters,streams,handshake_scheduler,connection}.ex`, facade and focused tests; `docs/quic/client-features-validation.md`.

- [x] Read immutable draft-11 definition; record exact parameter/frame IDs and receive/send requirements.
- [x] Add codec/parameter positive and malformed/unnegotiated tests. Expose `Quic.reset_stream_at(stream, code, reliable_size, opts)` only with successful bilateral negotiation.
- [x] Extend send reset state to retain/retransmit exactly the reliable prefix; discard tail transmission while preserving final-size flow control. Integrate range ACK/recovery accounting.
- [x] Extend receive reset state to defer reset delivery until contiguous reliable prefix is available; bound sparse ranges, charge final size once, release consumed/discarded credit, and preserve once-only event semantics under duplicate/reset/FIN/reordering.
- [x] Run scoped codec/stream/scheduler/recovery/runtime regressions; record independent matching-peer availability separately from source checks. Publish actual API/negotiation and limits for Task D. Keep capability false if independent acceptance is unavailable.

## Task 3: Provider-dependent R1/R2

Files: only owned QUIC runtime/store modules and focused tests/scripts.

- [x] Read actual `docs/quic/tls-continuation-contract.md` after Task B publishes it; map its actions to endpoint-owned bounded authority and store without modifying TLS.
- [x] Add endpoint-local atomic single-use ticket store, name/trust/ALPN/profile partitioning, expiry/redaction and bounded asynchronous continuation. Verify independent full/resumed flights in both roles before enabling resumption.
- [x] Separately implement default-off replayable early operations, early packet encryption sharing application PN space, remembered limits, staging and aggregate quotas, withheld-until-Finished receive delivery and rejection without automatic replay.
- [ ] Verify independent pre-Finished early packets and post-Finished exact delivery, rejection, quota isolation, cleanup and later migration. Record concrete provider/environment blockers; never label R1/R2 complete from provider availability alone.

## Task 4: Final scoped evidence

- [x] Run strict compilation and focused format/Credo/Dialyzer/docs checks where the concurrent umbrella state permits; preserve concrete out-of-scope failures.
- [x] Inspect owned diff; update `docs/quic/client-features-validation.md` with PASS/FAIL/BLOCKED/NOT RUN and exact commands. Stop without Git delivery.


## Execution record

Source implementation is in the current checkout. M2, reliable reset, R1 and R2
have passing positive runtime/independent traffic. The global capability claims
remain false because their complete independent adversarial matrices are not yet
accepted. Open checkboxes above include these unrun acceptance cases, not missing
source APIs. Exact PASS/FAIL/NOT RUN evidence and commands are maintained in
`docs/quic/client-features-validation.md`.

Additional R2 files are `quic/{early_data,resumption_store,protection,recovery,runtime}.ex`;
focused continuation/early/runtime tests and the `scripts/quic_client_features/`
fixtures stay inside Task A ownership. There are no branch/worktree, lockfile,
version, commit, push or release changes from this task.

Independent positive gates:

- M2: quic-go v0.62.0, port then loopback IP, exact stream/FIN/DATAGRAM, all eight resources down.
- Reliable reset: bilateral prefix/reset against quic-go v0.62.0; local draft-11 loss/reorder/ACK regressions.
- R1: aioquic 1.2.0 full then resumed in both roles, early disabled, exact stream/FIN.
- R2: aioquic 1.2.0 in both roles with Finished deliberately withheld; no early application delivery at the runtime server, then exact STREAM/FIN/DATAGRAM.
- Combined: quic-go resumed 0-RTT followed by port and IP migration, exact later traffic, nine resources down.

Concrete environment limitation: aioquic 1.2.0 does not answer a pure challenge
on its unpromoted candidate path, so that M2 peer gate remains failing; the
unmodified quic-go alternative passes. aioquic also has no HRR support, so its
independent HRR resumption gate is NOT RUN. No peer-stack workaround was applied.


Final source checkpoint: 470 engine tests including integration pass, as do strict
compilation, owned formatting, normal engine Credo and seven independent positive
gates. Two actual retirement races (late old-path packet accounting and queued
receive credit against closed native IO) and ready metadata ordering now have
deterministic regressions. The wire harness verifies complete retained cleanup
receipts and post-early-migration peer bytes/FIN. Strict changed-file Credo retains
two baseline suggestions; direct private-PLT Dialyzer retains the documented
MapSet opaque-origin exception whose root ignore line has shifted. Docs generate
with unresolved link/hidden-type warnings. These findings and the still-open
independent negative/HRR matrices are recorded in the owned validation document;
source completion does not mark those acceptance checkboxes complete.
