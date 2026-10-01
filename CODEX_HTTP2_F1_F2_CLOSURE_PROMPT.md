# Codex task: implement the remaining HTTP/2 runtime fixes and finish acceptance

Work in `gsmlg-dev/http_fetch`.

Reference main: `ec53f21584b435d37768890b13c71a18a4584554` (0.15.0).
Previous review: `e24c4a139703afd14c11a3bc03cd73f71eb84074`.
Read `AGENTS.md`, `HTTP2_REVIEW_ec53f215.md`, and the existing HTTP/2 plans and validation report. Reconcile current HEAD before editing; preserve unrelated work. This is an implementation task, not a request for another release-only cleanup or a documentation-only completion claim.

## Verified current state

The prior deadline-fixture, missing-sixth-package, format and Credo issues have been addressed. CI `36668263712` and Test `36668263716` succeeded at `e3cad137aef03a5a3ee4749df541a6076382975f`; its next commit bumps versions to 0.15.0. Preserve these changes. The TLS resumption fixture intentionally uses a fresh connection; do not misinterpret that fixture setting as a production workaround.

F1/F2 have not been implemented at the reference main. The following implementation blobs are unchanged from the previous review:

- `apps/http_fetch/lib/http/socket_client.ex`: `22deca5215d361cce1010023fdcee63d16441c86`
- `apps/http_fetch/lib/http/http2/connection_owner.ex`: `e9c0862e2b00fa0c2cbb1b1a7f95c417ac6eefdd`
- `apps/http_fetch/lib/http/http2/body_bridge.ex`: `44618d66e3e481f662dbe8f52d11ff7d8e3cf285`
- `apps/http_fetch/lib/http/http2/pool.ex`: `8f670dbc95be1fff4739b3a556eb68e746d07525`

The review's defect scenarios are source-derived, not claimed executed reproductions. Begin by writing and running the targeted failing tests. If a newer HEAD already fixes a scenario, prove that with the relevant executed test and source change rather than duplicating the fix.

## Step 1 — F1: own early-response upload termination in the connection runtime

Current failure chain: final response headers call `BodyBridge.early_response`; producer shutdown does not deliver upload EOF or atomically clear owner pending upload state; response cleanup can delete a stream that still has an unfinished request half on the wire.

Implement an explicit, serialized owner/protocol transition for stopping an upload after a final response. Stop further producer reads and pending unsent DATA scheduling, without confusing request-body abandonment with a response-body failure. Retain the connection's shared HPACK and unrelated streams.

Response completion and request-direction completion are distinct. Before releasing peer concurrency capacity, guarantee a valid on-wire closing transition for an unfinished request half. A reset after the complete response can be appropriate; do not reset an incomplete response merely to stop upload. Do not manufacture a normal END_STREAM that contradicts a declared request Content-Length. Handle the peer's optional NO_ERROR reset after a complete response without discarding that response. Already-completed uploads must not acquire duplicate EOF/reset events.

Add real-socket/public-fetch regressions with a scripted or independent peer:

1. Peer advertises INITIAL_WINDOW_SIZE=0 and MAX_CONCURRENT_STREAMS=1, receives POST headers without END_STREAM, sends a complete 413 without RST, and leaves the connection open. Verify valid response retention, correct on-wire request-half closure, no abandoned upload, agreement of peer/local active counts, and successful next request on the same connection.
2. Final headers arrive while an owner-held upload chunk is blocked. Keep the response incomplete, then grant upload credit. No abandoned DATA may resume after the stop decision; valid response DATA/trailers must still complete.
3. Exercise binary and streamed bodies, already-completed uploads, delayed body events/ACKs, a peer NO_ERROR reset after completion, and an unrelated sibling stream. Assert exact-once terminal delivery and eventual bridge/reservation/state cleanup.

Tests must observe the wire or independent peer state, not merely that local maps became empty. Use event barriers rather than arbitrary sleeps to establish the race conditions.

## Step 2 — F2: make existing queued admission work progress

Current production pool has no owner_factory. A request claims connection creation once and then waits for reservation. `do_dispatch` has no progress mechanism when no existing owner is eligible; global capacity changes do not promote waiters under other keys.

Introduce a coherent connection-creation/admission contract: either pool-managed supervised connectors or atomic promotion of an already-queued waiter to a connector claim. Integrate it with the actual SocketClient path. Do not fix only a test-only owner_factory path.

When an owner drains/dies, or global capacity becomes available, revisit relevant queued never-sent work and start or assign a connection when limits allow. Preserve one connector per key, per-key/global connection budgets, FIFO or documented fairness, original deadlines, cancellation, caller monitoring and reservation cleanup. Account for connecting and draining owners consistently. Losing a promoted caller must return its claim and allow another waiter to advance.

Required deterministic tests:

1. Queue requests, then drain/close every eligible owner. Without submitting any new request, the original waiters progress through a replacement connection when capacity permits.
2. Set a global connection limit of one: origin A consumes it, origin B queues, and A expires/closes. B must progress without another request, while the limit is never exceeded.
3. Cancel or expire a waiter before/during promotion; kill the promoted connector; race GOAWAY/capacity updates. Assert no ghost request, leaked reservation, abandoned claim, deadline reset, or sibling failure.

These waiters have not sent a request. This is not permission to automatically replay a sent POST, a consumed producer, or any ambiguous request.

## Step 3 — Execute final-candidate acceptance

Use separate reviewable changes for F1 and F2. Once source is frozen, run their regression suites plus repository-required format, compile, full tests, Credo and Dialyzer checks. Preserve existing HTTP/1, HTTP/3, TLS and API compatibility tests. Do not globally disable pooling, add backend fallback, replace the protocol stack, remove wire profiles, or weaken tests to obtain green results.

Run the already-agreed independent HTTP/2 gates on that same candidate, including both independent peer implementations and supported transports/backends; 10 MiB binary/stream transfers with 1/16/64 KiB source chunks; 10,000 sequential requests at peer limits 1/2/100; overlapping requests and a paused consumer with live siblings; HPACK/profile wire checks; complete package consumers; and a full 30-minute mixed soak under the existing explicit resource budgets. Keep the existing gate scope rather than treating unit tests as a replacement for the matrix or soak.

The existing starting points include `scripts/http2_interop_gate.py`, `scripts/external_consumer_smoke.sh`, and `scripts/ex_ssl_published_feature_gate.sh`. Inspect the current CLI/options and environment prerequisites before execution. The companion review links the prior successful CI runs for comparison.

Update `docs/http2-production-validation.md` with a clear current-candidate section: exact source SHA/tree and dirty state, runtime and peer versions, commands and seeds, F1/F2 code-to-test mapping, actual outcomes, resource bounds, and accessible artifact/log references. Keep historical runs distinctly labeled; they are not final-candidate passes. If final acceptance is blocked by unavailable tooling or a failing test, report NOT RUN/BLOCKED or FAIL honestly, with the precise cause. Never claim production readiness while F1/F2 or mandatory gates remain open.

Do not change release status, publish another package, merge, deploy, or start unrelated protocol expansion without a separate instruction. Deliver the implementation, executed evidence, and an accurate remaining-blocker report.
