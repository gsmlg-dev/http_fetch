# WebTransport Task D validation

Status 2026-11-09 (WP4): the draft-17 live adapter is implemented end to end on
an exclusive `HTTP.HTTP3.ConnectionOwner` and passes an in-repo QUIC peer
integration suite. Independent draft-17 interoperability is **BLOCKED** (no
qualifying peer; see `webtransport-peer-profile.md`). Local reliable reset
under the session's cleanup scope works after the engine fix below. No
WebTransport capability is enabled: `HTTP.WebTransport.Profile.supported?/0`
remains false. No branch/worktree, commit, lockfile, CI or engine change.

## WP4 live adapter (2026-11-09)

- `HTTP.WebTransport.Transport.QUIC` starts one inert, exclusive owner
  (`max_streams: 1`, `webtransport: true`) under the runtime connection
  supervisor with a session-owned `Quic.Cleanup` scope and `reliable_reset: true`,
  then sends one `webtransport-h3` CONNECT with `wt-available-protocols` when
  protocols are offered. Refusals (missing draft-17/DATAGRAM/CONNECT SETTINGS,
  reliable reset or QUIC DATAGRAM not negotiated, non-2xx, deadline, owner
  death) are explicit errors, and the owner and its native resources are retired
  before `connect/2` returns. There is no fallback.
- Owner deliveries carry router credit receipts. The session returns a stream
  receipt when its bytes reach a reader (or are discarded) and a datagram receipt
  on arrival (datagram retention is already bounded by drop-oldest). The owner
  reads a WT stream only with 16 KiB/1 item headroom in its at most 262144-byte
  router budget, so slow readers backpressure the peer through QUIC flow control.
- `Session` gained a backend `handle_message/2` hook (push delivery), receipts on
  `{:webtransport_stream_data, ref, bytes, receipt}` and a send-side
  `{:webtransport_send_stopped, ref, code}` event.
- `close/2` sends CLOSE_WEBTRANSPORT_SESSION with FIN, lingers (default 500 ms)
  for the peer FIN, stops the owner and returns `:ok` only if the cleanup receipt
  is `:confirmed`; otherwise the session reports `{:cleanup_failed, reason}`.
- Owner operation calls that exit without a result return
  `{:error, {:indeterminate_operation, ref}}`; they are never replayed.

Engine findings (apps/elixir_quic, out of scope; reported, not worked around):

1. `Quic.Cleanup.operation/5` rejects kind `:reset_stream_at`
   (`apps/elixir_quic/lib/quic/cleanup/observer.ex` allow-list), so a cleanup-
   scoped session cannot retain a RESET_STREAM_AT intent:
   `SendStream.abort/2` returns `{:error, :invalid_operation_kind}` and nothing
   is sent (no RESET_STREAM substitution). **Fixed** by the coordinator: the
   observer admits `:reset_stream_at` (regression in `cleanup_test.exs`); the
   integration suite now asserts the peer receives the WT prefix and then
   RESET_STREAM_AT with the draft-17 code. The H3 layer computes
   `reliable_size` = WT prefix length.
2. On peer STOP_SENDING the engine automatically sends an ordinary RESET_STREAM
   (`handshake_scheduler.ex` `peer_stop_sending`). Draft-17 §4.4 prefers a
   reset that keeps the WT header reliable; the adapter only records the event
   and closes the local send side.

Other bounds: a blocked write holds the session process until admission or its
deadline (5 s default); the H3 session's terminal-stream ledger caps one
connection at 1024 retired streams; no keepalive is sent, so the QUIC idle
timeout applies; the QPACK/peer stream budget admits 16 peer bidi and 16 peer
WT uni streams concurrently.

## Application behavior (Task D, 2026-11-08)

- Owner monitoring terminates and cleans the session on owner death. Backend
  close is attempted once across close/failure/termination; callback errors are
  retained and explicit close returns `{:error, {:cleanup_failed, reason}}`. This
  does not claim a native resource cleanup receipt. Lifecycle and read
  waiters have finite capacity, timers and caller monitors; finite promise
  waits are removed inside Session, and dead callers release reservations.
- New stream creation stops when draining; existing streams can finish.
  Direction checks and sticky FIN/error/send terminal states reject late writes
  and ignore duplicate terminal or unknown-stream input. FIN/reset can settle
  with a full application-data queue; receive cancellation discards queued data.
  Draining events and resolved promises settle once even if failure follows.
  Legacy speculative H3 message handlers were removed; a real adapter must use Task C's actual contract.
- Defaults bound pending waiters to 128, tracked stream handles to 128, aggregate
  retained receive/outgoing bytes to 262144 and items to 1024. Limits must be
  positive integers. Receive stream overflow fails the session and clears retained
  state instead of truncating reliable data. Excess incoming streams fail closed.
  Whole datagrams may be dropped; empty and duplicate datagrams count as items.
  Existing drop-oldest datagram count semantics remain. Stream handles, including
  terminal handles, remain counted until session cleanup; admission can return
  backpressure after reaching that finite handle limit.
- Mutating public calls carry a unique local operation ref and absolute admission
  deadline. Expired undispatched calls cannot invoke the backend. Caller timeout
  returns `{:error, {:indeterminate_operation, ref}}`; it is never retried.
  `HTTP.WebTransport.operation_status/2` reads the last 128 local callback results;
  evicted/unknown refs return `:unknown`. These are local callback results, not
  proof of remote delivery or native cleanup. Backend-level refs/receipts still
  require the real network integration.
- Pure admission requires exclusive single-session ownership and decoded draft-17
  SETTINGS plus both DATAGRAM and reliable-reset transport parameters and
  Task A's actual `%{draft: 11, local: true, peer: true, negotiated: true}` engine
  negotiation info. No parser
  was copied into this app. (2026-11-08: `Transport.QUIC` was then a stub; WP4
  replaced it with the live adapter above.)

Synchronous backend callbacks must themselves honor transport bounds and return;
Session cannot interrupt an indefinitely blocking backend. The live adapter
bounds every owner call by its operation timeout.

## Reproducible commands

Run from the umbrella root:

```sh
MIX_ENV=test mix compile --warnings-as-errors
mix test apps/http_web_transport/test apps/elixir_quic_http3/test \
  apps/http_runtime/test/http/http3 apps/http_core/test/http/h3 --include integration
mix test apps/http_web_transport/test/http/web_transport/quic_integration_test.exs --include integration
mix test apps/http_web_transport/e2e --include e2e
python3 scripts/webtransport/probe_peer.py   # pinned source probe; exits 2 (BLOCKED)
```

## Evidence ledger (2026-11-09)

| Gate | Result | Evidence / limitation |
| --- | --- | --- |
| Strict compilation | PASS | `MIX_ENV=test mix compile --warnings-as-errors`. |
| Scoped suites with integration | PASS | http_core 28, elixir_quic_http3 177, http_runtime/http3 78, http_web_transport 61 tests; 0 failures. |
| In-repo QUIC peer, live adapter | PASS (5 repeated runs) | `quic_integration_test.exs`, 13 tests: bidi/uni both directions with exact bytes and FIN (40000-byte uni write), empty/duplicate/boundary and foreign-session datagrams, streams and datagrams before CONNECT acceptance, foreign session ID rejected per stream (`WT_BUFFERED_STREAM_REJECTED`), peer reliable reset (code 43) and STOP_SENDING code mapping both ways, local Close capsule + FIN with owner exit, peer Drain then Close, missing draft-17 SETTINGS refused with no CONNECT stream, peer without reliable reset refused, 404 refusal, silent-peer deadline with no owner left, owner kill fails the session. The peer is our own engine: not independent acceptance. |
| Local reliable reset (cleanup scope) | PASS (in-repo peer) | Peer reads the WT prefix then RESET_STREAM_AT with the mapped draft-17 code. |
| Unit: H3 session, router, owner, budget | PASS | `quic_http3_web_transport_session_test.exs` (refusal order, single session, prefix, reliable size, receipts, capsules), router local/reset/forget, `webtransport_owner_test.exs` (subscriber-only ops, credit ack, deadline, receive budget). |
| E2E | PASS | 2 tests; default backend refuses without explicit QUIC trust. |
| Regression | PASS | Fetch H3 + Alt-Svc 26, EventSource H3 9, WebSocket completion 6 (integration); full http_runtime units 210; aioquic 1.2.0 RFC 9220 gate 9/9 PASS. |
| Format / Credo | PASS | Changed files formatted; `mix credo` clean; `--strict` reports only pre-existing design notes. Global `mix format --check-formatted` fails on unrelated `apps/abyss/lib/abyss/quic/service.ex`. |
| Independent draft-17 peer | BLOCKED | 2026-11-09 re-audit of 18 implementations, none qualifies (`webtransport-peer-profile.md`). |
| Browser / production / published artifacts | NOT RUN | Separate acceptance; no publication authorized. |

## Task D evidence (2026-11-08, historical; superseded above)

| Gate | Result | Evidence / limitation |
| --- | --- | --- |
| Existing unit baseline | PASS | 24 tests, 0 failures before changes. |
| New lifecycle reproductions | PASS as reproductions | Seven added tests initially failed on owner cleanup, waiter retention, draining admission, unknown refs, late events, stream bounds and sticky terminal state. |
| Application scoped units | PASS | Final 47 tests, 0 failures, root `mix test --no-compile apps/http_web_transport/test`; includes finite/invalid timeouts, dead callers, sticky terminal, full-buffer FIN, duplicate draining, local unknown outcomes and idempotent cleanup. |
| Isolated root strict compilation | PASS | Final root `mix compile --warnings-as-errors` exited 0 after Task D final source edits. Earlier intermediate compile saw a transient Task A missing `Connection.migrate/3` warning; it did not recur at final check. Other lanes remain concurrently changing. |
| Scoped formatting | PASS | Explicit changed Task D files pass `mix format --check-formatted`; no global formatter was run. |
| Scoped Credo | PASS | `mix credo apps/http_web_transport --strict --format oneline` exited 0 with no findings after cleanup and actual-engine profile regressions. Initial incorrect include syntax scanned root; no external files changed. |
| Pinned independent peer audit | BLOCKED | webtransport-go revision and exact setting mismatch in `docs/webtransport-peer-profile.md`; source probe exits 2 as designed. Two additional implementations inspected also mismatch. |
| Default QUIC adapter | BLOCKED | Task C contract explicitly says no live WT stream/datagram API yet; Task A now publishes reliable-reset source APIs and negotiation info; its independent acceptance remains pending. The app consumes that info in pure profile admission, but live adapter still requires Task C. No guessed runtime or dependency change. |
| Actual bidi/uni/FIN/reset/DATAGRAM/reorder/refusal/close/drain/owner cleanup traffic | NOT RUN / BLOCKED | Requires matching independent peer plus actual Task A/C contracts and adapter. No older aioquic pass substituted. |
| Browser / production / published artifacts | NOT RUN | Separate acceptance; no publication authorized. |

Task C owns all shared H3/HTTP runtime work. Task A owns QUIC reliable reset.
Concrete required behavior is listed in `docs/webtransport-peer-profile.md`.
