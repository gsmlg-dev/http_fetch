# WebTransport Task D validation

Status: independent application work implemented; network adapter and draft-17
interoperability **BLOCKED**. No WebTransport capability is enabled. All checks
use the current checkout; no branch/worktree, commit, push, package version or
lockfile change, publication, or external source change was performed.

## Implemented application behavior

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
  was copied into this app. Default `Transport.QUIC` remains explicitly unsupported
  while its required shared network contract is unavailable.

Synchronous backend callbacks must themselves honor transport bounds and return;
Session cannot interrupt an indefinitely blocking backend. Network admission,
credit and cleanup guarantees await the actual adapter/runtime gate.

## Reproducible commands

Run from the umbrella root with task-private build state. Do not run deps.get or
write shared `_build`.

```sh
ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-task-d-build/test mix compile --warnings-as-errors
ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-task-d-build/test mix test apps/http_web_transport/test
ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-task-d-build/test mix credo apps/http_web_transport --strict
python3 scripts/webtransport/probe_peer.py
```

## Evidence ledger

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
