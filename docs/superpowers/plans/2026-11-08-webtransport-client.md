# WebTransport draft-17 Client Implementation Plan

> **For agentic workers:** Use executing-plans to implement this plan task by task in the current checkout. No additional agents, branches, worktrees or commits are authorized.

**Goal:** Establish the approved draft-17 profile and bounded WebTransport lifecycle, then integrate real H3 and reliable-reset interfaces when available.

**Architecture:** Session owns bounded application state and owner/waiter monitoring. Shared H3 parsing and event credit remain owned by Task C; QUIC reliable reset remains owned by Task A. One WT session uses one exclusive connection and post-handshake operations only.

**Tech Stack:** Elixir/OTP GenServer, umbrella Mix, pinned independent Go WebTransport source.

## Task 1: Pin independent profile evidence

Files: `docs/webtransport-peer-profile.md`, new `scripts/webtransport/`.

- [x] Inspect immutable webtransport-go revision for CONNECT token, SETTINGS, HTTP/QUIC DATAGRAM and reliable reset; record source identity and exact incompatibilities.
- [x] Add a reproducible read-only source probe under `scripts/webtransport/`; do not patch peer source.
- [x] Implement pure profile admission in `apps/http_web_transport/lib/http/web_transport/profile.ex`; require explicit draft-17, exclusive connection, matching negotiation and reset support. Test each missing prerequisite in `apps/http_web_transport/test/http/web_transport/profile_test.exs`.

## Task 2: Bound session lifecycle

Files: `apps/http_web_transport/lib/http/web_transport/{session,options,promise}.ex`, scoped tests.

- [x] Reproduce waiter leaks, missing owner cleanup, post-terminal event retention and unbounded streams with deterministic tests.
- [x] Add finite positive options `max_pending_waiters`, `max_streams`, `max_buffered_bytes`, `max_buffered_items`; default byte budget 262144. Test invalid/zero limits.
- [x] Monitor owner and pending callers; cancel timers/monitors on delivery, timeout, failure and close. Pass finite promise timeouts to Session; reject excess waiters with `:backpressure`.
- [x] Track stream directions and terminal send/receive state; reject unknown refs and writes after FIN/reset. Ignore duplicate terminal/data-after-terminal events. Bound aggregate receive bytes/items and admitted stream count; reject overflowing streams without silently truncating reliable bytes.
- [x] On close/failure clear retained queues, settle all waiters once, close backend once; on owner death terminate Session and clean backend. Draining rejects new streams but allows established streams.

## Task 3: Integrate actual shared interfaces

Files: `apps/http_web_transport/lib/http/web_transport/transport/quic.ex`, app `mix.exs`, owned validation docs.

- [x] Read `docs/http3-extensions-contract.md` and `docs/quic/client-features-validation.md` when published. Record exact unavailable APIs instead of inventing them.
- [ ] When real WT owner/events/credit and reliable-reset negotiation exist, add exact coordinated `http_runtime` dependency and implement adapter against them. Preserve explicit unknown-operation refs; no automatic replay.
- [ ] Run independent peer bidi/uni/FIN/reset/DATAGRAM/reordering/refusal/close/drain/owner-cleanup gates if profile-compatible server and dependencies exist. Otherwise record affected checks BLOCKED and retain false capability.

## Verification and delivery

- [x] Prepare isolated root compilation with `ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-task-d-build/test mix compile --warnings-as-errors`; no deps.get and no root build writes.
- [x] Run `mix test apps/http_web_transport/test` with the same environment and build path.
- [x] Format only explicitly owned changed Elixir files, then run scoped format check and inspect scoped diff.
- [x] Record PASS/FAIL/BLOCKED/NOT RUN in `docs/webtransport-validation.md`. No browser, release or published-package claim.

## Execution checkpoint

Independent application implementation is complete and scoped units pass (47
cases). The peer audit completed, with matching-peer selection BLOCKED: three
pinned independent implementations have incompatible profiles. Task C explicitly
has no live WT stream/datagram API. Task A's latest checkpoint publishes reset
source APIs and exact negotiated info; the pure profile gate consumes that info,
while Task A's independent acceptance remains pending. Adapter/dependency and
wire acceptance steps remain unchecked for those concrete reasons. No capability
was enabled and no parser/runtime was copied into this app. Detailed evidence:
`docs/webtransport-validation.md` and `docs/webtransport-peer-profile.md`.
