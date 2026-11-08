# HTTP/3 CONNECT and WebSocket Implementation Plan

> Execute inline using writing-plans, scoped-prd-execution and executing-plans.
> Current checkout only; no branch, worktree, commit, release, lock or version changes.

**Goal:** Add explicit RFC 9220 tunnels and WebSocket/H3 while preserving ordinary H3 requests; publish bounded extension primitives for Task D.

**Architecture:** `QuicHttp3.Session.extended_connect/4` owns explicit negotiation and request purpose. A dedicated response mode handles accepted tunnels. `ConnectionOwner` remains the only QUIC consumer; the supervised H3 stream relay translates bounded events and writes into the existing WebSocket runtime protocol. Pure versioned SETTINGS, Capsule, Datagram and stream-prefix codecs supply the WT boundary without advertising acceptance.

**Tech Stack:** Existing Elixir umbrella, ExUnit, RFC 9114/9220/9297, draft-17 codecs, independent aioquic peer.

## 1. Session and negotiation

Files: `apps/elixir_quic_http3/lib/quic_http3/{session,response}.ex`, new `connect.ex`, focused tests.

- [x] Characterize peer SETTINGS pending/refused/enabled, ordinary `:protocol` rejection and tunnel response rules.
- [x] Add `extended_connect(session, protocol, fields, opts)`; require SETTINGS before allocating a bidi stream; headers carry CONNECT, HTTPS, authority/path and exactly the selected protocol; keep upload open.
- [x] Distinguish tunnel response mode from ordinary content-length/trailers behavior. Reject tunnel trailers; allow DATA after accepted 204/205; preserve informational/rejected responses.
- [x] Run focused engine tests through root with `ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-task-c-20261108/test mix test apps/elixir_quic_http3/test`.

## 2. Shared primitives and adapter contract

Files: `apps/http_core/lib/http/h3/{settings,capsule,datagram,web_transport}.ex`, tests under `apps/http_core/test/http/h3/`, `QuicHttp3.Settings` facade, `docs/http3-extensions-contract.md`.

- [x] Preserve `wt_enabled=0x2c7cf000`; add explicit `wt_enabled_draft17=0x20b8933b` and draft negotiation setting after consulting normative text.
- [x] Implement incremental finite capsule decoding with unknown-payload skipping, quarter-stream Datagram association and bounded uni/bidi WT prefix parsing.
- [x] Publish actual implemented APIs and explicitly mark unavailable transport/session routing.
- [x] Verify split varints/payloads, finite lengths, malformed IDs and no legacy substitution.

## 3. Live tunnel ownership and WebSocket

Files: `apps/http_runtime/lib/http/http3/{connection_owner,stream,pool_key}.ex`, `apps/http_web_socket/lib/http/web_socket/{options,connection}.ex`, focused tests.

- [x] Carry explicit tunnel purpose into owner admission, defer pending SETTINGS under absolute opening deadline, preserve request sibling cancellation and control progress.
- [x] Keep sending direction open on accepted 2xx and terminal delivery once only. Reuse owner receive credit; account relay DATA until consumer ACK.
- [x] Extend relay with one bounded outstanding write, finite write deadlines and explicit indeterminate errors; expose existing runtime event format to WebSocket.
- [x] Allow explicit H3 options with QUIC TLS policy, no fallback; reuse handshake/frame parser/masking/Close/ping/pong and delivery ACK.
- [x] Run engine/runtime/WebSocket unit and applicable integration tests with isolated build directory.

## 4. Independent traffic and final evidence

Files: new `scripts/http3_websocket/**`, `docs/http3-websocket-validation.md`.

- [x] Pin independent peer version/source identity; exercise actual RFC9220 CONNECT and text/binary/fragmented/Close+FIN traffic with finite owned peer lifetime.
- [x] Cover refusal, protocol selection, limits, cancellation and siblings; rerun existing H1/H2/H3 consumer gates.
- [x] Format explicit owned files, strict compile, scoped Credo; inspect owned diff.
- [x] Record PASS/FAIL/BLOCKED/NOT RUN. Capability remains false until complete independent profile passes.

## Initial dependencies

Task A owns QUIC reliable reset and DATAGRAM transport negotiation. Task D owns WT adapter and independent draft-17 peer. No HTTP/3 server product is added here. No public pooled migration control is introduced.

## Completion boundary and remaining gates

The items checked above have source and local evidence in
`docs/http3-websocket-validation.md`. The contract records actual owner/relay
messages, write outcomes, ACK accounting and the pure association router.

- [ ] Wire a sole-owner live WT uni/bidi/datagram interface and the Task D adapter.
  The pure router is implemented; there is no live WT network support.
- [ ] Complete draft-17/reliable-reset acceptance against a matching independent
  implementation. Task D's audited peers do not match; this gate is BLOCKED.
- [ ] Expose certified native QUIC cleanup through the public WebSocket completion
  barrier. H3 explicitly returns `unsupported_completion`; a Close event is not
  a native resource receipt.
- [ ] Strict scoped Credo fully green. Existing findings remain in the scanned
  applications; no unrelated cleanup was authorized.
- [ ] Dialyzer, generated docs, browser, production and published-artifact gates.
  NOT RUN; no publication or shared generated-state mutation was performed.

Capability flags remain false. No HTTP/3 server application, branch, worktree,
commit, push, lockfile or version change is included. Concurrent QUIC/TLS edits
caused intermediate connection-start failures; the evidence document preserves
those checkpoints and the subsequent independent-peer reruns.
