# HTTP/3 remaining work plan

Date: 2026-11-09. Follows `docs/http3-quic-integration-validation.md`.
User decisions: start with Alt-Svc auto-HTTP/3 for Fetch; it is opt-in
(`alt_svc: true`) and `http_version: :auto` keeps its H2/H1 default.

No branches or worktrees. Capability flags stay false until each profile passes
its independent acceptance gate.

## Roadmap

| WP | Scope | Depends on | Status |
| --- | --- | --- | --- |
| 1 | Fetch Alt-Svc discovery, opt-in H3 for `:auto`, safe fallback | none | Implemented; locally verified (uncommitted) |
| 2 | Dynamic QPACK (RFC 9204 encoder/decoder streams, bounded table) | none | Planned |
| 3 | WebSocket/H3: native completion receipt, drop experimental label | QUIC cleanup receipt contract | Planned |
| 4 | WebTransport live adapter on `HTTP.HTTP3.ConnectionOwner` | WP3 runtime contract; matching draft-17 peer for acceptance | Planned; acceptance blocked |
| 5 | HTTP-layer 0-RTT / migration exposure | QUIC engine negative acceptance (Lane A) | Deferred |

## WP1: Alt-Svc auto-HTTP/3 (Fetch)

### Contract

- `HTTP.fetch(url, http_version: :auto, alt_svc: true)`. `alt_svc` defaults to
  `false`; any other `http_version` with `alt_svc: true` raises `ArgumentError`.
- Learning: final `https` responses (H1/H2/H3) carrying `Alt-Svc` update a
  bounded per-origin cache (`{host, port}`) when `alt_svc: true`. Only `h3`
  entries whose alternative host is empty or equal to the origin host are kept;
  `ma` defaults to 86400 s; `clear` removes the origin. Malformed values are
  ignored. Cache size is bounded; expired entries are evicted first.
- Routing: an eligible request (`https`, no proxy, Unix socket, connect address,
  explicit TLS backend, socket opts, transport scope or explicit pool) with a
  fresh entry uses the H3 runtime, dialing the alternative port while keeping
  the origin `:authority`, SNI and certificate identity.
- Fallback: only when the H3 connection was never established (no request
  stream admitted): `{:http3_not_established, _}` or `:opening_timeout` before
  connection readiness. The request then runs on the normal `:auto` H2/H1 path
  within the original deadline, and the origin is marked broken (no H3 use and no
  re-learning for 5 minutes). Any error after readiness, including
  indeterminate admission, is returned without replay.
- Redirects followed on an Alt-Svc H3 route re-select per hop: cached H3 origin
  stays on H3, otherwise the hop uses H2/H1.
- `response.http_version` reports the actual protocol.

### Verification

- Pure parser unit tests (RFC 7838 grammar, quoting, `ma`, `clear`, malformed).
- Cache tests: expiry, bounds, clear, broken marking.
- Integration: H1 origin advertising `h3=":<udp port>"` → second fetch is
  `:http3` against the in-repo QUIC fixture; dead UDP port → falls back to
  `:http1` and marks broken; post-readiness H3 failure does not fall back.
- Existing Fetch H3 and options suites stay green; strict compile, format, Credo.
