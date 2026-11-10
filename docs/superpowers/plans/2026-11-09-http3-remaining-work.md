# HTTP/3 remaining work plan

Date: 2026-11-09. Follows `docs/http3-quic-integration-validation.md`.
User decisions: start with Alt-Svc auto-HTTP/3 for Fetch; it is opt-in
(`alt_svc: true`) and `http_version: :auto` keeps its H2/H1 default.

No branches or worktrees. Capability flags stay false until each profile passes
its independent acceptance gate.

## Roadmap

| WP | Scope | Depends on | Status |
| --- | --- | --- | --- |
| 1 | Fetch Alt-Svc discovery, opt-in H3 for `:auto`, safe fallback | none | Committed 6d8bbbc; independent Alt-Svc gate (`scripts/http3/alt_svc_gate.py`, aioquic 1.2.0) passes and runs in CI (`independent-aioquic` job in `.github/workflows/http3-public.yml`) |
| 2 | Dynamic QPACK decoder (RFC 9204), bounded table and blocked streams | none | Done; aioquic gate PASS |
| 3 | WebSocket/H3: native completion receipt, drop experimental label | QUIC cleanup receipt contract | Done; independent gate PASS |
| 4 | WebTransport live adapter on `HTTP.HTTP3.ConnectionOwner` | WP3 runtime contract; matching draft-17 peer for acceptance | Live adapter done (in-repo peer); independent acceptance BLOCKED: no qualifying peer |
| 5 | HTTP-layer resumption, 0-RTT for safe requests, migration for exclusive long-lived sessions | WP3, WP4 | Done: 5a resumption + 0-RTT (aioquic gate PASS), 5b migration for exclusive WebSocket/H3 and WebTransport (in-repo peer; independent WebSocket/H3 port migration gate PASS locally against unmodified quic-go/http3 v0.65.0, `scripts/http3_migration/gate.py`; source-IP case PASS in CI (`17bd1c8`); WebTransport has no independent peer); engine flags flipped 2026-11-10 after the M2/R1/R2 negative matrices passed in CI (`Quic.capabilities()` `resumption: true`, `migration.local: [:client]`; `SSL.QUIC` `resumption`/`zero_rtt` true); `http3` and `Profile.supported?/0` stay false |

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

## WP2: Dynamic QPACK decoder

### Contract

- The client advertises `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (default 4096) and
  `SETTINGS_QPACK_BLOCKED_STREAMS` (default 16). Both are configurable per
  session/profile; `0`/`0` restores the previous static-only profile exactly.
- Peer encoder-stream instructions are applied to a bounded dynamic table: Set
  Dynamic Table Capacity (above the advertised maximum is
  `QPACK_ENCODER_STREAM_ERROR`), Insert With Name Reference (static/dynamic),
  Insert With Literal Name and Duplicate. Partial instructions are buffered,
  with a bound.
- Field sections decode Required Insert Count/Base, dynamic indexed, post-base
  indexed and dynamic/post-base name references, per RFC 9204 §4.5.
- A section whose Required Insert Count exceeds the current insert count is
  blocked until enough inserts arrive. More blocked streams than advertised is
  `QPACK_DECOMPRESSION_FAILED`. Blocked bytes count against existing header
  limits.
- The client opens its decoder stream and sends Section Acknowledgment (for
  sections with a nonzero Required Insert Count), Stream Cancellation (reset or
  abandoned streams with references) and Insert Count Increment.
- The client's encoder stays static/literal (RFC 9204 allows this); the client
  still opens the encoder stream as required.

### Verification

- Pure tests: RFC 9204 Appendix B examples, eviction, capacity changes,
  invalid references, blocked/unblocked ordering, size bounds.
- Session tests: encoder/decoder stream wiring, acknowledgements, cancellation,
  blocked limit errors.
- Independent: the pinned aioquic 1.2.0 peer (pylsqpack, which uses the
  dynamic table) serving repeated and large header sets over public Fetch.
- No regressions in the existing H3, Fetch H3, EventSource H3 and WebSocket H3
  suites.

## WP3: WebSocket/H3 supported

- `HTTP.WebSocket` H3 completion receipt backed by the runtime's native QUIC
  cleanup contract; a receipt is confirmed only when cleanup is proven, and its
  meaning for shared pooled owners is documented precisely.
- Remove the experimental label once the receipt and the independent gates pass.

## WP4: WebTransport live adapter

- Wire `HTTP.WebTransport.Transport.QUIC` to `HTTP.HTTP3.ConnectionOwner` on an
  exclusive H3 connection using the draft-17 profile: extended CONNECT
  `webtransport-h3`, WT bidi/uni stream association, HTTP DATAGRAM, capsules,
  reliable reset, close/drain, bounded credit.
- Independent acceptance needs a peer matching draft-17 plus reliable reset
  draft-11. Re-audit current upstream releases; if none matches, the gate stays
  BLOCKED and `Profile.supported?/0` stays false. In-repo fixture tests still
  cover the live path.

## WP5: HTTP-layer resumption, 0-RTT and migration

- Resumption (R1): opt-in `http3_resumption: true` for Fetch, EventSource and
  WebSocket H3 using an endpoint-local ticket authority shared by the runtime
  pool, partitioned by origin/trust/profile.
- 0-RTT (R2): opt-in `early_data: true` per Fetch request, allowed only for safe
  methods with no request body (GET/HEAD/OPTIONS). Requires remembered peer
  SETTINGS (RFC 9114 §7.2.4.2). If 0-RTT is rejected, the request is re-sent
  once after the handshake (it is safe). A 425 Too Early response to an early
  request is retried once after the handshake (RFC 8470). Unsafe methods are
  never sent early.
- Migration: `migrate/2` for long-lived exclusive H3 sessions (WebSocket with
  `http3_reuse: false`, WebTransport), forwarding to `Quic.migrate/2` through the
  owner. Pooled Fetch connections are not migratable.
  Independent HTTP-level evidence (2026-11-10): `scripts/http3_migration/gate.py`
  runs WebSocket/H3 (`http3_reuse: false`) against unmodified quic-go/http3
  v0.65.0 (pinned in the committed `go.mod`/`go.sum`; RFC 6455 framing in the
  harness). The peer reports, per message, its connection's current
  `RemoteAddr()` and per-source datagram byte counts; the gate requires the
  post-migration text and 96 KiB binary messages with exact bytes on the same
  connection and CONNECT stream from the client's new address, nearly all bytes
  from the new path, and echoes back, then a clean Close + FIN. Port migration
  on loopback: PASS locally and in CI. Source-IP migration (`--ip`, 127.0.0.2):
  PASS in the CI `independent-http3-migration` job (`17bd1c8`). A pooled WebSocket refuses with
  `:not_exclusive_owner` and keeps exchanging. On retirement the owner
  sends CONNECTION_CLOSE with H3_NO_ERROR (0x100) before the cleanup receipt
  (`4c1bf8f`), and the gate requires the peer to observe it.
- Engine capability flags (2026-11-10): Lane A's negative acceptance passed in
  CI (M2 on `2d333b5`/`1d5dbe7`; reliable reset, R1, R2 on `1d5dbe7`), so
  `Quic.capabilities()` reports `resumption: true` and
  `migration: %{peer: [:server], local: [:client]}`, and
  `SSL.QUIC.capabilities()` reports `resumption`/`zero_rtt` true. Rows that
  need a dishonest peer are accepted with in-repo evidence by ruling (see
  `docs/quic/client-features-validation.md`, capability decision).
  `Quic.capabilities().http3` stays false by design and
  `HTTP.WebTransport.Profile.supported?/0` stays false (no draft-17 peer).
  These HTTP options remain documented as beta.
