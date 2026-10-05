# http_fetch: HTTP/3 review and implementation plan

Review date: 2026-10-05
Repository: gsmlg-dev/http_fetch
Reviewed main revision: `6e33bcba7dae9acee1924af744c766b8e1d6147d`
Commit timestamp: 2026-10-04T11:29:53Z
Local shared package version: `0.16.1`

## Decision

**Ready to begin HTTP/3 completion work; not ready to enable supported HTTP/3 beta or claim production HTTP/3.**

The latest commit consolidates TLS, raw QUIC, and the experimental HTTP/3 companion into this repository. The next work is application-protocol and runtime completion, not another repository migration. The public Fetch HTTP/3 route is still deliberately unsupported. The companion findings below concern the code to be integrated, not an already-enabled public HTTP/3 client. [S1–S4]

This is a fixed-revision source/contract review plus a live GitHub Actions status check. I did not execute ExUnit, build the repository, perform UDP interoperability tests, or run a load/soak test. The review environment has no Elixir/Mix and could not resolve github.com for cloning. GitHub connector reads succeeded. Migration-validation results are the repository author's recorded evidence, not independently rerun results. Full failing CI logs were not accessible through the available connector endpoint; test failure root causes remain unverified.

## What changed since the October 2 review

- `apps/ex_ssl`, `apps/elixir_quic`, and `apps/elixir_quic_http3` now live inside `http_fetch`. The companion was imported from `ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6`.
- Internal candidate dependency requirements were aligned to exact `== 0.16.1`. Do not repeat the previous recommendation to implement the companion in a separate ex_quic repository.
- The old consumer-contract documentation has been updated to describe the imported source and unsupported HTTP/3 boundary.
- Source graph alignment is distinct from release publication. The migration snapshot records six previously published immutable 0.16.1 packages with old metadata and three imported candidate packages not published at that version. This review did not independently re-query the live Hex registry. [S1, S2, S14]

## Current architecture and ownership

| Application | Responsibility for the next work |
| --- | --- |
| `ex_ssl` | TLS handshake, authentication, traffic secrets, fingerprint controls. Change only for a demonstrated TLS contract defect. |
| `elixir_quic` | QUIC packets, reliable streams, congestion/recovery, transport credit, generation handles, operation admission/status. Keep HTTP semantics out. |
| `elixir_quic_http3` | Transport adaptation, HTTP/3 sessions, control/request stream state, SETTINGS, QPACK orchestration, framing and message validation. |
| `http_core` | Shared request/response types and existing shared codecs. Avoid application-runtime ownership here. |
| `http_runtime` | Proposed supervised HTTP/3 connection owner, pool/admission, body bridge, cancellation, deadlines and resource accounting. Existing stream implementation is HTTP/2-specific. |
| `http_fetch` | Public Fetch dispatch, Promise/Response/body behavior, explicit protocol selection and observable errors. |

The companion already depends on `http_core`. Do not add a reverse hard dependency from `http_core` to `elixir_quic_http3`. Move the HTTP/3 execution facade to an appropriate higher application or introduce a deliberate backend boundary with exactly one module implementation. Add explicit dependencies where runtime code actually uses the companion; umbrella compilation must not hide undeclared package dependencies. [S14–S17]

Abyss remains a raw QUIC consumer; HTTP/3 does not need to be implemented in Abyss.

## Findings

### F0 — Public HTTP/3 is a stub, not an integrated request path

`apps/http_core/lib/http/http3.ex` returns `:http3_not_supported_by_elixir_quic_http3` from both request forms. The public HTTP/3 E2E test asserts precisely that error. The current capability document reports the companion's `http3`, `qpack`, and `webtransport` flags as false. `http_fetch` directly depends on `http_core` and `http_runtime`, not the companion. [S1, S3, S4, S16]

**Required:** integrate a genuine request path only after the lower contracts and acceptance tests work. Keep `http_version: :http3` strict: no silent fallback to HTTP/2 or HTTP/1.1. Raw `Quic.capabilities().http3` should not be flipped just because the separate application companion gains support.

### F1 — Nonempty request bodies are sent without HTTP/3 DATA framing

`QuicHttp3.Session.send_request/5` writes an encoded HEADERS frame, then passes the raw body directly to `send_chunks/5`. The session test explicitly expects raw `"body"` with FIN. This is not an HTTP/3 message body encoding. [S5, S6; RFC 9114 §§4.1, 7.2.1]

**Required:** encode body content as DATA frames. Separate HTTP frame boundaries from the QUIC API's 16 KiB write-admission boundary. Preserve empty-body FIN behavior and implement a demand-driven producer for streaming bodies rather than requiring one complete binary.

**Regression:** concatenate all writes belonging to the request stream and decode the byte stream independently. Assert HEADERS, zero or more DATA frames, optional trailers and correct stream termination. Test arbitrary binary bodies, multiple frame/write boundaries and large uploads. Never validate only transport call boundaries.

### F2 — The real transport adapter and the session disagree on handles and results

`Transport.Quic.open_stream/3` wraps native handles in its own `Stream` struct. `events/3` forwards native events unchanged. The session matches request streams by exact equality, while adapter `read/3` accepts only its wrapper. Consequently, native readable events cannot be matched to stored request wrappers; newly opened peer streams also reach a wrapper-only read API in native form. [S5, S7, S8]

`Session.cancel/2` expects `:ok` from `stop_stream/3`, but `Quic.stop_stream/3` returns `{:ok, operation_ref}` on admission. Native reads can also return `{:reset, stream_id, code, final_size}`, for which session parsing has no clause. Mock tests hide these differences. [S5–S8]

**Required:** choose one stable handle representation across opens, events, reads and cancellation, preserving generation identity. Normalize return contracts; propagate receive resets. Implement independent send-half reset and receive-half stop as required for cancellation and early responses. Use the appropriate HTTP/3 application error codes.

**Regression:** test `Session + Transport.Quic + native generation handles` together, including real UDP tests. Simulate native return shapes in unit seams; do not replace the adapter with an incompatible simplified mock.

### F3 — Partial writes and destructive reads can lose recoverable progress

A request is inserted into `session.requests` only after stream allocation and every write succeed. If a later write blocks or becomes unknown, the returned result loses the allocated stream and the offset already admitted. `open/1` has the same problem after control-stream allocation. Event/read batches can be destructively consumed before a later failure returns without advanced session state or the remaining batch. [S5]

The QUIC contract distinguishes definitely blocked, admitted and unknown outcomes. A timeout may mean the operation was admitted; destructive reads and event drains can be recovered through original operation references. The bounded cache may eventually evict results, and eviction is not evidence of non-admission. [S8]

**Required:** represent pending operations and advanced state explicitly. Retain stream identity, frame/byte offsets, FIN state, original operation refs and unprocessed batch items. Retry definitely blocked writes only after credit; reconcile unknown results via `operation_status` or the original ref. Never blindly replay non-idempotent requests or allocate replacement streams after unknown admission.

### F4 — SETTINGS, QPACK orchestration and response state remain incomplete

`Control` sends defaults `{1, 0}, {6, 0}, {7, 0}`. Setting 0x06 is the advisory maximum field-section size; explicit zero advertises a zero-sized budget, not unlimited headers. The session does not expose a useful alternative when it constructs its control state. [S9; RFC 9114 §7.2.4.1]

The session tracks only `headers_received?`, not informational/final/trailer phases. FIN can emit completion without final response headers; DATA after trailers is not distinguished; unknown response frames are rejected indiscriminately. Peer QPACK stream data is discarded, while unknown unidirectional stream types are treated as fatal. [S5]

Existing QPACK primitives already include static/literal fields and Huffman decoding. They should be reused, not described as absent. Their presence does not establish session-level QPACK synchronization. A complete HEADERS frame with an incomplete QPACK prefix can return `:more` from the QPACK decoder; that value can escape the parser and encounter a case expecting only success/error tuples. This source-level error path needs a regression, not a claim of an executed reproduction. [S5, S10]

**Required initial profile:** static/literal QPACK, maximum dynamic table capacity zero and blocked-stream allowance zero; retain Huffman decoding. Permit peer QPACK streams and validate instructions against the negotiated profile rather than silently discarding arbitrary bytes. A proposed 64 KiB decoded field-section budget should be configurable and separately bounded from encoded frame buffers and field counts. Do not confuse a small local QUIC read chunk with a protocol header-size limit.

Validate informational/final/trailer ordering, pseudo-fields, response status, content-length semantics, bodyless responses and end-of-stream completeness. Distinguish unknown extensibility elements from known forbidden frame types. Map errors to the proper stream/connection scope. Add malformed complete-HEADERS tests and ensure no parser exception escapes. [RFC 9114 §§4, 6, 9; RFC 9204]

### F5 — Buffers, completion cleanup and draining are not production-ready

The session accumulates binary buffers. The shared frame decoder waits for the complete declared payload. There is no session-wide retained-byte budget demonstrated by the 16 KiB read/write cap. A single large declared frame can retain much more than one read chunk; DATA should be consumable incrementally with bounded memory. [S5, S11]

After FIN, the session emits `done` but writes the request record back into its map. GOAWAY is parsed and retained but not consulted by request admission. [S5, S9]

The raw QUIC consumer contract documents a default 1024 lifetime stream-record budget with bounded terminal tombstones. Long-lived connection reuse therefore requires proactive rotation/draining, not an assumption of unlimited sequential stream creation. [S8]

**Required:** separate application, parser and transport budgets; demand-driven read/credit handling; bounded event work; terminal cleanup exactly once; monotone GOAWAY validation and admission control; finite-lifetime rotation; fairness across streams; explicit owned-versus-shared endpoint cleanup.

### F6 — Runtime and secure H3 dialing still need an explicit integration layer

`HTTP.Runtime.Stream` is coupled to `HTTP.HTTP2.ConnectionOwner`, its pool and `:h2 | :h2c` handles. It is not an HTTP/3 owner or body bridge. The raw `HTTP.QUIC.TLSOptions` path deliberately rejects H3 ALPN, while the companion adapter separately compiles an H3 profile. This requires a reviewed secure integration path, not simply removing a guard. [S12, S13]

**Required:** retain certificate trust, reference identity and SNI independently of DNS resolution; require verified readiness and negotiated `h3`; define total opening/read/write/idle deadlines; reject incompatible TCP backend options. Protect pool identity across origin, trust configuration, client identity, profile and endpoint ownership. Serialize session operations under a supervised connection owner, with bounded request queues and body demand. Preserve the existing H1/H2 behavior and fingerprint/profile controls.

### F7 — Latest remote test baseline is not green

For exact SHA `6e33bcba...`, the GitHub Test run `37199061203` completed with failure. `Test http_web_socket` and `Test http_event_source` failed in their `Run tests` steps. The other seven app test jobs succeeded, including `elixir_quic_http3`, `elixir_quic` and `ex_ssl`. The E2E run `37199061252` reports success, but the public H3 E2E remains an unsupported-boundary assertion. [S4, S18–S20]

This review could not retrieve the failing logs, so it does not attribute these failures to a particular implementation bug, race, fixture or migration change. Investigate and restore the baseline; do not delete assertions or add skips to obtain green status.

The migration document records local unit, TLS/QUIC, UDP smoke and package-consumer checks. Those scoped checks are valuable but do not demonstrate a working public Fetch HTTP/3 path. [S2]

### F8 — Candidate source and released package graph must stay distinct

Local internal requirements are now aligned. The reviewed migration snapshot nevertheless records an immutable pre-migration six-package 0.16.1 publication and the need for a later coordinated nine-package version. Do not treat the previous source-level version-range mismatch as unchanged; the remaining concern is distributable artifacts and verification of the new dependency graph. [S2, S14]

Use a later authorized shared version when releasing, not a republish of existing 0.16.1 artifacts. Prove an isolated consumer resolves the actual artifacts without workspace paths, sibling repository assumptions or overrides. Do not publish or tag merely as part of this review task.

## Recommended implementation sequence

### WP0 — Restore a trustworthy baseline

Investigate the two failing remote app test jobs. Reproduce with the CI environment and capture diagnostics. Confirm all-nine app boundaries, current package identities, immutable publication state and the source provenance. Preserve explicit unsupported selectors until their replacements pass. No unrelated TLS or HTTP/2 rewrite.

### WP1 — Repair transport composition and resumable operation state

Implement F2/F3 first, together with secure H3 dialing and endpoint ownership. Test native handle generations, reset/stop results, connect/control-open/write/read/event unknown outcomes, deadlines and cancellation races. Every side effect must have a retained identity and a resolvable outcome or an explicit indeterminate failure.

### WP2 — Complete a bounded initial HTTP/3 protocol profile

Implement correct DATA framing and streamed upload, a complete response state machine, bounded incremental decoding, SETTINGS correction, static-QPACK profile enforcement and extension handling. Add the malformed-HEADERS regression and completion cleanup. Test these through the real adapter as well as deterministic fault seams.

### WP3 — Add HTTP/3 runtime ownership and pooling

Create a serialized supervised H3 connection owner and explicit H3 stream/body bridge in an acyclic package graph. Add bounded admission, fair scheduling, slow-consumer backpressure, cancellation, early-final-response cleanup, GOAWAY draining and rotation before raw stream-record exhaustion. Match existing Promise, response and body lifecycle semantics.

### WP4 — Enable the explicit Fetch path

Replace the unsupported route only with a working `HTTP.fetch(..., http_version: :http3)` implementation. Keep strict H3 selection, expose actual protocol in the agreed response/telemetry contract, preserve existing timeouts/abort/headers/body behavior and do not silently downgrade. Add SSE acceptance after the body bridge works; do not infer it automatically from H2 SSE support.

### WP5 — Independent acceptance and beta release gate

Use two pinned independent HTTP/3 server implementations, for example the repository's Caddy and aioquic fixtures. Confirm actual H3 at the public API boundary, not just TLS ALPN or a raw UDP smoke test. Add certificate-negative cases, faults, cleanup measurements and external artifact consumers. Update capability reporting only for the layers actually validated.

## Proposed acceptance targets — not executed results or RFC requirements

| Area | Proposed gate |
| --- | --- |
| Public behavior | GET, POST/PUT binary integrity, empty body, status/headers, informational responses, trailers, error propagation and abort through public Fetch. |
| Streaming | Large uploads/downloads with slow producers and consumers; bounded retained data independent of total body size; correct FIN and early response behavior. |
| Multiplexing | At least 32 simultaneous requests when peer credit allows, with fairness and cancellation isolation; valid bounded admission when peer limits are lower. |
| Connection lifetime | At least 10,000 sequential requests across deliberate connection rotation, checking both session cleanup and raw stream-record policy. |
| Faults | Loss, reorder, duplication, blocked UDP, partial writes, unknown admission, resets, STOP_SENDING, GOAWAY, peer closure and deadline expiry; no blind replay. |
| TLS | Wrong CA, wrong reference name, expired certificate and wrong ALPN fail; no insecure verification fallback. |
| Protocol robustness | Fragmented varints/frames, malformed complete QPACK blocks, unknown extensions, invalid message ordering, oversized headers and critical stream closure. |
| Distribution | Clean isolated consumer of the coordinated artifacts, correct application boot and no hidden umbrella-only dependencies. |
| CI | Required H3 acceptance fails on unsupported return, silent downgrade or skipped peer fixtures; H1/H2/WS/SSE baseline stays green. |
| Canary | A proposed 24-hour scoped canary after functional gates, with predefined memory, mailbox, endpoint, connection, request and error thresholds. |

Initial beta should focus on ordinary HTTP/3 requests, secure TLS, streamed bodies, multiplexing, cancellation and connection reuse. Defer dynamic QPACK tables, 0-RTT, migration, Alt-Svc/racing, WebSocket-over-H3 and WebTransport until this path is verified. Deferred features must remain explicitly reported as unsupported.

## Codex execution prompt

```text
Work in gsmlg-dev/http_fetch. Start by reading AGENTS.md and inspecting the current
HEAD; this review was based on 6e33bcba7dae9acee1924af744c766b8e1d6147d. Revalidate
all findings against any newer changes rather than assuming they remain open.

Complete the first supported HTTP/3 Fetch path in small reviewable work packages.
The TLS, QUIC and HTTP/3 companion now live inside this umbrella. Do not move them
back to a separate repository. Do not implement HTTP/3 in Abyss.

First investigate the exact baseline's failed WebSocket and EventSource test jobs,
and capture their actual causes. Then repair real transport handle/result
normalization and resumable operation state before enabling public HTTP/3.

Treat these as hard requirements:
- Encode request content as HTTP/3 DATA, not raw stream bytes.
- Test concatenated request-stream bytes with an independent decoder.
- Preserve state after stream allocation, partial admission and destructive pulls.
- Keep original operation refs; never blindly retry unknown outcomes.
- Match actual Quic generation handles and reset/stop/read/event return contracts.
- Retain verified TLS trust/reference identity and require negotiated h3.
- Start with static/literal QPACK, Huffman decoding, dynamic capacity zero and
  blocked-stream allowance zero; fix the zero field-section-size advertisement.
- Validate full response/message state and convert malformed inputs to structured
  protocol errors, including complete HEADERS carrying incomplete QPACK data.
- Use bounded incremental DATA parsing, explicit resource budgets and cleanup.
- Add a supervised H3 owner/body bridge, safe pool keys, GOAWAY drain and connection
  rotation before the raw QUIC lifetime stream-record budget is exhausted.
- Preserve all existing H1/H2, Promise, response/body, abort and fingerprint behavior.
- Do not create http_core -> elixir_quic_http3 -> http_core dependency cycles.
- Do not rely on undeclared applications being compiled by the umbrella.
- Keep strict http_version: :http3; never silently downgrade.
- Do not turn Quic's raw-transport HTTP/3 capability true just to enable the companion.
- Keep WebTransport, WebSocket-over-H3, migration and 0-RTT out of the first beta.

Build deterministic regressions first, then real adapter/UDP tests, then independent
Caddy/aioquic public Fetch acceptance. Existing H3 unsupported-boundary tests and
mock tests are not proof of protocol support. Restore, do not weaken, existing tests.

Implement WP0 through WP5 in dependency order. After each package, record modified
files, command/environment/seed, actual results, remaining defects and unsupported
features. Distinguish source review, mocked results, independent wire interop and
load/soak evidence. Never describe unrun checks as passing. Do not publish packages,
push tags or alter immutable 0.16.1 artifacts without separate authorization.
```

## Source manifest

All repository file anchors below use the reviewed immutable SHA.

- S1: `docs/quic_http3_design.md`
- S2: `docs/migration-validation.md`
- S3: `apps/http_core/lib/http/http3.ex`
- S4: `apps/http_fetch/e2e/http3_test.exs`
- S5: `apps/elixir_quic_http3/lib/quic_http3/session.ex`
- S6: `apps/elixir_quic_http3/test/quic_http3_session_test.exs`
- S7: `apps/elixir_quic_http3/lib/quic_http3/transport/quic.ex`
- S8: `docs/quic/consumer-contract.md` and `apps/elixir_quic/lib/quic.ex`
- S9: `apps/elixir_quic_http3/lib/quic_http3/control.ex`
- S10: `apps/elixir_quic_http3/lib/quic_http3/qpack.ex`, especially source lines 370–610
- S11: `apps/http_core/lib/http/h3/frame.ex` and `apps/elixir_quic_http3/lib/quic_http3/frame.ex`
- S12: `apps/http_runtime/lib/http/runtime/stream.ex`, source lines 1–200
- S13: `apps/http_core/lib/http/quic/tls_options.ex`, source lines 1–230
- S14: `docs/ex-quic-consumer-contract.md`
- S15: `apps/elixir_quic_http3/mix.exs`
- S16: `apps/http_fetch/mix.exs`
- S17: `docs/quic_http3_design.md` dependency direction
- S18: GitHub Test run 37199061203, exact reviewed SHA
- S19: Test jobs 111426819401 (http_web_socket), 111426819440 (http_event_source)
- S20: GitHub E2E run 37199061252, exact reviewed SHA

Repository file URL pattern:
`https://github.com/gsmlg-dev/http_fetch/blob/6e33bcba7dae9acee1924af744c766b8e1d6147d/<path>`

Normative references:
- RFC 9114: https://www.rfc-editor.org/rfc/rfc9114.html
- RFC 9204: https://www.rfc-editor.org/rfc/rfc9204.html
