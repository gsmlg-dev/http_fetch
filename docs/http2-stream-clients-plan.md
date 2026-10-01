# HTTP/2 stream clients implementation plan

Baseline: `b5d17bfe3a6be9fbb20a3f3c185dc36773b9f367` (v0.15.1).
The task is `CODEX_HTTP2_EVENTSOURCE_WEBSOCKET_PROMPT.md`, phases P0–P5.
The user's current instruction authorizes per-step commits/pushes and a release
after final acceptance; it supersedes the prompt's historical publication ban.
User-owned prompts/reviews and the deleted historical prompt remain untouched.

## Dependency and ownership contract

`http_core` owns pure HTTP/2 state, codecs and transport primitives.
`http_runtime -> http_core + telemetry` owns the existing pool and connection
owners, their supervision, generic dialing, and logical stream I/O.
`http_fetch`, `http_event_source`, and `http_web_socket` each depend on
`http_runtime` and `http_core`; no concrete client depends on another.
Fetch retains BodyBridge, HTTP.Stream, responses, promises and abort adapters.
Keep the existing owner/pool algorithms and module names. Shared runtime code
must have no Fetch module or task-supervisor dependency.

## Stream contract

Admission/opening have a monotonic deadline. A handle records connection owner,
stream ID, request reference and attempt generation. Only the owner writes or
rearms the transport. Ordered notifications carry informational/final headers,
DATA, trailers, remote end and terminal errors. DATA credit is settled after
bounded parser admission, independently of complete event/message delivery.
Writes are finite and cancellable, preserve frame byte order, and never block
control processing while windows are zero. Release/reset are idempotent.

Immutable purpose is `:request` or `:extended_connect`. Fetch retains F1 upload
abandonment on final headers. SSE opens an ordinary bodyless GET. Accepted
Extended CONNECT keeps both stream directions usable and does not use ordinary
response Content-Length/body-forbidden/upload-abandonment rules. Rejection never
establishes a tunnel. F2 connector promotion/deadlines/monitoring remain intact.

## Option matrix

Both clients keep HTTP/1 by default and validate flat/string-alias options:
`http_version`, `http2_profile`, `http2_scope`, `http2_reuse`.

| Selection | Cleartext HTTP/WS | TLS HTTPS/WSS |
| --- | --- | --- |
| `:http1` | Existing behavior | HTTP/1-compatible ALPN |
| `:h2c` | Prior knowledge | Reject |
| `:http2` | Reject | Require h2 ALPN |
| `:auto` | Existing HTTP/1 | Negotiate h2/HTTP1; explicit profile requires h2 |

Reject H2 Unix sockets and contradictory ALPN before dialing. Preserve the
selected TLS backend (`:ssl` default, `:ex_ssl` explicit). Expose actual HTTP
version separately from WebSocket subprotocol. Auto WS capability fallback is
one separate HTTP/1 connection before establishment only; certificate, malformed
response, subprotocol/extension and ambiguous write failures never downgrade.

Legacy envelopes remain unchanged; acknowledged delivery uses opaque refs with
idempotent settlement. Define finite parser, assembled event/message, delivery
byte/count, write, worker and timer budgets. A paused acknowledged consumer must
not starve mixed siblings. Default established idle timeout may be infinite;
opening and close deadlines are finite. SSE reconnects carry attempt tokens and
Last-Event-ID without stale parser fragments; WS never replays/reconnects.

## Requirement-to-test map

| Gate | Deterministic or independent proof |
| --- | --- |
| A0 | Extraction/F1/F2 suites; standalone runtime/client package startup |
| A1 | SSE raw-wire UTF8/BOM/CRLF/event/status/MIME/204/redirect cases |
| A2 | SSE cursor/reconnect, stale generation, owner death, reset/GOAWAY, idle |
| A3 | Above-window event, many short lines, acknowledged pause bounds |
| B1 | Raw SETTINGS 0x8 absent/0/1/invalid/reversed/delayed; exact CONNECT |
| B2 | Independent RFC8441 codec/peer, bidirectional split frames/control/close |
| B3 | Zero/shrunk windows, producer/consumer pressure, bounded close/writes |
| C1 | Independently observed single connection carrying Fetch + SSE + WS |
| C2 | Mixed sibling survival under cancellation/reset/overload/paused consumer |
| C3 | TLS/profile/scope isolation, capacity and existing F2 promotion |
| D1 | h2c and TLS ssl/ex_ssl matrix with actual protocol/settings/stream IDs |
| D2 | Selected-only standalone and mixed consumer, metadata/startup/shutdown |
| D3 | Frozen full/static/package/interop/churn/soak and Fetch 42-gate ledger |

## Sequence and acceptance

1. P0: inspect baseline, run existing suites, record contracts and this mapping.
2. P1: extract runtime/telemetry/dialing and stream API; migrate Fetch; prove F1/F2
   and individual package consumers before adapters depend on it.
3. P2: SSE options, bounded parser/delivery, asynchronous opening/reconnect and
   H2 adapter; deterministic tests and two independent SSE peers must pass.
4. P3: RFC8441 capability, immutable duplex purpose, header/profile support and
   protocol negatives while keeping Fetch/SSE tests green.
5. P4: WS H2 handshake, duplex frame I/O, bounded delivery/write/close and limited
   fallback; independent RFC8441 peer and mixed clients must pass.
6. P5: freeze executable candidate; run all required gates, 10,000 SSE events,
   10,000 WS messages, 1,000 reconnect/open-close cycles, >=1,800-second mixed
   soak, and unchanged Fetch 42-gate acceptance. Archive sanitized logs, exact
   commands, peer versions, budgets/maxima, seeds and checksum manifest.

Commit and push each completed phase. Release next minor version after successful
final acceptance using the repository workflow; verify CI, release/tag, all seven
Hex packages and standalone consumers. Do not count historical Fetch acceptance
as new stream-client acceptance. Record FAIL/BLOCKED/NOT RUN honestly.

## Risks and current progress

The baseline compile initially sees stale local 0.11.0 app metadata. An absolute
isolated build directory successfully compiles unchanged v0.15.1 with warnings
as errors. Relative MIX_BUILD_PATH is unsuitable for these child projects.
No source defect or dependency workaround is inferred from that cache failure.

P0 is complete and committed as `592cd780`. Baseline core/Fetch/SSE/WS suites
passed 633 tests and 20 doctests (three existing gated core skips).
P1 extraction is implemented and independently reviewed. Shared dialing retains
Fetch's existing protocol selection and cancellable worker algorithm. New stream
tasks expose generation-qualified notifications and opaque, idempotent FIFO
transport settlement; remote end releases after settlement, while GOAWAY keeps
accepted streams alive. Opening deadlines/liveness are checked before owner
writes, and cancellation/exclusive shutdown do not block behind a stalled owner.
The runtime caps supervised stream/dial tasks at 2,048; adapters must monitor
returned stream PIDs to settle runtime restarts. HTTP/1 and bodyful requests are
explicitly rejected by this initial bodyless stream adapter before admission.
Four unpacked standalone consumers passed, with no Fetch modules in SSE/WS
consumers and stable shared-runtime PIDs across individual client shutdown.

P2 implements ordinary H2 GET event streaming, explicit acknowledged delivery,
total event/part bounds, asynchronous opening, attempt-qualified timers and bounded
redirects. Public negotiated version is `:http1` or `:http2`; the internal stream
handle preserves `:h2` versus `:h2c` route provenance. Byte-stream clients preserve
valid pending DATA before terminal notifications; Fetch's default delivery path
and F1/F2 algorithms remain unchanged. Runtime ACK/EOF settlement is asynchronous.
Raw SSE input admits at most 1 MiB before withholding credit and reserves the
advertised stream window separately; adjacent safely admitted chunks are packed
without raising parser/event limits. Invalid queued input does not discard already
accepted acknowledged deliveries. The independent backend matrix and churn are
recorded in the validation document; full final-source acceptance remains P5.

P3 adds peer SETTINGS 8 capability and immutable `:request` / `:extended_connect`
stream purposes. Capability waiters consume no pool stream slots; ordinary siblings
can pass an unknown-capability waiter, and known refusal is typed without opening
CONNECT or discarding a healthy owner. Later enablement is per owner; capability
and concurrent-stream capacity are observed atomically before waiter dispatch. CONNECT
pseudo-header ordering extends each profile after `:method`; ordinary ordering and
factory settings remain unchanged. A 2xx response enters `:tunnel`, keeps outbound
scheduling, and ignores ordinary response body/Content-Length rules. Rejection
retains ordinary response bounds and denies tunnel writes.

The internal stream writer admits one frame-sized write at a time, capped by
`max_write_bytes` (default 16 MiB + 14 framing bytes). Adapters must bound their
own queue and wait for `:done`; the runtime forwards generation-qualified accepted,
progress, done, and error notifications. The owner schedules 16 KiB quanta through
its existing scheduler alongside Fetch uploads. Zero credit does not block control
processing or cancellation. Remote EOF retains a tunnel reservation until local
half-close and receive settlement, or explicit cancellation. Local half-close is
an empty END_STREAM DATA write, allowed at zero credit. Empty non-terminal writes
complete as no-ops. Invalid/non-finite writer limits reject before admission;
opening-stage writes receive typed errors. New SETTINGS 8 violations send a
PROTOCOL_ERROR GOAWAY, preserving preceding opt-in byte-stream data. A bounded,
monitored capability wait also covers exclusive
(non-reused) owners before their initial SETTINGS.

P3 is complete: the final scoped suite passed 738 tests plus 20 doctests and all
strict quality gates, with raw-wire capability/tunnel regressions and independent
Fetch/SSE mixed routes. Its source/BEAM manifests and archive are recorded in the
validation document. P4 public WebSocket integration and P5 acceptance remain.

P4 is implemented and locally validated. WebSocket opens RFC 8441 tunnels through
the shared Stream adapter, keeps HTTP/1 opening asynchronous, and restricts auto
fallback to protocol/capability unavailability before establishment. Its codec,
ACK/raw/send/control queues and fragment counts are bounded; close preserves the
current frame's byte order and releases only the logical stream. Internal terminal
errors stop parsing later bytes, while accepted bytes preceding external terminal
events still drain. Binary masking now builds binary words without per-byte lists.
The final independent audit passed 834 tests plus 20 doctests and all quality
checks, standalone traffic/start-stop checks and mixed/fault gates. Three WS
routes completed 10,000 round trips and 1,000 real cycles passed. Phase evidence
and exact snapshot differences are recorded in the validation document. P5 will
freeze version 0.16.0 and rerun all executable acceptance, including Fetch42 and
genuine 1,800-second Fetch and mixed-client soaks, before authorized publication.

WebSocket buffering must reject an oversized declared frame before receiving its
payload. Shared telemetry must preserve Fetch event names without calling Fetch.
Profile ordering must explicitly retain `:protocol` for Extended CONNECT without
changing ordinary Fetch wire bytes. Acceptance budgets must be frozen before
running workloads and evidence invalidated after executable changes.

P5 preparation freezes the shared seven-package version at 0.16.0. The explicit
slow entrypoint is `scripts/http2_stream_clients_acceptance.py`; its manual CI
workflow exports an immutable Git tree and saves gate logs/manifests. It runs all
42 preserved Fetch gates plus 36 new SSE/WS/package/docs gates. SSE churn uses
1,001 stream opens to prove 1,000 actual reconnects, and WS uses 1,000 cycles.
Both hyper-h2 and Node/nghttp2 independently observe simultaneous Fetch/SSE/WS
traffic. The Fetch and mixed-client soaks each require genuine 1,800-second
completed-workload markers. Signal interruption settles runner process groups;
candidate drift or added executable files fail before acceptance can pass.
Published consumer mode runs only after release and checks Hex SCM, exact versions,
package identities, isolated code paths and fresh locks without local path pins.

Historical P5 executable acceptance completed on commit
`d99b9de655b3367c91eea0d59af14cc4b0afa7a7`, tree
`01dd03d447f709b27dea32f74d95050edadfbc18`. All 42 preserved Fetch gates and 36
new gates passed, including both genuine 1,800-second soaks. The final report
maps A0–D3 to outcomes, sampled resources, exact workload counts and an accessible
source/log/checksum archive. The initial Node SSE terminal-fixture race was fixed
with explicit post-Open controls and all final routes rerun; no runtime change
followed the accepted P4 source. Evidence/docs-only commits preserve this
executable candidate. Authorized release and fresh published consumers follow
the completed acceptance; production rollout remains a separate operation.

The later task-baseline fixture, Hex-cache isolation and HTTP/1 WebSocket
handoff repairs require a fresh frozen candidate. The original accepted archive
remains historical evidence; final acceptance and publication are pending until
the new whole-source run finishes. The H1 repair preserves validated Upgrade
bytes on terminal ownership transfer and stages subsequent data/EOF in order
within existing raw-byte/count bounds. Opening deadline and cancellation remain
active while the result is pending. F1/F2 and all 78 gates are rerun unchanged.

Final requirements review adds explicit H2 SSE comment-heartbeat idle coverage:
connection PING and sibling DATA do not refresh its token; acknowledged local
pausing remains covered separately. This test and corrected README option/package
statements require refreezing the whole source before final acceptance. Runtime
algorithms remain those of da7adbb.

The SSE mixed fixture now waits for independently observed cancellation of the
exact stream before its two-sibling trigger. Local close is not a remote
acknowledgement. The new bounded barrier retains all mixed traffic assertions;
both peers and all transport routes passed preparatory checks.

F1 warm-up now explicitly waits for the exact coordinator to terminate after
releasing its reservation. Delivery of the warm response alone did not ensure
a free reusable slot. This test-only precondition repair preserves all early
response/cleanup/wire assertions and requires refreezing the full candidate.
