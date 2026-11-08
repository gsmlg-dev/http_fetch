# HTTP/3 client extensions and QUIC completion

Status: approved by the user on 2026-11-08, with explicit authorization to split
implementation into concurrent tasks. This is a source-backed design; no
capability, interoperability, or implementation completion is claimed.

Baseline: current checkout `main`, commit
`44251b363808871c32fc7106f97044bf73dc0d5d`, package version `1.0.0-rc.9`.
Preserve the existing untracked `2026-11-07-http-test-http-pool-phase1-plan.md`.

## Scope and responsibilities

The user requested continued work on HTTP/3 clients, WebTransport, WebSocket over
HTTP/3, explicit client migration, QUIC resumption, and 0-RTT. This project's
server responsibility is UDP, TCP, SSL/TLS, and QUIC. HTTP/3 application serving
belongs to gaoxy. Independent/reference servers are acceptance fixtures; they do
not add an HTTP/3 server product to this project or authorize changing gaoxy.

Retain the approved transport architecture in
`2026-11-07-quic-migration-and-early-data-design.md`. M1 exists in source. M2,
R1, and R2 remain implementation milestones, each requiring fresh acceptance.
The new design below supplies the HTTP/3 client work previously excluded there.
It does not turn the earlier exclusion into an implementation claim.

Work in this checkout and branch. No new branch/worktree, commit, push, version
bump, release, or external project changes are authorized by this design.
The user requested continued implementation. The existing transport design is
reused; review of this document selects the newly added application-layer
protocol profile and implementation contracts before their implementation.

## Source findings

| Area | Current source behavior | Work required |
| --- | --- | --- |
| HTTP/3 Fetch/EventSource | Explicit verified H3, pooled owners, streamed DATA, ordered upload/response trailers, cancellation and GOAWAY | Preserve and regression-test these clients as extensions are added |
| `QuicHttp3.Session` | Caller-driven bounded operation reconciliation, static/literal QPACK, fixed local SETTINGS | Add explicit extended-CONNECT purpose and extension negotiation |
| Peer streams | Unexpected peer bidirectional streams are rejected; unknown uni types are discarded | Add negotiated WebTransport classification and session ownership |
| WebSocket | H1 and H2 runtimes; H2 has extended-CONNECT handshake validation | Reuse framing, limits and lifecycle through an H3 adapter |
| WebTransport | Public API, streams, promises and session lifecycle; default network backend returns unsupported | Supply a real H3 backend and audit its capacity/lifecycle contract |
| QUIC migration | Public capability is `peer: [:server], local: []`; one standalone socket | Implement the approved exclusive-client two-socket M2 contract |
| QUIC TLS | `SSL.QUIC.capabilities()` reports resumption/0-RTT false | Implement approved R1/R2 public continuation and transport boundaries |
| Reliable stream reset | No `RESET_STREAM_AT` codec, parameter or stream semantics | Required before claiming the selected WebTransport profile |

Relevant implementation owners:

- `apps/http_core/lib/http/h3/settings.ex`: shared pure SETTINGS primitives.
- `apps/elixir_quic_http3/lib/quic_http3/{session,control,response,stream}.ex`:
  pure/client application state, framing, stream classification and negotiation.
- `apps/http_runtime/lib/http/http3/{connection_owner,stream,pool_key}.ex`:
  live ownership, delivery credit, leases and connection reuse.
- `apps/http_web_socket/lib/http/web_socket/{options,connection,handshake,frame}.ex`:
  public selection, established WebSocket behavior and frame semantics.
- `apps/http_web_transport/lib/http/web_transport/{session,options,transport}.ex`
  and `transport/quic.ex`: existing API-to-network boundary.
- `apps/elixir_quic/lib/quic/{endpoint,connection,handshake_scheduler,paths}.ex`,
  `io/{gen_udp,endpoint}.ex`, stream/recovery/cleanup modules: transport work.
- `apps/ex_ssl/lib/ssl/quic.ex` and its pure TLS dependencies: QUIC TLS work;
  read `apps/ex_ssl/AGENTS.md` and its architecture documents before implementation.

## Approaches and selected order

1. **Recommended: complete QUIC milestones first, then client extensions.**
   M2 -> R1 -> R2 -> H3 extended CONNECT -> WebSocket/H3 -> reliable reset ->
   WebTransport. This preserves the existing migration-first design, separates
   authentication/replay failures from new application framing, and makes each
   step independently reviewable. WebTransport arrives later.
2. **Application-first alternative:** H3 extended CONNECT -> WebSocket/H3 ->
   reliable reset/WebTransport, followed by M2/R1/R2. It delivers new application
   protocols sooner; they initially retain ordinary full-handshake 1-RTT behavior.
3. **Single combined change:** shortest apparent route to a feature checklist,
   but combines socket ownership, TLS state, and several application parsers in
   one acceptance boundary. Do not select this approach.

The user approved concurrent execution after reviewing this design. The order
above remains the logical milestone/acceptance order; independent TLS,
transport, HTTP/3 and WebTransport work may start concurrently under exclusive
file ownership. Dependencies are explicit: extended CONNECT precedes
both application clients; reliable reset additionally precedes modern WebTransport;
R1 precedes R2. WebSocket/WebTransport do not inherently require resumption or
0-RTT, and their first supported profiles use post-handshake 1-RTT operations.

## M2: explicit client migration

Reuse the approved `Quic.migrate(connection, local: {ip, port}, ref: ref,
deadline: bound)` contract. Start with one connection on an exclusive standalone
client endpoint. Reject shared/external endpoints, preconfirmation calls, peer
disable-active-migration, insufficient unused CIDs, and a busy two-path budget
before allocating another socket.

Endpoint owns both sockets and authenticates the ingress socket/path generation.
Register candidate resources with `Quic.Cleanup` before traffic. Connection and
scheduler transitions remain asynchronous across Endpoint/Connection boundaries;
do not introduce a synchronous call cycle. Bind/probe/validate/commit/retire is one
deduplicated operation. Admission is separate from final outcome. Resolve caller
timeouts through retained refs; never replace a connection to simulate migration.

Retain the unchanged server-address validation while resetting new-path counters,
RTT, congestion and MTU state. Admit the client's first padded probe without fresh
receive credit under the approved RFC 9000 rule. After validation, send a
non-probing packet on the new local socket/CID. Keep the old socket until local
send receipts and bounded recovery permit retirement. Failure preserves a usable
old path or completes ordinary connection cleanup.

Acceptance: actual Quic client against an independent server; source-port then
source-IP changes, same connection/stream, exact bytes and FIN, DATAGRAM traffic,
zero-receive-credit first probe, peer-disabled migration, CID exhaustion, bind
failure, validation loss, duplicate refs, owner death and socket cleanup receipts.
Expose `migration: %{peer: [:server], local: [:client]}` only after acceptance.

## R1 and R2: resumption and early data

Implement the approved design without changing TCP TLS policy:

- R1 adds pure public `SSL.QUIC.continue/3` actions, exact-transcript binder and
  fresh DHE validation, bounded endpoint-local stores, atomic single-use ticket
  consumption, trust/name/ALPN/profile partitioning, expiry and redaction.
- Prove full then resumed flights with an independent peer in each role.
  Include HRR, invalid binder/Finished, stale/duplicate/concurrent ticket use,
  changed trust/name, authority timeout, store failure and restart. Early data
  stays disabled until this milestone passes.
- R2 adds the early encryption level in the existing application packet-number
  space. Endpoint opt-in and per-operation `early_data: :replayable` are required.
  STREAM/DATAGRAM reservations, staged ciphertext and aggregate quotas remain
  independently bounded. No automatic application replay follows rejection.
- Withhold Finished at the independent peer to prove early packets exist while
  application delivery remains blocked; then verify exact eventual bytes/FIN.
  Test rejection, remembered limits, quota isolation, stale stream epochs,
  teardown and monotonically increasing application packet numbers.

TLS resumption is not path validation. R2 supports transport early data with
application delivery after handshake completion. The initial HTTP clients continue
to send their requests/CONNECT and application data after readiness. Enabling
automatic early Fetch, WebSocket or WebTransport operations is outside this design;
it needs a separate application replay/remembered-SETTINGS contract.

## H3 extended CONNECT and runtime ownership

Add an explicit client CONNECT operation to `QuicHttp3.Session`, rather than
loosening ordinary request validation. Preserve HTTPS authority/path/scheme and
permit `:protocol` only for the selected extension. Wait for peer
`SETTINGS_ENABLE_CONNECT_PROTOCOL=1` before sending extended CONNECT. A missing
setting after SETTINGS receipt is a refusal; absence before receipt is pending
under the opening deadline. No HTTP/1 or HTTP/2 fallback/replay occurs.

A successful 2xx opens the bidirectional DATA tunnel, with sending direction left
open. Informational headers and rejected final headers remain distinguishable.
Tunnel data uses a dedicated response state so ordinary HTTP content-length,
trailers and body-completion rules are preserved for Fetch/EventSource. FIN,
reset, STOP_SENDING, GOAWAY and connection failure have explicit once-only terminal
events. Closing a tunnel does not close pooled sibling requests.

`HTTP.HTTP3.ConnectionOwner` remains the sole consumer of its underlying QUIC
connection. It owns control/QPACK streams and demultiplexes normal requests,
tunnels and negotiated WebTransport streams/datagrams. Clients receive bounded
events with consumption acknowledgements; they cannot independently drain QUIC
events. Reserve progress for control/cleanup work and cap pending tunnel/session
opens using the existing finite owner stream and receive budgets.

Retain absolute operation deadlines, known blocked versus unknown admission, and
cleanup receipts. An indeterminate public backend write returns an explicit
indeterminate-operation error with its ref; it does not report ordinary success
or invite a blind retry. Keep total retained extension data inside the owner's
existing default 262,144-byte application budget, with separate finite item and
stream limits. Do not bypass it by forwarding into an unbounded client mailbox.

Include negotiated application policy in reuse eligibility and pool identity.
Exclusive endpoint ownership must be explicit before forwarding a migration call;
ordinary shared HTTP owners cannot be migrated by an arbitrary request consumer.
First expose migration through raw Quic and the caller-owned H3 Session. Adding
public migration controls to pooled Fetch/WebSocket/WebTransport handles is a
separate follow-up contract, not an implicit effect of the raw API.

## WebSocket over HTTP/3

Select explicitly with `HTTP.WebSocket.new(..., http_version: :http3)`, initially
for `wss` URLs. Keep the existing default and H1/H2 behavior. Reuse shared option
normalization with H3 enabled, reject explicit TCP `tls_backend`, and preserve
QUIC certificate/reference-identity verification.

Use RFC 9220 extended CONNECT with `:protocol=websocket`, RFC 8441 handshake
rules, 2xx acceptance, subprotocol validation, and no HTTP/1 Upgrade/key/accept
fields. Retain the existing RFC 6455 frame codec, client masking, message/control
limits, fragmentation, ping/pong and Close handling. The adapter only translates
H3 tunnel DATA/credit/terminal events; it does not duplicate the WebSocket parser.
Drain a received Close before treating a later stream FIN as abnormal closure.

Acceptance: independent RFC 9220 server; exact text/binary and fragmented messages,
ping/pong, close code/reason, Close plus FIN ordering, tiny receive credit,
oversized frames, opening refusal, unsupported subprotocol, TLS negatives,
cancellation and retained sibling request operation. Existing H1/H2 wire gates
must continue to pass. A fake transport alone cannot enable the H3 capability.

## WebTransport protocol profile and prerequisites

Pin the new profile to **draft-ietf-webtrans-http3-17**, as retrieved from IETF
on 2026-11-08. Pin its reliable-reset dependency to
**draft-ietf-quic-reliable-stream-reset-11**. These are draft support claims,
not final-RFC or universal browser compatibility claims.

The inspected profiles differ materially:

| Profile | WebTransport setting | Extended CONNECT token | Reliable reset |
| --- | --- | --- | --- |
| Current shared codec | `0x2c7cf000` | No network backend | Not implemented |
| aioquic 1.2.0 source | `0x2b603742` | Historical profile | No implementation found in the inspected H3 source |
| Proposed draft-17 | `0x20b8933b` | `webtransport-h3` | Negotiated `reset_stream_at` required |

Existing codec names/codepoints are not proof of a complete protocol version.
Preserve previously exposed codec behavior; add an explicit versioned profile for
the new codepoint rather than silently redefining the existing public setting.
Advertise/select exactly the implemented profile. Unsupported draft negotiation
fails explicitly; no legacy fallback or silent codepoint substitution is added.

Implement negotiated `RESET_STREAM_AT` in QUIC before WebTransport admission:
parameter and frame validation, reliable-prefix/final-size accounting, receive
reassembly under loss/reordering, stream credit, recovery and event semantics.
Resetting a WebTransport stream must reliably deliver enough header bytes for the
peer to associate its session before application reset delivery. Do not substitute
ordinary RESET_STREAM or advertise a parameter with no supporting behavior.

Extend H3 with RFC 9297 HTTP Datagrams/Capsules: quarter-stream-ID association,
incremental capsule parsing, finite lengths, correct unknown-capsule skipping and
DATAGRAM payload limits after association overhead. Reliable control capsules
use CONNECT DATA; do not make application datagrams reliable.

Both endpoints must negotiate the selected WT profile, H3 DATAGRAM, QUIC DATAGRAM
receive support and reliable reset; the server must advertise extended CONNECT.
The client validates all requirements before CONNECT. For draft-17, include the
draft negotiation setting as required by its section 7.1.

Start with **one WebTransport session per exclusive H3 connection**, with session
flow control disabled according to draft-17 section 5.1 (zero initial WT limits).
Enforce QUIC credit and local finite byte/item/stream limits. When session flow
control is not negotiated, ignore the corresponding flow-control capsules as
specified. Multiple sessions and the optional session-level flow-control extension
are subsequent work; do not advertise them. This keeps shared-session quota and
cross-application migration policy outside the first interoperable profile.

Recognize uni stream prefix `0x54` and bidi signal `0x41`, followed by Session ID,
before handing subsequent stream bytes to WebTransport. Associate by CONNECT
stream ID, not an arbitrary local ref. Bound reordered streams/datagrams awaiting
CONNECT acceptance within the same receive budget; reset excess streams, drop
whole excess datagrams, and discard rejected-session data. Expose streams/data
only after successful session acceptance. Close/drain capsules, application error
code mapping and reliable-reset header lengths follow the pinned draft.

Implement the existing `HTTP.WebTransport.Transport` behavior behind
`Transport.QUIC`. Add its dependency on `http_runtime` through the existing exact
coordinated umbrella version; the runtime already owns `elixir_quic_http3`.
No new third-party runtime dependency is proposed. Audit owner monitoring, waiter
counts, stream/byte queues, datagram expiry and terminal notifications before
connecting the currently API-only session to network input. Bounded protocol
buffers do not make unbounded public waiter lists safe.

Acceptance requires a separately implemented server pinned to the same profile
and reliable-reset version. Pin its immutable source/tool identity before feature
implementation. Stock aioquic 1.2.0 remains useful for existing HTTP/3, QUIC, and
WebSocket tests; it cannot establish draft-17 WebTransport acceptance. If no
matching independent implementation is available, mark this acceptance BLOCKED
and keep the WT capability false. Do not modify gaoxy or a peer to mirror our
implementation and call that independent acceptance.

Exercise both-direction bidi/uni streams with exact bytes and FIN; empty,
duplicate and boundary datagrams; stream reset before header acknowledgement;
reordering before CONNECT acceptance; malformed session IDs/capsules; blocked
writes; unsupported settings; close/drain; owner death and finite cleanup.
Independent Chromium interoperability is an additional separately reported gate
for the browser version's actual negotiated profile, not inferred from this one.

## Verification, delivery and status reporting

Each milestone begins by characterizing current behavior and adding meaningful
regressions. Prepare/test apps from the umbrella root using the locked dependency
graph. Serialize shared Mix state. Use a task-owned build path if needed without
repairing caches through source/lockfile changes.

Run targeted pure tests, integration tests and independent wire gates, then
formatting, strict compilation, Credo and applicable Dialyzer/docs checks.
Preserve actual failing evidence and distinguish PASS, FAIL, BLOCKED and NOT RUN.
Capabilities become true only when their complete advertised profile passes.

Allowed implementation paths after review are the listed apps and their tests,
the existing protocol docs, protocol-specific peers under `scripts/`, and required
package graph/CI routing. Any exact internal dependency declaration change must
also update the package/consumer inventory checks that enforce that graph.
Shared workflow/tooling changes require full manual regression once push/remote
execution is authorized. Publication stays publication-only: preparation/compile,
packaging, documentation and artifacts; tests and analysis belong to dedicated
CI/Test/Integration/E2E workflows. Earlier plans' release-time test wording is
superseded by this current repository policy.

Do not change lockfiles, package identities, licenses, unrelated user files or
default protocol/replay behavior without a concrete in-scope requirement.
No external issue is filed for missing capabilities owned by the in-scope imported
apps; external covered dependency blockers follow `upstream-issue-routing`.

Implementation, source tests, independent-peer traffic, published artifacts and
browser/production observations are separate outcomes. This document has only
source/standards inspection evidence. No new tests or network feature acceptance
have run during preparation; no code or capability flags have changed.

## Sources inspected

- Existing approved QUIC migration/resumption design and current source above.
- RFC 9000/9001/9002 and RFC 9221 for transport contracts; RFC 9846 for project TLS
  policy; RFC 9114 and RFC 9204 for H3/QPACK.
- [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220.html) and
  [RFC 8441](https://www.rfc-editor.org/rfc/rfc8441.html): WebSocket bootstrapping.
- [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html): HTTP Datagrams/Capsules.
- [WebTransport draft-17](https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-17.txt):
  current profile, token, requirements and single-session non-flow-controlled mode.
- [Reliable reset draft-11](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-11):
  WebTransport's pinned prerequisite; read full normative text before implementation.
- [aioquic 1.2.0 H3 source](https://github.com/aiortc/aioquic/blob/1.2.0/src/aioquic/h3/connection.py):
  older WebTransport setting and current independent-peer compatibility boundary.

## Review decision

Approve the recommended staged order and draft-17 single-session WebTransport
profile, including its reliable-reset prerequisite and independent-peer gate.
Then write the M2 implementation plan using the already approved architecture and
execute milestones in order. This approval covers implementation and local
verification in the stated paths, not commit/push/publication or other projects.
