# QUIC connection migration, resumption, and early data

Status: approved by the user on 2026-11-07; M1 implementation authorized.
This document records a staged feature design, not an implementation or
interoperability claim.

Baseline: `main` at `1d815a4e0c82f697f7ef689f9b06a1a0e1ef19da`.
The previous DATAGRAM RC and its test repairs are complete. This work starts from
that baseline and does not repeat their publication.

## Goal and delivery order

Allow an established QUIC connection to survive a client address change, then let
explicitly opted-in clients transmit replayable data while a resumed handshake is
in progress. Preserve Abyss's ready-before-handler contract, optional engine
dependency, finite operation deadlines, and receipt-based resource cleanup.

Use four milestones, each with its own implementation plan, actual-traffic gate,
and RC after acceptance:

| Milestone | Observable behavior | Primary owners |
| --- | --- | --- |
| M1 | A standalone Quic server or Abyss listener accepts authenticated client NAT rebinding and peer migration without replacing the connection or streams. | `apps/elixir_quic`, `apps/abyss` |
| M2 | An exclusive standalone Quic client explicitly changes its local UDP address while retaining the connection. | `apps/elixir_quic` |
| R1 | A second QUIC connection uses an authenticated PSK-DHE resumed handshake; early data remains disabled. | `apps/ex_ssl`, `apps/elixir_quic`, `apps/abyss` |
| R2 | Explicitly replayable STREAM and DATAGRAM operations can use 0-RTT; servers expose application data only after verified handshake completion. | `apps/ex_ssl`, `apps/elixir_quic`, `apps/abyss` |

This order is recommended because M1/M2 can establish path, CID, IO, and recovery
contracts without changing TLS authentication. R1 then isolates resumption from
early-data replay and transport-state rollback.

The alternative is R1/R2 before migration. It provides resumption sooner but puts
the security policy and new TLS continuation boundary on the first critical path.
Implementing everything in one release would make failures harder to attribute;
it is not the selected approach.

## Scope and compatibility

Work remains in the current checkout and branch. This design does not authorize a
new branch or worktree. Allowed implementation areas are the three apps above,
their tests and architecture/consumer documents, protocol-specific peers under
`scripts/`, and the existing CI/release gate wiring required to enforce acceptance.
Changes to shared release versions and exact internal requirements occur only as
part of the established unified RC workflow. Lockfile changes require a concrete
in-scope dependency need; no dependency change is currently proposed.

Keep HTTP/3's existing capability contract. This work does not add automatic early
HTTP requests, HTTP/3 SETTINGS replay, dynamic QPACK, WebTransport, multipath,
preferred-address migration, server mTLS, persistent/distributed ticket storage,
or QUIC revocation-policy integration. Hell, `abyss_raw`, and TCP TLS behavior
receive only required regression/release coverage, with no feature rewrite.

Normative sources are RFC 9000 (transport), RFC 9001 (QUIC TLS), RFC 9002
(recovery), RFC 9221 (DATAGRAM), and RFC 9846 (TLS 1.3). Follow the ExSSL
architecture/record-free adapter contracts when extending its pure TLS core.

## Current implementation boundaries

- `Quic.Endpoint.route/4` requires the registered remote address to match; only one
  local CID and one concrete local UDP bind are routed.
- `Quic.Connection.deliver/4` carries bytes and time, without arrival-path metadata;
  `flush/1` sends all packets to the connection's one remote address.
- `Quic.IO.Endpoint` correctly reserves amplification credit before a local send,
  but has one aggregate address-validation ledger.
- `Quic.HandshakeScheduler` owns pure TLS/recovery/stream scheduling. It has no
  usable path-validation state machine and rejects all local-CID retirement.
- `Quic.Recovery` owns three packet-number spaces and one RTT/congestion state.
- `Quic.PeerCIDs` tracks peer-issued CIDs, not local issuance.
- `SSL.QUIC` rejects PSK profiles, discards NewSessionTicket messages, and supplies
  no resumed session to the handshake core. TCP binder primitives exist, but the
  server core needs PSK selection, a resumed flight, and ticket issuance.
- Abyss creates its handler only after the engine accepts a ready connection.
  Keep that behavior throughout all four milestones.

## M1: reactive peer migration

### Path identity and ownership

Carry a path identity consisting of endpoint/socket generation, concrete local
address, remote address, and path generation from receive through authenticated
packet effects, IO reservations/receipts, recovery, and timers. Preserve the actual
incoming DCID as well. An address is not an authentication credential.

The endpoint may route a packet with an active local CID from a new remote address
to the existing connection. Only successful 1-RTT authentication can create a path
candidate or change send selection. Unknown CIDs and forged packets cannot create
path state. Before handshake confirmation, do not activate migration.

Keep at most two live path records: the selected path and one candidate or retained
previous path. Only one migration attempt is active. Additional unknown addresses
are dropped while that attempt settles, without a protocol close. Packet records
may retain a retired path generation within the existing bounded recovery history;
they do not keep additional live path controllers or sockets.

The highest authenticated non-probing packet number governs reactive peer-address
selection. Reordered traffic from the previous path cannot select it again.
Non-probing follows RFC 9000's frame definition. A path probe alone cannot redirect
application traffic. Preserve connection handles, stream handles, operation refs,
stream offsets, and packet-number progression.

### Validation, amplification, and failure

Maintain independent received, reserved, and locally-sent byte counters per path.
Track peer-address validation separately from path reachability and MTU validation.
All output to an unvalidated peer address, including probes and responses, must
fit its amplification allowance, including reserved and uncertain sends; credit
from a validated old path is not borrowed.
Retain the current distinction between queue admission, local send completion,
uncertain completion, and peer acknowledgment.

Use unpredictable eight-byte challenges, with at most three outstanding challenge
values per live path and generation-checked finite deadlines. A PATH_RESPONSE is
sent on the path where its PATH_CHALLENGE arrived. A matching PATH_RESPONSE received
on any path validates the path where that challenge was sent, as RFC 9000 §8.2.3
requires. Wrong, duplicate, expired, and superseded challenges have no effect.
Each retry uses a fresh value; do not blindly retransmit PATH_RESPONSE frames.

Pad validation probes to 1200 bytes when available credit permits. Track address
reachability separately from successful validation of a 1200-byte datagram. A
short valid response alone cannot certify that MTU. Start validation of the
previous active path as required by RFC 9000 §9.3.3; retain a usable validated
fallback during the attempt.

The validation deadline is finite, initially three times the larger old/new PTO,
and is also bounded by any explicit operation deadline and the connection's
lifecycle. Candidate failure restores the usable last validated path. If no usable
path remains, finish through the ordinary bounded connection-failure/cleanup path.
Packets already queued retain their selected path generation; never reinterpret
an uncertain old-path write as a new-path send.

### Recovery and congestion

Packet-number allocation and ACK ranges remain global to each of the existing
three spaces. Annotate sent packets with their send path. Attribute loss, bytes in
flight, and RTT to that path; cross-path ACK timing must not contaminate a new
path's RTT. ACK/loss of old-path packets cannot grow or reduce the new path's cwnd.
Reset new-path congestion and RTT conservatively, including port-only rebinding.
Reliable STREAM recovery can retransmit ranges on the selected usable path with
new packet numbers; DATAGRAM frames are never retransmitted.

### Local and peer connection IDs

Add bounded local issuance separately from `PeerCIDs`. Target
`min(4, peer_active_connection_id_limit)` issued, unretired local CIDs, with hard
capacity `min(8, peer_limit)`. Count initial sequence zero, unpublished route
reservations, and unacknowledged issuances against capacity. The independently
advertised receive limit bounds peer-issued CID storage.

Use consecutive published sequence numbers, one pending issuance, a highest-sent
watermark, and a bounded active map. Install a CID route before advertising its
NEW_CONNECTION_ID. Connection-to-endpoint requests and acknowledgments must be
asynchronous or returned as effects: Endpoint currently waits synchronously for
delivery, so Connection must not call it synchronously in return. Do not publish
the CID until registration is acknowledged for the same connection generation.

Valid RETIRE_CONNECTION_ID removes its active record, route, reset token, and
obsolete retransmission work. Repeated retirement below the highest-sent watermark
is idempotent. Coalesce replenishment into one request toward the target; defer it
under queue pressure rather than queuing one replacement per retired frame.
Legitimate rapid retirement is not a protocol violation. Unsent sequence numbers,
zero-length-CID violations, and retiring the containing packet's DCID receive the
RFC-appropriate error handling.

Individual retired local CIDs do not need three-PTO routing retention. The
connection closing/draining lifetime is separate. Recent-CID tombstones remain
bounded, and unknown established-connection traffic drops regardless of tombstone
eviction. Retired reset tokens never generate resets. Finite tombstones provide
only finite stale-Initial suppression; do not claim permanent Initial replay
exclusion or weaken the existing Initial/Retry admission checks.

Respect the peer's `disable_active_migration`. NAT rebinding still needs receive
and validation support, including traffic using the same active CID. A Quic client
does not accept an unsolicited change of the server's address in M1. Abyss retains
one shared listening socket and changes only per-connection peer paths.

### M1 acceptance

Use pinned independent aioquic clients against both standalone Quic and Abyss.
An owned UDP relay changes source port, then source IP, during an active stream.
Require the same connection/stream identities, exact bytes and FIN, and DATAGRAM
continuity without imposing reliable DATAGRAM delivery. Keep a second shared
listener connection active and prove it is unaffected.

Add deterministic adversarial cases for forged traffic, all probing frame shapes,
wrong/stale/duplicate/cross-path responses, reordered old-path packets, blocked
amplification including reserved bytes, validation loss and fallback, old-path
late ACK/send receipts, and local/peer CID churn/exhaustion. Assert bounded state
and protocol-correct retirement. Real integration cases use synchronization and
traffic receipts rather than sleeps to infer migration or cleanup.

## M2: explicit client migration

Add `Quic.migrate(connection, local: {ip, port}, ref: ref, deadline: bound)` using
the existing finite operation/ref contract. `{:ok, ref}` means admission. Expose
the final validation or failure through operation status/events; a caller timeout
does not imply no effect, and repeating a retained ref does not start another bind.

Initially permit only an exclusive standalone client endpoint with one connection.
Reject shared/external endpoints, pre-confirmation calls, peer-disabled active
migration, and exhaustion of suitable unused peer CIDs before starting a bind.
Migration does not silently create a replacement QUIC connection.

Enroll the candidate socket in the retained cleanup graph before it can produce
traffic. Keep the old socket until validation and outstanding-send settlement.
Probe, commit the new path, and close only task-owned obsolete sockets after
receipts establish settlement. Bind failure or failed validation leaves the old
usable path intact. Preserve global packet numbers and operation deduplication.

RFC 9000 §9.2 permits a client changing only its local address to retain validation
of the unchanged server address. The new path's byte counters start at zero and
its reachability, MTU, RTT, and congestion state start fresh. Its first padded
PATH_CHALLENGE may therefore be sent without new receive credit, subject to the
ordinary bounded admission/congestion policy. The server sees a new client address
and starts an unvalidated three-times-received ledger; the client's probe supplies
that credit. No old-path byte allowance is transferred. Once the client validates
the path, commit with a non-probing packet such as PING from the new socket using
its unused peer CID, so the server can select it for application traffic; probes
alone cannot do so. Reject another migration as busy while the two-path/socket
allowance remains occupied by validation or settlement.

Acceptance uses a real Quic client against pinned aioquic, with local source-port
and source-IP changes, exact stream/FIN continuity, DATAGRAM traffic, failed binds,
lost validation, duplicate refs, owner death, and confirmed two-socket retirement.
Explicitly test that a new client socket with zero received bytes admits its first
1200-byte probe while the server's resulting response allowance stays bounded.

## R1: QUIC-specific authenticated resumption

### Public pure TLS continuation boundary

Extend only the public `SSL.QUIC` adapter boundary. Quic must not call private
`SSL.Protocol.*` functions. Add `SSL.QUIC.continue(state, continuation_id, result)`
with the same success/error contract as `feed/3`, and one outstanding continuation
per TLS state. Reject stale, duplicate, and mismatched IDs. Abort destroys pending
session material. Use redacted opaque request/session structs.

The provider actions are session lookup, session commit, session store, and client
session-ticket receipt. The TLS core performs no process, filesystem, callback,
storage, or network IO. Internally reuse/extend exact-transcript binder and fresh
DHE primitives shared with the TCP core without changing TCP policy.

PSK lookup, binder verification, ticket consumption, and early-data acceptance
never validate the current client network address. A session ticket is not a QUIC
address-validation token. Keep server amplification limits until the ordinary
QUIC address-validation condition succeeds on this connection/path.

Server processing is ordered:

1. Parse and retain exact ClientHello bytes, validate structural constraints, and
   initially consider PSK identity zero. Legal additional identities may remain
   unselected.
2. Emit lookup; the runtime returns a miss or an opaque session and live lease.
   No selected-PSK flight, early secret, or early acceptance is emitted yet.
3. TLS checks compatibility and verifies the selected binder over the exact
   truncated ClientHello. A selected binder mismatch is fatal, with no fallback.
4. Emit commit. An independent endpoint-owned admission authority atomically
   consumes the still-live single-use ticket and, in R2, reserves early capacity.
5. Only a positive commit receipt permits the selected-PSK flight. A miss or lost
   lease before that flight permits a normal certificate handshake, rejecting
   early data. Capacity shortage permits PSK resumption with early data rejected.

Here a selected-PSK flight starts with the ordinary ServerHello selecting PSK,
distinct from HRR. The resumed HRR sequence below additionally consumes before HRR.

The authority is not Endpoint and never synchronously calls Endpoint, Connection,
or a handler. Pass its capability when creating a connection. Bound local requests
for lookup/commit by the existing handshake deadline and a shorter authority
deadline. The initial authority timeout is 100 ms; late replies are generation/ref
checked. Post-handshake store requests instead have a separate deadline of at most
100 ms, bounded by connection lifecycle; they cannot reopen or extend the handshake
deadline. No external
IO is performed by the authority. A timeout has an unknown consumption outcome:
it permits no PSK flight or ticket restoration. Abandon its reservation by ref;
quota remains charged until the authority processes release or observes owner
death. Full-handshake fallback is safe only before a selected-PSK flight.

Admit at most one outstanding authority request per connection and cap retained
authority requests at the endpoint's configured maximum connection count. Reject
over-capacity requests before allocating session/quota records. Released and
superseded requests cannot accumulate an independent unbounded history.

For HRR, validate CH1's binder and consume once before emitting HRR. Reject early
data and retain the consumed session only in that TLS state. Validate CH2's binder
over the rewritten HRR transcript without a second lookup/consume. Abandonment or
failure burns the ticket. The selected resumed path requires a valid CH2 binder.
An unselected/incompatible PSK offer may use the ordinary legal full-handshake/HRR
path; do not require a resumed binder for that path. Structurally invalid TLS
offers still fail as required by TLS.

After verified client Finished, register at most one new server ticket. Emit NST
only after store acknowledgment. A store failure skips the optional ticket without
failing the established connection. The client receives opaque session material
through the private runtime/cache action, never ordinary application event output.

### Cache, identity, and policy

Resumption is opt-in at the endpoint with `resumption: [enabled: true]`. Use
separate bounded QUIC client/server stores and no TCP session-cache namespace.

| Store | Initial limits |
| --- | --- |
| Server, endpoint lifetime | 1024 entries, 4 MiB, maximum 4 KiB per entry, 10-minute TTL |
| Client, endpoint lifetime | 128 entries, 4 MiB, maximum 32 KiB per entry, no longer than ticket/certificate validity |
| Server issuance | One ticket per successfully completed full or resumed handshake |

Enforce entry and byte ceilings, own bounded binary copies, and recheck monotonic
expiry on lookup and atomic consume. Oversized/unstoreable sessions skip caching;
eviction, expiry, and endpoint restart safely lead to full handshakes. Never
restore consumed tickets, even after a failed later handshake.

Partition by QUIC version, peer/reference identity, SNI, ALPN, trust/credential
policy, application-profile version, algorithms, and versioned cache schema.
Remember transport parameters separately. Hash static profile policy, excluding
ephemeral keys, generated CID/TP fields, binders, and ticket ages.

Before offering PSK or sending early bytes, revalidate the cached peer chain under
current trust anchors, certificate time validity, name/depth/hostname policy,
signature policy, algorithms, ALPN, and application context. A changed/ineligible
session is not offered; the new full handshake must satisfy current authentication.
Invalid current credentials never receive a weaker fallback. Selected-PSK or
Finished authentication failures are fatal.

QUIC currently exposes no CRL, OCSP, certificate-policy, or `verify_fun` seam.
Continue explicitly rejecting unsupported options; do not claim revocation-aware
QUIC resumption or copy TCP PolicyIO into the pure provider. That integration needs
a separate design if requested. Redact tickets, PSKs, leases, private keys, and
traffic secrets from logs, inspect output, status, and reports.

R1 acceptance requires independent aioquic interoperability in both roles, full
then resumed flights, binder vectors including HRR, changed trust/name/profile,
expired/unknown/reused/concurrently claimed tickets, authority timeout/late reply,
store failure, restart/eviction, no callback deadlock, and fresh DHE. Keep early
data disabled and prove no early application packet is emitted in this milestone.

## R2: opt-in 0-RTT transport

### Negotiation and operation semantics

Early data defaults off. Enabling it requires resumption and an explicit endpoint
policy such as `early_data: [enabled: true, application_profile: "protocol-v1"]`.
The application-profile version is required and bound into the ticket context.
Before ready, STREAM open/write and DATAGRAM send additionally require
`early_data: :replayable` on each operation. Unmarked operations retain ordinary
not-ready behavior. No HTTP consumer starts using this option automatically.

Model `:early_data` as an encryption level sharing the existing application
packet-number space, never a fourth space. Implement type-1 long headers, packet
protection/coalescing, bounded pre-key staging, level-specific frame legality,
and retransmission across key transitions without packet-number reuse. No ACK or
CRYPTO frames are sent in 0-RTT; ACKs for early packets are sent in 1-RTT. QUIC
never sends TLS EndOfEarlyData. NST's QUIC early-data maximum is `0xffffffff`.
HRR rejects early data; Retry alone does not imply TLS rejection.

Before early keys are available, retain at most 16 candidate early UDP datagrams
and 32 KiB per connection, under a separate 1 MiB endpoint staging quota. Drop
whole excess datagrams, without treating staging loss as a TLS rejection. Retained
ciphertext does not count as accepted plaintext or reserve reliable stream credit.
Keep existing TLS CRYPTO and connection-admission limits independently enforced.

Check TLS/ALPN/cipher continuity, ticket age, remembered transport parameters,
application policy, atomic ticket consumption, and quota before emitting early
acceptance in EncryptedExtensions. Parameter changes that make early transmission
unsafe reject early data without unnecessarily rejecting valid ordinary resumption.

Operations retain admission history and separately expose accepted/rejected early
outcomes through status/events. Rejection invalidates early stream epochs and
state, so stale handles cannot address a reused stream ID. Keep the live connection
handle. Repeating a retained operation ref never submits those bytes again.
Do not automatically replay application data after rejection or reconnect. The
application must explicitly submit new operations. Accepted reliable STREAM ranges
remain subject to normal transport retransmission; DATAGRAM never retransmits.

### Receive capacity and application delivery

Reserve reliable early capacity against the remembered *wire* allowance, before
accepting early data. Defaults for early-enabled ticket-issuing connections are
at most 64 KiB initial connection credit and eight bidirectional plus eight
unidirectional streams. Per-stream credit must fit the connection reservation.
Grant larger configured ordinary credit after readiness and remember the correct
initial parameters for future tickets. Do not silently accept a remembered
256 KiB/32-stream allowance behind a 64 KiB/16-stream private buffer.

Early packet construction uses immutable remembered transport limits. Fresh
handshake parameters and later MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS increases
apply to 1-RTT output, never additional 0-RTT packets. Installing fresh parameters
cannot reset offsets or credit consumed by accepted early streams. Tickets retain
the original handshake parameters, not later MAX_* credit increases.

Default reliable early reservation is 64 KiB and 16 combined stream slots per
connection. Keep explicit fragment/range and zero-byte-stream metadata bounds
within the existing stream and packet budgets. DATAGRAM, when enabled, has a
separate 64 KiB/64-item reservation and drops complete new messages on overflow.
It cannot consume the reliable-stream reservation.

The endpoint's aggregate payload quota is 8 MiB for unused reservation plus
retained early data. Receipt converts reservation to occupancy without double
charging. Fully reserving 64 KiB STREAM plus 64 KiB DATAGRAM allows at most 64 such
simultaneous early connections. Additional connections resume with early rejected.
This is a payload budget, not a bound on total VM memory: pending handshakes, TLS
bytes, staged packets, fragments, metadata, and authority requests remain bounded
independently. Oversized or incompatible remembered allowances reject early data.

`ready` stays false until verified Finished and authenticated transport-parameter
checks pass. Before then no pull, event, or Abyss handler may read early application
bytes. On readiness, transfer retained data into ordinary ownership, queue ready
before readable notifications, and avoid duplicate delivery. That transfer releases
the early quota without duplicating ownership in ordinary bounded receive storage.
Failure discards all
retained early application data and releases reservations through owned receipts.

The precise support claim is **0-RTT transport with application delivery after
handshake completion**. It does not provide server application responses before
Finished or exactly-once processing across connections. Single-use atomic tickets
constrain replay within one authority lifetime; ticket sharing across instances
and distributed replay guarantees are outside this design.

R2 acceptance must observe actual early STREAM/DATAGRAM packets on the second
connection, before handshake completion, against independent aioquic in both roles.
Withhold Finished to prove no application delivery, then release it and verify
exact eventual STREAM/FIN delivery and DATAGRAM message boundaries. Cover rejection,
no automatic replay, concurrent ticket reuse, HRR/Retry, capacity exhaustion,
remembered-limit mismatch, DATAGRAM/STREAM quota isolation, zero-byte-stream floods,
rejected-handle reuse, invalid binders/Finished, teardown/late receipts, and
monotonic packet numbers across 0-RTT/1-RTT. Run a final scenario combining resumed
early traffic with a later validated migration.

## Capability, verification, and RC gates

Add role-specific migration capability reporting rather than a generic true flag:
after M1, `migration: %{peer: [:server], local: []}`; after M2,
`migration: %{peer: [:server], local: [:client]}`. Resumption becomes true only
after R1 acceptance; early-data support is reported only after R2 acceptance.
Here `peer` reports acceptance of a changed remote address. Both roles implement
PATH_CHALLENGE/PATH_RESPONSE semantics; M2 changes the client's local path while
retaining the established server address.
Support reporting is separate from enabled endpoint/connection policy in `info/1`.
Keep `http3: false` in raw Quic. Update consumer contracts and implementation
matrices with each accepted capability; parsers alone are not support evidence.

For each milestone:

1. Add deterministic state/vector/negative regressions and independent socket
   acceptance. Protocol IO, filesystem, and process cases belong to integration.
2. Prepare and run all app tests from the umbrella root. Serialize shared build
   state. Use isolated task-owned build paths only when needed; do not repair
   state by changing a lockfile or modifying unrelated caches.
3. Require formatting, strict compilation, Credo, applicable Dialyzer/docs checks,
   affected TLS/QUIC/Abyss tests, and exact-byte independent traffic acceptance.
   Retain failed first attempts and diagnose before retrying.
4. Review the final integrated diff, then commit/push within the already authorized
   release workflow. Wire new gates into source and candidate/published consumers.
   Shared tooling/workflow changes require the repository's manual full regression.
5. Use the next unclaimed RC version through the existing `release.yml` inputs
   `version`, `git_ref`, `publish_docs`, and `defer_static_analysis`. The unified
   workflow covers eleven portable packages plus asynchronous `abyss_raw`; do not
   invent a separate Abyss release path or defer failing checks silently.
6. Verify tag/source identity, workflow jobs, all twelve GitHub/Hex artifacts,
   documentation/source parity, and a fresh published-only consumer that exercises
   the milestone. Retain native and no-OTP-SSL evidence under their existing scopes.

Every gate records PASS, FAIL, BLOCKED, or NOT RUN, with immutable source/tool
identity, concrete commands, exit codes, byte/FIN checks, finite deadlines, and
cleanup receipts. A localhost relay proves controlled address-change acceptance;
it is not distributed-network acceptance. Do not label an unfinished later
milestone complete because an earlier RC passed. Stop after verified authorized
delivery, preserving any concrete blocker and the next milestone's status.

## Approval decisions

Approval of this written design selects the migration-first sequence, the bounded
CID/path policy, exclusive-client local migration, endpoint-local single-use
ticket stores, default-off early data, reduced initial wire credit on early-enabled
listeners, separate early DATAGRAM capacity, buffered-until-Finished delivery,
and no automatic application replay. It keeps the explicitly listed larger
protocol and revocation-policy features outside these milestones.

After approval, write and execute the M1 implementation plan in this checkout.
Use the same approved architecture for the subsequent milestone plans. Return for
scope/design review only if new evidence requires a consequential change to these
contracts or acceptance criteria.
