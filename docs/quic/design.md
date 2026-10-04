# Detailed design constraints

Proposed implementation; module names are targets. This document complements, rather than replaces, the task breakdown in [implement-plan.md](implement-plan.md). Standards/source identifiers are listed in [sources.md](sources.md).

## Module boundaries

| Target | Responsibility |
|---|---|
| `Quic` / connection and stream handles | Explicit application operations; handles include connection identity/generation |
| `Quic.Engine` | Immutable transport transition state and ordered effects |
| `Quic.Connection` | `:gen_statem`, current TLS/transport states, effect execution, deadlines and application ownership |
| `Quic.Endpoint` / `Quic.CIDRouter` | Admission, provisional Initial lookup, CID registry and connection lifecycle |
| `Quic.Wire.*` | Version-aware packet/header/frame/varint codecs |
| `Quic.Protection.*` | Initial, packet AEAD, header protection, Retry and key phases |
| `Quic.TransportParameters` | Ordered serialization and semantic/role/CID validation |
| `Quic.CryptoStream` / `Quic.RangeSet` | Sparse bounded CRYPTO storage, emitted byte retention and ACK/loss bookkeeping |
| `Quic.Recovery` / `Quic.Congestion.NewReno` | Sent-packet metadata, RTT, loss/PTO, congestion and pacing |
| `Quic.Stream` / `Quic.FlowControl` | Stream state, final size, offset accounting, cancellation and credit |
| `Quic.TLS.ExSSL` | Serialized public-provider calls and typed return adaptation, no copied handshake logic |
| `Quic.Inspector` / `Quic.Profile` | Passive observation and capability-validated wire policy |
| `Quic.IO.GenUDP` / external IO behaviour | Socket operations or borrowed send capability with explicit outcomes |

Keep modules small and functional. Avoid a process wrapper for each data structure, dynamic atom creation from peer input, and macros that hide protocol transitions.

## Engine inputs and outputs

Inputs distinguish received datagram, application operation, consumer credit, TLS result, local send outcome, timer expiry, entropy completion and endpoint failure. Include an operation identifier and generation where delayed responses are possible. Time is an explicit monotonic value in one documented unit.

Effects distinguish TLS initialization/feed, datagram send reservation, route installation/retirement, application delivery, observations and deadline updates. The engine cannot report successful network delivery merely by producing a send effect.

The connection interprets TLS effects synchronously and folds returned actions before accepting the next dependent TLS operation. Actual credential loading is outside per-datagram processing. Test-only recorded TLS results make transport simulations deterministic; genuine TLS tests use provider-generated fresh keys.

## Datagram and packet processing

A received value carries bytes, remote socket address, local destination/bind address, endpoint ID, generation and monotonic receipt time. Optional ECN/interface metadata is represented explicitly; absence is not fabricated as measured data.

Split a datagram only at valid QUIC packet boundaries. Packet numbers, encryption levels, CRYPTO offsets and stream offsets are different identifiers. Never concatenate decrypted payloads from different levels and feed them as a single TLS stream. Reject or discard malformed input in the correct authentication/version context. [S1,S2]

The inspector may report malformed/incomplete captures without generating any network error. A live endpoint follows QUIC's discard-versus-close rules. Do not convert every parse failure from arbitrary UDP into CONNECTION_CLOSE.

## CRYPTO and stream storage

Use ordered sparse intervals plus byte/item counters. Normalize overlaps consistently, detect contradictory data where policy/spec requires, and suppress duplicates. Store only needed bytes; do not allocate to the largest received offset. Bound out-of-order intervals, buffered levels and distinct contexts.

Retain exact emitted TLS bytes with stable per-level offsets. Delivery to TLS and acknowledgement of sent CRYPTO are separate progress markers. ACK/loss references ranges; retransmission re-packetizes information and never recreates a ClientHello or repeats a TLS feed.

For streams, keep sent offset, unique flow-control consumption, acknowledged ranges, receive final size, contiguous received/consumed position and local/peer limit state. FIN/RESET_STREAM must not change a previously established final size. Cancelling one stream must not discard required connection-level protocol work. [S1]

## Send receipt model

Use four states: prepared/reserved, writer-admitted, locally sent or failed, and peer-acknowledged/lost. The first two do not create a measured RTT sample. Congestion, pacing and anti-amplification reservations include work waiting in the writer so several queued sends cannot overspend the same budget.

Allocate a packet number once and never recycle it after attempted construction/encryption or an ambiguous send failure. On definitive local failure, release reservation and return unsent information to scheduling without presenting it as network loss. Report attempted and successful bytes separately.

With separate receive/writer processes, an authenticated ACK can be observed before its corresponding local-send receipt is processed. Represent that race explicitly: defer resolution for known pending packet numbers within a bound, or use a documented ordering design that proves the race impossible. Do not incorrectly diagnose a peer for acknowledging a packet whose send completion is merely delayed locally. ACKs for genuinely never-issued packet numbers remain protocol violations. Test this race.

## Recovery, deadlines and fairness

Each packet-number space maintains its own receive ranges and sent-packet history. Connection/path state owns RTT, congestion, pacing and amplification policy as appropriate. Apply packet/time threshold loss detection and PTO from a documented RFC9002 requirements map. Do not make one timer per packet. [S3]

Maintain one next-needed deadline per connection, selected from loss/PTO, ACK scheduling, pacing, idle/handshake/path timeouts and close/drain deadlines. Carry a token and generation; ignore superseded timers. Cap processing per event so a large ACK/range list or handshake flight cannot monopolize a scheduler indefinitely.

## CID, paths and versions

An established route is keyed by local endpoint and destination CID, not solely the remote IP/port. Keep provisional Initial routing before server-issued CIDs and validate collision/admission behavior. Different peers reusing an untrusted original DCID must not share TLS state accidentally. Endpoint-wide registration of all active local CIDs precedes outgoing advertisement.

Track original DCID, current peer/local CIDs, Retry context and address-validation state independently. Authenticate transport-parameter CID relationships. Receiving an authenticated packet from a changed address does not authorize unlimited sending to that address. [S1]

Use a version-parameter module from M1. v1 is the first implemented transport. v2 requires its own wire mapping and protection constants; unknown-version observations return unsupported, not guessed v1 results. Optional version extensions must not be advertised before support. [S6]

## Application and observation APIs

Design connection, stream, send, receive, shutdown/reset, information and close operations as explicit results. `send` is bounded queue admission, not peer acknowledgement, unless a separately named acknowledged-send API exists. Timeouts cancel or detach waiters without corrupting retransmission state; document accepted-byte ownership.

Observation events include opaque connection/capture ID, direction, hello sequence, source visibility, transport/version, fingerprints and optional raw fields. Default logs/telemetry use redacted summaries. Raw ClientHello bytes can contain SNI or PSK-related values; exposing them is explicit diagnostic policy, not a default metrics label.

## Memory and security invariants

Every buffer needs both an amount limit and an entry-count limit. Add endpoint totals in addition to connection limits. Keep a finite handshake lifetime and finite incomplete-inspection TTL. Admission loss cannot spawn per-packet retry tasks. Do not log traffic secrets, private keys, arbitrary action maps or full payloads.

Avoid retaining small sub-binaries that pin entire long-lived source datagrams; deliberately copy retained slices when beneficial and test heap behavior. Keep protocol state out of shared ETS; ETS/atomics may serve bounded routing/admission counters with one clear lifecycle owner.

## Protocol support matrix

By M6 enumerate every baseline v1 frame, role, legal encryption level, error domain and test. In a partial milestone return explicit unsupported/local-capability outcomes rather than claiming full support. A later HTTP/3 layer owns h3-specific controls and QPACK. The transport does not default to h3 or send arbitrary application bytes to an HTTP/3 peer. [S5]
