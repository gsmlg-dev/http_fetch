# Architecture — ex_quic, revision 3

2026-09-23. Proposed implementation architecture. Public ex_ssl interfaces below exist at the reviewed pin; all QUIC/Abyss adapter module names below are target interfaces, not claims of implemented code.

## Product boundary

Build three first-class surfaces: a bounded passive Initial inspector, a profile-controlled QUIC client, and a server using Abyss-owned UDP sockets. Both active endpoint roles use the same transport engine. HTTP/3 is a separate application protocol, not an implicit property of the transport. [S1,S5]

```text
Supplied / mirrored datagrams                 Application
          |                                      |
    Quic.Inspector                         QUIC public API
          |                                      |
   Initial + CRYPTO                   Quic.Connection (:gen_statem)
          |                              /        |        \
          |                    Quic.Engine    TLS.ExSSL    IO adapter
          |                       |              |          |
          |                Wire / Protection   SSL.QUIC    OTP UDP
          |                       |                         or
          |                 OTP :crypto              Abyss send capability
          |                                                 |
          +--------------> SSL.Fingerprint <------ exact ClientHello bytes

Abyss listener -> opt-in dispatch/admission -> Quic.Endpoint / CID routes
                                               |
                                     persistent Quic.Connection
```

## Ownership

| Owner | State and responsibilities |
|---|---|
| `ex_ssl` | TLS authentication, transcript, fresh key exchange, traffic secrets, ClientHello serialization/observation and JA3/JA4 calculation |
| `Quic.Engine` | Transport state, packet-number spaces, streams, CRYPTO ranges, recovery, flow/congestion control, path/key lifecycle and typed effects |
| `Quic.Connection` | Sole current engine and TLS states, synchronous TLS calls, monotonic time, one next-deadline timer, operation/IO receipts and application ownership |
| `Quic.Endpoint` | Bounded admission, provisional and established CID routes, endpoint generation, accept queue and connection monitors; no private keys in route indexes |
| `Quic.Inspector` | Bounded observational reassembly and provenance; no handshake, transmit path or application decryption |
| Standalone IO / Abyss | Socket ownership, receive metadata, bounded egress, actual local-send result, shutdown |

Dependency direction is `abyss -> ex_quic -> ex_ssl`. `ex_quic` never imports Abyss modules or relies on its structs. The standalone adapter and Abyss adapter implement the same external IO boundary. Do not introduce a native QUIC library as a hidden fallback.

## Functional core and TLS boundary

The transport engine consumes explicit input events plus monotonic time and produces replacement state plus ordered effects. Packet codecs and protection use deterministic OTP cryptographic primitives. No protocol helper creates processes or performs network IO.

`SSL.QUIC.new/2` and handshake advancement are functional-style state operations but are not wholly deterministic: the provider owns entropy generation and certificate checks. Execute them at the serialized connection boundary, then fold their returned actions into the engine. Do not describe the entire system as pure or inject fake deterministic entropy into production to make that description true. Test the pure transport engine with recorded TLS events; keep separate tests using real TLS.

A connection owns both states; only one TLS request is in progress. Returned TLS bytes enter a reliable CRYPTO send buffer before transport packetization. TLS action order is not sorted by type or level. The TLS adapter uses public APIs only. [R3]

## Runtime design

Use one temporary `:gen_statem` connection process, not one process per packet or per stream. Stream handles refer to connection-owned state. Slow application processing happens outside the connection loop and cannot block ACK/recovery indefinitely. Limit work per turn and use generation-tagged continuations when necessary.

Begin with one UDP socket per standalone client endpoint and one shared socket per server endpoint. Server connections obtain an egress capability, not socket ownership. Multiple issued CIDs map to the same connection, and routes are installed before advertising those CIDs. Start with fixed nonzero locally issued CIDs on shared listeners; reject unsupported local policy rather than misroute short headers. Peer CID handling still follows v1 rules. [S1]

The existing Abyss listener dispatches accepted datagrams into a new handler path and its unicast receive can block. Insert an additive dispatcher before legacy handler creation. A separate bounded writer or validated direct-send capability supplies results without asking that blocked listener to process a call. [R5]

## State separation

Track TLS completion, server certificate authentication, parameter authentication, QUIC parameter semantic validity, address validation, and QUIC handshake confirmation separately. A server can complete without a client certificate identity. Application access is gated by the role-appropriate handshake and parameter state, never a fingerprint match. [R3,S2]

Keep the three packet-number spaces and per-level CRYPTO offsets separate. Do not release Handshake transmit data when only application secrets become available. Initial secrets and packet/header protection belong to QUIC; TLS record key states and TLS KeyUpdate are not used. [S2]

## Backpressure and failure

Every boundary has byte and item/range limits: endpoint admission, connection inbox, CRYPTO gaps, stream buffers, pending writes, accepts and observations. Acquire credit before sending messages; observing mailbox length after an unbounded cast is not backpressure.

Distinguish send reservation, queue admission, local-send completion and peer acknowledgement. A local send failure releases the pending budget, not a packet number for reuse. Timers and receipts carry endpoint/connection generations so an old callback cannot affect a restarted endpoint.

Packet authentication failures usually produce bounded discard behavior, not a reflection response. Authenticated protocol violations use the appropriate transport error. Closing/draining limits responses; no reset/close amplification loops. [S1]

## Incremental adoption

M2 delivers observation; M3 provides both-role handshakes; M4 adds stream/profile acceptance; M5 mounts that server on Abyss; M6 is the experimental endpoint gate. Abyss is required, not a future optional product. See [implementation plan](implement-plan.md), [TLS contract](ex-ssl-quic-contract.md), and [Abyss integration](abyss-integration.md).

References use the identifiers in [sources](sources.md).
