# Abyss integration — opt-in QUIC endpoint

Target inspected: `gsmlg-dev/abyss@37cda66` (pushed to `gsmlg-dev/abyss/main`). The additive dispatcher seam and ex_quic adapter are implemented and covered by the cross-repository acceptance run below.

## Actual starting behavior

`Abyss.Listener.accept_packet` applies a size check and calls `Abyss.Connection.start`. The latter starts a handler child for that data arrival and can schedule retry tasks on capacity exhaustion. Handlers share the listener socket. Unicast receipt uses `transport.recv(socket, 0, :infinity)` from the listener process, and the ancillary-data branch currently discards that metadata. [R5]

Do not route every QUIC datagram through that handler lifecycle. QUIC requires durable per-connection state and several CIDs can identify the same state. Do not rely on changing the UDP handler module alone.

## Dispatcher seam (implemented in Abyss)

The Abyss patch adds a general `datagram_dispatcher` configuration option. Omitted means the exact existing UDP path. Opt-in mode invokes a persistent callback before handler creation, passing datagram bytes, remote address, local endpoint metadata, monotonic receipt time and endpoint generation.

The listener still blocks in `recv(:infinity)`. A separate bounded writer owns egress admission and reports local send results while the listener remains blocked. Routes are monitored and removed when their connection process exits. See `gsmlg-dev/abyss@37cda66` and `docs/dispatcher.md` in that repository.

`Quic.AbyssDispatcher` is the dependency-free callback adapter in this repository. It starts an externally owned `Quic.Endpoint`, forwards each datagram through its CID router, and uses the injected `send_fun` for egress. New connections are admitted only after minimal structural/version checks and a resource reservation. Established routes use destination CID; a provisional map covers Initial packets before the selected server CID becomes usable. Untrusted CID fields are routing hints, not authentication.

In terminate mode, observe the ClientHello inside the admitted connection using the shared reassembly path; avoid a second always-on inspector doing duplicate decryption. Optional inspect-only mode sends observations but never creates a TLS server or transmits protocol responses.

## Socket and route ownership

Abyss remains the socket owner. Connections receive a restricted egress capability and generation identifier. They cannot close the shared socket. The endpoint holds only routing/admission metadata; secrets remain in each connection's TLS/transport state.

Start with one listener socket per QUIC endpoint and a configured nonzero local CID length. Maintain an endpoint-wide CID registry when later introducing listener pools; reuseport peer-address hashing is not CID routing. Install new local CID mappings before sending them, retire mappings coherently, and monitor connection death to reclaim every route and reservation.

Register endpoint generation in all routes/receipts. A stale packet-routing result, send completion or timer cannot target a replacement connection after teardown. A connection crash does not restart the old TLS transcript or reuse old traffic keys.

## Send path and backpressure

Do not use `GenServer.call(listener, ...)` for egress while it is blocked in receive. Use a separately supervised bounded writer or a supported/verified direct send path. Respect the transport's real cross-process sending semantics; retaining socket ownership does not imply every backend permits the same call pattern.

Each send carries a stable ref and reports local success/error with a monotonic completion timestamp. Admission is not success. Budget both pending and sent bytes so the queue cannot bypass congestion, pacing or per-path anti-amplification limits. A failed/uncertain send cannot cause packet-number reuse.

Use byte and item credits before message enqueue. Overload should cause measured drops/backpressure rather than unbounded casts or `Task.start` per datagram. Existing UDP retry behavior remains on its legacy path; QUIC admission does not inherit task-based packet retries. The QUIC recovery engine handles network loss.

## Receive metadata

Preserve destination address/interface information when required for multihomed/wildcard sockets. Until implemented, bind a concrete local address and document the restriction. Receiving UDP on a socket does not inspect all machine traffic; host-wide observation needs a separate capture/mirror input.

Do not enable unbounded `active: true` or replace the existing unicast behavior with short polling timeouts as a shortcut. Any later network backend change has its own measured review and must preserve ordinary UDP semantics.

## Lifecycle

Connection close releases that connection's streams, routes, timers and queued sends; other connections and the listener remain usable. Endpoint stop first refuses new admissions, then gives existing connections a bounded drain period, invalidates stale work, and asks the owner to close its socket. Writer/listener death fails dependent connections and cannot leave restart loops or stale route indexes.

Default to a dedicated QUIC port/endpoint. Do not invent mixed-protocol demultiplexing from weak heuristics. Ordinary DNS/DHCP or other UDP users keep their prior port, handler, telemetry and shutdown behavior.

## Required tests and separate task scope

The M5 acceptance run uses two ex_quic clients against the Abyss-owned listener with certificate verification, transfers two streams, closes one connection, suspends/resumes the listener, and admits a third client after restart. An independent aioquic client also sends two FIN-terminated streams to an ex_quic server in `scripts/interop/stream_interop.exs`; the two runs provide separate shared-socket and peer-stream evidence.

The existing Abyss test suite passes in default mode with the dispatcher option omitted (`501 passed`, `12 excluded`). A dedicated dependency-disabled regression remains pending; ordinary UDP behavior is covered by the existing default suite but has not been isolated as a separate acceptance command.

This document is a work specification, not permission for the first ex_quic Codex task to edit another repository. M0 defines the generic endpoint contract; the scoped Abyss change follows once it stabilizes. There is no dependency cycle.

See [implementation plan](implement-plan.md) and [sources](sources.md).
