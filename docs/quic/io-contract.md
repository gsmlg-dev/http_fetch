# I/O capability contract

The application protocol belongs to its consumer. QUIC does not import Abyss or
select HTTP/DNS handlers from ALPN. Standalone and external endpoints share the
same connection engine and packet protection.

## Existing callable boundary

`Quic.Endpoint.start_link(role: :server, io: {:external, local, send_fun}, tls: opts)`
creates a server endpoint without owning a UDP socket. The public consumer variant is
`Quic.listen(io: {:external, local, send_fun}, tls: opts)`. External client
endpoints are not supported in this phase. `local` is the local metadata
reported by `Endpoint.local/1`. The external owner calls
`Endpoint.receive_datagram(endpoint, {ip, port}, datagram, monotonic_microseconds)`
synchronously. Each input is a complete UDP datagram, potentially containing
multiple QUIC packets. It is not a stream chunk or a TLS message.

The endpoint routes by destination CID to a persistent `Quic.Connection`
`:gen_statem`. Its generation is a reference, checked by `Connection.deliver/4`.
Only the endpoint owner may deliver to that connection. Streams are data inside
that connection, never separate processes. The owner must serialize ingress and
apply credit before forwarding; unrestricted concurrent calls are not a bounded
receive queue.

`Quic.IO` adapters implement `send(writer, bytes, remote)`, `close(writer)` and
`monotonic_time/0`. A successful send returns `{:ok, completed_at}` in monotonic
microseconds. An error returns `{:error, reason}`. These are local writer results,
not peer acknowledgements.

The external writer invokes `send_fun.(remote, bytes)` outside the shared receive
process. The callback returns `:ok`, `{:ok, monotonic_microseconds}`, or
`{:error, reason}`. An admission reference is rejected as an invalid completion;
an asynchronous writer requires a separate receipt adapter. The callback must
finish within the writer call deadline. A timeout cannot establish that bytes
were not sent. The connection terminates on an uncertain writer outcome; reserved
packet numbers are never reused.

The caller owns the shared socket. Stopping an external endpoint stops its
restricted writer and connections; it does not close that socket. Writer and
owner death terminate dependent connections. Standalone endpoints use
`Quic.IO.GenUDP` with one outstanding receive credit and a concrete bind address.
Wildcard/ancillary destination metadata and connection migration are unsupported.

## Accounting and lifecycle

Pure `Quic.IO.Endpoint` separates queue admission, dequeue, local completion and
peer ACK (the latter belongs to `Quic.Recovery`). Pending bytes reserve server
anti-amplification credit. Generation invalidation conservatively treats pending
bytes as spent because a late completion might follow transmission. Queue items,
bytes, connection count, routing records and handshake lifetimes are finite.

No application callback is executed during shared-socket reception. Application
consumption is specified separately in [consumer-contract.md](consumer-contract.md).

## Phase 1 verification

Current commands, source pin, Retry capability routing, fake sender tests and
remaining limitations are recorded in [phase1-acceptance.md](phase1-acceptance.md).
Historical shared-socket runs in [abyss-integration.md](abyss-integration.md) do not
constitute the new G-A/G-P1 gate. No changes to Abyss are part of this task.
