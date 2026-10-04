# M3 runtime evidence and remaining gates

The standalone runtime uses `Quic.Endpoint` for bounded CID admission/routing,
`Quic.Connection` as a temporary `:gen_statem` owning Scheduler/TLS state, and
`Quic.IO.GenUDP` as a separately owned send/receive capability. Closing a
connection does not close the shared socket. Concrete IPv4/IPv6 binds are
required; wildcard binds and ancillary multihoming are unsupported.

Reception forwards one datagram per consumption credit. Queue item and byte
budgets include writes awaiting receipts. The server's amplification budget
includes pending and actually sent bytes. Local receipts carry actual monotonic
microseconds; peer acknowledgements are processed separately in Recovery.
Writer/owner death, generation replacement and handshake deadlines terminate
or invalidate the appropriate work.

TLS completion, authenticated parameters, parameter/CID validity, certificate
verification at the client, address validation and QUIC confirmation remain
separate. HANDSHAKE_DONE confirms the client handshake. The established state
cancels its handshake deadline; it does not imply streams or HTTP/3 support.

## Executable local evidence

- `test/quic/io_endpoint_test.exs`: pending/sent amplification accounting,
  item/byte limits, failed receipts, signed monotonic time, timer and generation
  invalidation. ACK bookkeeping is exclusively in Recovery.
- `test/quic/io_gen_udp_test.exs`: loopback send completion, consumption-credit
  backpressure, concrete binds, malformed input, stale credit and owner death.
- `test/quic/connection_test.exs`: protected Initial transmission, server
  amplification holds, authenticated Handshake address validation, writer
  failure/death, handshake deadline, stale input, parameter authentication and
  CID rejection, fresh-number PTO retransmission.
- `test/quic/endpoint_test.exs`: shared-socket isolation, bounded admission,
  route cleanup, actual both-role certificate handshakes, authenticated ACKs,
  HANDSHAKE_DONE and deadline cancellation, wrong hostname and ALPN rejection.
  A controlled UDP proxy drops one client Initial or one server Handshake packet
  and requires successful confirmation afterward.
- `test/quic/recovery_test.exs`: distinct send/receive histories, packet and time
  threshold loss, PTO without false loss, deadline cancellation, independent
  spaces, delayed receipt/ACK accounting, and bounded terminal sent-history
  reclamation without packet-number reuse.
- `test/quic/handshake_scheduler_test.exs`: large TLS CRYPTO flights are split
  against the actual protected packet size with contiguous offsets and fresh,
  monotonically increasing packet numbers; each fragment remains retained for
  retransmission without another TLS call.
- `test/quic/connection_test.exs` and `test/quic/endpoint_test.exs`: idle,
  closing and draining transitions, stale recovery events, old-CID late packets,
  and shared endpoint route cleanup.
- `test/quic/streams_test.exs` and application scheduler checks cover
  connection-owned stream IDs, bounded reassembly, FIN/reset/STOP_SENDING,
  flow-control admission, and protected STREAM frame scheduling.
- `test/quic/protection_test.exs`: fixed short-header mask regression (five low
  bits for short headers, four for long headers).

Certificate tests read disposable fixtures from the full-SHA pinned ex_ssl
checkout (`test/fixtures/server_flight`), not system/runtime credentials.
The UDP peer on both sides is ex_quic: this is **self-connection evidence**, not
independent QUIC interoperability. The test ALPN is `ex-quic-test`.

## Remaining acceptance work

The requested M3-C through M3-E route now has [acceptance evidence](m3-acceptance.md).
This document records the earlier local-runtime increment. The subsequent
[independent peer matrix](m3-interop.md) covers both-role ordinary handshakes,
Retry, deterministic loss/reordering/duplication/corruption and certificate/ALPN
rejection. These bounded scenarios do not complete the wider M3/M6 lifecycle gates.

Initial/Handshake key and buffer retirement is implemented and independently
regressed; see [retirement evidence](m3-key-retirement.md).
Before broader endpoint acceptance, also review strict packet
header/CID and frame legality, congestion-full PTO behavior and recovery edge
cases. Deterministic idle/closing/draining coverage is present, but independent
lifecycle network validation remains pending. Current bounded resource limits can
terminate a connection rather than silently extend unsupported behavior. Independent
multi-stream transfer, profile wire fidelity, path migration and Abyss integration
are not part of this runtime increment.

## Local validation record

2026-09-24, macOS, Elixir 1.20.1 / Erlang OTP 29 (ERTS 17.0.2):
`mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix test`
(138 tests, seed 839122), and `git diff --check` exited 0. Focused stream,
codec, scheduler and profile tests also exited 0.
Independent-peer tests, CI runtime combinations and packet captures were not run
for this increment.
