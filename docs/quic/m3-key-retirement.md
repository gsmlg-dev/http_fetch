# Handshake key retirement and associated state cleanup

Implemented against parent `34f071e0c5a86d6fc0e224214d36282aebe258ae` on
2026-09-24. This is one local ex_quic increment; the ex_ssl pin and its public
API boundary are unchanged. Normative timing follows RFC 9001 sections 4.1.2
and 4.9.1/4.9.2, with recovery cleanup from RFC 9002 section 6.4.

## Triggers and ownership

| Role / level | Trigger | Evidence |
| --- | --- | --- |
| Client Initial | First successful local Handshake send receipt | Recorded tests distinguish installed Application keys, queued packet, failed send and actual success |
| Server Initial | Successful authenticated Handshake packet processing, including behind a coalesced Initial | Recorded tests reject bad tags, preserve Initial after a corrupt trailing packet, and retire after valid processing |
| Server Handshake | TLS completion plus authenticated, semantically valid parameters establishes server confirmation | Connection readiness invokes confirmation before scheduling HANDSHAKE_DONE |
| Client Handshake | Authenticated HANDSHAKE_DONE after TLS completion | Recorded tests retain Handshake before the frame and retire on its receipt; independent loss recovery also passes |

The server's address-validation fact now follows successful Handshake packet
processing rather than the UDP datagram's first byte. This handles coalescing and
prevents a mere header observation from driving either validation or retirement.

`HandshakeScheduler.retire_level/2` removes QUIC packet/HP read and write keys,
Initial key contexts, pending CRYPTO emissions, ACK/control queues, retained send
effects and the corresponding TLSDriver buffers. Runtime egress filters obsolete
effects both before admission and while flushing, since a local Handshake receipt
can retire Initial midway through a flush.

`TLSDriver.retire_level/2` drops sent CRYPTO bytes, contiguous future-level pending
bytes and sparse receive intervals, and releases its buffer counters. Send and
receive offsets are retained as scalar bookkeeping. The provider's private TLS
state is never read or mutated to perform cleanup. This releases current
QUIC-owned references; it makes no physical BEAM memory-zeroization claim and
cannot erase prior immutable state snapshots held by a caller.

`Recovery.retire_space/2` permanently closes Initial/Handshake reservation,
clears sent history, ACK ranges and pending ACKs, releases only outstanding
reserved/queued/sent congestion bytes, resets PTO backoff and recomputes the next
deadline while invalidating the old timer generation. The next packet-number
counter is preserved. Retirement is idempotent and late successful/failed receipts
return `[:retired]` without changing counters. Application recovery remains live.

Retry continues to use `discard_space/2`: it changes Initial context while
preserving packet-number allocation and retained TLS bytes needed for retransmit.
It is not permanent retirement. A late Retry cannot reinstall retired keys.
Retired-level datagrams are discarded without keys/TLS/ACK work, and parsing
continues to later packets in the same bounded datagram. Late recovery work from
a retired space cannot resurrect its queued packets.

HANDSHAKE_DONE remains retained in Application recovery. Losing it after the
server has retired Handshake produces a fresh-number Application retransmission;
it does not resurrect Handshake keys or call TLS again.

## Validation

Runtime: Elixir 1.20.1, OTP 29, ERTS 17.0.2. Independent peer: aioquic 1.2.0,
Python 3.12.12. All of the following exited 0:

- `mix format --check-formatted`
- `mix compile --warnings-as-errors`
- `mix test`: 117 tests, seed 787543
- `uv run --python 3.12 --with aioquic==1.2.0 python scripts/interop/test_peer.py`:
  four harness qualification tests
- `git diff --check` and staged diff check before committing

`test/quic/key_retirement_test.exs` covers the triggers, buffer cleanup, preserved
packet-number counters, pending ACK/late receipt accounting, old timers, obsolete
runtime pending effects, authenticated coalescing and HANDSHAKE_DONE retransmission.
The real certificate UDP test inspects both established connections: obsolete
keys, CRYPTO buffers and recovery history are empty, and Application ACK processing
continues. Its old assertion requiring retained Initial/Handshake ACK history was
replaced with these retirement assertions because that history must now be freed.
Initial red tests failed before implementation; no test was disabled.

The complete prior 20 independent cells were rerun, plus
`drop_handshake_done` in both roles: **22/22 passed**. Commands, final results and
raw UDP transport-boundary captures are archived in
`test/fixtures/interop/aioquic-1.2.0/key-retirement/`, with `matrix.json` and
SHA256SUMS (45 digests). Run any cell using:

```sh
INTEROP_SCENARIO=<scenario> mix run scripts/interop/run.exs <client|server> _build/interop/key-retirement-final/<role>-<scenario>
```

Positive cells now require local confirmation, both locally retired levels, and
an independent `quic_confirmed` event in addition to HandshakeCompleted. Negative
cells continue requiring the specific TLS error and no established connection.
For `drop_handshake_done`, the pinned peer's read-only packet crypto context first
authenticates and parses the target frame; a generic short-header packet is not
sufficient. Only encrypted datagrams and event names are recorded, never keys or
plaintext. A qualification test proves ordinary PING and corrupted ciphertext
are not misidentified. This private-peer inspection is test-only, not a production
dependency on aioquic internals.

An early server loss run revealed that HandshakeCompleted alone could return
success before the independent client recovered the lost HANDSHAKE_DONE. That
run was not accepted as recovery evidence. The gate was strengthened to wait for
independent QUIC confirmation, and all 22 final cells were run with that gate.

No portable-runtime CI matrix, sustained-loss/load benchmark, physical secret
erasure test, second independent peer, ChaCha negotiation or security audit ran
in this increment. Strict packet/frame legality, large-flight fragmentation,
congestion-full PTO, general Application sent-history reclamation and connection
idle/closing/draining remain separate work. No streams, profiles or Abyss changes
are included.
