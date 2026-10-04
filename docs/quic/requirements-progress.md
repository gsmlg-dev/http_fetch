# Implementation progress

The application ALPN / RFC 9221 DATAGRAM increment is tracked separately in
[DATAGRAM acceptance](datagram-acceptance.md), including independent peer checks.
It extends transport capabilities without implementing HTTP/3 or QPACK.

This record tracks incremental work against `docs/implement-plan.md`; intermediate runtime tests do not complete the M3 independent-peer gate.

The 2026-09-28 Phase 1 increment and current consumer/I/O contract are recorded in
[Phase 1 acceptance](phase1-acceptance.md), [consumer contract](consumer-contract.md),
and [I/O contract](io-contract.md). The older milestone rows below are historical
checkpoints, not the Phase 1 gate decision.

| Area | Current evidence | Status |
|---|---|---|
| Mix app and pinned ex_ssl dependency | `mix.exs`, `mix.lock`, G-S SHA `f1327e0bb7fb2093b8dc2b07e72b26233a739963` | implemented |
| Runtime ownership contracts | `Quic.Runtime`, `Quic.Error` | implemented, pure data contracts only |
| CI checks | `.github/workflows/ci.yml` | implemented |
| TLS public contract checks | `test/ex_ssl_contract_test.exs`; real both-role UDP certificate tests in `test/quic/endpoint_test.exs` | local tests and independent aioquic both-role handshakes pass |
| QUIC varints/headers/packet numbers | `Quic.Codec`, `test/quic/codec_test.exs` | implemented and passing |
| QUIC Initial protection | `Quic.Protection`, `test/quic/protection_test.exs` | implemented and passing RFC9001 vector checks |
| Strict packet/frame validation | `Quic.Codec.validate_frame_levels/2`, authenticated header/CID checks in `Quic.HandshakeScheduler`, early authenticated transport-parameter validation, ACK-range tests and terminal corrupted-Finished driver test | local negative checks pass; `scripts/interop/raw_negative.exs` independently sends reserved-bit, fixed-bit and truncated Initials with zero routes and no UDP responses; invalid transport-parameter and corrupted-Finished independent network cases remain pending |
| Bounded Initial inspector | `Quic.Inspector`, `test/quic/inspector_test.exs` | partial M2: encrypted fixture, fingerprint event, bounded contexts and passive path implemented |
| Transport parameters | `Quic.TransportParameters`, authenticated parameter/CID readiness checks in `Quic.Connection` | basic v1 semantic validation implemented |
| UDP runtime | `Quic.Connection`, `Quic.Endpoint`, `Quic.IO.GenUDP`; lifecycle, ACK/PTO, Initial/Handshake loss tests | experimental M3-D runtime; requested M3-E matrix passes |
| M3-C packet keys and protected handshake packets | Recorded Secret actions, independent OTP packet oracle, authenticated level/space errors, retained CRYPTO and fresh-number retransmission | requested C.1/C.2/C.3 checks pass |
| Handshake key retirement | Role-specific receipt/confirmation triggers; bounded buffer/history cleanup; late-event tests; all 20 prior network cases plus both-role HANDSHAKE_DONE loss | implemented; [evidence](m3-key-retirement.md) |
| Large CRYPTO and recovery bounds | Actual protected-packet-size fragmentation, contiguous CRYPTO offsets, fresh packet numbers, PTO/loss boundaries and terminal sent-history reclamation | focused 30-test scheduler/recovery checks and full 124-test local gate pass; independent large-flight network impairment remains pending |
| Connection lifecycle | Idle timeout, closing/draining states, generation-checked timers, old-CID routing retention and terminal route cleanup | focused lifecycle tests and full 127-test local gate pass; independent lifecycle network validation remains pending |
| M4 reliable streams | Connection-owned bounded stream state, bounded `Connection.open_stream/3` and `send_stream/5`, application STREAM/control frame codecs, flow-control admission and protected scheduler dispatch | focused stream/codec/scheduler checks and full local gate pass; two-stream transfer through the Abyss integration script and independent aioquic peer initiated stream transfer both pass; stream transport parameters are materialized per endpoint |
| M4 backpressure and profiles | Bounded send/receive admission, Endpoint profile injection with fresh materialization, two capability-checked legal WireProfile policies and manual delivery limits | focused profile/stream checks and full 144-test local gate pass; independent aioquic runs distinguish JA3 and raw ClientHello observations for ordered/compact profiles, while normalized JA4 remains equal as expected |
| Abyss M5 dispatcher and external endpoint seam | Opt-in persistent dispatcher, monitored route registry, bounded writer with local-send receipts, externally owned `Quic.Endpoint`, legacy UDP path preserved | `gsmlg-dev/abyss@37cda66` and current ex_quic worktree; ex_quic 144-test gate and Abyss 501-test gate pass; focused ordinary UDP echo regression passes 2/2; refreshed cross-repo run passes two clients, single-close isolation, two-stream transfer, listener suspend/resume and restarted-listener admission |
| M3-E independent handshake matrix | aioquic 1.2.0; both roles, Retry, Initial/Handshake loss, reorder, duplicate, corruption, wrong CA/hostname/ALPN; archived UDP bytes and results | requested matrix passes; not full QUIC conformance |
| Initial inspector / fingerprint replay | pinned independent aioquic 1.2.0 Initial replay, duplicate suppression, incomplete completion, expiry/conflict checks and two-ClientHello ordinal lifecycle tests pass; independent HRR peer replay remains pending | M2 |

The endpoint runtime supports the controlled independent network-handshake scenarios in [M3 acceptance](m3-acceptance.md), independent stream transfer, profile comparison, and the Abyss shared-socket run. M6 remains open for independent malformed authenticated packets, sustained large-flight loss/resource measurements, independent lifecycle validation, and an HRR-capable peer. See [runtime evidence and limits](m3-runtime.md).

See the requirement-by-requirement [M6 audit](m6-audit.md) for exact commands and evidence boundaries.
