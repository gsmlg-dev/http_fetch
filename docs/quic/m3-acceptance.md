# M3-C.1 through M3-E requested-route acceptance

Verified 2026-09-24. This records the requested packet-key, protected-handshake,
UDP-runtime and independent-network route. It does not mark all of M3–M6 or the
three-product implementation plan complete. Runtime: Elixir 1.20.1, OTP 29
(ERTS 17.0.2). TLS dependency remains pinned to
`02eb981f59d4e182d4473e264a9f8b093ec6bf3d`.

## Requirement-to-evidence audit

| Requirement | Implementation and checked evidence |
| --- | --- |
| C.1 consume actual `SSL.QUIC.Secret` actions | `HandshakeScheduler.install_secret/2`; recorded-action tests in `handshake_scheduler_test.exs`; independent real TLS handshakes use the public provider |
| C.1 separate level/direction key, IV and HP contexts | `keys[level][direction]`; `handshake_scheduler_levels_test.exs` asserts opposite peer directions match at both Handshake/Application levels |
| C.1 suite, AEAD and HP availability; duplicate/unsupported rejection | `Protection.packet_keys/5` checks suite/hash/cipher consistency and OTP crypto capabilities; scheduler tests assert duplicate, conflict and incompatible algorithm errors |
| C.2 remove HP, reconstruct PN and decrypt | `decode_protected_packet/2`; malformed and bad-tag tests; independent RFC vectors; network peer consumes emitted encrypted flights |
| C.2 ACK, CRYPTO, PADDING, close and HANDSHAKE_DONE | Authenticated scheduler decode/dispatch tests, including an independent OTP-generated padded close; runtime and independent peer tests require HANDSHAKE_DONE confirmation |
| C.2 offsets/levels to TLSDriver, ACKs to Recovery | Scheduler/TLSDriver tests check contiguous delivery, future-level buffering and duplicate suppression; authenticated ACK tests inspect Recovery state |
| C.2 explicit wrong-space/level errors | Independent authenticated Handshake packet with HANDSHAKE_DONE returns `wrong_encryption_level`; Handshake ACK for an Application-only packet returns `invalid_ack/ack_never_issued` without changing state |
| C.2 independent decrypt and replay without duplicate TLS feeds | Outbound-level tests remove HP/decrypt via raw OTP primitives independently of `Quic.Protection`; Initial replay/coalescing and independently decrypted Handshake replay/retransmission tests preserve TLS state and feed each range once |
| C.3 protected Handshake/Application flights and independent PNs | `handshake_scheduler_levels_test.exs` verifies plaintext through the independent oracle and checks each level starts at PN zero |
| C.3 retain exact bytes/level/CRYPTO range/PN; failed send does not recycle PN | Recovery packet metadata, retransmit tests and failed-send tests inspect retained bytes and monotonically increasing reservations |
| C.3 ACK bookkeeping | Authenticated ACK and per-level Recovery tests prove matching-space acknowledgement and separation from local send |
| D socket-free IO and real UDP both roles | `Quic.IO` callbacks; `Quic.IO.Endpoint` bounded pure accounting; `GenUDP`, Connection and Endpoint tests plus independent real UDP runs |
| D enqueue/local completion/peer ACK separation | IO receipt and Recovery tests, including ACK preceding a delayed local completion timestamp |
| D handshake deadline, amplification and address validation | Connection deadline tests; pending+sent amplification tests; authenticated Handshake and Retry-token address validation tests |
| D writer failure and stale generations | IO/Connection tests cover failed receipt, writer death, old timers, old receive credit and old datagram generations |
| D concrete bind restriction | `io_gen_udp_test.exs` rejects wildcard addresses; ancillary multihoming remains unsupported |
| E verified independent certificate handshake, both roles | aioquic 1.2.0 / Python 3.12.12, explicit `ex-quic-test` ALPN, ordinary and Retry captures; both local confirmation and independent HandshakeCompleted required |
| E Retry, Initial/Handshake loss, reorder, duplicate and corruption | Two roles times six non-baseline scenarios: Retry plus five single-fault cases; actual Retry/impairment events required in addition to handshake completion |
| E wrong certificate and ALPN | Six role/scenario cells for wrong CA, hostname and ALPN require precise rejection and no ready endpoint; timeout/generic close alone fails |
| E version, capture, commands, runtime and unrun checks | `m3-interop.md`, 20 archived result files and 20 UDP JSONL captures, SHA256SUMS; detailed earlier failed harness attempts remain documented |
| Completed increments committed and pushed | C.1 `599c2b9`, C.2 `83aa60f`, C.3 `538db6b`, reliability `1b4b6b1`, D `f35c888`, ordinary E `7b3986f`, client Retry `36bec72`, server Retry `5a4856f`, impairment `cd408b5`, authentication negatives `926e71c`; final acceptance increment follows these commits |

Test paths in the table are under `test/quic/` unless otherwise stated. Test
oracles use public disposable fixtures, not production credentials. Independent
network captures record UDP transport-boundary bytes, not kernel PCAP.

## Final checks

- `mix format --check-formatted`: exit 0.
- `mix compile --warnings-as-errors`: exit 0.
- `mix test`: exit 0, 109 tests, seed 571324.
- `uv run --python 3.12 --with aioquic==1.2.0 python scripts/interop/test_peer.py`:
  exit 0, three impairment-harness qualification tests.
- `git diff --check`: exit 0; staged diff checked before publication.
- Archive audit recomputed all 40 SHA-256 digests and verified all 20 expected
  role/scenario results, version events, success readiness or negative no-ready
  conditions. Each executed network command and earlier failure is described in
  [the independent evidence](m3-interop.md).

The final packet-oracle tests initially expected a PADDING event. The codec's
existing contract consumes padding without emitting it; the assertion now checks
successful authenticated parsing and the CONNECTION_CLOSE error code. No
production behavior or error gate was weakened to satisfy this check.

## Remaining wider acceptance work

These results cover the requested route, not all endpoint lifecycle behavior.
Role-specific Initial/Handshake retirement is now covered by
[the key-retirement increment](m3-key-retirement.md), including all 20 prior
network scenarios and both-role HANDSHAKE_DONE loss. Strict header/CID/frame
legality now has authenticated focused coverage. Remaining work includes large
CRYPTO fragmentation, congestion-full PTO, long-lived sent-history
reclamation and idle/closing/draining behavior. Independent invalid-parameter and
corrupted-Finished scenarios, ChaCha negotiation, HRR-capable second independent
peer, sustained/burst loss, resource/load limits and the portable CI runtime
matrix were not run in this route's final verification. Those wider gates remain
open in `implement-plan.md` and `testing.md`.

Streams, profile fidelity, path migration, Abyss integration, HTTP/3 and production
security review are not delivered by handshake acceptance. No cross-repository
edits, release, tag changes or package publication were performed.
