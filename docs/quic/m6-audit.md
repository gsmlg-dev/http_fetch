# M6 experimental acceptance audit

This audit records the evidence available in the current `ex_quic` and Abyss
checkouts. A green local suite does not replace an independent network result.

| Requirement | Evidence | Status |
| --- | --- | --- |
| Reserved/fixed-bit/truncated Initial rejection | `mix run scripts/interop/raw_negative.exs`; zero UDP responses, zero routes, zero Retry sends | passed for these unauthenticated packet forms |
| Authenticated transport-parameter rejection | `HandshakeScheduler` validates authenticated actions transactionally; local `connection_test.exs` and scheduler action-order test; invalid value produces `{:transport_parameters, :invalid_max_udp_payload_size}` and no retained route | local rejection and same-batch zero-emission boundary passed; zero-reflection independent case pending |
| Corrupted Finished and ACK-range errors | `test/quic/tls_driver_test.exs`, `test/quic/recovery_test.exs`, `test/quic/handshake_scheduler_levels_test.exs` | local passed; independent malformed authenticated packet pending |
| Large CRYPTO fragmentation and bounded recovery | `test/quic/handshake_scheduler_test.exs`, `test/quic/recovery_test.exs`; 144-test gate; temporary aioquic run with 5 and 20 extra certificate entries | local passed; the large-flight probe hit bounded admission drops (8), zero routes, and no established handshake; independent sustained large-flight completion under loss remains pending |
| Loss/reorder handshake recovery | aioquic 1.2.0 impairment matrix; reverse role `drop_initial`, `drop_handshake`, `reorder`, `corrupt` all exit 0 | passed for single impairment cases |
| Lifecycle and shared endpoint | `test/quic/connection_test.exs`, `test/quic/endpoint_test.exs`, `scripts/interop/abyss_m5.exs` | local/shared-endpoint close/restart and retired-CID replay rejection pass; independent stale timer/CID/late-ACK network case pending |
| Reliable streams | `scripts/interop/stream_interop.exs`; two independent aioquic peer streams with complete payload and FIN | passed |
| Profiles and backpressure | ordered/compact aioquic captures, JA3 difference, equal normalized JA4, bounded queue tests | passed for current profile scope |
| Abyss dispatcher and ordinary UDP | Abyss `37cda66`, `mix test --cover=false` (501 passed), echo integration 2/2, M5 script | passed |
| HRR-capable independent peer | no qualifying peer run is available; aioquic 1.2.0 harness does not establish HRR evidence | pending |

The current experimental release boundary therefore remains M6-partial. The
open rows require stronger independent network evidence or a provider-level
ordering change; they are not hidden by the passing local gates.
