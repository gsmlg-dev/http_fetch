# Verification and evidence plan

All items here are requirements for future ex_quic work, not tests performed by this review. Actual ex_ssl evidence is separated in [ex-ssl-review.md](ex-ssl-review.md). The current umbrella runs the full suite with `mix test` at the root; scoped checks from the root are `mix test apps/elixir_quic/test/`, `mix test apps/ex_ssl/test/`, and `mix test apps/elixir_quic_http3/test/`. After the umbrella import, the HTTP/3 scoped run passed 30 tests and the full umbrella suite passed. Archived results cited below predate the umbrella import and do not validate the new layout by themselves.

## Test layers

| Layer | Test oracle | Required evidence |
|---|---|---|
| Wire/protection | RFC and independent implementation vectors | Exact bytes, inputs, expected output, provenance and fixture hash |
| TLS adapter | Real pinned `SSL.QUIC` + public contract | Actions, flags, directional secrets, error classification, no record wrapping |
| Pure engine | Explicit time, recorded TLS events, generated event sequences | Deterministic state/invariant checks and reproducible seed |
| Inspector | External capture and independent JA observer | Datagram-to-ClientHello-to-fingerprint results, not only analyzer self-tests |
| Active endpoint | Independent network implementation | Verified both-role handshake, ALPN, streams, impairment and packet capture |
| Abyss | Real shared socket and legacy suite | CID isolation, lifecycle, overload and unchanged default UDP |
| Load | Measured actual runtime | CPU, packet rate, latency, heap/queue bounds and environment |

Self-connection is useful but not independent verification. A TLS-only interop harness is not a full QUIC network test. Golden expected hashes must not be computed solely by the production function under test. [S1–S4,R3]

## Required negative and boundary coverage

Wire tests cover truncated headers/samples, varint extrema, packet-number reconstruction boundaries, invalid AEAD/header protection, illegal frame levels, unknown types, coalesced packets, incorrect length fields and excessive frame/range counts. Include actual v1 Initial and Retry vectors and separate suite-specific protection checks.

CRYPTO/stream tests cover bytewise fragments, out-of-order ranges, duplicates, agreeing/conflicting overlap policy, sparse large offsets, final-size conflicts, level transitions, duplicate old-level data after TLS advancement and buffer limits before full payload arrival. Termination clears current references and cannot emit success after fatal state.

TLS contract tests preserve upstream R1–R3 behavior at the public boundary: missing-vs-empty key_share, ServerHello/HRR inbound limits, and exact alert domains. Tests must not mutate upstream structs or call internal decoders from production code. Actual TLS tests validate certificates/hostnames and reject changed CV/Finished.

Resource tests lower configuration limits to exercise exact boundary and one-over cases. Bound contexts, bytes, intervals, pending writes, streams and accepts. Prove that an input stream cannot create unlimited mailbox growth despite nominal buffer counters.

## Live handshake and stream scenarios

Execute both ex_quic client -> independent server and independent client -> ex_quic server. Use a private test CA and verified test hostname; never turn verification off to get green results. Include ordinary handshake, legal HRR with a capable peer, Retry, no-common ALPN, parameter/CID mismatch, no-common algorithm, corrupted packet, missing flight and delayed datagrams.

Transfer multiple unidirectional/bidirectional streams; verify byte-for-byte integrity, FIN/reset behavior, flow-control blocking/unblocking, slow consumers and cancellation. Test key updates under reordered packets, CID retirement, NAT rebinding, path validation, idle timeout, graceful drain and stateless-reset recognition.

An upstream server may export 1-RTT secrets before client Finished. Assert that application acceptance remains blocked until the chosen role's full readiness gate, including semantic transport-parameter validation. Fingerprint candidates cannot satisfy authentication checks.

## Impairment matrix

Use deterministic simulations for exhaustive transition properties and a controlled UDP proxy/network emulator for end-to-end tests. Exercise no loss, deterministic single-flight loss, sustained moderate loss, burst loss, reorder, duplication, corruption, delayed ACKs and MTU-relevant boundaries. Record the exact impairment settings rather than claiming a generic loss-tolerance percentage.

Include local writer failure, queue-admission rejection, send receipts delayed past an incoming ACK, partial endpoint shutdown, expired timer tokens and generation reuse. Distinguish local queue delays from RTT measurements.

## Fingerprint acceptance

Use at least two legal profiles and an external observer. Check exact selected ordered fields and each hash component; separately check QUIC transport parameters, Initial size and CRYPTO packetization because these are not the same measurement as JA4. Capture client hello 1 and hello 2 separately for HRR. Deduplicate retransmitted hello bytes while retaining retry/capture provenance.

Keep GREASE/unknown IDs in raw observations and apply only upstream analyzer normalization to hashes. Exercise h3 ALPN observation without claiming HTTP/3 application support. For unsupported current mobile/browser profiles report required unsupported capability and observed fields, not a target hash labeled as successful simulation. [R4,S7]

## Abyss acceptance

A real independent client must connect to the Abyss-owned shared socket. Keep two connections open, terminate one and prove the other still transfers. Test same-peer multiple connections, Initial retransmissions without duplicate connection creation, multiple local CIDs, changed peer address, route cleanup, listener/writer crash and invalidated receipts.

Execute legacy tests with no QUIC option, and where feasible without the optional dependency started. Verify no new calls into a receive-blocked listener and no per-datagram connection/retry process creation in QUIC mode.

## CI and completion evidence

Default CI is offline/deterministic and fails when zero tests execute. Independent peer/container tests are explicit jobs with pinned dependencies, test credentials and timeouts. Publish command, SHA, runtime, seed, count, exit status and run/job ID. Do not mark missing credentials, unavailable tools, skipped cases or unfinished jobs as passes.

At M6 two independent QUIC stacks must pass actual network scenarios. Select and pin an HRR-capable peer from demonstrated behavior; the upstream aioquic 1.2.0 TLS harness does not cover HRR. A failed requirement remains open; document smaller supported scope rather than deleting its assertion.

Historical ex_ssl macOS full-suite failures are neither ex_quic regressions nor passes. For a suspected upstream defect, provide a minimal public-API reproduction against the pinned source. Do not expand every downstream issue into an unrelated TLS rewrite.

No benchmark or audit was executed when authoring this plan. Production-security certification is not implied by any experimental milestone.
