# ex_quic implementation plan — revision 3

Date: 2026-09-23. Status: approved direction for implementation, not implemented functionality.
Supersedes the v1 client-only plan and the v2 plan that treated the ex_ssl interface as a proposal.

## 1. Decision and starting point

Proceed with an independent Mix library: package/application `elixir_quic` / `:elixir_quic` (repository `ex_quic`; renamed for Hex publication on 2026-09-29), public namespace `Quic`. Its three required deliverables are **Initial/ClientHello fingerprint observation**, **profile-controlled client behavior**, and **QUIC server integration in Abyss**. Neither observation alone nor a standalone client satisfies the complete project.

The original TLS review used `gsmlg-dev/ex_ssl@02eb981f59d4e182d4473e264a9f8b093ec6bf3d` (v0.7.1). The current umbrella uses sibling `apps/ex_ssl` source imported from upstream `fb47051355c9d0a29caee046fa060a745ad0ce5b` (v0.7.2); see the [contract](ex-ssl-quic-contract.md) for historical Hex and source-review evidence. The previous R1–R3 protocol-boundary findings and F1 formatter finding are closed within the incremental review scope. Use the actual `SSL.QUIC` and `SSL.Fingerprint` contracts rather than a new TLS proposal. See [review](ex-ssl-review.md) and [sources](sources.md), R1–R4.

The original M0 dependency was a full-SHA Git dependency. Its reviewed release notes stated that v0.7.1 did not publish to Hex; a GitHub tag alone did not establish Hex availability. The later v0.7.2 Hex dependency and current sibling import are recorded in the [contract](ex-ssl-quic-contract.md). Future dependency changes need explicit source and lockfile review. Do not reopen ex_ssl merely to add conveniences that belong in QUIC.

The GitHub read for `gsmlg-dev/ex_quic` returned 404 in this review. That does not establish the absence of a local/private workspace. Codex must inspect its actual working tree, preserve existing work, and adapt this plan before generating project scaffolding.

## 2. Scope and acceptance policy

Initial transport scope is QUIC v1 with client and server certificate handshakes, streams, mandatory transport-control behavior, packet protection, loss recovery, congestion/flow control, and bounded resource use. Standards baseline: RFC 9000/9001/9002; TLS stays in ex_ssl, whose current normative baseline is RFC 9846. Maintain a requirements-to-test matrix rather than treating successful self-connection as conformance. [S1–S4]

Defer HTTP/3/QPACK, WebTransport, 0-RTT, resumption, server-side client-certificate authentication, multipath, v2 execution, and batching optimizations. These are not silently accepted configuration options. The current TLS provider also cannot initiate a client handshake with an empty key-share profile. Its server can receive a legal empty share vector and request HRR. [R3]

A server's verified client Finished authenticates the handshake transcript, not a client certificate identity. A fingerprint match is an observation, not identity authentication. Public readiness and telemetry must preserve those distinctions.

## 3. Delivery sequence

| Milestone | Required deliverable | Depends on | Exit gate |
|---|---|---|---|
| M0 | Buildable library, TLS contract tests, endpoint/IO contract | Reviewed ex_ssl pin | CI and real socket-free TLS contract checks |
| M1 | v1 wire codecs and packet protection | M0 | Independent vectors and malformed-input tests |
| M2 | Bounded Initial inspector and fingerprint results | M1 | Independent capture replay, no transmit effects |
| M3 | Both-role QUIC handshake transport with recovery | M1 + TLS contract | Verified handshakes against an independent peer under loss |
| M4 | Reliable streams and actual client profile fidelity | M3; fingerprint gate uses M2 | Stream integrity/backpressure and independently observed wire profiles |
| M5 | Opt-in Abyss QUIC server | M3; final stream gate uses M4 | Shared-socket lifecycle, routing and legacy UDP regression tests |
| M6 | Complete experimental endpoint acceptance | M2–M5 | Two independent network peers, impairment/resource suite, support matrix |

M2 and M3 can progress in parallel after M1. The Abyss dispatch design and generic endpoint seam start in M0; the separately scoped Abyss patch can begin once those contracts stabilize. Do not wait for HTTP/3 to implement the server. An intermediate milestone must identify itself as partial; no intermediate milestone claims full QUIC support.

## 4. M0 — repository and dependency contracts

**M0.1 — establish the actual baseline.** Read local AGENTS.md and existing code before changes. Record branch, HEAD, dirty files, runtime versions and baseline command results. Preserve user changes. Copy/adapt this document set without retaining obsolete v1/v2 instructions as active guidance.

**M0.2 — build the project.** Add formatting, warnings-as-errors compilation and test CI. Prefer Elixir 1.18+/OTP28+ for the portable path and a 1.20/OTP29 lane aligned with the reviewed dependency. Verify actual available toolchain patches when configuring CI. A single documented formatting toolchain is acceptable; compile/test compatibility must remain separate. Runtime network/crypto dependencies use OTP; property-testing dependencies stay test-only.

**M0.3 — lock the upstream boundary.** Tests depend only on `SSL.QUIC.capabilities/0`, `new/2`, `feed/3`, `info/1`, `abort/2`, `SSL.QUIC.Secret`, and public fingerprint/profile types. Execute a real socket-free certificate handshake in both roles using isolated test credentials. Check directional secret pairing, required raw transport parameters, action ordering, explicit authentication flags, empty legal feeds, fatal/aborted states, and an actual emitted ClientHello fingerprint. This checks integration contracts; it is not QUIC network interop.

**M0.4 — model runtime ownership.** Define datagram metadata, endpoint generation, send receipt, timer token, connection/stream handles, error categories and bounded admission. Add a fake IO adapter and a virtual clock. The QUIC transition core does not call sockets, Logger, GenServer, wall-clock APIs or randomness directly. TLS operations run synchronously at the serialized runtime boundary because the existing provider generates entropy and performs authentication internally.

**Exit:** `mix format --check-formatted`, `mix compile --warnings-as-errors`, `mix test`, and `git diff --check` pass on actually executed lanes. No UDP or fingerprint stub returns invented success.

## 5. M1 — wire and protection foundations

**M1.1 — bounded codecs.** Implement varints, invariant-header extraction, v1 long/short headers, packet-number reconstruction, datagram coalescing boundaries, and typed frames. Start with Initial-relevant frames, then complete all baseline v1 frame formats before M6. Unknown QUIC versions must not be decoded using v1 packet-type bits; unknown frame types cannot generally be skipped as opaque length-delimited records. Keep parser errors distinct from authenticated transport errors. [S1]

**M1.2 — protection.** Implement v1 Initial derivation, packet AEAD, AES and ChaCha header protection, and Retry integrity validation. Check the dependency's TLS suite availability separately from the OTP primitives needed for QUIC header protection. A suite is usable only when both are available. QUIC HKDF labels, salts, nonces and packet-number handling belong here, not in TLS record state. Never invoke `SSL.Crypto.TrafficState` as a QUIC cipher. Small QUIC-owned HKDF helpers over OTP primitives are acceptable; duplicating the TLS handshake/key schedule is not. [S2]

**M1.3 — transport parameters.** Implement both an ordered wire representation and a semantic view. Validate sizes, duplicate parameter IDs, role constraints, numeric bounds/defaults and CID relationships in QUIC. TLS validates the extension envelope, not these values. Model connection-specific placeholders in profiles; materialize actual CID fields before calling TLS. Preserve unknown parameter bytes for observation without negotiating unsupported behavior.

**M1.4 — verification.** Commit independently sourced Initial/Retry/ChaCha vectors with origin, revision and digest. Check encode/decode boundaries, short samples, authentication failure, wrong packet number, truncated packets, multiple coalesced packets and byte-exact outputs. Include structural/property tests; do not generate every expected answer with the function under test.

**Exit:** wire and crypto tests pass without a network. The packet decoder does not allocate a connection per malformed input, and the API makes no TLS/QUIC network-readiness claim.

## 6. M2 — the first useful product: Initial fingerprint observation

**M2.1 — inspector state.** Build `Quic.Inspector` using the M1 codecs, Initial protection and a bounded CRYPTO interval store. Track flow provenance, direction, version, Initial key context, packet-number reconstruction and expiry. Support fragmented/overlapping/reordered/duplicate CRYPTO data without delivering a byte twice. Count intervals and contexts as well as byte totals; sparse offsets must not allocate dense buffers.

**M2.2 — upstream observation.** Extract one complete ClientHello, including its handshake header, and call `SSL.Fingerprint.client_hello(bytes, :quic)`. Its streaming observer is for one hello, not an entire CRYPTO stream with subsequent messages. Separate ClientHello1 and a post-HRR ClientHello2 when both are observed. A QUIC Retry can retransmit the same TLS bytes under a changed Initial key context; it is not TLS HRR.

**M2.3 — observable outcomes.** Return complete, incomplete/expired, unsupported-version, malformed or resource-limited outcomes; do not manufacture a fingerprint from partial bytes. Include raw observation provenance and JA3/JA4 projections. Expose ECH outer-only visibility and uncertainty. The inspector produces **no sends, ACKs, Retry, close frames or TLS secrets**.

**M2.4 — matching.** Add an optional local, versioned catalogue with candidate matches and matched fields. Exact hash equality is not a unique client identity. Do not hardcode current browser names onto a generic hello. Catalogue fixtures need capture provenance; live downloading of fingerprint databases is not a default runtime dependency.

**Exit:** replay pinned external QUIC captures through the complete datagram-to-fingerprint path and compare against an independent observer. Test packet loss leaving an incomplete hello, retransmission deduplication, concurrent clients, per-flow/endpoint exhaustion, TTL cleanup and zero transmit effects. This milestone is useful before a live client/server exists.

## 7. M3 — genuine client and server QUIC handshakes

**M3.1 — reliability first.** Maintain independent Initial, Handshake and Application packet-number-space state, sent-packet metadata, receive ACK ranges, RTT estimator, loss deadlines and PTO. Start with an RFC9002-based NewReno controller and bounded pacing. Congestion control and handshake retransmission are required for live testing, not optional optimization work at the end. [S3]

**M3.2 — TLS driver.** Maintain separate receive/transmit CRYPTO offset spaces per encryption level. Supply only new contiguous bytes at `SSL.QUIC.info(state).receive_level`; buffer future levels within limits. Fold the provider's ordered actions exactly once. Hold generated bytes for retransmission; never call TLS again merely because an emitted CRYPTO range was lost. Translate errors using a tested transport error map.

**M3.3 — handshake state.** Track TLS completion, server authentication, parameter semantic validity, address validation, and QUIC confirmation independently. Implement role-specific key retirement and HANDSHAKE_DONE processing. Do not discard Handshake transmit buffers merely because application secrets exist. A late duplicate of already consumed CRYPTO data is filtered in QUIC, not fed to a terminal/advanced TLS level.

**M3.4 — external IO.** Add standalone `:gen_udp` adapters for both endpoint roles and the generic externally owned-socket seam used later by Abyss. Bind a concrete local address in the first adapter unless ancillary metadata is retained. Maintain separate enqueue, local-send-success and peer-ACK states. Store monotonic timestamps from the actual local send path; reserve pending egress budgets so asynchronous writers cannot oversubscribe anti-amplification or congestion limits.

**M3.5 — server protections.** Apply bounded admission, handshake deadlines, minimum datagram rules, address validation and anti-amplification before exposing an internet-facing listener. Implement Retry verification on the client and a rate-limited, authenticated, expiring server-token policy when Retry is enabled. Retry is not permission to reset/reuse packet numbers or redo TLS arbitrarily. Observe normative v1 Retry/Initial handling. [S1,S2]

**Exit:** both roles complete verified certificate handshakes with a separately implemented network peer using an explicit test ALPN. Repeat with lost Initial/Handshake flights, reordering, duplication and delayed local sends. Wrong CA/hostname, invalid parameters and corrupted Finished fail closed. A no-socket TLS test does not satisfy this gate.

## 8. M4 — streams and profile-controlled clients

**M4.1 — stream state.** Implement bidirectional/unidirectional stream IDs, send/receive permissions, offset reassembly, FIN/final-size consistency, RESET_STREAM/STOP_SENDING, stream limits, MAX_DATA/MAX_STREAM_DATA/MAX_STREAMS and blocked signaling. Count retransmitted bytes only once toward flow-control consumption. Test independent stream progress and cancellation without closing unrelated streams. [S1]

**M4.2 — application backpressure.** Provide bounded send and receive APIs with explicit admission/timeout results. Application `send` completion means admission into a bounded queue unless a separate acknowledgement API is implemented. Return receive credit based on consumption policy, not unlimited buffering. Use one connection state owner; stream handles are data references, not mandatory processes.

**M4.3 — client profile compilation.** Compose public ex_ssl WireProfile policy with ordered QUIC transport-parameter and legal packetization/padding/CID-length policies. Validate required capabilities before opening/sending. Per-connection randomness and key shares remain fresh. Compile connection-dependent parameters once into the exact payload passed to both the TLS config and profile. JA hashes remain outputs, not setters.

**M4.4 — fidelity evidence.** Provide at least two legal distinguishable profiles using currently implemented capabilities. For each, capture real packets at an independent endpoint and compare ClientHello fields, JA3/JA4 and selected QUIC features. Separately prove a verified handshake and successful stream transfer. Packetization/transport-parameter differences may not change JA4; report those checks separately. Browser/mobile labels require versioned capture evidence and a documented fidelity level.

**M4.5 — key and path lifecycle.** Implement receiving and initiating v1 key updates, key-use limits and reordered packets across key phases. Provide baseline CID retirement, path challenge/response, NAT-rebinding handling, idle/closing/draining and stateless-reset recognition before M6. Deferring a user-initiated migration API does not remove required peer/path handling. [S1,S2]

**Exit:** multi-stream content matches under impairment and bounded-memory slow-consumer tests; independent wire observations match each profile's stated scope. No claim that matching JA4 reproduces a complete browser or HTTP/3 stack.

## 9. M5 — Abyss integration is a required delivery

Abyss remains the UDP socket/lifecycle owner. Add an opt-in dispatcher before the legacy per-datagram `Abyss.Connection.start` path. `ex_quic` exposes a transport-neutral endpoint; only the Abyss adapter imports Abyss modules. Inspect the actual Abyss HEAD before making the separately scoped patch. [R5]

Deliver bounded admission, provisional Initial routing and established multi-CID routing to persistent temporary connection processes. Register locally issued CID routes before packets using them can leave. Test route generations and cleanup on process death. Start with one listener socket per QUIC endpoint; do not rely on reuseport hashing to keep a migratable connection on one worker.

Use a writer/send capability that can operate while the listener blocks in `recv(:infinity)`. Never route egress through a call to that blocked listener. Do not change ordinary UDP mode into polling or unbounded active reception. Preserve ancillary destination/interface information, or explicitly restrict the first deployment to concrete local binds.

The default non-QUIC path must remain unchanged. Closing one connection cannot close the shared socket. Endpoint shutdown stops admission, drains within a bounded deadline, then lets the socket owner close it. Unknown traffic on a QUIC-designated port has explicit drop/version-negotiation policy, not an accidental fallback into arbitrary UDP handlers.

**Exit:** independent client connects to Abyss, completes verified TLS and uses streams; observation events correlate to that connection. Concurrent clients remain isolated; single-connection teardown, listener restart, writer failure, overload and ordinary UDP regression tests pass. See [Abyss contract](abyss-integration.md).

## 10. M6 — experimental release gate

Maintain an executable requirements matrix, not only a README feature checklist. Complete baseline v1 frame handling, version/Retry/CID rules, transport parameters, key lifecycle, flow/recovery control and protocol error domains. Unsupported extensions and policy-limited features are explicit.

Use two independently implemented QUIC network peers and record their exact revisions and commands. At least one must demonstrably exercise HRR; the existing pinned aioquic TLS-only upstream harness is not independent HRR evidence. Do not invent or silently skip that result. Keep this requirement as a later network acceptance gate rather than reopening the completed formatter task.

Run deterministic impairment/property tests and real UDP tests; add corruption, local-send failure, old timeout messages, mailbox pressure, tiny fragmented ranges and simultaneous streams. Record per-connection and aggregate memory bounds, admission/drop counts and scheduler/mailbox behavior. Benchmark packet rate, bytes/s, CPU, latency and memory separately for inspection, handshake and streaming. Publish methodology, not unmeasured throughput promises.

**Release meaning:** documented experimental library suitable for controlled integration. It is not a claim of production security certification. Historical ex_ssl TCP integration failures remain tracked separately; new QUIC/TLS failures must be reproduced against the pinned upstream contract before attribution.

## 11. First Codex execution slice

Execute M0 and M1 now. Finish with real code, tests and build commands, not another feasibility report. Design the inspector and external-endpoint seams so M2 and Abyss are not retrofits, but do not pretend that a packet codec completes networking. If M0–M1 are larger than one implementation session, land coherent tested increments locally and report exact incomplete items without marking the milestone done.

Later task slices: M2 observation; M3 both-role transport; M4 streams/profiles; a separately scoped Abyss patch for M5; M6 acceptance. No automatic repository creation, commits, pushes, releases or upstream changes are authorized by this plan.
