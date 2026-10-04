# Product requirements — ex_quic

Status: proposed first experimental release. Date: 2026-09-23.

## Problem and users

Provide an Elixir-owned QUIC transport for applications that need observable and controllable ClientHello/QUIC behavior and for existing Abyss UDP services that need QUIC termination. Reuse the reviewed TLS engine instead of implementing another TLS stack.

The required use cases are offline/live Initial observation, capability-validated outbound profiles, and an Abyss-hosted multi-connection server. An HTTP/3 client alone is not the product; HTTP/3 is a future application layer.

## Functional requirements

| ID | Requirement | Release gate |
|---|---|---|
| OBS-1 | Decode bounded QUIC v1 Initial traffic and reassemble visible ClientHello | Independent capture replay |
| OBS-2 | Reuse upstream JA3/JA4, explicit provenance/visibility and incomplete outcomes | Hash/raw-field goldens and no transmit effects |
| OBS-3 | Optional candidate catalogue, not identity assertions | Ambiguity and retention tests |
| SIM-1 | Versioned TLS+QUIC profile with fresh key material and upfront capability validation | Two real measured profiles |
| SIM-2 | Independent observer sees expected selected wire behavior | Capture plus verified handshake/stream transfer |
| TLS-1 | Actual existing SSL.QUIC interface, both endpoint roles | Consumer contract and independent network tests |
| TRN-1 | Reliable uni/bidirectional streams, flow/recovery/congestion control | Integrity and impairment tests |
| TRN-2 | Correct key/CID/path/close lifecycle for declared v1 scope | Requirements-to-test matrix |
| ABY-1 | Optional Abyss dispatcher, CID routing and shared socket | Live independent client |
| ABY-2 | Legacy UDP default and single-connection isolation | Existing suite plus teardown/overload tests |
| SAFE-1 | Bounded bytes/items/contexts, admission, timing and redacted diagnostics | Adversarial resource and lifecycle tests |

## Nonfunctional constraints

Use Elixir for protocol logic and OTP for sockets/cryptographic primitives; no extra native QUIC runtime dependency. Pure transport transformations and explicit runtime effects, one state owner per connection, and no process per packet. Observation, transport and application authentication have separate semantics.

Start with portable `:gen_udp`, concrete local binds and a single shared server socket. Performance optimizations follow benchmarks. There is no promised throughput target without measurements; publish packet rate, bandwidth, latency, CPU and memory separately.

## Explicit first-release exclusions

HTTP/3/QPACK, WebTransport, multipath, arbitrary browser equivalence, resumption, 0-RTT, upstream-unsupported server mTLS and empty-share client startup, and a public active-migration API are deferred. Required peer/path behavior is not removed by deferring a convenience API. QUIC v2 gets a version seam but is not advertised before implementation/tests.

No default public fingerprint database, no cloud dependency, no raw-secrets logging, no verification bypass and no automatic edits to ex_ssl or Abyss from the initial ex_quic task.

## Definition of delivery

M2 can ship a clearly labeled observer increment. Full project acceptance requires observation + measured client profiles + Abyss termination on the shared transport engine, with two independent network peers and an explicit support matrix. Experimental release is not production security certification.

Reviewed prerequisite status and remaining upstream limitations are in [ex-ssl-review.md](ex-ssl-review.md); implementation sequence is in [implement-plan.md](implement-plan.md).
