# Historical M0–M1 task — start ex_quic against the reviewed ex_ssl API

This document records the original M0–M1 execution slice and is not a current implementation assignment. The current repository is an umbrella: `apps/elixir_quic` is `:elixir_quic`, `apps/ex_ssl` is `:ex_ssl`, and `apps/elixir_quic_http3` is the experimental `:elixir_quic_http3` companion. The apps use shared root Mix build, dependency and configuration paths. Read [the current TLS contract](docs/ex-ssl-quic-contract.md) for source provenance.

Implement actual code, tests and project documentation in the current ex_quic workspace. Do not output another feasibility report or a plan-only response.

## Goal

Build an independent Elixir QUIC v1 library with three first-class purposes:

1. Observe real Initial traffic and derive JA3/JA4 from the visible ClientHello.
2. Simulate legal, versioned client wire profiles and verify their actual on-wire behavior.
3. Terminate QUIC in an opt-in integration with Abyss's UDP server.

This execution slice implements **M0 and M1** from `docs/implement-plan.md`. The architecture must accommodate all three goals now; complete networking and the Abyss repository patch are later explicit slices, not placeholder successes in this one.

## Read and inspect first

Read local `AGENTS.md`, this document, `docs/implement-plan.md`, `docs/architecture.md`, `docs/design.md`, `docs/ex-ssl-quic-contract.md`, `docs/fingerprint-design.md`, `docs/abyss-integration.md`, and `docs/testing.md`. Read `docs/ex-ssl-review.md` for dependency acceptance and limitations.

Inspect the actual workspace: branch, HEAD, tracked/untracked changes, existing modules and test suite. Preserve user work. A prior GitHub metadata read returned 404 for `gsmlg-dev/ex_quic`; this is not permission to overwrite a local project or create a remote repository. If code already exists, map it to the milestones and fill verified gaps rather than regenerating it.

Record actual Elixir/OTP versions and baseline commands. Verify applicable RFC errata and source references in `docs/sources.md` while implementing protocol details; do not invent normative behavior from a stub or from successful self-connection alone.

## Dependency and ownership rules

At the time of this initial slice, `gsmlg-dev/ex_ssl@02eb981f59d4e182d4473e264a9f8b093ec6bf3d` was the reviewed Git dependency. The historical `apps/elixir_quic` requirement here was `{:ex_ssl, "== 0.7.2", in_umbrella: true, hex: :ex_ssl}`. In the current destination candidate it is `== 0.16.1`; see [migration provenance](../migration-provenance.md). The sibling source came from upstream `fb47051355c9d0a29caee046fa060a745ad0ce5b` through `ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6`. The `hex` option preserves package metadata while Mix resolves the umbrella sibling. The historical Hex package and source-review evidence remain in the TLS contract.

`SSL.QUIC` and `SSL.Fingerprint` already exist. Do not reopen the completed upstream refactor. Use their documented public contracts, not `SSL.Protocol.*` internals. TLS owns authentication/transcript/fresh key exchange; QUIC owns packet protection, offsets, recovery and transport parameters. Do not implement TLS again, use TLS record TrafficState for packets, or call OTP :ssl as the production handshake implementation.

Use Elixir protocol logic and OTP :crypto/:public_key/network primitives; no C/Rust QUIC dependency or hidden fallback. Name the app `:elixir_quic` (Hex package `elixir_quic`; repository `ex_quic`) and public namespace `Quic`; module names do not use an Ex/Elixir prefix or replace OTP :ssl.

## Required code in this slice

### A. Project and real upstream contract tests

Make the library buildable, document current partial scope and add CI for formatting, warnings-as-errors compilation and real tests. Retain intended portable runtime compatibility and verify actual toolchain availability.

Create isolated test credentials/fixtures and a genuine socket-free both-role handshake using only the upstream public API. Check action order, local read/write secret pairing, actual emitted bytes, transport parameters, role-specific authentication/completion, fatal/abort semantics and an actual ClientHello fingerprint. Do not use hardcoded success/secret values or copied private structs to satisfy the test.

This validates the TLS dependency boundary only. Label it accordingly; it is not QUIC network interop. Never print test traffic secrets in failure output.

### B. Core contracts and helpers

Define explicit tagged errors, datagram metadata, version parameters, connection generation, send receipts, timer tokens and public handles. Implement foundational pure codec/range helpers where used; avoid unused broad frameworks or one GenServer per helper.

Keep the transport core deterministic with explicit time/effects. Invoke the real TLS provider at the serialized runtime boundary because it owns randomness/authentication. Establish a test IO/virtual-clock seam and an external-socket contract suitable for Abyss without importing Abyss modules.

### C. v1 codec/protection implementation

Implement and test varints, invariant/v1 packet headers, packet-number reconstruction, coalesced datagram bounds, Initial-relevant frame codecs, Initial secret derivation, packet AEAD, header protection and Retry integrity. Fill additional frame formats in coherent tested increments, with the remaining baseline formats tracked explicitly.

Use version-specific constants and QUIC labels. Check both TLS-suite availability and OTP packet/header-protection primitives. Unsupported algorithms fail explicitly. Unknown versions must not be parsed as v1. Bounds must be applied before allocation, slicing or expensive operations.

Use RFC9001 Initial/Retry/ChaCha vectors and independently specified codec expectations. Include malformed lengths, short samples, bad tags, boundary packet numbers, unknown frame types, multiple packets and randomized bounded inputs. Expected outputs must not all be produced with the code under test.

Implement the ordered transport-parameter representation and semantic validation foundation. Keep CID-dependent placeholders distinct from fixed profile values. Define bounded CRYPTO reassembly primitives needed by the forthcoming inspector; no dense allocation to a peer-supplied offset.

### D. Documentation and progress

Update a requirements-to-test/progress record listing implemented code, exact tests and remaining M1/M2+ work. Mark QUIC public networking operations as unavailable until real implementation exists. Do not expose a fabricated connect/send success for scaffolding purposes.

Keep `docs/implement-plan.md` authoritative. Archive competing old v1/v2 proposed TLS contracts if present; do not leave two active startup instructions. Preserve user changes and historical review evidence.

## Hard constraints for later compatibility

- Observation uses exact reconstructed ClientHello bytes through SSL.Fingerprint with explicit `:quic` provenance. No target-hash setters and no fingerprint-based identity authentication.
- A streaming fingerprint observer handles one ClientHello; do not feed it unrelated trailing TLS messages.
- Per-level CRYPTO offsets, packet-number spaces and stream offsets are independent.
- TLS emit means committed bytes for a reliable queue, not a successful UDP send; queue admission, actual local-send completion and peer ACK are distinct.
- Keys and retransmission buffers outlive the correct protocol phases; application-secret availability alone does not retire Handshake state.
- Abyss must eventually route CIDs to persistent connections and retain socket ownership. Do not design around per-datagram connection processes or calls into its receive-blocked listener.
- Match capability limits honestly: no implied 0-RTT/resumption/server mTLS/empty-share client support, no automatic HTTP/3 from ALPN h3.
- Every buffer has bounded bytes and items/ranges; every incomplete context has finite lifetime. No unbounded cast queues or packet retry tasks.

## Verification and completion report

Run the actual available equivalents of:

```sh
mix deps.get
mix format --check-formatted
mix compile --warnings-as-errors
mix test
git diff --check
```

Record runtime, source pin, test/property counts and exit status. Report unavailable tools, missing independent captures, skipped runtime combinations and incomplete milestones explicitly. Do not call a missing/empty suite green. No network test, benchmark or security certification is claimed by unit-vector success.

Finish by listing the implemented files, M0/M1 acceptance status, public APIs actually usable, failed/not-run checks and the next precise M2 task. Deliver coherent tested increments rather than marking the whole stack complete.

This task authorizes local work in ex_quic only. It does not authorize edits to ex_ssl or Abyss, remote repository creation, commit, push, release, tag changes, workflow dispatch or publication. A separately scoped Abyss task follows after the generic endpoint contract is stable.
