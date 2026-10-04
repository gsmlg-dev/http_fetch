# Revision 3 — move from TLS prerequisite work to QUIC implementation

Date: 2026-09-23.

## Changes from revision 2

| Previous planning assumption | Revision 3 decision |
|---|---|
| SSL.QUIC is a proposed interface to implement upstream | Pin and consume the actual v0.7.1 public API; no prerequisite TLS refactor task |
| Fingerprint parser/projections need to be exposed | Reuse actual SSL.Fingerprint direct and fragmented APIs |
| First release can be understood as a client-only increment | Observer, profile client and Abyss server remain required product deliverables |
| Whole protocol path can be described as deterministic pure functions | Transport core is deterministic; actual TLS/entropy/authentication runs at serialized runtime boundary |
| TLS output means a packet was sent | Explicit CRYPTO retention, send reservation, local receipt and ACK semantics |
| Server integration is a transport-module substitution | Add an opt-in pre-handler dispatcher plus bounded CID routing and independent egress |
| v0.7.0 CI formatting remains a dependency blocker | F1 fixed by minimal equivalent syntax; supported compiler/test lanes pass |
| Dependency can simply name a Hex version | Start with reviewed Git SHA; GitHub release is not proof of Hex availability |

## Supersession rules

Use this package as the active plan. In an existing workspace, preserve historical documents in an explicitly non-authoritative archive rather than leaving competing CODEX-START instructions active. In particular, retire `docs/revision-2.md` and any older proposed ex_ssl export API from active reading lists. Existing local code and user edits must be preserved and mapped to the new milestones, not overwritten.

The architecture and initial contracts can be implemented now. Current provider limitations stay in the support matrix; future TLS feature proposals need a separate justified task, not speculative scope growth in M0.

## Immediate work

Run [CODEX-START.md](../CODEX-START.md) for M0–M1. Deliver real scaffolding, public-provider contract checks, codecs, Initial/Retry protection and vectors. M2 provides the first observer result; M3 covers both-role handshakes; M4 covers streams/profiles; M5 is the Abyss deliverable; M6 is the experimental acceptance gate.

No new ex_ssl fix prompt is issued. No implementation or remote write was performed while authoring this package.
