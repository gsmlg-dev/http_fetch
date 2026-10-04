# Fingerprint observation and simulation

## Three separate operations

**Observation** extracts fields and JA3/JA4 from the actual visible ClientHello. **Matching** produces candidate catalogue entries with evidence. **Simulation** materializes a legal profile into actual wire behavior. None is a client authentication mechanism, and equality of a hash alone proves neither a unique implementation nor complete browser equivalence. [R4,S7]

Reuse `SSL.Fingerprint.client_hello(encoded_handshake, :quic)`. Input contains the TLS handshake header, not a TLS record or a QUIC packet. Its direct and streaming forms already exist at the ex_ssl pin; do not copy the algorithms into ex_quic. The streaming form observes one hello and rejects trailing data, so split CRYPTO handshake messages correctly before use. [R4]

## Observation pipeline

Datagram metadata -> version-aware packet extraction -> Initial protection -> bounded CRYPTO reassembly -> complete ClientHello bytes -> upstream fingerprint -> optional candidate lookup.

Keep transport provenance `:quic`, QUIC version, direction, context/connection ID and hello sequence. JA4 uses the QUIC prefix `q`; JA3 is a ClientHello projection carrying explicit QUIC provenance, not a separate invented "JA3Q" standard. SNI and ALPN affect only their defined projections. Unknown IDs and wire order remain available in raw observation. [R4,S7]

Initial visibility does not grant application-traffic decryption. An ECH capture describes visible outer fields only. Incomplete captures yield incomplete results; never fill missing fields with a profile template. A UDP listener observes packets delivered to its socket, not all host/network traffic.

Handle QUIC Retry, Initial retransmission and TLS HelloRetryRequest separately. Retry changes packet/key context under the v1 rules, while HRR can produce a distinct ClientHello2. A result should identify which hello it describes, not silently replace the first with the second. [S1,S2]

## Profile model

A versioned profile has an ID, source/provenance, supported transport versions, required capabilities and separate TLS/QUIC policy. TLS policy uses the public ordered ex_ssl WireProfile. QUIC policy controls ordered transport parameters and permitted packetization, padding and locally issued CID-length behavior.

A profile never stores real reusable ephemeral private/public key shares, fixed production nonces or live traffic secrets. Per-connection material stays fresh. Expected fingerprints belong in test/validation metadata, not a network setting. The same emitted bytes feed the observation pipeline and the actual transport.

Transport parameters contain fields derived from the connection, not all fixed constants. Resolve the real CID/Retry-dependent placeholders and use the exact resulting payload in both TLS config and WireProfile. Preserve order without using map iteration as the wire format.

The current TLS provider limits negotiation to implemented/available algorithms and does not support resumption, 0-RTT, an empty-share initial client profile or arbitrary server profiles. A requested browser/mobile fingerprint can therefore be unsupported. Report the actual missing capability; do not weaken verification or add fake extensions just to return the desired digest. [R3]

## Fidelity levels

| Level | Evidence | Does not establish |
|---|---|---|
| F0 | Same derived JA3/JA4 fields/hash | Exact original handshake or browser identity |
| F1 | Selected ordered ClientHello fields match a versioned source | Entire QUIC behavior |
| F2 | Selected QUIC parameter/packetization behavior also matches | HTTP/3/QPACK/request behavior |
| F3 | Future implemented application-layer behavior is measured too | An authenticated device identity |

For every named client profile, record the claimed level, capture source/version/date, supported parameters and known deviations. At the initial milestone provide two legitimate measured profiles without unsupported browser branding.

## Acceptance and catalogue

Capture on an independent receiver/observer after real serialization and packetization. Compare hashes and raw selected fields, then separately verify certificate-authenticated handshake and actual stream transfer. A hash calculated from local config alone is insufficient.

Catalogue matching is optional and local/versioned first. Return candidate IDs, matched features and ambiguity; avoid uncalibrated numeric probabilities. Capture timestamps, SNI and other raw fields are sensitive diagnostic information. Store only what the caller explicitly opts to retain, with bounded retention and low-cardinality metrics.

JA4 TLS client fingerprinting and the broader JA4+ family have different licensing. This project integrates the upstream TLS client analyzer only; other JA4+ algorithms require a separate scope/license review. Preserve the upstream fixture attribution and pinned definition rather than copying an unversioned online database. [R4,S7]

See [sources](sources.md), [TLS contract](ex-ssl-quic-contract.md) and [testing](testing.md).
