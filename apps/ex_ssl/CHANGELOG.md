# Changelog

## Unreleased

## [0.7.2] - 2026-09-28

- Reject malformed IPv4/IPv6 reference identities at QUIC TLS construction,
  before emitting a ClientHello; retain mandatory certificate verification and
  the existing public API and ordered actions.
- Add phase-one contract coverage for authentication milestones, terminal states,
  bounded ignored tickets, opaque ALPN, independent SNI and fresh profiles.
- Document the consumer configuration/startup contract and add a packaged
  standalone-consumer smoke check without an OTP `:ssl` runtime dependency.

## [0.7.1] - 2026-09-23

- Use equivalent block syntax and a local binding so all supported Elixir
  formatters accept the same source; retain the full compile/test matrices.

## [0.7.0] - 2026-09-23

- Reject missing certificate/ECDHE key_share and supported_groups while accepting
  a present empty key_share vector for HRR, without restricting fingerprint observation.
- Enforce the configured inbound extension budget on ServerHello and HRR before
  processing cookies or emitting CH2, including fragmented length declarations.
- Preserve shared TLS alert classification in QUIC EncryptedExtensions and ticket
  parsing; retain terminal action atomicity and existing TCP behavior.

## [0.6.0] - 2026-09-23

- Extract the TLS 1.3 client authentication and traffic-secret core from its TCP
  record adapter; preserve client identity and resumption processing.
- Share ClientHello/HRR orchestration with the new experimental `SSL.QUIC`
  caller-owned client/server certificate-handshake API, including ordered traffic
  secrets, raw transport parameters, limits and redacted state/actions.
- Add actual duplex/HRR, cipher/group, fragmentation and authentication-negative
  checks, bounded malformed-input properties and explicit RFC 9001 error domains.
- Add `SSL.Fingerprint` for record-free JA3/JA4 observation of actual ClientHello
  bytes, with explicit TCP/QUIC context and pinned official/reference fixtures.
- Add a pinned aioquic TLS-only comparison and CI job covering both roles,
  all three suites, ECDSA/RSA identities and client CertificateRequest handling.

## [0.5.0] - 2026-09-22

- Run mandatory integration coverage across all three supported Elixir/OTP tuples.
- Add peer capability/version preflight, guarded nonempty test runs, isolated builds,
  sanitized CI summaries, and scheduled resource campaigns.
- Expand deterministic resumption isolation, ticket ordering, restart, ownership,
  closure, cancellation, deadline, and blocked-write cleanup regressions.
- Add an immutable http_fetch source-candidate check and standalone package startup
  validation, plus an independent security-review evidence map.
- Clarify the tested TLS 1.2 peer boundary and fix a resource-test termination race.

This release changes validation, CI, and documentation; the production TLS engine
is unchanged from 0.4.0. Existing consumers can retain 0.4.0. Mandatory verification,
TLS 1.3 defaults, and disabled-by-default resumption are unchanged. Independent
human security review remains incomplete.

## [0.4.0] - 2026-09-22

- Add P-384 ECDHE/ECDSA, Ed25519 and RSA-PSS-PSS with runtime-filtered capabilities.
- Add bounded PEM/DER client identities and initial-handshake mutual TLS.
- Add explicit ordered algorithm policies and a safe TCP option allowlist.
- Add an independent opt-in TLS 1.2 ECDHE/EMS/AES-GCM client engine with four suites.
- Add opt-in TLS 1.3 PSK-DHE resumption with partitioned, bounded in-memory tickets,
  current certificate revalidation, fresh key shares and authenticated HRR binders.
- Add non-secret connection information, peer certificate and address diagnostics.
- Expand interoperability, negative, fragmented-input and lifecycle regressions.

TLS 1.3 remains the library default. Resumption defaults to disabled. Peer
verification remains mandatory. TLS 1.2/mTLS resumption, early data, automatic
backend fallback and request replay are unsupported. This remains an experimental
OTP-compatible client subset; it is not full OTP parity or security certification.
