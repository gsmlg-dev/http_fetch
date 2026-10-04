# ex_ssl Product Requirements Document

## 1. Product

**Name:** ex_ssl\
**OTP application:** `:ex_ssl`\
**Primary module:** `SSL`

## 2. Problem statement

Erlang/OTP `:ssl` provides a mature TLS implementation, but applications that need controlled TLS ClientHello wire behavior cannot freely reproduce the observable handshake characteristics of specific clients such as mobile applications or browsers.

A separate TLS library is needed that:

1. exposes an API compatible with OTP `:ssl` for ordinary client use;
2. implements TLS independently in Elixir/OTP;
3. allows declarative control over ClientHello wire characteristics;
4. remains secure and standards-compliant rather than treating fingerprint spoofing as a replacement for TLS correctness.

## 3. Product vision

An Elixir application should be able to change:

```elixir
:ssl.connect(host, port, options)
```

to:

```elixir
SSL.connect(host, port, options)
```

and retain familiar socket behavior, while gaining an optional profile mechanism that controls ClientHello wire presentation.

## 4. Goals

### G1 — OTP-compatible client API

Provide behavioral compatibility with the commonly used Erlang/OTP `:ssl` client surface.

### G2 — Correct TLS 1.3 client

Implement interoperable TLS 1.3 according to RFC 9846 without delegating the handshake to `:ssl`.

### G3 — Programmable wire profile

Allow exact ordering/control of ClientHello components required to reproduce target wire profiles.

### G4 — Secure server authentication

Support certificate chain and service identity verification using OTP `:public_key` facilities and fail closed on verification errors.

### G5 — OTP socket semantics

Support passive receive and OTP-style active modes/messages sufficiently for existing Elixir/Erlang client libraries.

### G6 — Testable compatibility

Maintain a behavioral compatibility suite that can run equivalent scenarios against OTP `:ssl` and `SSL`.

### G7 — Fingerprint observability

Compute JA3, JA4, and exact-wire diagnostics from the same ClientHello representation emitted by the TLS engine.

## 5. Non-goals for initial release

The current record-free TLS integration is an explicit scope extension described
in [ADR_QUIC_TLS_CORE.md](ADR_QUIC_TLS_CORE.md). It adds a handshake engine for a
future QUIC caller, not QUIC networking, HTTP/3, or TCP server APIs. The following
list describes the historical initial release.

The initial release does not aim to provide:

- TLS server APIs;
- DTLS;
- QUIC/HTTP/3;
- HTTP/2 framing/fingerprinting;
- TLS 1.2;
- 0-RTT;
- client certificate authentication;
- full parity with every historical `:ssl` option;
- passive network sniffing;
- deterministic secret zeroization;
- a native Rust/C NIF TLS implementation.

## 6. Target users

### 6.1 Elixir/Erlang application developer

Needs a `:ssl`-like client API but requires control over the TLS wire profile.

### 6.2 Protocol/library author

Needs to inject `SSL` into an HTTP, IMAP, SMTP, or other client transport with minimal adapter work.

### 6.3 Test/compatibility engineer

Needs reproducible ClientHello layouts, GREASE behavior, and fingerprint diagnostics for interoperability testing.

## 7. Primary user stories

### US1 — Basic TLS connection

As an Elixir developer, I can connect to a TLS 1.3 server with `SSL.connect`, send data, receive data, and close the connection using familiar `:ssl` conventions.

### US2 — Verify peer

As a developer, I can enable peer verification and trust only correctly chained certificates with the expected service identity.

### US3 — STARTTLS

As a protocol developer, I can upgrade an existing connected `:gen_tcp` socket using `SSL.connect(socket, options, timeout)`.

### US4 — Active mode

As a developer, I can configure `active: false`, `true`, `:once`, or a positive integer and receive OTP-compatible SSL messages.

### US5 — ALPN

As an HTTP/client-library author, I can advertise ALPN protocols and inspect the negotiated protocol.

### US6 — Wire profile

As a developer, I can select a named or supplied `ex_ssl` profile that controls ClientHello ordering and extension composition without replacing ordinary TLS options.

### US7 — GREASE

As a profile author, I can place GREASE placeholders in defined positions and choose deterministic test behavior or appropriate randomized production behavior.

### US8 — Fingerprint introspection

As a developer, I can inspect the resulting JA3/JA4 and ordered wire features for a materialized ClientHello.

### US9 — Ownership transfer

As a library author, I can move socket control to another process using `SSL.controlling_process/2` and receive future active messages there.

### US10 — Post-handshake control

As a TLS client, the connection remains valid when it receives TLS 1.3 post-handshake messages such as NewSessionTicket or KeyUpdate.

## 8. Functional requirements

### FR-1 Public naming

- package name SHALL be `ex_ssl`;
- OTP application SHALL be `:ex_ssl`;
- primary public module SHALL be `SSL`;
- internal modules SHALL use `SSL.*`.

### FR-2 Client connection API

The MVP SHALL implement:

- `SSL.connect/2` for existing TCP socket upgrade;
- `SSL.connect/3` overloaded compatibly with OTP forms;
- `SSL.connect/4` for host/port/options/timeout.

### FR-3 Data API

The MVP SHALL implement:

- `SSL.send/2`;
- `SSL.recv/2`;
- `SSL.recv/3`;
- `SSL.close/1`;
- `SSL.shutdown/2` where semantics are supported.

### FR-4 Ownership and options

The MVP SHALL implement:

- `SSL.setopts/2`;
- `SSL.getopts/2` for supported options;
- `SSL.controlling_process/2`;
- application-visible active/passive behavior.

### FR-5 Active messages

For supported modes, the owner SHALL receive OTP-compatible forms:

```elixir
{:ssl, socket, data}
{:ssl_closed, socket}
{:ssl_error, socket, reason}
{:ssl_passive, socket}
```

### FR-6 TLS protocol

The first protocol implementation SHALL support TLS 1.3 and at least:

- ClientHello;
- ServerHello;
- HelloRetryRequest;
- EncryptedExtensions;
- Certificate;
- CertificateVerify;
- Finished;
- alerts;
- close_notify;
- NewSessionTicket parsing;
- KeyUpdate.

### FR-7 Cipher suites

Target support:

- TLS_AES_128_GCM_SHA256;
- TLS_AES_256_GCM_SHA384;
- TLS_CHACHA20_POLY1305_SHA256.

Actual runtime availability SHALL be checked against OTP crypto capabilities.

### FR-8 Key exchange groups

Initial target groups:

- X25519;
- secp256r1.

Additional groups may be added after core interoperability.

### FR-9 Certificate verification

With peer verification enabled, ex_ssl SHALL perform:

- X.509 path validation;
- trust-anchor validation;
- service identity/hostname validation;
- CertificateVerify verification;
- Finished verification.

### FR-10 ALPN

The client SHALL support ALPN advertisement and expose the negotiated protocol via `SSL.negotiated_protocol/1` where a protocol is negotiated.

### FR-11 ClientHello profile

Custom profile configuration SHALL be namespaced under `:ex_ssl`.

A profile SHALL be able to define the ordered ClientHello structure needed by the supported profile model.

### FR-12 Fresh ephemeral material

Real KeyShare values SHALL be generated freshly per connection and SHALL NOT be reusable fixed values in a named profile.

### FR-13 Fingerprints

The library SHALL provide JA3 and JA4 projections from its parsed/materialized ClientHello model.

Fingerprint calculations SHALL not control TLS negotiation.

### FR-14 Stream framing

The implementation SHALL correctly process arbitrary valid fragmentation across:

- TCP chunks;
- TLS records;
- handshake messages.

### FR-15 Introspection

The compatibility roadmap SHALL include:

- `peername/1`;
- `sockname/1`;
- `peercert/1`;
- `negotiated_protocol/1`;
- `connection_information/1,2`;
- `getstat/1,2`;
- `versions/0`.

### FR-16 Key update/exporter

TLS 1.3-compatible `update_keys/2` and exporter APIs SHALL be implemented before declaring broad OTP client compatibility.

## 9. Non-functional requirements

### NFR-1 Security correctness before fingerprint fidelity

A profile may shape only behavior permitted by implemented TLS semantics. Fingerprint fidelity SHALL NOT justify bypassing authentication or accepting malformed peer behavior.

### NFR-2 Isolation

Each TLS connection SHALL isolate its cryptographic and buffering state from every other connection.

### NFR-3 No global hot-state contention

Per-connection traffic state SHALL not use a shared ETS table or centralized key process.

### NFR-4 Throughput

The implementation SHOULD use binary matching, iodata, and native OTP crypto primitives. It SHALL avoid one-process-per-record/message architectures.

### NFR-5 Backpressure

The raw socket SHALL not run uncontrolled `active: true`. Internal receive flow SHALL permit backpressure.

### NFR-6 Memory limits

Record, handshake, and application buffers SHALL have explicit/configurable size limits to prevent unbounded memory consumption from malformed or stalled peers.

### NFR-7 Secret hygiene

Secrets SHALL not be logged or emitted in ordinary telemetry/crash metadata. Documentation SHALL not claim deterministic BEAM memory zeroization.

### NFR-8 Deterministic testing

Wire profiles SHALL support deterministic test materialization without weakening production randomness.

### NFR-9 Documentation

Every public compatibility function and every custom profile option SHALL be documented.

## 10. Compatibility requirements

Compatibility is measured in levels.

### Level A — function API

Same function names, arities, and ordinary return shapes for implemented calls.

### Level B — option semantics

Common TLS and socket options behave equivalently in covered cases.

### Level C — socket behavior

Passive receive, active modes, ownership transfer, timeouts, and close behavior are equivalent in covered cases.

### Level D — active messages

Message tags and socket term identity behave compatibly.

### Level E — introspection

Negotiated and transport information is available through corresponding OTP-style functions.

### Level F — advanced TLS

Key update, exporters, tickets/resumption, and broader options are supported.

The README MUST state the achieved level/features rather than simply claiming full replacement before tests demonstrate it.

## 11. Security requirements

- RFC 9846 is the normative TLS 1.3 reference.
- GREASE behavior follows RFC 8701.
- Service identity behavior follows current OTP/public_key semantics and RFC 9525 where applicable.
- `verify_peer` fails closed.
- malformed records/messages terminate the connection with the correct alert/error where possible.
- sequence counters never wrap silently.
- AEAD authentication failure is fatal.
- Finished verification failure is fatal.
- CertificateVerify failure is fatal.
- KeyShare ephemeral values are not reused across connections.
- profile `raw` escape hatches, if exposed, are documented as advanced and validated against structural safety constraints.

## 12. MVP acceptance criteria

The MVP is accepted when all of the following pass:

1. `SSL.connect(host, port, opts, timeout)` completes TLS 1.3 with an independent OTP `:ssl` server.
2. The same succeeds against OpenSSL `s_server`.
3. `SSL.send/2` and `SSL.recv/3` exchange application data.
4. `active: false`, `true`, `:once`, and positive integer modes pass compatibility scenarios.
5. `SSL.controlling_process/2` transfers future active delivery to the new owner.
6. `SSL.connect(existing_tcp_socket, opts, timeout)` performs a working STARTTLS-style upgrade.
7. certificate path failure is rejected.
8. hostname mismatch is rejected.
9. ALPN negotiation is exposed.
10. arbitrary TCP chunk fragmentation does not alter valid handshake parsing.
11. a deterministic test profile produces its golden ClientHello layout.
12. JA3 and JA4 golden outputs are correct for that ClientHello.
13. HelloRetryRequest succeeds against a test endpoint that requires it.
14. inbound NewSessionTicket does not disrupt the established connection.
15. inbound/outbound close_notify behavior is tested.
16. the TLS handshake code does not call OTP `:ssl` to perform TLS.

## 13. v0.1 release target

The first public development release should be described as experimental and include:

- TLS 1.3 client;
- core OTP-like client API;
- peer verification;
- X25519/secp256r1 where available;
- three primary TLS 1.3 cipher suites where available;
- ALPN;
- active/passive modes;
- STARTTLS;
- custom WireProfile;
- GREASE;
- JA3/JA4 introspection;
- compatibility matrix and test results.

It should not claim production parity with OTP `:ssl`.

## 14. Follow-up milestones

### v0.2

- wider option compatibility;
- session ticket storage/resumption;
- exporter completion;
- packet mode expansion;
- key logging callback;
- multiple verified real-world ClientHello profiles.

### v0.3

- TLS 1.2 client to support legitimate fallback in mobile/browser-like profiles;
- expanded cipher/signature compatibility;
- additional differential tests.

### Later

- server-side APIs;
- optional passive ClientHello analyzer;
- broader transport hooks;
- performance optimization based on benchmarks.

## 15. Product risks

### R1 — "Fingerprint match" is broader than JA3

Matching JA3 alone does not reproduce a client. Raw extension order, extension contents, GREASE, record behavior, TCP behavior, HTTP/2, and QUIC may remain distinguishable.

Mitigation: market/configure the feature as TLS wire-profile control, not perfect device impersonation.

### R2 — OTP compatibility is large

`:ssl` has a wide historical option/API surface.

Mitigation: maintain an explicit compatibility matrix and incremental levels.

### R3 — TLS implementation security

A new TLS stack can contain security defects.

Mitigation: narrow protocol scope, use native vetted primitives, require differential/interoperability/vector/property tests, and keep a clear experimental status until audited/mature.

### R4 — BEAM secret lifetime

Garbage collection prevents strict deterministic erasure.

Mitigation: minimize secret references/lifetime and document the limitation.

## 16. Success metrics

Engineering success is measured by:

- percentage of targeted OTP client compatibility tests passing;
- TLS interoperability matrix pass rate;
- zero known protocol-vector failures;
- golden profile wire accuracy;
- absence of unbounded parser/buffer behavior under fuzz/property tests;
- ability to adopt `SSL` in at least one existing application/library with only module substitution plus profile configuration.
