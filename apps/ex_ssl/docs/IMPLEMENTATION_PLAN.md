# ex_ssl Implementation Plan

The cross-repository TCP TLS expansion follows
[ex_ssl-http_fetch-implementation-plan.md](ex_ssl-http_fetch-implementation-plan.md),
with current evidence in [EX_SSL_HTTP_FETCH_PROGRESS.md](EX_SSL_HTTP_FETCH_PROGRESS.md).
The historical roadmap below is retained.

The active record-free TLS task is defined in root `CODEX-PROMPT.md`, with the
accepted boundary in [ADR_QUIC_TLS_CORE.md](ADR_QUIC_TLS_CORE.md) and executed
evidence/remaining gates in [QUIC_TLS_IMPLEMENTATION.md](QUIC_TLS_IMPLEMENTATION.md).

## 1. Delivery strategy

The current implementation cycle targets the restricted Manifold client subset
documented in [COMPATIBILITY.md](COMPATIBILITY.md), following Phases 4–6 and 8,
with the necessary Phase 10 post-handshake processing and Phase 12 limits.
Application active modes and general API breadth remain later milestones.
The library gate must pass before a separate Manifold consumer change starts.

Implement `ex_ssl` in vertical protocol slices. Do not create dozens of empty modules first and do not attempt full OTP `:ssl` parity before the first real handshake.

Every phase ends in an executable/testable capability.

Primary target:

```text
OTP app    :ex_ssl
Public API SSL
Protocol   TLS 1.3 client
Baseline   OTP 29 client behavior
```

## 2. Work rules

1. RFC 9846 is normative for TLS 1.3.
2. Do not use OTP `:ssl` to implement the ex_ssl handshake.
3. `:ssl` is allowed in tests as an independent comparison/interoperability endpoint.
4. Use `:crypto` and `:public_key` for primitives/PKIX.
5. Protocol parsers/encoders should be pure.
6. Socket I/O stays in the connection runtime.
7. No profile may contain reusable real ephemeral KeyShare material.
8. Security verification must fail closed.
9. Unsupported OTP options must error explicitly.
10. Add compatibility tests alongside API functions, not later.

## 3. Phase 0 — Repository bootstrap

### Task 0.1 — Mix project

Create the library/application skeleton:

```text
mix.exs
README.md
ARCHITECTURE.md
DESIGN.md
PRD.md
IMPLEMENTATION_PLAN.md
AGENTS.md
lib/ssl.ex
lib/ssl/application.ex
lib/ssl/supervisor.ex
lib/ssl/connection_supervisor.ex
```

Requirements:

- OTP application name `:ex_ssl`;
- public module `SSL`;
- start `SSL.ConnectionSupervisor`;
- no dependency on OTP `:ssl` in runtime application code;
- add formatter, ExUnit, Credo/Dialyzer only if project conventions justify them;
- choose a supported Elixir/OTP baseline and document it.

### Task 0.2 — CI/test foundation

Set up:

- `mix format --check-formatted`;
- `mix test`;
- static checks selected for the project;
- optional integration test tag excluded by default;
- deterministic crypto/profile test helpers.

### Exit gate

Application starts and test pipeline is green.

## 4. Phase 1 — Pure binary foundations

These tasks can proceed largely in parallel.

### Task 1A — TLS constants and alert codec

Implement:

- content types;
- handshake types;
- extension IDs used by MVP;
- TLS versions;
- cipher suite IDs;
- named groups;
- signature scheme IDs;
- TLS alert encoding/decoding.

Avoid giant atom lookup layers where direct integers are clearer internally.

### Task 1B — Record framer

Implement `SSL.Protocol.RecordFramer`:

- partial 5-byte header;
- partial record body;
- multiple records per feed;
- length validation;
- retained remainder.

Tests:

- all split points for representative records;
- multiple concatenated records;
- malformed length/bounds;
- property-based random fragmentation.

### Task 1C — Handshake framer

Implement `SSL.Protocol.HandshakeFramer` independently of records.

Tests:

- multiple messages in one input;
- one message split across arbitrary feed chunks;
- 24-bit handshake length;
- size limit.

### Task 1D — Transcript

Implement `SSL.Protocol.Transcript`:

- append exact encoded message;
- digest;
- immutable checkpoint;
- HRR message_hash rewrite.

Add RFC/reference vectors where available.

### Exit gate

Record and handshake framing are fragmentation-safe with property tests.

## 5. Phase 2 — TLS 1.3 crypto primitives

Tasks 2A–2D can be developed in parallel behind stable pure APIs.

### Task 2A — HKDF

Implement:

- extract;
- expand;
- expand_label;
- derive_secret.

Use known vectors and independent checks.

### Task 2B — Traffic state and nonce

Implement `SSL.Crypto.TrafficState`:

- secret;
- key;
- IV;
- sequence;
- generation.

Implement deterministic nonce derivation and overflow checks.

### Task 2C — AEAD

Implement encrypt/decrypt wrappers using `:crypto.crypto_one_time_aead` for:

- AES-128-GCM;
- AES-256-GCM;
- ChaCha20-Poly1305.

Runtime capability checks required.

### Task 2D — Key exchange

Implement fresh ephemeral key generation/shared secret for:

- X25519;
- secp256r1.

Test both success and malformed peer keys.

### Task 2E — Key schedule

After 2A/2B are stable, implement TLS 1.3 key schedule:

- early secret;
- handshake secret;
- client/server handshake traffic secrets;
- main/master secret;
- application traffic secrets;
- exporter/resumption derivations as needed;
- Finished keys;
- traffic update derivation.

### Exit gate

Crypto modules pass vectors and have no connection/process dependencies.

## 6. Phase 3 — ClientHello and profile engine

### Task 3A — Extension codecs

Implement typed encoders/decoders for MVP extensions:

- server_name;
- supported_groups;
- ec_point_formats where profile compatibility requires it;
- signature_algorithms;
- signature_algorithms_cert;
- ALPN;
- supported_versions;
- psk_key_exchange_modes;
- key_share;
- padding;
- selected safe raw/unknown extension pass-through for parser diagnostics.

### Task 3B — WireProfile model

Implement:

- ordered cipher list;
- ordered extension specs;
- session-id policy;
- GREASE policy;
- record policy;
- validation against engine/runtime capabilities.

### Task 3C — GREASE materializer

Implement symbolic GREASE slots and deterministic/random policies following RFC 8701.

Never confuse GREASE placeholders with arbitrary invalid values.

### Task 3D — ClientHello materialization/serialization

Pipeline:

```text
profile -> validate -> materialize -> AST -> exact bytes
```

Generate fresh random/session/key-share state per connection.

### Task 3E — ClientHello parser

Implement parser needed for:

- self inspection;
- fingerprint calculation;
- golden tests;
- later passive analysis reuse.

### Task 3F — JA3/JA4

Implement separate analyzers with golden vectors.

### Exit gate

At least one deterministic test profile produces exact golden ClientHello bytes and stable JA3/JA4 outputs.

## 7. Phase 4 — ServerHello and handshake cryptographic verification

### Task 4A — ServerHello/HRR parser

Implement semantic parsing and validation for:

- ServerHello;
- HelloRetryRequest distinction;
- supported_versions selection;
- selected cipher;
- key_share;
- allowed extensions.

### Task 4B — HRR transition

Implement:

- HRR validation;
- transcript rewrite;
- fresh second KeyShare;
- ClientHello2 generation;
- profile-preserving CH2 rules.

### Task 4C — Encrypted handshake message codecs

Implement:

- EncryptedExtensions;
- Certificate;
- CertificateVerify;
- Finished;
- CertificateRequest enough to reject/handle defined MVP behavior;
- NewSessionTicket;
- KeyUpdate.

### Task 4D — PKIX

Implement:

- trust source normalization;
- certificate path verification using `:public_key`;
- service identity verification;
- peer certificate exposure.

### Task 4E — CertificateVerify

Implement role/context construction and signature verification for MVP schemes.

Prioritize schemes encountered by interoperability targets and current OTP crypto availability.

### Task 4F — Finished

Implement Finished key derivation, verify-data generation, constant-time comparison, and client Finished generation.

### Exit gate

Pure/in-memory handshake sequence can consume a captured server flight and verify it correctly.

## 8. Phase 5 — Connection runtime and first real handshake

### Task 5A — `SSL.Socket` and connection supervisor

Implement stable socket identity and worker lifecycle.

### Task 5B — TCP connect path

Implement `SSL.connect(host, port, opts, timeout)`:

- normalize options;
- establish TCP;
- transfer ownership to connection process;
- materialize/send ClientHello;
- internally use active-once receive;
- honor handshake timeout.

### Task 5C — `:gen_statem` handshake orchestration

Wire record framing, decrypt, handshake framing, handshake machine, key transitions, errors, alerts.

### Task 5D — First interoperability target

Use an OTP `:ssl` TLS 1.3 server in integration tests.

Do not optimize API breadth until this handshake is working.

### Task 5E — OpenSSL interoperability

Add opt-in test script/harness against `openssl s_server`.

### Exit gate

`SSL.connect` reaches `:connected` and establishes authenticated TLS 1.3 against two independent server implementations.

## 9. Phase 6 — Application data API

### Task 6A — Record protection for application data

Implement write/read application records with independent read/write epochs and sequence counters.

### Task 6B — Passive `send/recv`

Implement:

- `SSL.send/2` accepting iodata;
- `SSL.recv/2`;
- `SSL.recv/3`;
- pending receive timeout;
- close/error wakeup.

### Task 6C — Packet mode foundation

Implement `packet: 0` first, then 1/2/4 and line.

### Exit gate

Echo request/response passes with binary data and fragmented records.

## 10. Phase 7 — OTP active-mode compatibility

### Task 7A — active false/true/once

Implement application-visible virtual active state while raw TCP remains controlled internally.

Messages:

```text
{:ssl, socket, data}
{:ssl_closed, socket}
{:ssl_error, socket, reason}
```

### Task 7B — active N

Implement decrementing positive integer mode and exact transition message:

```text
{:ssl_passive, socket}
```

### Task 7C — ownership transfer

Implement `SSL.controlling_process/2` and differential tests against OTP.

### Exit gate

Active-mode behavioral suite passes for the covered modes against OTP reference scenarios.

## 11. Phase 8 — STARTTLS and transport compatibility

### Task 8A — existing socket connect forms

Implement:

- `SSL.connect(tcp_socket, tls_opts)`;
- `SSL.connect(tcp_socket, tls_opts, timeout)`.

### Task 8B — handoff correctness

Test:

- ownership transfer;
- existing option normalization;
- no plaintext loss;
- timeout/error paths.

### Exit gate

A simple plaintext protocol can issue STARTTLS then exchange protected application data.

## 12. Phase 9 — OTP compatibility facade breadth

Tasks may be parallelized once the connection core is stable.

### Task 9A — introspection

Implement/test:

- `peername/1`;
- `sockname/1`;
- `peercert/1`;
- `negotiated_protocol/1`;
- `connection_information/1,2`;
- `getstat/1,2`.

### Task 9B — options

Expand `setopts/getopts` and TLS option compatibility based on a checked-in matrix.

### Task 9C — lifecycle/errors

Implement/test:

- close_notify;
- fatal alerts;
- `shutdown/2`;
- `format_error/1`;
- `close/2` subset or explicit unsupported status.

### Task 9D — versions/utilities

Implement `versions/0` and selected cipher/group utility functions if needed by users/libraries.

### Exit gate

README compatibility matrix accurately reflects test coverage and no documented supported item lacks tests.

## 13. Phase 10 — Post-handshake and advanced TLS 1.3

### Task 10A — NewSessionTicket

Parse safely. Add ticket state abstraction.

### Task 10B — KeyUpdate

Implement inbound/outbound updates and `SSL.update_keys/2`.

### Task 10C — exporters

Implement `export_key_materials/4,5` using correct TLS 1.3 exporter secrets and compatible consume semantics where applicable.

### Task 10D — session resumption

Add only after ticket parsing and key schedule are mature.

0-RTT remains explicitly deferred.

### Exit gate

Long-lived connections survive post-handshake messages and key rotation tests.

## 14. Phase 11 — Verified profiles

### Task 11A — capture format

Define a reproducible test fixture format containing:

- raw ClientHello;
- ordered parsed fields;
- expected JA3;
- expected JA4;
- expected variable masks/fields;
- source/client version metadata.

### Task 11B — profile verification tooling

Build a developer tool that materializes a profile and compares it to a fixture while masking declared random/fresh fields.

### Task 11C — first real profiles

Add profiles only when backed by captures and clearly versioned. Do not create vague aliases like `:chrome` that pretend fingerprint stability across versions.

Prefer names that encode client/platform/version policy.

### Exit gate

At least one real target profile passes golden structural comparison and real TLS interoperability.

## 15. Phase 12 — Hardening

Parallel work streams:

### Task 12A — fuzz/property expansion

- malformed record lengths;
- malformed handshake lengths;
- malformed extensions;
- duplicate extensions;
- padding edge cases;
- AEAD failures;
- alert storms;
- random TCP segmentation.

### Task 12B — resource limits

Add explicit limits for:

- record buffers;
- handshake message size;
- certificate chain bytes/count;
- application buffering;
- pending outbound data.

### Task 12C — concurrency/load

Test many connections with:

- bounded mailboxes;
- active delivery;
- slow consumers;
- abrupt peer closure.

### Task 12D — secret/log review

Audit logs, exceptions, inspection implementations, and crash paths for secret leakage.

### Exit gate

No unbounded parser path found by tests; load tests show stable connection isolation; secret audit passes.

## 16. Parallel execution map for Codex agents

After bootstrap, use separate worktrees/agents where practical:

```text
Agent A  Record + Handshake framing
Agent B  HKDF + KeySchedule
Agent C  AEAD + TrafficState
Agent D  WireProfile + GREASE
Agent E  ClientHello extension codecs + serializer
Agent F  PKIX + CertificateVerify
Agent G  Compatibility test harness
```

Integration order:

```text
A + B + C
    │
    ├──────────────┐
    ▼              ▼
E + D          F
    │              │
    └──────┬───────┘
           ▼
     Connection runtime
           │
           ▼
    Compatibility APIs
```

Avoid parallel edits to `SSL.Connection` until pure subsystem APIs are stable; it will otherwise become the merge-conflict hotspot.

## 17. Testing matrix

### Unit

```text
codec         ExUnit
crypto        vectors
framing       all split points + property tests
profiles      golden AST/bytes
fingerprint   golden hashes/components
options       table-driven compatibility
```

### Integration

```text
OTP :ssl server         required
OpenSSL s_server        required opt-in/CI service
public endpoint         optional opt-in
HRR fixture/server      required
STARTTLS harness        required
```

### Differential

For each supported compatibility feature:

```text
same scenario -> :ssl
same scenario -> SSL
compare externally visible behavior
```

## 18. Commit strategy

Keep commits narrowly reviewable:

- one protocol primitive or coherent vertical slice per commit;
- tests in the same commit as behavior;
- no "implement TLS" mega-commit;
- no formatting-only churn mixed with crypto/protocol logic;
- docs updated when compatibility claims change.

Suggested early commit sequence:

1. `bootstrap ex_ssl application and SSL facade`
2. `add TLS record stream framer`
3. `add handshake stream framer and transcript`
4. `implement TLS 1.3 HKDF primitives`
5. `implement AEAD traffic state`
6. `add WireProfile and GREASE materialization`
7. `serialize programmable ClientHello`
8. `parse ServerHello and HelloRetryRequest`
9. `verify TLS 1.3 server flight`
10. `establish first authenticated TLS 1.3 connection`

## 19. Release gates

Do not publish a release claiming a capability until its gate passes.

### Gate A — protocol correctness

Vectors + independent server interoperability.

### Gate B — authentication

Bad chain, hostname mismatch, bad CertificateVerify, and bad Finished are all rejected.

### Gate C — stream correctness

Arbitrary fragmentation tests pass.

### Gate D — API behavior

Differential tests pass for every documented compatible function/mode.

### Gate E — profile fidelity

Golden ClientHello tests pass, including allowed randomness masks.

## 20. Definition of done for Codex initial assignment

For the first Codex execution cycle, stop after a coherent **foundation PR** containing:

- Mix/OTP application;
- `SSL` facade skeleton with documented planned API;
- supervisor/connection supervisor;
- record framer;
- handshake framer;
- transcript including HRR rewrite tests;
- HKDF including Expand-Label tests;
- traffic nonce helper/tests;
- `WireProfile` initial data model and validation skeleton;
- CI/test configuration;
- compatibility test harness skeleton;
- all project documents committed.

Do **not** attempt the entire TLS handshake in the foundation PR. The second cycle should target deterministic ClientHello generation plus ServerHello parsing; the third should target the first authenticated handshake.
