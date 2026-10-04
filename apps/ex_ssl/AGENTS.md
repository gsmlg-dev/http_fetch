# AGENTS.md — ex_ssl

## Mission

Implement `ex_ssl`, an independent Elixir/OTP TLS stack with:

- OTP application name `:ex_ssl`;
- public compatibility module `SSL`;
- TLS 1.3 client first;
- behavioral compatibility with Erlang/OTP `:ssl` for implemented client features;
- programmable ClientHello wire profiles;
- JA3/JA4 as derived analyzers, not protocol configuration.

Read these files before changing architecture:

1. `docs/ARCHITECTURE.md`
2. `docs/DESIGN.md`
3. `docs/PRD.md`
4. `docs/IMPLEMENTATION_PLAN.md`
5. `README.md`

## Source-of-truth hierarchy

For protocol questions use this order:

1. RFC 9846 for TLS 1.3
2. RFCs referenced/updated by it, including RFC 8701 for GREASE
3. current IANA TLS registries
4. current Erlang/OTP public docs for API compatibility
5. independent interoperability behavior

RFC 8446 is historical background; RFC 9846 is the normative TLS 1.3 specification for this project.

For OTP compatibility, target the documented public behavior of OTP 29 initially. Do not copy private OTP SSL internals merely to make structures look similar.

## Hard constraints

### Do not use `:ssl` as the implementation

Runtime TLS handshakes, encryption, record parsing, transcript handling, and negotiation MUST be performed by ex_ssl.

`:ssl` may be used only as:

- a test/reference server;
- a differential API behavior reference;
- a source of documented public semantics.

### Use OTP crypto primitives

Use `:crypto` and `:public_key` for cryptographic primitives and PKIX.

Do not implement AES, ChaCha20, SHA, HMAC, elliptic-curve arithmetic, or X.509 path validation in Elixir.

### No reusable KeyShare

Never put reusable real private/public ephemeral KeyShare bytes in a profile. Every connection generates fresh key exchange material.

### Security beats fingerprint fidelity

Never bypass certificate verification, Finished verification, AEAD authentication, protocol constraints, or fresh-key requirements to match a fingerprint.

### No hidden option acceptance

If a caller supplies a standard OTP `:ssl` option that ex_ssl does not support, return an explicit compatible option error. Do not silently ignore it.

### No map-based wire ordering

Ordered TLS fields, especially extensions and cipher suites, use ordered lists/AST nodes. Do not depend on map enumeration order for wire serialization.

### Do not conflate boundaries

Never assume:

- one TCP message == one TLS record;
- one TLS record == one handshake message;
- one TLS application record == one `recv` result;
- one TLS record == one OTP packet-mode item.

## Naming rules

Use:

```text
package       ex_ssl
OTP app       :ex_ssl
public module SSL
internals     SSL.*
```

Do not introduce `ExSSL.*` unless the architecture is deliberately changed first.

Do not create an Erlang module named `:ssl`; it would conflict with OTP.

## Architecture rules

The record-free TLS 1.3 integration follows `docs/ADR_QUIC_TLS_CORE.md`.
Share handshake authentication and secret derivation between TCP and `SSL.QUIC`;
keep TLS record keys/encryption in the TCP adapter. QUIC networking and TCP server
APIs remain outside this task. Track actual implementation and verification in
`docs/QUIC_TLS_IMPLEMENTATION.md`; a contract document is not a support claim.

### Public layer

`SSL` translates OTP-compatible calls/options/results into the internal implementation.

### Runtime

One `SSL.Connection` `:gen_statem` per connection.

It owns:

- raw socket;
- protocol state;
- traffic keys;
- transcript;
- buffers;
- application owner state.

### Pure core

Protocol codecs, framers, transcript operations, key schedule, ClientHello materialization, and fingerprinting should be pure functions wherever practical.

They must not call `GenServer`, `:gen_tcp`, Logger, Registry, or send process messages.

### Dependency direction

```text
SSL
 ↓
Connection / Options / Socket
 ↓
Protocol orchestration
 ↓
Codec / Crypto / PKIX / ClientHello / Packet
```

Lower layers may not depend on `SSL.Connection`.

## Runtime socket rule

The TLS connection process keeps control of the underlying TCP socket and normally uses internal `active: :once`.

Application-visible modes (`false`, `true`, `:once`, positive integer) are virtual TLS modes implemented above decryption/packet framing.

Do not directly map user `active` mode to raw TCP active mode.

## Active message compatibility

For supported active modes, emit exactly the OTP-style shapes:

```elixir
{:ssl, socket, data}
{:ssl_closed, socket}
{:ssl_error, socket, reason}
{:ssl_passive, socket}
```

`{:ssl_passive, socket}` is emitted when positive-integer active mode reaches zero.

Preserve the same public socket term across messages for a connection.

## STARTTLS requirement

Do not treat existing-socket connect forms as optional convenience. They are part of the MVP compatibility target:

```text
SSL.connect(tcp_socket, tls_options)
SSL.connect(tcp_socket, tls_options, timeout)
```

Be careful with ownership and already-received plaintext during transport handoff.

## TLS 1.3 record rules

For encrypted TLS 1.3 traffic:

- outer TLS record content type is application_data;
- inner content type appears in TLSInnerPlaintext;
- strip zero padding correctly;
- construct AEAD AAD from the TLSCiphertext header;
- use `:crypto.crypto_one_time_aead`;
- maintain independent read/write sequence counters per traffic epoch;
- reject sequence overflow.

## Transcript rules

Keep exact encoded handshake bytes.

Do not reconstruct peer handshake bytes from semantic AST for transcript hashing unless exact byte equivalence is guaranteed.

HelloRetryRequest requires the TLS `message_hash` transcript rewrite.

Do not assume mutable crypto hash contexts are clonable.

## ClientHello profile rules

`WireProfile` is the source of truth.

A profile may control:

- ordered cipher suites;
- ordered extensions;
- supported versions/groups;
- signature algorithms;
- ALPN;
- GREASE slots;
- padding;
- compatibility session ID/CCS behavior;
- supported record-shaping policy.

JA3 and JA4 are projections computed from the resulting ClientHello.

Do not define a profile as "a JA3".

## Custom options

Project-specific behavior belongs under:

```elixir
ex_ssl: [
  profile: ...
]
```

Do not add many custom top-level SSL options.

## Coding style

- Prefer small pure functions and immutable structs.
- Prefer pattern matching and explicit tagged data over class-like abstractions.
- Prefer iodata for binary assembly.
- Prefer binary pattern matching for parsing.
- Avoid macros unless they materially reduce protocol-table repetition without obscuring control flow.
- Avoid process abstraction around pure computation.
- Avoid ETS for per-connection state.
- Avoid a process per record/handshake message.
- Keep protocol integers visible where that improves auditability.
- Add types/specs for public APIs and security-sensitive structures.

## Parser policy

A parser must return structured success/error; malformed external data must not rely on uncontrolled MatchError/FunctionClauseError as the expected protocol response.

It is acceptable for programmer invariant violations to crash tests/development, but wire input errors should become protocol errors/alerts.

Every parser that consumes a stream must define:

```text
input bytes
parsed values
unconsumed remainder
error cases
size limits
```

## Buffer policy

All externally influenced buffers need limits.

At minimum plan limits for:

- TLS record size;
- handshake message size;
- certificate chain count/bytes;
- plaintext receive buffer;
- pending outbound data.

Never concatenate an unbounded peer-controlled stream indefinitely.

## Error policy

Internal structured errors are encouraged.

The public `SSL` facade maps them to OTP-compatible public return/error forms.

When a protocol error occurs and the connection state permits it, send the appropriate TLS alert before closing.

## Logging policy

Never log by default:

- traffic secrets;
- private keys;
- ephemeral private keys;
- Finished keys;
- raw application plaintext;
- decrypted authentication material.

Do not put secrets in Logger metadata or inspectable exception structs.

NSS/keylog-style output must be explicit opt-in functionality.

## Testing requirements for every change

### Protocol/crypto changes

Must include deterministic vectors or independent expected results.

### Parser/framer changes

Must include fragmented-input tests. Prefer property tests when the input space is broad.

### Public `SSL` API changes

Must include a corresponding OTP `:ssl` behavioral reference test/scenario where meaningful.

### WireProfile changes

Must include golden serialized output or structural golden checks.

### Security-sensitive changes

Must include negative tests, not only success tests.

Examples:

- invalid cert;
- wrong hostname;
- invalid AEAD tag;
- invalid Finished;
- invalid CertificateVerify;
- illegal extension duplication/order where constrained.

## Integration references

The project should test against independent implementations:

1. OTP `:ssl` test server
2. OpenSSL `s_server`
3. optional external TLS endpoint in integration tests

Never consider an ex_ssl-to-ex_ssl test sufficient evidence of interoperability.

## Performance rule

Do not optimize before correctness, but avoid obviously expensive architecture:

- no per-byte recursion that rebuilds binaries;
- no repeated `<>` growth of large buffers;
- no unnecessary flattening of iodata;
- no central connection bottleneck;
- no process-per-record.

Benchmark after the first correct vertical handshake exists.

## Compatibility claims

Update the compatibility matrix/documentation whenever behavior changes.

Do not write "drop-in replacement" unless the documented compatibility level and tests justify it.

Preferred wording during development:

> OTP `:ssl`-compatible client API for the implemented feature subset.

## Work sequence

Follow `docs/IMPLEMENTATION_PLAN.md` unless a failing test or newly discovered protocol requirement forces a dependency change.

For the first implementation cycle, prioritize:

1. repository/application bootstrap;
2. record framer;
3. handshake framer;
4. transcript + HRR rewrite;
5. HKDF + traffic nonce helpers;
6. WireProfile data model;
7. compatibility harness skeleton.

Do not jump directly into a huge `SSL.Connection` handshake implementation before those pure pieces are tested.

## Review checklist

Before marking a task complete, ask:

- Is this behavior required by RFC 9846 or compatibility?
- Is external input length-bounded?
- Are exact transcript bytes preserved?
- Is key material fresh where required?
- Can this be unit tested without a process/socket?
- Does this change affect OTP observable behavior?
- Does it need a differential test?
- Does it leak secret material through logs/inspect/crash state?
- Does it accidentally make a fingerprint analyzer authoritative?
- Is the README/compatibility claim still accurate?

## Stop conditions

If an RFC requirement conflicts with the current architecture, do not patch around it. Update the design documents in the same change and explain the architectural correction.

If OTP public behavior is unclear, reproduce it in a focused executable test against the supported OTP baseline before emulating it.

If a target profile requires advertising a protocol capability ex_ssl does not implement, do not advertise it by default. Record the requirement and schedule the missing protocol feature.
