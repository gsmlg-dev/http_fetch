# ex_ssl Detailed Design

## 1. Design objective

`ex_ssl` provides an Elixir module named `SSL` that behaves like Erlang/OTP `:ssl` for supported client functionality while using an independent TLS protocol implementation.

The first implementation target is a secure TLS 1.3 client with programmable ClientHello wire behavior.

This document turns the architecture into concrete module contracts, data models, algorithms, and compatibility rules.

## 2. Public API design

### 2.1 Compatibility facade

`SSL` is the only public compatibility facade that applications need for normal use.

Initial required API:

```elixir
SSL.start/0
SSL.start/1
SSL.stop/0

SSL.connect/2
SSL.connect/3
SSL.connect/4

SSL.send/2
SSL.recv/2
SSL.recv/3

SSL.close/1
SSL.close/2
SSL.shutdown/2

SSL.setopts/2
SSL.getopts/2
SSL.controlling_process/2

SSL.peername/1
SSL.sockname/1
SSL.peercert/1
SSL.negotiated_protocol/1
SSL.connection_information/1
SSL.connection_information/2
SSL.getstat/1
SSL.getstat/2

SSL.update_keys/2
SSL.export_key_materials/4
SSL.export_key_materials/5

SSL.format_error/1
SSL.versions/0
```

Utility compatibility functions such as cipher-suite conversion/listing may be added after the handshake core stabilizes.

Server APIs are deliberately deferred.

The separate record-free TLS 1.3 client/server engine follows
[ADR_QUIC_TLS_CORE.md](ADR_QUIC_TLS_CORE.md). It does not add server socket APIs.
The public boundary is specified in [QUIC_TLS_INTERFACE.md](QUIC_TLS_INTERFACE.md),
with implementation status distinguished in its ledger.

### 2.2 API compatibility rule

For every implemented OTP function, create an explicit compatibility test covering:

- accepted argument shapes;
- success tuple shape;
- common error tuple shape;
- timeout behavior;
- process ownership behavior if relevant;
- active message behavior if relevant.

A function must not be marked supported merely because its name and arity exist.

## 3. `SSL.Socket`

The socket is opaque at the public contract level.

Suggested internal representation:

```elixir
defmodule SSL.Socket do
  @opaque t :: %__MODULE__{pid: pid(), ref: reference(), status: reference()}
  defstruct [:pid, :ref, :status]
end
```

`ref` protects against stale/cross-connection calls and gives the connection a stable public identity.

`status` is an atomic terminal-status cell (open/orderly/failed), written by the
connection process and omitted from inspection. It preserves closure information
after the process exits; it stores no TLS secrets or application data.

All active messages contain the same public socket term handed to the caller.

## 4. `SSL.Options`

### 4.1 Normalized internal options

Normalize user options exactly once before starting the handshake.

Suggested shape:

```text
Options
├── transport
│   ├── mode
│   ├── packet
│   ├── header
│   ├── active
│   └── gen_tcp options
├── tls
│   ├── versions
│   ├── verify
│   ├── cacerts/cacertfile
│   ├── server_name_indication
│   ├── signature_algs
│   ├── groups
│   ├── ciphers
│   ├── ALPN
│   ├── keylog callback
│   └── supported callback options
└── ex_ssl
    ├── profile
    ├── profile_overrides
    ├── fingerprint_debug
    └── experimental flags
```

### 4.2 Standard-option policy

Options fall into four categories:

1. **implemented** — same semantics as OTP where feasible;
2. **accepted/translated** — compatible option translated into ex_ssl internal form;
3. **known but unsupported** — explicit `{error, {options, ...}}`;
4. **unknown** — explicit option error.

Never silently ignore a standard security-relevant option.

### 4.3 Custom option namespace

All project-specific options live under one `:ex_ssl` option:

```elixir
ex_ssl: [
  profile: :mobile_profile,
  profile_overrides: [],
  fingerprint_debug: false
]
```

No custom top-level key should be added unless compatibility ergonomics later justify it.

## 5. Host/SNI normalization

The connect path must distinguish:

- DNS host passed as binary/list;
- literal IPv4/IPv6 tuple;
- an existing TCP socket for STARTTLS.

The normalized connection target should preserve both:

- network destination;
- logical service identity/SNI.

Do not infer a DNS SNI from an IP literal.

When `verify: :verify_peer`, perform both path and service identity verification in the same circumstances expected by the supported OTP option semantics.

## 6. Connection state

Suggested `SSL.Connection.State` fields:

```text
public_socket
owner
owner_monitor
transport_module
transport_socket
transport_tags
transport_armed?

options
host_identity

runtime_phase
handshake_state
transcript

record_input_buffer
handshake_input_buffer
application_buffer
packet_state

read_epoch
write_epoch

pending_recv
active_mode

peer_cert_chain
peer_certificate
negotiated_version
negotiated_cipher
negotiated_group
negotiated_alpn

close_state
statistics
```

Avoid storing large duplicated handshake structures after they are no longer needed.

## 7. Ownership model

### 7.1 Underlying transport

Normal ownership:

```text
TCP socket controlling process = SSL.Connection pid
```

For `connect(existing_tcp_socket, ...)`, the caller transfers transport control to the newly created connection as part of the upgrade sequence.

### 7.2 Application owner

The application owner is separate from the TCP controlling process.

`SSL.controlling_process(socket, new_owner)` updates the application owner and associated monitor after validating that the caller is the current owner when OTP semantics require it.

Pending active TLS messages must not continue being intentionally sent to the old owner after transfer.

Mailbox race behavior should be tested against OTP and documented where exact emulation is impossible.

### 7.3 Owner death

Initial policy: closing the connection when the owner dies is acceptable if it matches expected socket ownership semantics for the tested scenarios.

Do not leave orphaned TLS connections indefinitely.

## 8. Passive receive design

`SSL.recv(socket, length, timeout)` is implemented as a synchronous request to `SSL.Connection`.

Rules:

- valid only while application `active: false`;
- the connection continues reading/decrypting raw TCP internally while a receive is pending;
- timeout applies to delivery of requested application data/packet, not raw TCP reads;
- one pending `recv` per socket is the initial supported model;
- close/error wakes pending receiver with a compatible result.

`length` semantics depend on `packet` mode and must be compared against OTP behavior in compatibility tests.

## 9. Active receive design

Application-visible active mode is represented separately from raw TCP mode:

```text
:passive
:true
:once
{:count, positive_integer}
```

Delivery algorithm:

1. feed decrypted plaintext into `SSL.Packet`;
2. while a complete application delivery unit exists and active mode permits:
   - convert binary/list mode;
   - send `{:ssl, public_socket, data}` to owner;
   - update active mode;
3. when count mode reaches zero:
   - switch to passive;
   - send `{:ssl_passive, public_socket}` exactly once.

## 10. Raw transport adapter

Initial transport is `:gen_tcp`.

Create a thin internal behavior so STARTTLS and future compatible reliable transports do not contaminate TLS logic.

Suggested callbacks:

```text
send(socket, iodata)
setopts(socket, opts)
getopts(socket, opts)
peername(socket)
sockname(socket)
getstat(socket, opts)
controlling_process(socket, pid)
close(socket)
shutdown(socket, how)
```

Do not build a generic transport framework beyond what current compatibility requires.

## 11. TLS record framing

### 11.1 Input

`SSL.Protocol.RecordFramer.feed(buffer, bytes)` returns zero or more complete raw records plus the new remainder.

TLS record header:

```text
ContentType:     1 byte
legacy_version:  2 bytes
length:          2 bytes
fragment:        length bytes
```

The parser must:

- handle partial headers;
- handle partial bodies;
- return several complete records from one TCP chunk;
- reject lengths beyond allowed/configured limits;
- preserve unconsumed bytes without repeated full-buffer concatenation where practical.

### 11.2 Encrypted TLS 1.3 records

After handshake protection activates, outer content type is application data. Decryption yields:

```text
content || inner_content_type || zero_padding
```

Parsing strips trailing zero padding and recovers the final non-zero content-type byte.

AEAD AAD is the encoded TLSCiphertext header.

## 12. Handshake framing and encoding

Handshake message format:

```text
msg_type: 1 byte
length:   3 bytes
body:     length bytes
```

The framer is independent of TLS record framing.

Each decoded message should expose:

```text
semantic representation
exact encoded handshake bytes
```

The exact bytes are appended to the transcript.

Do not re-serialize a parsed peer message for transcript hashing unless byte-equivalence is guaranteed; preserve the bytes received on the wire.

## 13. ClientHello data model

### 13.1 `SSL.ClientHello.WireProfile`

Suggested semantic shape:

```elixir
%SSL.ClientHello.WireProfile{
  name: atom() | String.t() | nil,
  legacy_version: 0x0303,
  session_id: :random_32 | :empty | {:fixed, binary()},
  cipher_suites: [suite_spec()],
  compression_methods: [0],
  extensions: [extension_spec()],
  grease: %SSL.ClientHello.GreasePolicy{},
  record: %SSL.ClientHello.RecordPolicy{}
}
```

The profile is declarative. Per-connection generated values must not be written back into a reusable named profile.

### 13.2 Extension specification

Suggested tagged structures rather than Keyword:

```text
{:server_name, :from_connection}
{:supported_groups, [group_spec, ...]}
{:ec_point_formats, [...]}
{:signature_algorithms, [...]}
{:signature_algorithms_cert, [...]}
{:alpn, [binary, ...]}
{:supported_versions, [version_spec, ...]}
{:psk_key_exchange_modes, [...]}
{:key_share, [key_share_spec, ...]}
{:padding, padding_policy}
{:grease, slot_id}
{:raw, extension_id, binary}
```

`{:raw, ...}` is intentionally advanced/unsafe and should be gated by profile validation rules.

### 13.3 GREASE

Represent GREASE placeholders by symbolic slot, not fixed magic constants:

```text
{:grease, :a}
{:grease, :b}
```

At connection materialization time, the GREASE policy selects concrete values. A deterministic seeded policy is useful for golden tests; production/mobile profiles may request randomized values consistent with their target behavior.

The same symbolic slot may be reused where the target client reuses a GREASE value across relevant fields in one ClientHello.

### 13.4 KeyShare

A key-share extension spec describes group/order and optional GREASE placeholder but never reusable private key bytes.

Materialization generates a fresh ephemeral key for each real key share.

## 14. ClientHello builder pipeline

```text
profile
  │
  ▼
SSL.ClientHello.Profile.validate/2
  │ considers implemented crypto/capabilities
  ▼
SSL.ClientHello.Materializer.materialize/2
  │ random, session id, GREASE, keypairs
  ▼
SSL.ClientHello.AST
  │
  ├──► SSL.Fingerprint.*
  │
  ▼
SSL.ClientHello.Serializer.encode/1
```

Validation checks at minimum:

- no duplicate extension type after GREASE resolution;
- `pre_shared_key` placement if PSK is enabled;
- advertised protocol versions are supported unless experimental override;
- selected key-share groups are implemented and available;
- cipher suites align with advertised versions;
- ALPN entries are valid;
- encoded field lengths fit protocol limits;
- extension payloads satisfy local invariants.

## 15. Fingerprint design

### 15.1 JA3

Input: actual naked ClientHello handshake bytes and explicit `:tcp`/`:quic`
context via `SSL.Fingerprint.client_hello/2`; observation retains original IDs
and extension bytes. See [FINGERPRINTS.md](FINGERPRINTS.md).

Output structure should expose both canonical string and digest, for example conceptually:

```text
%{raw: "...", hash: "..."}
```

JA3 implementation strips GREASE values where required by the algorithm.

### 15.2 JA4

JA4 must implement its documented normalization independently rather than by mutating/reusing JA3 ordering logic.

Expose raw components for testability before hashing.

### 15.3 Exact-wire inspection

Add a project-native debug projection that reports:

- ordered cipher IDs;
- ordered extension IDs;
- groups;
- signature algorithms;
- ALPN;
- supported versions;
- GREASE locations;
- record layout.

This is more useful for validating impersonation than JA3/JA4 alone.

## 16. Handshake state machine

### 16.1 Initial flow

```text
connect
  ↓
materialize ClientHello + fresh KeyShare
  ↓
send ClientHello
  ↓
ServerHello OR HelloRetryRequest
```

### 16.2 Normal TLS 1.3 flow

```text
ClientHello
ServerHello
  ├─ derive handshake keys
  ▼
EncryptedExtensions
[CertificateRequest]
Certificate
CertificateVerify
Finished
  ├─ verify server flight
  ├─ derive application traffic secrets
  ▼
[client Certificate]
[client CertificateVerify]
client Finished
  ▼
connected
```

Client authentication is not required in v0.1; if CertificateRequest cannot be correctly handled for the configured mode, fail with the correct protocol/error behavior rather than improvising.

### 16.3 HelloRetryRequest

On HRR:

1. validate HRR constraints;
2. apply transcript `message_hash` rewrite;
3. append HRR;
4. generate a new appropriate KeyShare;
5. produce ClientHello2 consistent with TLS rules and profile constraints;
6. append/send ClientHello2;
7. continue waiting for ServerHello.

The profile must support a distinction between ClientHello1 and ClientHello2 materialization where required.

## 17. Transcript design

Suggested structure:

```elixir
%SSL.Protocol.Transcript{
  hash: :sha256 | :sha384,
  messages: iodata(),
  length: non_neg_integer()
}
```

Avoid flattening on every append.

A transcript checkpoint can be represented by an immutable transcript value at that moment. Digest computation calls `:crypto.hash(hash, iodata)` or an equivalent correct strategy.

Optimize only after profiling; handshake transcript sizes are normally small compared with application traffic.

## 18. HKDF design

Implement TLS-specific label encoding explicitly and test it independently.

Required operations:

```text
extract(hash, salt, ikm)
expand(hash, prk, info, length)
expand_label(hash, secret, label, context, length)
derive_secret(hash, secret, label, transcript_hash)
```

The TLS 1.3 label encoding includes the protocol-defined `tls13 ` prefix and length-encoded label/context fields.

Do not use string concatenation scattered across handshake code.

## 19. AEAD design

Supported mapping:

```text
TLS_AES_128_GCM_SHA256       -> AES-128-GCM / SHA-256
TLS_AES_256_GCM_SHA384       -> AES-256-GCM / SHA-384
TLS_CHACHA20_POLY1305_SHA256 -> ChaCha20-Poly1305 / SHA-256
```

`SSL.Crypto.AEAD` receives a complete `TrafficState` and plaintext/ciphertext record metadata.

Record sequence overflow is a fatal condition. KeyUpdate handling creates a new generation with sequence reset to zero.

## 20. Certificate verification design

### 20.1 Chain/path

Use OTP `:public_key` facilities rather than implementing ASN.1/X.509 path validation from scratch.

### 20.2 Identity

Use `:public_key.pkix_verify_hostname` or an equivalent correct OTP integration to match expected hostname verification semantics.

### 20.3 CertificateVerify

Verify the peer's signature over the TLS 1.3 context construction, including the required repeated-space prefix and role-specific context string.

Do not verify the signature directly over raw transcript bytes; it is over the protocol-defined signed structure containing a transcript hash.

## 21. Finished design

Derive the Finished key from the correct traffic secret and compute the verify data over the correct transcript prefix.

Server Finished must be verified before accepting the server handshake.

Comparison must use a constant-time primitive where available/appropriate rather than ordinary equality for authentication tags.

## 22. Post-handshake handling

### 22.1 NewSessionTicket

Parse and surface/store enough data for future resumption support. v0.1 may discard ticket state after valid parsing if resumption is explicitly unsupported.

### 22.2 KeyUpdate

`SSL.update_keys/2` maps to TLS 1.3 KeyUpdate behavior for supported types.

Inbound KeyUpdate:

- update receive traffic secret;
- reset read sequence;
- optionally schedule/respond with requested update according to TLS rules.

Outbound KeyUpdate:

- send KeyUpdate under the old sending keys as required;
- install the next sending traffic secret at the correct point;
- reset sequence.

## 23. Closing and alerts

Maintain a close state distinct from process termination.

In the passive client milestone, authenticated close_notify drains already
decrypted bytes before returning `:closed`. An abrupt TCP EOF or unexpected
connection-process exit returns `:econnreset`, also on later calls through the
same handle. Undelivered plaintext is discarded on transport failure so an HTTP
consumer cannot mistake a truncated close-delimited response for a complete one.

Support:

- inbound/outbound `close_notify`;
- fatal alerts;
- transport close without alert;
- `shutdown` direction semantics where supported;
- `close/2` downgrade behavior as a later compatibility feature if not in first milestone.

Application active messages should distinguish normal close and errors like OTP does.

## 24. `connection_information`

Internally store negotiated metadata in a stable structure and map supported keys to OTP-compatible output.

Initial useful keys:

- protocol;
- selected_cipher_suite;
- sni_hostname where applicable;
- negotiated_protocol (ALPN);
- session_resumption state when implemented.

Unsupported requested information keys should follow observed OTP behavior rather than inventing values.

## 25. `versions/0`

`SSL.versions/0` reports `ex_ssl` implementation/runtime capability, not OTP `:ssl` capability.

For the initial release, only TLS 1.3 should appear as implemented by `ex_ssl`.

Availability may additionally depend on the running crypto provider exposing the required primitives/groups.

## 26. Secret logging

Provide no secret logging by default.

If OTP-compatible key logging is implemented, it must be explicit opt-in and pass data only to the configured callback. Secret data must not enter Logger metadata.

## 27. Performance design

First optimize architecture, not microbenchmarks.

Priorities:

1. avoid per-byte parsing;
2. use binary pattern matching;
3. use iodata for assembly;
4. avoid flattening buffers repeatedly;
5. avoid copying large ciphertext/plaintext unnecessarily;
6. deliberately copy small retained slices if keeping a sub-binary would retain a very large parent binary;
7. keep crypto calls in native OTP primitives;
8. use one process per connection, not one process per TLS record/message.

Do not use ETS for hot per-connection state.

## 28. Testing contracts

### 28.1 Unit tests

Pure modules get deterministic unit tests:

- codecs;
- framing;
- HKDF;
- key schedule;
- transcript;
- JA3/JA4;
- option normalization;
- profile validation.

### 28.2 Property tests

Use StreamData or equivalent for:

- arbitrary chunk fragmentation;
- encode/decode round trips;
- length-bound checks;
- packet framing;
- valid profile materialization invariants.

### 28.3 Differential tests

Define a test adapter conceptually:

```text
SSLTestBackend
  connect
  send
  recv
  setopts
  controlling_process
  close
```

Run the same behavioral scenarios with `:ssl` and `SSL`.

Do not compare opaque socket terms.

### 28.4 Wire tests

A deterministic test profile uses seeded randomness and deterministic test-only ephemeral inputs where safe/isolated to produce golden ClientHello bytes.

Production paths MUST use fresh cryptographically secure randomness and fresh ephemeral keys.

## 29. Compatibility matrix

Maintain a checked-in compatibility table, preferably in tests or documentation, with states:

```text
supported
partial
planned
not applicable
```

At minimum track:

- API functions;
- client options;
- socket options;
- active modes;
- packet modes;
- certificate verification features;
- post-handshake features.

This prevents the phrase "OTP compatible" from becoming untestable marketing language.

## 30. Initial module tree

```text
lib/
├── ssl.ex
└── ssl/
    ├── application.ex
    ├── supervisor.ex
    ├── socket.ex
    ├── options.ex
    ├── connection.ex
    ├── connection_supervisor.ex
    ├── packet.ex
    ├── protocol/
    │   ├── alert.ex
    │   ├── record.ex
    │   ├── record_framer.ex
    │   ├── inner_plaintext.ex
    │   ├── handshake.ex
    │   ├── handshake_framer.ex
    │   ├── transcript.ex
    │   ├── extension.ex
    │   └── handshake_machine.ex
    ├── crypto/
    │   ├── hkdf.ex
    │   ├── aead.ex
    │   ├── key_exchange.ex
    │   ├── signature.ex
    │   ├── key_schedule.ex
    │   └── traffic_state.ex
    ├── pkix/
    │   ├── path.ex
    │   └── identity.ex
    ├── client_hello/
    │   ├── wire_profile.ex
    │   ├── grease_policy.ex
    │   ├── record_policy.ex
    │   ├── profile.ex
    │   ├── materializer.ex
    │   ├── ast.ex
    │   └── serializer.ex
    └── fingerprint/
        ├── client_hello.ex
        ├── ja3.ex
        └── ja4.ex
```

This tree is a guide, not a requirement to create empty modules before functionality needs them.

## 31. Explicit non-designs

The first implementation MUST NOT:

- call `:ssl` internally to perform the TLS handshake;
- use JA3 strings as configuration source of truth;
- assume one TCP packet contains one TLS record;
- assume one TLS record contains one handshake message;
- store extension order in a map;
- reuse KeyShare private/public values across connections;
- disable verification merely to make fingerprint profiles work;
- claim deterministic secret erasure on BEAM;
- add a Rust NIF before a measured requirement exists;
- implement HTTP/2 or HTTP/3 inside this library;
- advertise TLS 1.2 support before TLS 1.2 is implemented.

## Bounded dual-version client decision

The TLS1.2 extension follows [ADR_TLS12_CLIENT.md](ADR_TLS12_CLIENT.md). It keeps
the socket/runtime contract and separates version-specific pure handshake, key
schedule and record logic. See the progress ledger for implementation status;
this decision alone does not claim TLS1.2 support.
