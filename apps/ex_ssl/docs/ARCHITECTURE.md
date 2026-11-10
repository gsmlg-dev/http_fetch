# ex_ssl Architecture

## 1. Purpose

`ex_ssl` is an Elixir/OTP implementation of a programmable TLS stack whose public API is intentionally compatible with Erlang/OTP `:ssl` wherever the implemented feature set overlaps.

The OTP application is `:ex_ssl`. The primary public module is `SSL` (`Elixir.SSL`), so an application can migrate from:

```elixir
:ssl.connect(host, port, opts)
```

to:

```elixir
SSL.connect(host, port, opts)
```

with minimal behavioral change.

The defining capability of `ex_ssl` is **wire-level ClientHello control**. A caller can select or provide a profile that controls observable TLS handshake characteristics such as cipher ordering, extension ordering and payloads, GREASE placement, key-share shape, ALPN ordering, signature algorithms, compatibility-mode behavior, padding, and record shaping.

The fingerprint model is not the TLS engine. The TLS engine emits deterministic wire behavior from a `WireProfile`; JA3, JA4, and other fingerprints are projections of that emitted/parsed ClientHello.

## 2. Normative baseline

Implementation decisions MUST be checked against current standards and OTP behavior, with this precedence:

1. RFC 9846 — TLS 1.3 (obsoletes RFC 8446)
2. Relevant updates and referenced RFCs, including RFC 8701 for GREASE and RFC 9525 for service identity
3. Erlang/OTP 29 `:ssl`, `:crypto`, and `:public_key` public behavior for compatibility
4. IANA TLS registries
5. JA3/JA4 algorithm specifications for fingerprint analyzers only

RFC 8446 may be used as historical background but RFC 9846 is the TLS 1.3 normative target.

## 3. Architectural principles

### 3.1 Compatibility at the edge, independent implementation inside

`SSL` owns the compatibility contract. Internal modules are free to use structures and state transitions that do not resemble OTP `:ssl` internals.

Compatibility includes, where supported:

- public function names and arities;
- return tuple shapes;
- timeout behavior;
- active/passive socket behavior;
- active message tags;
- controlling-process semantics;
- common transport and TLS options;
- STARTTLS upgrade from an existing TCP socket;
- introspection behavior;
- TLS alerts mapped into compatible error forms.

Exact private OTP record layouts are explicitly not part of the contract.

### 3.2 Pure protocol core

Parsing, encoding, extension construction, transcript construction, key-schedule transformations, and handshake transitions should be modeled as deterministic transformations wherever practical.

OTP processes coordinate lifecycle and I/O; they should not contain ad-hoc protocol logic.

### 3.3 One connection, one owner of cryptographic state

For TCP, handshake secrets, traffic secrets, sequence numbers, transcripts,
plaintext buffers, ciphertext buffers, and socket ownership live in a single
connection process. The record-free integration instead has one caller-owned
immutable handshake state; see [ADR_QUIC_TLS_CORE.md](ADR_QUIC_TLS_CORE.md).

No global process may hold per-connection traffic keys.

### 3.4 Wire profile is authoritative

A `WireProfile` describes what must appear on the wire. JA3/JA4 are computed from the resulting ClientHello and never drive protocol logic directly.

### 3.5 Cryptography remains native

Elixir implements TLS protocol semantics. Cryptographic primitives use OTP `:crypto` and `:public_key`, which delegate to native crypto implementations where appropriate.

A native NIF is not part of the initial architecture. It may later be introduced only for a measured requirement such as deterministic secret zeroization or a primitive unavailable through OTP.

### 3.6 Stream boundaries are explicit

TCP chunks, TLS records, TLS handshake messages, decrypted application bytes, and OTP packet-mode messages are five distinct framing domains.

No implementation may assume that any two of these boundaries coincide.

## 4. System overview

```text
                    Existing Erlang/Elixir Application
                 Mint / Finch / IMAP / SMTP / custom code
                                  │
                                  ▼
                         ┌─────────────────┐
                         │       SSL       │
                         │ OTP-compatible  │
                         │ public facade   │
                         └────────┬────────┘
                                  │
                   option normalization / API mapping
                                  │
                                  ▼
                       ┌────────────────────┐
                       │   SSL.Connection   │
                       │     :gen_statem    │
                       └─────────┬──────────┘
                                 │
              ┌──────────────────┼───────────────────┐
              ▼                  ▼                   ▼
      ┌───────────────┐  ┌───────────────┐   ┌───────────────┐
      │ Handshake     │  │ Record Layer  │   │ App/Packet    │
      │ Machine       │  │ + Framing     │   │ Buffering     │
      └──────┬────────┘  └──────┬────────┘   └───────────────┘
             │                  │
             └──────────┬───────┘
                        ▼
               ┌──────────────────┐
               │ Crypto / PKIX    │
               │ HKDF / AEAD /    │
               │ ECDHE / X.509    │
               └────────┬─────────┘
                        │
                        ▼
                     :gen_tcp
```

The ClientHello path adds an independent composition layer:

```text
WireProfile
    │
    ▼
ClientHello Builder
    │
    ▼
ordered ClientHello AST
    │
    ├───────────────► JA3 / JA4 analyzers
    │
    ▼
Serializer
    │
    ▼
TLS record layer
```

## 5. OTP supervision

```text
SSL.Application
└── SSL.Supervisor                     strategy: :one_for_one
    ├── SSL.ProfileRegistry            optional named profile registry
    └── SSL.ConnectionSupervisor       DynamicSupervisor
        └── SSL.Connection             :gen_statem, one per TLS connection
```

A passive fingerprint sniffer, if implemented later, belongs under a separate supervisor and must not be in the TLS connection trust path.

`one_for_all` MUST NOT be used for the root tree. Failure of one registry or worker must not terminate unrelated established TLS connections.

## 6. Public boundary

### 6.1 Application and module names

- Hex/Mix package: `ex_ssl`
- OTP application: `:ex_ssl`
- public compatibility module: `SSL`
- internal namespace: `SSL.*`

`SSL` compiles to `Elixir.SSL`, which does not collide with Erlang's `:ssl` module.

### 6.2 Socket abstraction

The public socket is opaque from the caller's perspective. Initial implementation may use:

```elixir
%SSL.Socket{pid: pid, ref: ref, status: terminal_status}
```

The caller MUST NOT depend on this representation.

The passive client milestone uses one atomic terminal-status cell written by the
connection process. It contains only open/orderly/failed state, never keys or
payloads, and survives process exit while the caller retains the handle.
This lets later calls distinguish authenticated closure (`:closed`) from abrupt
transport/process loss (`:econnreset`) without tombstone processes or a global table.

A stable socket identity is required across:

- `setopts/2`;
- `recv/3`;
- active message delivery;
- `controlling_process/2`;
- shutdown/close;
- key updates;
- introspection.

## 7. Connection process

Each connected TLS session is represented by one `SSL.Connection` `:gen_statem` process.

### 7.1 Responsibilities

The connection process owns:

- the underlying connected TCP socket;
- controlling process identity and monitor;
- raw TCP receive mode;
- ciphertext input buffer;
- record-framing state;
- handshake-framing state;
- current handshake machine state;
- transcript;
- current read and write traffic epochs;
- decrypted application buffer;
- OTP packet framing state;
- active-mode state/counter;
- pending passive `recv` requests;
- negotiated connection metadata;
- close/shutdown state.

### 7.2 Coarse runtime states

Do not encode every handshake message as a `:gen_statem` state. Recommended states:

```text
:init
:connecting
:wait_server_hello
:wait_server_flight
:send_client_flight
:connected
:closing
:closed
```

The pure handshake machine handles semantic message sequencing inside these runtime states.

### 7.3 Event pipeline

Inbound:

```text
{:tcp, socket, bytes}
  │
  ▼
TCP accumulation
  │
  ▼
TLS RecordFramer
  │ complete records
  ▼
Record decode/decrypt
  │
  ├─ handshake bytes ──► HandshakeFramer ──► Handshake decode
  │                                           │
  │                                           ▼
  │                                  HandshakeMachine.step/2
  │
  ├─ application bytes ──► AppBuffer ──► Packet framing ──► recv/active
  │
  └─ alert ──► close/error state
```

Outbound:

```text
application iodata
  │
  ▼
packet handling where applicable
  │
  ▼
TLSInnerPlaintext
  │
  ▼
AEAD + TLSCiphertext
  │
  ▼
:gen_tcp.send/2
```

## 8. Raw TCP semantics

`SSL.Connection` remains the controlling process of the underlying TCP socket during normal operation.

The raw socket should normally run with internal `active: :once` semantics. Application-visible active/passive state is virtualized above TLS.

This prevents application `active` options from interfering with handshake processing or TLS record consumption.

After processing each internal TCP message, the connection rearms `active: :once` when it can accept more ciphertext. It may delay rearming to create backpressure when internal buffers or owner mailbox pressure exceed configured limits.

## 9. Application-visible socket semantics

`SSL` must emulate OTP `:ssl` message forms:

```elixir
{:ssl, ssl_socket, data}
{:ssl_closed, ssl_socket}
{:ssl_error, ssl_socket, reason}
{:ssl_passive, ssl_socket}
```

Application active modes:

- `active: false`: data stays buffered for `recv`;
- `active: true`: deliver continuously;
- `active: :once`: deliver one packet/data item, then switch to passive;
- `active: N`: deliver N packet/data items, decrementing the counter and emitting `{:ssl_passive, socket}` at zero.

The application-visible mode is independent of raw TCP mode.

## 10. Protocol core

### 10.1 Record layer

Modules:

```text
SSL.Protocol.Record
SSL.Protocol.RecordFramer
SSL.Protocol.InnerPlaintext
```

Responsibilities:

- parse and encode TLSPlaintext/TLSCiphertext headers;
- enforce record length bounds;
- accumulate fragmented TCP data;
- decode TLS 1.3 inner content type and padding;
- construct AEAD associated data;
- never expose encrypted record boundaries as application packet boundaries.

TLS 1.3 encrypted records use outer content type `application_data` (`0x17`); the actual inner type is carried inside `TLSInnerPlaintext`.

### 10.2 Handshake framing

Modules:

```text
SSL.Protocol.Handshake
SSL.Protocol.HandshakeFramer
```

The framer handles both:

- multiple handshake messages in one decrypted TLS record;
- one handshake message fragmented across multiple records.

The decoded handshake representation is semantic, but each message also retains or can reproduce its exact encoded handshake bytes for transcript use.

### 10.3 Handshake machine

`SSL.Protocol.HandshakeCore` now owns the existing client's post-ServerHello
authentication, transcript and traffic-secret derivation. The TCP
`ServerFlightVerifier` adapts this core to records. `ClientHandshake` shares
ClientHello/HRR orchestration between TCP and `SSL.QUIC`; `ServerHandshake`
implements the record-free certificate server role using shared cryptographic
primitives. Remaining verification gates are tracked in
[QUIC_TLS_IMPLEMENTATION.md](QUIC_TLS_IMPLEMENTATION.md).

`SSL.Protocol.HandshakeMachine` is a pure transition engine where practical.

Conceptual contract:

```text
step(state, event) -> {new_state, actions}
```

Actions may include:

- append transcript bytes;
- derive handshake keys;
- install read/write epoch;
- verify certificate path;
- verify service identity;
- verify CertificateVerify;
- verify Finished;
- emit handshake message;
- generate fresh KeyShare;
- process HelloRetryRequest;
- transition application keys;
- store session ticket;
- update traffic secret;
- surface negotiated ALPN.

The state machine MUST explicitly support HelloRetryRequest from the first implementation because HRR changes transcript semantics and requires a newly generated KeyShare.

## 11. Transcript architecture

`SSL.Protocol.Transcript` stores exact encoded handshake messages as iodata/binaries and computes hashes for the required transcript prefix.

Do not design around copying a mutable `:crypto` hash context. OTP does not expose a portable hash-context clone contract.

Required operations:

```text
new(hash)
append(encoded_handshake)
digest(transcript)
checkpoint(transcript)
apply_hello_retry_request_rewrite(transcript)
```

HelloRetryRequest handling replaces the logical first ClientHello in the transcript with the synthetic `message_hash` construction defined by TLS 1.3.

The transcript module MUST make message-prefix correctness explicit for:

- server CertificateVerify;
- server Finished;
- client Finished;
- exporters;
- resumption secrets.

## 12. Cryptography and key schedule

### 12.1 Modules

```text
SSL.Crypto.HKDF
SSL.Crypto.AEAD
SSL.Crypto.KeyExchange
SSL.Crypto.Signature
SSL.Crypto.KeySchedule
SSL.Crypto.TrafficState
```

### 12.2 Key schedule

Represent key-schedule progress explicitly:

```text
Early Secret
   │
   ▼
Handshake Secret
   │
   ▼
Main/Master Secret
   │
   ├─ client application traffic secret
   ├─ server application traffic secret
   ├─ exporter secret
   └─ resumption secret
```

The state is transformed as the handshake progresses; unavailable secrets must not be represented as fake zero-filled valid values.

### 12.3 Traffic epochs

Each direction has an independent traffic state:

```text
TrafficState
- secret
- key
- iv
- sequence_number
- generation
- cipher_suite
```

Sequence numbers start at zero for each newly installed traffic key and monotonically increase per protected record.

The per-record nonce is formed from the static IV XOR the padded 64-bit sequence number as required by TLS 1.3.

### 12.4 AEAD

Use OTP's AEAD API (`:crypto.crypto_one_time_aead`) rather than the non-AEAD one-time cipher API.

Initial cipher suites:

- TLS_AES_128_GCM_SHA256
- TLS_AES_256_GCM_SHA384
- TLS_CHACHA20_POLY1305_SHA256

The implementation must dynamically verify primitive availability through the running OTP/OpenSSL environment.

## 13. PKIX and peer authentication

Modules:

```text
SSL.PKIX
SSL.PKIX.Path
SSL.PKIX.Identity
```

Server authentication consists of independent checks:

1. parse certificate chain;
2. validate chain and trust anchor through `:public_key`;
3. validate service identity/hostname in accordance with OTP semantics and RFC 9525;
4. verify TLS CertificateVerify signature over the TLS-defined signed structure.

`verify: :verify_peer` must not silently degrade to `:verify_none`.

Option compatibility for CA sources and custom verification callbacks is phased, but unsupported security options must fail explicitly rather than be ignored.

## 14. ClientHello and WireProfile

### 14.1 Source-of-truth model

```text
SSL.ClientHello.WireProfile
```

A profile controls observable ClientHello behavior rather than storing a JA3 string.

Core fields include:

```text
legacy_version
legacy_session_id policy
cipher_suites ordered list
compression_methods
extensions ordered list
supported_versions ordered list
supported_groups ordered list
key_share policy/order
signature_algorithms ordered list
signature_algorithms_cert ordered list
ALPN ordered list
PSK modes
GREASE policy and insertion positions
padding policy
compatibility-mode CCS behavior
record-fragmentation policy
```

The precise Elixir structure is defined in `DESIGN.md`.

### 14.2 Ordered extension AST

Do not use a map or Keyword list as the canonical extension representation.

Use an ordered list of extension nodes with explicit type and payload/configuration. This preserves order and allows validation of duplicate/placement invariants.

Pipeline:

```text
WireProfile
  │
  ▼
validate capabilities
  │
  ▼
resolve per-connection randomness
  │ GREASE / random / fresh keyshares / session id
  ▼
ClientHello AST
  │
  ▼
serialize exact handshake bytes
```

A profile may control the **shape** and position of a KeyShare, but actual ephemeral private/public material MUST be fresh per connection as required by RFC 9846.

### 14.3 Capability invariant

A profile MUST NOT advertise protocol capabilities that the TLS engine cannot safely negotiate unless an explicit experimental override exists.

In normal operation:

```text
advertised capabilities ⊆ implemented capabilities
```

This matters when reproducing modern browser profiles that commonly advertise both TLS 1.3 and TLS 1.2.

## 15. Fingerprint subsystem

The public `SSL.Fingerprint` module accepts exact naked ClientHello bytes with
explicit TCP/QUIC context and returns an ordered observation plus JA3/JA4
projections. `new/1` and `feed/2` provide a bounded one-hello stream observer.
The wire envelope parser is shared with `ClientOffer`; fingerprint observation
does not apply the negotiation capability restrictions. See
[FINGERPRINTS.md](FINGERPRINTS.md) for the implemented contract and references.

They do not influence key negotiation or handshake correctness.

JA3 and JA4 have different normalization rules. In particular, JA4 sorts cipher and extension identifiers in portions of its standard hash, while raw ClientHello ordering remains independently observable. Therefore no generic "JA4 ordering" serializer exists.

The initial library may implement local introspection only. Passive TCP sniffing is a later optional subsystem and must reuse the same record/handshake framing rather than assuming ClientHello is contained in one TCP packet.

## 16. Packet layer

`SSL.Packet` implements application-visible packet semantics above decrypted TLS bytes.

Pipeline:

```text
TLS plaintext byte stream
  │
  ▼
SSL.Packet
  │
  ▼
recv result or active message
```

Initial support should prioritize:

- `packet: 0`;
- `packet: 1`;
- `packet: 2`;
- `packet: 4`;
- `packet: :line`.

Additional OTP packet modes are compatibility milestones, not record-layer concerns.

`mode: :binary` and `mode: :list` are presentation concerns after packet extraction.

## 17. Options architecture

`SSL.Options` separates:

```text
SSL.Options.Transport
SSL.Options.TLS
SSL.Options.ExSSL
```

The compatibility layer accepts OTP-style options.

Custom functionality is namespaced:

```elixir
ex_ssl: [
  profile: :profile_name,
  fingerprint_debug: false
]
```

Namespacing prevents collision with future OTP `:ssl` options.

Unsupported standard options must return an OTP-compatible option error. They must not be silently accepted.

## 18. Error architecture

Internal code may use structured errors such as:

```text
SSL.Error.Protocol
SSL.Error.Alert
SSL.Error.Option
SSL.Error.Certificate
SSL.Error.Transport
```

The public `SSL` facade maps those into return values/forms compatible with OTP `:ssl` for the corresponding public operation.

Protocol failures should generate the appropriate TLS fatal alert when the protocol state permits it before the transport is closed.

## 19. STARTTLS architecture

The compatibility surface must support upgrading an already connected TCP socket:

```elixir
SSL.connect(tcp_socket, tls_opts)
SSL.connect(tcp_socket, tls_opts, timeout)
```

Requirements:

- caller must own/control the TCP socket at upgrade time;
- ownership is transferred to `SSL.Connection`;
- TCP mode is normalized for TLS internals;
- no plaintext bytes may be accidentally discarded during handoff;
- failure semantics must define whether the underlying socket remains usable or is closed, matching OTP behavior where feasible.

STARTTLS support is an MVP requirement because it is part of the ordinary OTP client API and important for IMAP/SMTP/XMPP-style protocols.

## 20. Post-handshake TLS 1.3

The `:connected` state continues to process TLS handshake content.

It must support or explicitly handle:

- `NewSessionTicket`;
- `KeyUpdate`;
- post-handshake alerts;
- `close_notify`.

The architecture must not assume Finished means no more handshake messages will arrive.

Session resumption may be deferred, but NewSessionTicket parsing must not break established connections.

## 21. Memory and secret handling

BEAM immutable data and garbage collection do not provide deterministic secret zeroization.

Requirements:

- keep secrets connection-local;
- never log secrets by default;
- avoid placing secrets in ETS, Registry metadata, telemetry metadata, exceptions, or crash reports;
- replace state promptly when traffic epochs change;
- drop obsolete references as soon as protocol semantics allow;
- make NSS-style key logging explicit opt-in functionality only.

The project documentation must not claim guaranteed in-memory zeroization.

## 22. Observability

Use `:telemetry`-style events only if added deliberately and with a stable schema. Initial instrumentation may remain internal counters/logging.

Never include in ordinary telemetry/logs:

- private keys;
- traffic secrets;
- Finished keys;
- plaintext application data;
- certificate private material.

Useful safe metadata includes:

- connection duration;
- negotiated protocol version;
- negotiated cipher suite;
- ALPN;
- selected profile name;
- handshake phase timing;
- record counts/bytes;
- close reason category.

## 23. Testing architecture

### 23.1 Differential API tests

A central compatibility suite runs equivalent scenarios against:

```text
:ssl
SSL
```

and compares externally observable behavior rather than private socket structures.

### 23.2 Protocol vectors

Use RFC vectors or independently generated vectors for:

- HKDF-Extract;
- HKDF-Expand;
- HKDF-Expand-Label;
- nonce generation;
- record encryption/decryption;
- Finished calculation;
- transcript hashes;
- HelloRetryRequest transcript rewriting.

### 23.3 Interoperability

Test against independent TLS servers/clients, not only a self-hosted `ex_ssl` endpoint.

Initial matrix should include at least:

- OTP `:ssl` server;
- OpenSSL `s_server`;
- a common public TLS endpoint in opt-in integration tests.

### 23.4 Fragmentation/property tests

For every parser/framer, generate arbitrary TCP chunk boundaries and TLS record boundaries.

Required property:

```text
parse(fragment(binary)) == parse(binary)
```

for every valid input across all valid fragmentation boundaries within practical test limits.

### 23.5 Fingerprint golden tests

Profiles use captured/golden ClientHello bytes.

For each verified profile, assert:

- exact deterministic fields/order where the profile specifies them;
- valid variability only in fields declared random/fresh;
- expected JA3 projection;
- expected JA4 projection;
- successful real handshake against a compatible server.

## 24. Scope evolution

### Stage 1 — TLS 1.3 client core

- OTP-compatible client facade;
- TLS 1.3 handshake;
- X.509 server authentication;
- active/passive socket behavior;
- STARTTLS;
- ALPN;
- profile-driven ClientHello;
- JA3/JA4 introspection.

### Stage 2 — production compatibility

- broader OTP option coverage;
- session tickets/resumption;
- exporters;
- key updates;
- more packet modes;
- broader certificate callbacks;
- verified browser/mobile profiles.

### Stage 3 — TLS 1.2 client

TLS 1.2 becomes necessary for faithful profiles that legitimately advertise TLS 1.2 fallback. It should be implemented as a separate protocol-version module sharing transport/API/PKIX infrastructure.

### Stage 4 — server and optional analysis features

- server APIs (`listen`, `transport_accept`, `handshake`);
- passive ClientHello analyzer;
- additional fingerprint formats.

DTLS and QUIC networking are not implicit extensions of this architecture.
The explicit record-free TLS integration is defined in
[ADR_QUIC_TLS_CORE.md](ADR_QUIC_TLS_CORE.md); it does not add a QUIC stack.

## 25. Dependency direction

Allowed dependency direction:

```text
SSL facade
   ↓
Connection / Options / Socket
   ↓
Protocol orchestration
   ↓
Codec / Crypto / PKIX / ClientHello / Packet
```

Rules:

- `SSL.Crypto.*` MUST NOT depend on `SSL.Connection`;
- codecs MUST NOT send messages or touch sockets;
- `WireProfile` MUST NOT call the network;
- fingerprint modules MUST NOT mutate handshake behavior;
- public compatibility translation stays in or near `SSL`/`SSL.Options`;
- socket I/O stays in `SSL.Connection` or the transport adapter.

## 26. Architectural definition of done

The first architecture milestone is complete when:

1. an application can replace a basic `:ssl.connect/send/recv/close` client path with `SSL`;
2. TLS 1.3 handshakes succeed against independent compliant servers;
3. certificate and hostname verification fail closed;
4. fragmented TCP and handshake input is handled correctly;
5. active/passive semantics match OTP for covered modes;
6. STARTTLS upgrade works;
7. ClientHello output is generated from a validated `WireProfile`;
8. at least one golden custom profile proves exact controllable ordering/GREASE placement;
9. JA3 and JA4 are derived from that same ClientHello;
10. no native TLS implementation (`:ssl`) is used to perform the `ex_ssl` handshake itself.

## Bounded dual-version client decision

The TLS1.2 extension follows [ADR_TLS12_CLIENT.md](ADR_TLS12_CLIENT.md). It keeps
the socket/runtime contract and separates version-specific pure handshake, key
schedule and record logic. See the progress ledger for implementation status;
this decision alone does not claim TLS1.2 support.
