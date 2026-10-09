# ex_ssl

`ex_ssl` is an experimental TLS implementation for Elixir/OTP with two primary goals:

1. provide a client API that is behaviorally compatible with Erlang/OTP `:ssl` where implemented;
2. provide programmable TLS ClientHello wire profiles for applications that need precise control over observable TLS handshake behavior.

The OTP application is `:ex_ssl`. The public compatibility module is `SSL` (`Elixir.SSL`), which does not conflict with Erlang's built-in `:ssl` module.

This app was imported from `gsmlg-dev/ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6` into the `http_fetch` umbrella. Its original TLS source provenance is recorded in [the QUIC TLS contract](../../docs/quic/ex-ssl-quic-contract.md). The shared candidate version is `0.16.1`; all sibling dependencies use that exact version.

> **Status:** experimental TLS 1.3 client runtime with authenticated connections,
> passive and active-once binary/raw traffic, application ownership transfer,
> ALPN lookup, bounded streaming writes, initial-handshake client authentication,
> and TCP-to-TLS upgrades. See the
> [compatibility matrix](docs/COMPATIBILITY.md) for exact restrictions. OTP
> `:ssl` remains the default recommendation.

Version 0.4 also supports ordered TLS 1.3 algorithm options, explicit
certificate-chain signature restrictions, one client identity, and a validated
TCP option allowlist. These additions require ex_ssl 0.4 or newer;
see [compatibility](docs/COMPATIBILITY.md) and the
[implementation ledger](docs/EX_SSL_HTTP_FETCH_PROGRESS.md) for executed gates.

## Installation

Add the `ex_ssl` package to your dependencies:

```elixir
def deps do
  [
    {:ex_ssl, "== 0.16.1"}
  ]
end
```

The Hex package name is [`ex_ssl`](https://hex.pm/packages/ex_ssl).

## Why ex_ssl?

OTP `:ssl` is the correct default TLS implementation for normal Erlang/Elixir applications. `ex_ssl` exists for cases where an application also needs deterministic or profile-driven control of the ClientHello wire representation, including characteristics such as:

- cipher-suite ordering;
- extension ordering;
- supported versions/groups;
- KeyShare shape and placement;
- signature algorithm ordering;
- ALPN ordering;
- GREASE placement/policy;
- legacy session-id/compatibility behavior;
- padding and selected record-shaping behavior.

The library treats these as a **wire profile**, not as a JA3 configuration. JA3 and JA4 are derived fingerprints of the emitted/parsed ClientHello.

## Naming

```text
Package:              ex_ssl
Repository:           gsmlg-dev/http_fetch
OTP application:      :ex_ssl
Public API:            SSL
Internal namespace:    SSL.*
```

Migration is intended to look like:

```elixir
# OTP
:ssl.connect(host, port, options)

# ex_ssl
SSL.connect(host, port, options)
```

Custom behavior is additive and namespaced:

```elixir
SSL.connect(host, port,
  verify: :verify_peer,
  server_name_indication: host,
  ex_ssl: [
    profile: :default
  ]
)
```

To verify an IP certificate after connecting a TCP socket to a different address,
supply the original reference separately from SNI:

```elixir
SSL.connect(tcp_socket,
  verify: :verify_peer,
  server_name_indication: :disable,
  ex_ssl: [reference_identity: {:ip, "127.0.0.1"}]
)
```

The custom reference accepts IPv4/IPv6 tuples or strings, or
`{:dns_id, "service.example"}`. It selects certificate verification only;
SNI follows `server_name_indication` and the usual direct-dial defaults.
Trust, peer identity and handshake verification remain mandatory.

## Runtime baseline

The supported runtime baselines are Elixir 1.18 on Erlang/OTP 28, Elixir 1.19 on
Erlang/OTP 28, and Elixir 1.20 on Erlang/OTP 29. CI covers all three tuples. OTP 29
remains the behavioral reference target for the implemented `:ssl`-compatible client
feature subset.

The [validation and security evidence map](docs/SECURITY_REVIEW_EVIDENCE.md)
documents mandatory peer/runtime gates and the reproducible pinned downstream
source-candidate/package check. Independent human security review remains incomplete.

## Compatibility target

The initial compatibility baseline is the Erlang/OTP 29 `:ssl` client API.

Implemented client functions are `connect/2,3,4`, `send/2`, `recv/2,3`,
`close/1`, `setopts/2`, `controlling_process/2`, and
`negotiated_protocol/1`, `connection_information/1,2`, `peercert/1`,
`peername/1`, and `sockname/1`. Full handshakes verify CertificateVerify and
Finished; resumed handshakes verify the ticket-bound Finished. Connect succeeds
after the client Finished is transmitted. The connection runs
as a temporary supervised `:gen_statem`; a failed session is never restarted.

Defaults are deliberately restricted to binary, passive, raw, verified TLS 1.3.
They differ from OTP's defaults. Supported options and receive/upgrade ownership
rules are documented in the [compatibility matrix](docs/COMPATIBILITY.md).

TLS 1.3 resumption is opt-in with `session_tickets: :auto`; the default is
`:disabled`. Auto requires TLS 1.3-only versions and no configured client identity.
Tickets remain in a bounded in-memory cache, partitioned by endpoint and loaded
trust/security policy. Each use revalidates the saved peer certificate chain and
performs fresh ECDHE. A server declining PSK continues normal full authentication
on that connection. No early data, automatic reconnect, or request replay occurs.
See the [resumption policy](docs/ADR_TLS13_RESUMPTION.md) and
[compatibility details](docs/COMPATIBILITY.md).

The wider roadmap (not implemented API) includes:

```text
close/2
shutdown/2
getopts/2
getstat/1,2
update_keys/2
export_key_materials/4,5
format_error/1
versions/0
```

Compatibility means observable behavior, not only matching names and arities.

For implemented features, `ex_ssl` aims to match:

- success/error tuple forms;
- timeout semantics;
- active/passive socket semantics;
- controlling-process behavior;
- standard TLS/socket option behavior;
- STARTTLS-style upgrade of an existing TCP socket;
- active message forms.

The active message contract targets OTP forms:

```elixir
{:ssl, socket, data}
{:ssl_closed, socket}
{:ssl_error, socket, reason}
{:ssl_passive, socket}
```

## Protocol scope

The TCP protocol target is a **TLS client**, using RFC 9846 as the normative
TLS 1.3 specification. The separate `SSL.QUIC` engine also implements the
record-free TLS 1.3 server role; its acceptance status is documented separately.

Initial target features:

- TLS 1.3 ClientHello/ServerHello;
- HelloRetryRequest;
- EncryptedExtensions;
- server Certificate / CertificateVerify / Finished;
- client Finished;
- X.509 path and service-identity verification;
- ALPN;
- TLS alerts and close_notify;
- NewSessionTicket parsing;
- KeyUpdate;
- passive and OTP-style active receive modes;
- STARTTLS upgrade;
- programmable ClientHello WireProfile;
- GREASE (RFC 8701);
- JA3 and JA4 introspection.

Initial target cipher suites:

```text
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

Initial target groups:

```text
X25519
secp256r1
secp384r1
```

Runtime support depends on the crypto provider available to OTP. Implemented
TLS 1.3 handshake signatures are P-256/P-384 ECDSA, Ed25519, and RSA-PSS-RSAE /
RSA-PSS-PSS SHA-256/384/512, with strict key and parameter checks. See
[the compatibility matrix](docs/COMPATIBILITY.md) for the bounded subset; client
certificates and explicit bounded TLS 1.2 are implemented in version 0.4.

## Architecture

`SSL.QUIC` provides an experimental record-free TLS 1.3 client/server handshake
API with caller-owned state and ordered traffic-secret actions. The TCP client
shares its ClientHello/HRR and authentication core. This adds neither QUIC
networking nor TCP server APIs. See the [interface](docs/QUIC_TLS_INTERFACE.md)
and [implementation ledger](docs/QUIC_TLS_IMPLEMENTATION.md). The pinned
[aioquic comparison](e2e/quic_tls/README.md) exercises both roles and compares
traffic secrets without QUIC networking.

`SSL.Fingerprint.client_hello(bytes, :tcp | :quic)` computes JA3/JA4 from actual
naked ClientHello bytes; `new/1` and `feed/2` support bounded fragmented
observation. Unknown IDs and wire ordering remain available separately from the
analytical projections. See [fingerprint API and references](docs/FINGERPRINTS.md).

```text
Application
    │
    ▼
   SSL                     OTP-compatible facade
    │
    ▼
SSL.Connection             :gen_statem per connection
    │
    ├── SSL.Protocol.*     records / handshake / transcript
    ├── SSL.Crypto.*       HKDF / AEAD / key schedule / ECDHE
    ├── SSL.PKIX.*         certificate + identity verification
    ├── SSL.ClientHello.*  WireProfile / GREASE / serializer
    ├── SSL.Fingerprint.*  JA3 / JA4 / wire inspection
    └── SSL.Packet         application packet modes
    │
    ▼
:gen_tcp
```

The raw TCP socket is controlled by `SSL.Connection`, normally using internal `active: :once`. Application-visible `active` mode is implemented above TLS so handshake/record processing cannot be disabled by application socket mode.

## Wire profiles

The profile is the source of truth for what `ex_ssl` attempts to emit.

Conceptually:

```text
WireProfile
  │
  ▼
validate against TLS/runtime capabilities
  │
  ▼
materialize per-connection randomness, GREASE and fresh KeyShare
  │
  ▼
ordered ClientHello AST
  │
  ├──► JA3
  ├──► JA4
  └──► exact-wire inspection
  │
  ▼
serialize
```

Profiles may describe KeyShare group/order/position but may **not** reuse actual ephemeral private/public key material between real connections.

## Important limitations

### Not a complete device impersonation layer

A matching TLS ClientHello does not guarantee that a remote service will see a client as identical to a browser or mobile application. Other observable layers can include TCP/IP behavior, HTTP/2 SETTINGS and framing, header behavior, QUIC/HTTP/3 behavior, application protocol details, and timing.

`ex_ssl` focuses on the TLS layer.

### Explicit bounded TLS 1.2

Version 0.4 accepts explicit TLS1.2-only or mixed version lists while
keeping TLS1.3 as the default. TLS1.2 requires ECDHE, AES-GCM, Extended Master
Secret and secure-renegotiation indication; renegotiation is disabled. Peers
without EMS, including the observed local OTP28 TLS1.2 server, fail explicitly.
OpenSSL full/mTLS exchanges validate the bounded subset. See the compatibility
matrix and progress ledger for evidence and remaining gates.

### BEAM secret zeroization

Elixir/Erlang immutable binaries and garbage collection do not provide deterministic memory zeroization. `ex_ssl` minimizes secret lifetime and scope but does not claim guaranteed erasure of every in-memory copy.

## Security model

Fingerprint fidelity never overrides TLS authentication.

`ex_ssl` must fail closed for:

- invalid certificate chains;
- service identity mismatch;
- invalid CertificateVerify signatures;
- invalid Finished values;
- AEAD authentication failures;
- invalid protocol state;
- record/sequence limit violations.

The implementation uses OTP `:crypto` and `:public_key` for cryptographic primitives and X.509 functionality rather than reimplementing those primitives in Elixir.

## Development status

The authenticated TLS 1.3 client, passive/active-once raw application traffic,
STARTTLS, ownership transfer, public ALPN, KeyUpdate handling, and bounded
multi-record writes are implemented. Development continues toward broader OTP
API/options, active modes, packet modes, exporters, verified
real-world profiles, performance work, and independent security review.

See:

- [ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [DESIGN.md](docs/DESIGN.md)
- [PRD.md](docs/PRD.md)
- [IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md)
- [AGENTS.md](AGENTS.md)

## Testing philosophy

The project uses four complementary test classes:

### Protocol/vector tests

Cryptographic and transcript operations are checked against independent known results.

### Property/fragmentation tests

Parsers are tested across arbitrary TCP, record, and handshake fragmentation boundaries.

### Interoperability tests

Integration tests connect ex_ssl to generated local OTP `:ssl` peers and
OpenSSL. The dedicated Caddy workflow validates fingerprint behavior.

### Differential compatibility tests

Focused scenarios compare OTP `:ssl` and `SSL` behavior for implemented receive,
path-depth, ownership, timeout, and active-mode semantics.

A compatibility claim is not complete until covered by tests.

## Standards and references

Primary references:

- TLS 1.3: RFC 9846 — https://www.rfc-editor.org/info/rfc9846/
- GREASE: RFC 8701 — https://www.rfc-editor.org/info/rfc8701/
- TLS service identity: RFC 9525 — https://www.rfc-editor.org/info/rfc9525/
- Erlang/OTP `:ssl`: https://www.erlang.org/doc/apps/ssl/ssl.html
- Erlang/OTP `:crypto`: https://www.erlang.org/doc/apps/crypto/crypto.html
- Erlang/OTP `:public_key`: https://www.erlang.org/doc/apps/public_key/public_key.html
- JA4 technical details: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md

## License

Licensed under the [Apache License 2.0](LICENSE).
