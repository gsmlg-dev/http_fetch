# ex_ssl integration contract — umbrella sibling source

Historical source contract for `apps/ex_ssl`, first imported from `gsmlg-dev/ex_ssl@fb47051355c9d0a29caee046fa060a745ad0ce5b` (`v0.7.2`) into `ex_quic`. The destination candidate imports `ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6` and uses exact `== 0.16.1` internal requirements; see [migration provenance](../migration-provenance.md). The prior accepted source review was `f1327e0bb7fb2093b8dc2b07e72b26233a739963`, preceded by review baseline `02eb981f59d4e182d4473e264a9f8b093ec6bf3d`. The upstream API is experimental but exists; this document replaces the earlier proposed TLS-export interface. The imported source and interface document win if this summary drifts. [R1,R3]

## Allowed dependencies

Use `SSL.QUIC.capabilities/0`, `new/2`, `feed/3`, `info/1`, `abort/2`, `SSL.QUIC.Secret` and `SSL.QUIC.Error`; public `SSL.Fingerprint` functions; and documented public ClientHello profile types. Do not reach into `SSL.Protocol.HandshakeCore`, `ClientOffer`, `ServerHandshake`, or `SSL.Crypto.TrafficState` from production ex_quic code.

The historical QUIC dependency was `{:ex_ssl, "== 0.7.2", in_umbrella: true, hex: :ex_ssl}`. The destination candidate requirement is `{:ex_ssl, "== 0.16.1", in_umbrella: true, hex: :ex_ssl}`. The `hex` option preserves the package identity in dependency metadata while Mix resolves the umbrella sibling. The sibling was imported from the upstream v0.7.2 commit `fb47051355c9d0a29caee046fa060a745ad0ce5b`; upstream production `lib/` source is unchanged from the accepted G-S commit `f1327e0bb7fb2093b8dc2b07e72b26233a739963`. Historical Hex evidence: on 2026-09-29, all 58 packaged `lib/` files matched that accepted commit byte-for-byte, and the downloaded package SHA-256 matched the Hex API and then-current lockfile outer checksum, `f0f9532a6ac8b2dcb701b491394705df8f10c31f63fc7e5aad157eebb909aecb`. This checksum describes the historical Hex package, not the current sibling dependency. Keep a consumer contract test so an upstream upgrade cannot silently change levels, actions, capability fields, profile behavior or error categories. No fake TLS fallback in production; test doubles are clearly test-only.

## Calls

| Call | Actual result / meaning |
|---|---|
| `capabilities/0` | TLS algorithms, availability and role/feature limitations; not proof of QUIC header-protection support |
| `new(role, options)` | `{:ok, state, actions}` or `{:error, error}`; roles are `:client` and `:server` |
| `feed(state, level, bytes)` | `{:ok, next, actions}` or `{:error, error, terminal_state, actions}` |
| `info(state)` | Sanitized phase, receive level, flags, ALPN, suite and configured algorithm information |
| `abort(state, reason)` | Replacement terminal state; does not send a close or return a network-action list |

There is no TLS socket, process, handshake timer or CRYPTO offset management in this API. The connection runtime retains the only current state and discards old copies. Cryptographic erasure of immutable BEAM values is not guaranteed.

Levels are `:initial`, `:handshake`, `:application`, not `:one_rtt`, `:early_data` or a single global byte stream. Input is naked TLS handshake bytes with type/uint24 length, not TLS records. QUIC reassembles offsets, filters duplicates and supplies only contiguous new bytes at the current legal receive level. Future-level bytes wait in bounded QUIC buffers. Distinguish obsolete duplicates from genuinely illegal cross-level messages.

## Options and materialization

Require explicit ALPN and raw local `transport_parameters`. A client supplies trust anchors and a `reference_identity`, independent of optional `server_name`/SNI. A server supplies an in-memory certificate chain and matching key. Credentials are loaded outside the hot receive path. No `verify_none` workaround.

The client profile uses `SSL.ClientHello.WireProfile`, an empty legacy session ID and `SSL.ClientHello.RecordPolicy` with `mode: :none`. ALPN and transport-parameter bytes in the materialized profile must exactly match the corresponding config. Algorithms must be implemented and available. `ciphers`, `groups` and `signature_algorithms` use canonical integer IDs in this API.

QUIC must fill actual local/original/retry CID-dependent parameters before TLS starts. Profile compilation may control order but cannot replace negotiated or authenticated fields after serialization. Use the exact emitted ClientHello for the transcript-compatible fingerprint, never a separately regenerated copy.

## Ordered actions

The consumer understands these real action shapes:

- `%SSL.QUIC.Secret{level, direction, cipher_suite, aead, hkdf, secret}`;
- `{:emit, level, exact_handshake_bytes}`;
- `{:peer_transport_parameters, raw_bytes, :unverified | :authenticated}`;
- `{:peer_authenticated, :server}`;
- `{:negotiated_alpn, protocol}`;
- `:handshake_complete`;
- `{:error, %SSL.QUIC.Error{kind, alert, reason}}`.

Directions are local read/write, not wire sender names. Preserve list order. The client receives Handshake secrets after ServerHello; verified server Finished leads to application read material, authenticated peer/parameters, its outgoing Handshake flight, then application write material/completion. The server can export application secrets before client Finished; that is not permission to declare an authenticated client or completed handshake. [R3]

On `emit`, append exact bytes to the level's CRYPTO stream and assign offsets once. Retransmission references those ranges under new QUIC packet numbers. It never re-enters TLS. On fatal feed, adopt the terminal state and its returned error actions; do not synthesize secrets/events discarded by that failing feed. Earlier successful feeds remain committed.

The provider treats emitted bytes as committed to the caller's reliable queue. If QUIC cannot retain required output within its configured budget, abort the connection consistently; do not roll the TLS state back and regenerate different bytes. The transport send queue and TLS output budget need a deliberate relationship.

## Crypto ownership

TLS supplies handshake/application traffic secrets. ex_quic owns Initial derivation, version-specific packet key/IV/header-protection derivation, packet numbers, nonces, key phases, usage limits and retirement. It must check packet AEAD and header-protection primitive availability, not just `capabilities().cipher_suites`.

QUIC v1 labels and Initial constants must pass the RFC9001 vectors. Future v2 uses its own version parameters; do not assume changing only the version number suffices. The TLS transcript key schedule remains in ex_ssl. Small QUIC derivation helpers over OTP HMAC/hash/AEAD primitives are not a second TLS stack. [S2,S6]

## Transport parameters and error mapping

TLS enforces the extension envelope, presence and placement. ex_quic parses/validates its contents, including duplicate IDs, defaults, role constraints and CID bindings. An authenticated extension is not automatically semantically valid. Store unverified information separately; never overwrite configured policy or grant an application identity from it.

Map `kind: :tls` alerts to QUIC CRYPTO_ERROR using registered alert numbers. Known `kind: :quic` integration violations map to their documented transport domain. Configuration/closed errors and impossible local driver states must not all be sent as peer TLS decode errors. QUIC reassembly resource failures belong to the relevant QUIC error domain; upstream TLS resource alerts retain their actual classification. [R3,S1,S2]

The library's `handshake_complete` and authentication flags are historical TLS facts, even after a later post-handshake failure. QUIC connection phase still governs usability. `abort` does not undo previously observed facts or send HANDSHAKE_DONE.

## Existing limits and unsupported features

Upstream current hard defaults: 1,048,576-byte handshake body, 2,097,152 cumulative inbound+emitted handshake bytes, 65,535-byte ClientHello body, 16 certificates, 524,288 aggregate certificate bytes, 262,144 bytes per certificate, 65,535 inbound encoded extension bytes, and 16,384 signature bytes. Local parameter payloads are limited separately. Overrides lower, not raise, the upstream bounds. [R3]

`max_extension_bytes` is an inbound vector limit, not a total outbound ClientHello2 extension cap. QUIC adds its own aggregate/range/queue budgets; it cannot infer that TLS limits cover all network reassembly memory.

Current exclusions: local resumption and 0-RTT; server-side client-certificate authentication; client startup with an empty key-share profile; server profile/identity selection beyond the documented single configured identity. A client can answer a handshake CertificateRequest when configured. A peer's legal unselected PSK proposal is not itself proof of an error. Completed clients can boundedly parse/discard tickets; TLS KeyUpdate and post-handshake authentication are not QUIC key updates. [R3]

No independent HRR pass is claimed by the upstream pinned aioquic 1.2.0 TLS-only harness. Preserve upstream boundary/unit evidence and arrange independent HRR-capable network testing at M6. This is a test-coverage limitation, not a reason to implement TLS again.

## Consumer tests

Lock down role-specific actions, secret pairing, exact bytes, partial input, future-level buffering, duplicates, fatal-feed atomicity, empty feeds, abort, parameter-stage separation and profile validation. In the QUIC layer also test out-of-order Initial/Handshake datagrams, send failure, retransmission after TLS completion, and key retirement. Contract tests may use fixed public test credentials, never real credentials or application secrets in logs.

See [sources](sources.md), [design](design.md), and [testing](testing.md).
