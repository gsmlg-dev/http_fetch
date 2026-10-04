# Record-free TLS 1.3 handshake core

Status: implemented core and experimental public duplex API; acceptance
gates are tracked in the implementation ledger. No production-readiness claim.

The requested integration is `abyss -> ex_quic -> ex_ssl -> OTP crypto/public_key`.
Only ex_ssl changes here. RFC 9846 remains the TLS baseline; RFC 9001 supplies
the QUIC/TLS integration constraints. QUIC packets, Initial derivation, header
protection, retransmission, streams and handshake confirmation belong to the
caller. No TCP server API is added.

## Decision

Extract authentication, exact-byte transcripts, Finished, and TLS traffic secret
derivation into `SSL.Protocol.HandshakeCore`. Both transports must execute this
same implementation. `ServerFlightVerifier` becomes the TCP record adapter:
it derives record key/IV states, decrypts records, and encrypts the raw client
flight returned by the core. TLS 1.2 remains in its existing engine.

The first extraction starts after ServerHello, preserving the current client's
certificate authentication, client identity selection and PSK handling. ClientHello/HRR orchestration now lives in shared `ClientHandshake`;
`ServerHandshake` performs real server negotiation and certificate authentication
using the same key schedule and signature/transcript primitives.

`ClientAuthentication.messages/3` produces exact Certificate/CertificateVerify
messages. Its existing `emit/4` is retained as a record adapter. Signature and
Finished transcript inputs are the final messages, never reconstructed peer ASTs.

The public QUIC boundary holds one opaque immutable state in the caller,
with one totally ordered action stream. It does not create a hidden connection
process or fake TLS records. Required ordering and ownership are specified in
[QUIC_TLS_INTERFACE.md](QUIC_TLS_INTERFACE.md).

## Security and scope

Core input, incremental state and result inspection omit key material. The core
returns only the traffic secrets needed by its adapter; its master secret is
not part of the result. Public QUIC state must clear obsolete references on
completion/failure/abort. BEAM does not guarantee physical memory zeroization.

TCP retains mTLS, opt-in resumption, HRR, record KeyUpdate and STARTTLS. The
initial record-free server supports full certificate handshakes, not mTLS,
resumption or 0-RTT. Executed local self-connection and independent-peer evidence are recorded
in [QUIC_TLS_IMPLEMENTATION.md](QUIC_TLS_IMPLEMENTATION.md).

Fingerprint observation is separate from negotiation: unknown wire identifiers
must remain observable without becoming advertised supported algorithms. No
JA3/JA4 library implementation exists at the starting HEAD; the existing Caddy
fixture is an independent expected-output source, not a substitute for an
analyzer. Fingerprints must be recomputed from emitted/received bytes.
