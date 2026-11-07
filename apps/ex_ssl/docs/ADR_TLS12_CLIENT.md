# ADR: bounded TLS 1.2 client behind the pure protocol boundary

Date: 2026-09-22. Status: accepted for implementation; protocol and consumer gates
remain mandatory before public version acceptance. Plan tasks P4.1-P4.3.

## Context and decision

The verified TLS1.3 runtime already owns socket input, one blocking writer,
absolute operation deadlines, active-once delivery, bounded queues and teardown.
Keep that runtime. `HandshakeMachine` remains the pure init/feed/encrypt dispatch
boundary; a separate `SSL.Protocol.TLS12` state implements TLS1.2. Both expose the
same phase/event and outbound-record contract. No second socket, retries, OTP TLS
implementation, version fallback after failure or request replay is introduced.
`phase: :connected` retains its engine-neutral meaning for runtime output labels.

The initial dispatcher retains exact encoded ClientHello and all complete or
partial ServerHello-flight bytes. It selects the engine from the offered suite
and validated ServerHello, with no regenerated hello. TLS1.3 HRR remains inside
the existing engine. TLS1.2 ServerHello can share a record with later handshake
messages. Both engines reject cross-epoch message fragments and illegal ordering.

## Independent TLS1.2 core

Separate pure key-schedule and record modules implement the RFC5246 PRF using
OTP HMAC, RFC7627 Extended Master Secret or RFC5246 full-handshake master
derivation, client/server key-block partitioning,
and RFC5288 AES-GCM records using OTP AEAD. TLS1.2 has a four-byte fixed IV and
eight-byte explicit nonce, sequence/type/version/plaintext-length AAD, and no
TLS1.3 inner content type. Read and write sequences begin at zero at their own
CCS transitions. Reject sequence/record-use exhaustion; no TLS1.2 key update or
renegotiation is offered. Retain 16KiB plaintext and the shared bounded framer.

Authenticate leaf/chain/service identity through the existing PKIX boundary.
Verify signed ECDHE parameters over client_random || server_random || parameters,
using a dedicated raw-message signature entry point with key/scheme validation;
TLS1.3 CertificateVerify context construction must never be used for TLS1.2.
Generate fresh ECDHE material per handshake. Client CertificateVerify signs the
exact transcript through ClientKeyExchange. EMS hashes through ClientKeyExchange
(including client Certificate if requested), before CertificateVerify and Finished.
Client Finished precedes server CCS/Finished. Report connected only after the
server Finished is authenticated. Never expose application data before that gate.

Support requested initial client authentication through the bounded identity
loader. TLS1.2 CertificateRequest uses certificate types, signature pairs and CA
names, not the TLS1.3 request format. No compatible identity emits an empty
Certificate. The existing writer handles fragmented large client flights under
the original deadline. Clear ephemeral keys, identity and master secret after
handshake completion; retain only required traffic keys and non-secret metadata.

## Policy and negotiation

Only ECDHE_RSA / ECDHE_ECDSA AES128-GCM-SHA256 and AES256-GCM-SHA384 are in scope.
Always offer EMS and use it when the server acknowledges it. A legacy server
that omits EMS may complete a full handshake using the RFC5246 master-secret
PRF over client_random || server_random, as permitted by RFC7627 section5.2.
Record negotiated EMS explicitly in the handshake state. Legacy full handshakes
retain certificate/hostname, signed ECDHE, Finished and AEAD authentication, but
do not obtain EMS's handshake-context binding and must not be described as
providing equivalent master-secret security.

Only EMS connections may produce retained or cached session material. A legacy
connection never exports `session_data`, including with `reuse_sessions: true`
or `:save`; requesting it returns `{:error, :no_session}`. Accepting an offered
EMS session ID without EMS aborts. A declined ID may start a new legacy full
handshake, discarding all saved material. No legacy resumption, master-derived
application authentication exporters or channel bindings are supported (RFC7627
sections5.3-5.4). Require valid initial secure-renegotiation indication (RFC5746);
renegotiation itself remains disabled. Compression, static RSA, CBC,
RC4, anonymous suites and TLS1.0/1.1 remain unsupported. TLS1.2 session resumption
is limited to the separate EMS-only session contract.
Signature policy is version aware: TLS1.2 raw signatures cannot silently extend
TLS1.3 CertificateVerify. Existing modern PSS/ECDSA primitives may be reused with
validated raw data; unsupported combinations must reject explicitly.

Generated default profiles normalize the public `versions` list to highest
version first, matching OTP client API semantics, and retain explicit suite order.
Both accepted mixed lists therefore advertise TLS1.3 before TLS1.2. This avoids
selecting TLS1.2 on an OTP peer that negotiates the first shared wire version,
which would correctly trigger downgrade protection when TLS1.3 is also supported.
Explicit profiles must agree with the caller's ordered version and policy lists
exactly; never rewrite them. Mixed ClientHello offers TLS1.3 and TLS1.2 once.
Validate the TLS1.3 downgrade sentinel when a TLS1.3 offer receives TLS1.2. A TLS1.2-only offer can
connect to a newer peer without treating its mandated sentinel as an attack.
Default remains TLS1.3-only. Public version acceptance is the final integration
step, after pure engine and real-peer evidence; tests may exercise the pure engine
before that step. TLS1.3 PSK/ticket support is a separate Phase5 boundary.

## Required evidence and sources

Independent deterministic PRF/key-block/nonce/AEAD vectors; fragmented and
malformed parser tests; signature, Finished, AEAD, CCS, downgrade, EMS and identity
negative tests. OTP and OpenSSL full/mTLS peers; TLS1.3-only, TLS1.2-only and mixed
negotiation. Reuse lifecycle/ownership/deadline/backpressure tests on both engines.
Packaged HTTP1/2, WSS and SSE must pass before the P4 acceptance gate. HTTP2 requires
TLS1.2 or later, allowed AEAD suites, no compression/renegotiation and ALPN; retain
P256 support and ECDHE_RSA_AES128_GCM as required by RFC9113 section9.2.

Normative sources: [RFC5246](https://www.rfc-editor.org/rfc/rfc5246),
[RFC7627](https://www.rfc-editor.org/rfc/rfc7627),
[RFC5746](https://www.rfc-editor.org/rfc/rfc5746),
[RFC5288](https://www.rfc-editor.org/rfc/rfc5288),
[RFC5289](https://www.rfc-editor.org/rfc/rfc5289),
[RFC8422](https://www.rfc-editor.org/rfc/rfc8422),
[RFC9325](https://www.rfc-editor.org/rfc/rfc9325),
[RFC9113](https://www.rfc-editor.org/rfc/rfc9113), and
[RFC9846](https://www.rfc-editor.org/rfc/rfc9846) for mixed-version negotiation.
Independent human security review remains a release-readiness concern; local
interoperability is not a security certification.
