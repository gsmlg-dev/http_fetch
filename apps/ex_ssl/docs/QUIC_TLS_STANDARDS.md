# TLS / QUIC integration audit

Baseline: RFC **9846**, not superseded RFC 8446, for protocol requirements;
RFC 9001 for the record-free integration. Reviewed 2026-09-23 using the RFC
Editor's published texts and errata listings:

- https://www.rfc-editor.org/rfc/rfc9846.txt
- https://www.rfc-editor.org/errata/rfc9846
- https://www.rfc-editor.org/rfc/rfc9001.txt
- https://www.rfc-editor.org/errata/rfc9001

## Applied boundaries

RFC 9846 handshake/extension/transcript/CertificateVerify/Finished requirements
are shared with the TCP authentication core. The server signs the server context,
selects only offered supported algorithms and verifies client Finished against
exact encoded messages. HRR uses `message_hash`, permits only the specified CH2
changes and forbids another retry. Signature algorithms and certificate signature
policy are distinct. RFC 8448 vectors remain historical independent crypto
fixtures; complete records are never treated as QUIC input.

RFC 9001 sections 4, 6 and 8 require these integration choices:

| Input/event | Public result / responsibility |
| --- | --- |
| TLS KeyUpdate | `kind: :tls, alert: :unexpected_message`; caller maps the TLS alert to QUIC CRYPTO_ERROR **0x010a**, per section 6 |
| Post-handshake CertificateRequest received by client | `kind: :quic, reason: :post_handshake_authentication`; caller closes with **PROTOCOL_VIOLATION (0x0a)**, section 4.4 |
| Nonempty client legacy session ID | QUIC protocol violation (`:quic_session_id`), section 8.4 |
| Wrong level / partial message spanning levels | QUIC protocol violation; no internal future-level buffering |
| EndOfEarlyData | Never sent; unexpected TLS handshake message when supplied here; section 8.3 separately assigns CRYPTO-in-0RTT packet detection to the QUIC caller |
| Missing extension 57 | TLS `missing_extension`; present-empty remains valid TLS framing |
| NewSessionTicket after completion | Bounded structural parse and discard; no unsupported resumption claim |
| PHA capability offered in CH | Valid empty offer is ignored; this server never requests PHA |
| TLS alert | Structured atom, not an alert record; caller maps alert number to 0x100 + number under section 4.8 |
| Initial / packet / header-protection keys and key update | Entirely outside ex_ssl |

There is no 0-RTT input level. The caller owns CRYPTO frame legality, packet
validation, transport parameter semantics, HANDSHAKE_DONE and key retirement.
TLS completion does not imply QUIC handshake confirmation or an authenticated
client certificate identity.

## Errata disposition

The RFC 9001 listing contains rejected erratum **7785**, concerning reconstructed
packet number width. Its proposed 32-bit replacement is not applied; packet
numbers are outside this TLS engine in any case.

The RFC 9846 listing contains reported (not verified) errata **9040**, **9042**,
**9043**, **9161**, and **9157**. The first three concern obsolete pre-TLS-1.2
fallback wording; QUIC supports TLS 1.3 only. 9161 clarifies that a syntactically
empty CertificateRequest extension vector does not override the mandatory
`signature_algorithms` requirement; the shared parser already enforces it.
9157 is capitalization of Main Secret, with no wire change. None requires a
QUIC algorithm change. Reported text is not silently treated as an adopted RFC.

## Secret and random-material lifetime

The materializer/client retry boundary generates secure, fresh key pairs; the
QUIC server adapter obtains its secure random and key pair before invoking the
pure server flight. Neither traffic derivation nor the authentication core calls
socket/process/record/Logger APIs. The shared incremental core drops its client
ECDHE private-key reference after deriving handshake secrets. The server drops
identity/private-key configuration after signing its flight and keeps only the
client handshake secret and transcript needed for client Finished. Client state
retains its optional signing identity until its own authentication flight, then
clears it. Completion, failure and abort release obsolete core/config references.
Older immutable states and returned secrets are the caller's responsibility;
BEAM memory zeroization is not claimed.

## 2026-09-23 boundary corrections

- RFC 9846 section 9.2 and key_share semantics: certificate/ECDHE negotiation
  requires extension presence separately from the legal empty client_shares
  vector. The server may decline a valid PSK offer for certificate authentication;
  no PSK capability was added. Observation remains distinct from negotiation.
- ServerHello/HRR extension limits count the actual encoded vector entries.
  The shared decoder checks declared length before parsing the payload or
  advancing HRR. This is an independently configurable receive budget, not a
  claim that prior memory use was unbounded.
- RFC 9846 extension response/placement rules and the existing shared-core
  mapping distinguish unsupported/unoffered extensions, forbidden positions,
  and malformed encoding. QUIC pre-parsing now preserves that mapping, including
  NewSessionTicket. No TLS-to-QUIC CONNECTION_CLOSE encoder is added.
