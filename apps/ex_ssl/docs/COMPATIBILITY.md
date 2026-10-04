# TLS client compatibility

`ex_ssl` provides an experimental OTP `:ssl`-compatible client API for the
implemented subset below. Passing the repository tests is not a security
certification, and OTP `:ssl` remains the recommended default.

## Public API

| Surface | Supported behavior |
| --- | --- |
| `SSL.connect/2,3,4` | Authenticated TLS 1.3 and bounded TLS 1.2 client connections and passive binary/raw STARTTLS upgrades. Connect succeeds only after peer signature and Finished validation. |
| `SSL.send/2` | Valid iodata of any logical size supported by available caller memory. Data is traversed without flattening the entire write and protected in records of at most 16,384 plaintext bytes. One logical write is admitted at a time; another caller receives `{:error, :busy}`. There is no automatic replay. An unfinished admitted send is settled promptly as `{:error, :closed}` after an authenticated peer closure makes further writes impossible; a send already acknowledged in full remains `:ok`. |
| `SSL.recv/2,3` | Passive raw binary receive. Length zero returns available plaintext; a positive length waits for exactly that many bytes. One passive receive is admitted, and the maximum requested/buffered plaintext is 1 MiB. |
| `SSL.setopts/2` | Validates the whole request for `active: false` or `:once`, send timeouts and the mutable TCP allowlist below. Invalid options reject before changes. Driver failures can partially apply TCP options; TLS state changes only after driver success. |
| `SSL.controlling_process/2` | Transfers the application owner and monitor. The connection process remains the TCP owner and sole owner of TLS state. Only the current application owner may transfer. |
| `SSL.negotiated_protocol/1` | Returns authenticated ALPN as `{:ok, binary}` or `{:error, :protocol_not_negotiated}`. |
| `SSL.connection_information/1,2` | Only `:protocol`, `:selected_cipher_suite`, and `:session_resumption`; explicit ordered key lists reject unknown/duplicate keys. No secret-bearing OTP keys. |
| `SSL.peercert/1` | Authenticated leaf DER, including the revalidated cached chain for resumption. |
| `SSL.peername/1`, `SSL.sockname/1` | Live peer/local TCP address and port. |
| `SSL.close/1` | Idempotent local close. Sends close_notify when no application write is uncertain and wakes admitted calls. |

Closed and invalid handles follow the existing public call mapping. An orderly
TLS closure produces `:closed`; abrupt TCP loss or unexpected connection-process
loss produces `:econnreset`. TLS failures use redacted `{:tls_alert, ...}`
reasons. Other roadmap APIs are not exported as success-returning stubs.

## Ownership and active-once behavior

The public socket term is stable for the life of a connection. Ownership
transfer changes only future application delivery and owner-death monitoring;
it does not move TCP ownership, traffic keys, sequence counters, buffers, or
replies already assigned to admitted `send`/`recv` callers.

A self-transfer succeeds. A non-owner receives `{:error, :not_owner}`. A target
known to be dead before the transfer receives `{:error, :noproc}` without
changing the live connection. If the target dies after the transfer is
committed, the successful transfer stands and its `DOWN` closes the connection.
This deliberate pre-check differs from OTP versions that can return `:ok` for an
already-dead target and then asynchronously close. A stale `DOWN` from an old
owner is ignored after a successful monitor replacement.

Messages already sent to the old owner's mailbox stay there; mailbox contents
cannot be migrated by changing a monitor. The caller must transfer a passive
socket before activating it when it requires a clean mailbox handoff.

Application `active: :once` is independent of the raw TCP socket's internal
active-once processing. One activation permits at most one
`{:ssl, socket, binary}` message and then becomes application-passive. It emits
no `{:ssl_passive, socket}` notification. Rearming drains already-buffered
plaintext immediately. An explicit `active: false` stops future data messages
without retracting messages already delivered or dropping buffered bytes.

An activation request while a passive `recv` is admitted returns
`{:error, :einval}` and leaves that receive and all bytes untouched. Graceful
and abrupt terminal events are delivered once as `{:ssl_closed, socket}` or
`{:ssl_error, socket, reason}` for an active-once subscription, after earlier
deliverable plaintext. Handshake traffic, NewSessionTicket, and KeyUpdate never
consume application delivery credit.

## Connection options

Supported connection options are:

- `:binary` or `mode: :binary`;
- `packet: :raw | 0`;
- `active: false | :once` (default `false`);
- `verify: :verify_peer`;
- `cacerts` or `cacertfile`;
- one initial-handshake client identity through `cert`/`certfile` and `key`/`keyfile` (forms and bounds below);
- DNS `server_name_indication`;
- `customize_hostname_check: [match_fun: fun]`;
- `versions: [:"tlsv1.3"]` (default), `[:"tlsv1.2"]`, or either ordered, non-duplicate mixed list;
- ordered `ciphers`, `signature_algs`, `signature_algs_cert` and `supported_groups` (forms below);
- validated TCP options from the allowlist below;
- non-negative integer `depth` (default `10`);
- non-negative integer or `:infinity` `send_timeout` (default 5,000 ms);
- `send_timeout_close: true`;
- `alpn_advertised_protocols: [nonempty_binary, ...]`;
- `ex_ssl: [profile: :default | %SSL.ClientHello.WireProfile{}]`.

Verification cannot be disabled. Packet modes, list mode, active true/active-N, arbitrary TCP
options outside the allowlist and `send_timeout_close: false` remain
unsupported. Unsupported or malformed options return a redacted
`{:error, {:options, reason}}`; supplied option data is not echoed.

`depth` is passed to OTP `:public_key` path validation as the maximum number of
intermediate CA certificates. It is independent of the TLS Certificate-message
count and the separate certificate count/byte resource limits. Differential
tests cover direct root-signed and one-intermediate paths at both boundaries.

## ALPN and WireProfile precedence

Algorithm offers use the internal capability registry, with runtime checks for
the required hash, AEAD, HMAC, ECDHE/curve, and RSA-PSS padding/MGF/salt controls.
Generic RSA or ECDSA availability alone is insufficient. The supported subset is X25519/P-256/P-384 ECDHE, P-256/P-384 ECDSA, Ed25519,
RSA-PSS-RSAE and RSA-PSS-PSS SHA-256/384/512, and the three TLS 1.3 AEAD suites.
Supplied profile ordering remains authoritative. P-521, Ed448, X448, finite-field
and post-quantum groups remain unsupported.

ECDSA requires the scheme-specific curve and canonical DER signatures. Ed25519
uses PureEdDSA with the correct TLS CertificateVerify context. RSA-PSS-PSS
requires an RSASSA-PSS leaf key, distinct from RSAE; present key restrictions
must exactly match the scheme hash, MGF1 hash, digest-sized salt and trailer 1.
Absent PSS key parameters are unrestricted, while the TLS signature still uses
the scheme-specific parameters. P-384 ECDHE uses fresh 48-byte scalars and
97-byte uncompressed public points; invalid points fail closed.

Client and server CertificateVerify use distinct role contexts. Initial client
authentication is supported as described below; post-handshake authentication
remains unsupported.

Certificate-chain signature policy is separate from the leaf's TLS
CertificateVerify scheme. An explicit `signature_algs_cert` option or
`signature_algorithms_cert` profile extension restricts the signatures on the
validated chain, using the chosen trust anchor and issuer key type/curve/PSS
parameters. Trust-anchor and self-signed signatures are exempt, but normal PKIX
trust/path/identity validation still runs. RSA PKCS1 SHA256/384/512 is supported
for certificate signatures only, with the required runtime padding primitive.
It is never accepted as a TLS 1.3 CertificateVerify signature.

The default profile and trust behavior remain unchanged when no certificate
signature policy is supplied. `signature_algs` restricts CertificateVerify;
use `signature_algs_cert` to impose a chain restriction. This explicit-policy
boundary is a documented difference from OTP's default option derivation.

| TLS policy option | Supported forms |
| --- | --- |
| `ciphers` | Nonempty ordered list of exact OTP TLS1.3 suite maps (`key_exchange: :any`, `cipher`, `mac: :aead`, `prf`) or RFC cipher-name binary/charlist strings |
| `signature_algs` | Nonempty ordered list of supported OTP signature-scheme atoms |
| `signature_algs_cert` | Nonempty ordered list of supported certificate signature-scheme atoms, including `rsa_pkcs1_sha256/384/512` |
| `supported_groups` | Nonempty ordered list of `x25519`, `secp256r1`, `secp384r1` atoms available in the runtime |

Numeric IDs remain a WireProfile representation, not an additional public
option dialect. Empty, duplicate, unsupported or malformed supplied lists fail;
no supplied value falls back to a default. Generated profiles preserve requested
ordering and choose the first supported group for the initial fresh share.
Explicit profiles require exact ordered policy agreement and are not rewritten.
Legacy OpenSSL cipher expressions and legacy hash/signature tuples are unsupported.

- The default profile incorporates a top-level ALPN list in its declared order.
- An explicit profile with no top-level ALPN is emitted unchanged.
- An explicit profile plus top-level ALPN requires an exact ordered match.
- A profile without ALPN never silently gains ALPN.
- No ALPN option preserves the existing profile and does not inject HTTP
  protocols into non-HTTP connections.

The server selection is validated as exactly one protocol offered by the
materialized ClientHello. It is retained only after authenticated handshake
validation and is never inferred from the first advertisement.

## TCP option allowlist

`nodelay` and `keepalive` accept booleans. `sndbuf` and `recbuf` accept positive
signed-32-bit integers; the operating system may clamp or round their values.
`ip` accepts a local IPv4/IPv6 address tuple and `port` accepts 0..65535. Direct
`SSL.connect` accepts one bare `:inet` or `:inet6` family flag; literal remote or
local bind addresses infer the family when absent. Conflicting families reject.
DNS references and IP SAN references remain distinct; inferred IP literals do
not send SNI. Both textual and tuple IPv6 literals are supported.

Only `nodelay`, `keepalive`, `sndbuf` and `recbuf` are mutable. A complete
`SSL.setopts` request validates before I/O. Driver errors propagate; no stronger
rollback guarantee is made for partially applied driver settings. Virtual TLS
options and buffered delivery remain usable after raw TCP shutdown. STARTTLS
allows mutable options after ownership handoff but rejects local bind/family
requests, which cannot change an existing connection.

Raw `buffer`, active/packet ownership controls, arbitrary socket backends and
unsafe linger are unsupported. Driver buffer tuning cannot change the TLS record,
handshake or plaintext bounds. The private binary/raw/active-once configuration
remains controlled by the connection process.

## Send deadlines, ordering, and cleanup

Each admitted write captures the current `send_timeout` and creates one
monotonic deadline for the whole logical write. Record fragmentation does not
restart that deadline. `SSL.setopts/2` changes the timeout for the next admitted
write; it does not change a write that already holds admission.

A persistent connection-owned writer performs at most one bounded ciphertext
send at a time, including ClientHello, retry and Finished flights, application
records, KeyUpdate, close_notify, and fatal alerts. The connection process
remains authoritative for encryption, epochs, record order, deadlines, and
admission; the writer performs only cancellable transport I/O. Connect success
is withheld until the client Finished output completes.

Received TCP data and terminal events enter a bounded FIFO. An internal drain
processes older bytes, partial-record state, and saved protocol continuations
before any newer input. Raw TCP is rearmed only after that FIFO and the current
output barrier clear. During a multi-record logical write, rearming happens
before the next bounded `:write_next` step, so responses and peer KeyUpdate
messages continue to make progress without bypassing older input. Application
active-once credit remains independent of this internal rearming.

Timeout or sender death after transmission starts fails the connection closed;
uncertain application bytes are never retried. Close and owner death abort an
uncertain blocked output immediately, including for an infinite send timeout.
Likewise, after an authenticated peer closure under the current closure policy,
an unfinished admitted send settles promptly as `{:error, :closed}` independently
of inbound drainage. Its deadline timer and sender monitor are cancelled, its
admission is released, and its unsent cursor and retained write state are
discarded. Stale writer acknowledgements, timers, and sender `DOWN` messages
cannot produce a second completion. Plaintext authenticated before the closure
remains available to passive `recv` or active-once delivery, with data before the
terminal event. An already fully acknowledged logical send remains `:ok`.
Abrupt transport failure retains its existing `:econnreset` classification; it
is not treated as authenticated closure. Failure of the reciprocal close-notify
writer after authenticated closure does not discard buffered plaintext or
reclassify the terminal state. Orderly close and fatal-alert output use a bounded
writer shutdown; teardown releases the TCP port, monitors, timers, cursors, and
writer process.

Consuming the final buffered response does not bypass pending reciprocal
close-notify output. The connection continues servicing the existing 250 ms
shutdown deadline, allowing graceful completion when possible. Expiry or an
explicit local close aborts remaining output through the supported inet port
backend. Final termination never waits for TCP output to drain: it cancels
retained timers, releases monitors and the writer, and closes the port directly.
Pending writer output or a nonempty inet send queue uses zero linger so the
driver cannot retain a flushing port after the connection exits. Empty-queue,
acknowledged shutdowns retain ordinary graceful transport closure.
Passive reads and active-once delivery need not wait for reciprocal shutdown
before consuming authenticated response bytes.

## STARTTLS and security boundaries

STARTTLS callers must own a connected binary/passive/raw `:gen_tcp` socket,
fully consume and validate the positive upgrade reply, reject plaintext held in
their own parser, and supply a DNS reference identity through
`server_name_indication`. Queued or delivered TCP plaintext causes explicit
failure and owned-socket closure. A non-owner's TCP socket is not closed.

Profiles affect offered wire capabilities only. They cannot replace trust or
identity verification. Record, handshake, certificate, trust-store, and passive
plaintext bounds remain independently enforced. No traffic secrets, private
keys, or application payloads are exposed through public metadata or ordinary
inspection.

## Remaining limitations

The experimental `SSL.QUIC` record-free TLS integration has its own
[role/transport matrix](QUIC_TLS_IMPLEMENTATION.md) and
[public interface](QUIC_TLS_INTERFACE.md). It does not broaden TCP socket support.

TCP server TLS, DTLS, QUIC networking/HTTP/3, TLS 1.2/mTLS resumption,
0-RTT, post-handshake authentication, active true/active-N, packet framing,
exporters, and full OTP API parity are out of scope. ALPN negotiation alone is
not evidence of an HTTP/2 request. See
[HTTP_FETCH_INTEGRATION.md](HTTP_FETCH_INTEGRATION.md) for the opt-in consumer
integration and its executed evidence and validation limitations.

## Initial-handshake client authentication

`SSL.connect` accepts one client identity and sends it only in response to an
authenticated initial CertificateRequest. The request must offer a compatible
CertificateVerify scheme and certificate-chain signature policy. Requested CA
names constrain selection. Unknown OID filters are ignored as specified by TLS.
Recognized Key Usage and Extended Key Usage filters currently result in an empty
Certificate because filter-value matching is not implemented. A present leaf
Key Usage must permit digital signatures even without a filter. Missing or
incompatible identities also produce an empty Certificate, as required for
optional client authentication. No CertificateVerify is sent for an empty chain.

The client Certificate, role-specific CertificateVerify and Finished use exact
transcript bytes and the existing bounded writer and original connect deadline.
Large certificates span multiple records. In TLS1.3, connect success means the server was
authenticated and the client flight was written; the peer may reject the client
identity afterward. TLS1.2 waits for the server Finished after the client flight. Callers must handle subsequent alerts and HTTP failures.
Server trust and hostname verification are unchanged.

The loader handles one DER certificate or leaf-first DER chain, typed DER RSA/EC/
PKCS#8 private keys, and unencrypted PEM through binary or charlist paths. One
combined certificate/key PEM is supported when `certfile` supplies both. Separate
sources cannot conflict or hide additional private keys. Passwords, encrypted
keys, hardware signers and `certs_keys` multiple-identity selection are rejected.
Chain order and a scheme-specific signing/verification proof bind the key to the
leaf; the peer remains responsible for client certificate trust and validity.

Bounds: 16 certificates, 256 KiB per DER certificate, 512 KiB aggregate DER,
1 MiB per PEM file or typed DER key. The chain bound leaves room for TLS record
and handshake overhead within the existing 1 MiB writer ceiling. Errors contain
only fixed reason atoms; ordinary identity inspection exposes only scheme IDs.
CertificateRequest CA-name and OID-filter vectors each allow at most 64 entries
within the existing bounded extension envelope.
Restricted PSS private keys and leaf constraints are both checked through the
shared signature verifier. Unsupported key/parameter combinations fail explicitly.

## Advanced certificate-policy boundary (Phase 3 audit)

The http_fetch production inventory uses CA overrides, depth, inferred DNS/IP
identity, and the HTTPS hostname matcher. It has no production calls requesting
`verify_fun`, `partial_chain`, CRL or OCSP policies. Those options therefore do
not block the restricted backend, but consumers that depend on them cannot use
this subset unchanged.

| Policy | Candidate support |
| --- | --- |
| `cacerts` / `cacertfile` | Explicit trust sources; no silent replacement with system trust |
| `depth` | Intermediate-CA bound, independent of parser/resource limits |
| SNI / reference identity | DNS identity or IP SAN verification; SNI is omitted for IP addresses |
| `customize_hostname_check: [match_fun: fun]` | Supported hostname matching customization; path validation remains required |
| `verify_fun` | Rejected; supplied callbacks never replace authentication failures |
| `partial_chain` | Rejected; no user callback can introduce an intermediate trust anchor |
| `crl_check` / `crl_cache` | Rejected; no revocation freshness or retrieval guarantee is claimed |
| `stapling` | Rejected; OCSP response validation and availability policy are not implemented |
| `cert_policy_opts` / `allow_any_ca_purpose` | Rejected; no implicit acceptance of policy overrides |

These names follow the [OTP 29 public option documentation](https://www.erlang.org/docs/29/apps/ssl/ssl.html).
Each supplied unsupported policy fails before network I/O, with its value
redacted. Implementing one requires a separate trust-semantics design and
negative/availability tests; no permissive verification callback is installed.

## Explicit TLS1.2 subset (since 0.4)

The default remains TLS1.3-only. Explicit TLS1.2 or mixed lists negotiate on one
connection; failure never reconnects with weaker options. The independent engine
uses OTP crypto/public_key primitives and shares the existing socket owner, writer,
deadlines, bounded queues, active-once and cleanup.

Four suites are supported: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`,
`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`,
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, and
`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`. Ordered public suite maps use
`key_exchange: :ecdhe_rsa | :ecdhe_ecdsa`, `mac: :aead`, the matching cipher and PRF.
ECDHE groups remain X25519/P256/P384. The bounded handshake signature subset uses
RSA-PSS and P256/P384 ECDSA; legacy RSA-PKCS1 handshake signatures and EdDSA cipher
authentication are not offered by the TLS1.2-only generated profile.

Extended Master Secret and a valid initial secure-renegotiation indication are
mandatory. Missing EMS fails explicitly. The repository's observed OTP28/OTP29
TLS1.2 reference-server configurations omit extension23; their rejection is
fixture-specific evidence, not a claim about every OTP server configuration.
Positive full/mTLS interoperability uses capable independent OpenSSL peers;
the [current ledger](EX_SSL_HTTP_FETCH_PROGRESS.md) records actual runtime and
provider versions separately from configured CI. Missing capable peers fail
the mandatory gate rather than weakening EMS or skipping positive scenarios.
Static RSA, CBC, RC4, compression, TLS1.0/1.1,
renegotiation and TLS1.2 session resumption remain unsupported. A nonempty echoed
session ID rejects as unsupported resumption. Generated TLS1.2-only hellos use an
empty session ID; mixed offers retain TLS1.3 compatibility behavior.

Explicit profiles must agree with ordered versions and include typed EMS and
renegotiation extensions for TLS1.2. Only TLS1.3 offers require key shares. Mixed
negotiation validates downgrade sentinels; the TLS1.3 default wire policy remains
unchanged. HTTP2 uses the permitted ECDHE/AEAD subset with ALPN and no compression
or renegotiation; the library supports P256 and ECDHE_RSA_AES128_GCM as required.

TLS1.2 client authentication follows its distinct CertificateRequest and raw
transcript signature rules. Server certificate/identity and signed ECDHE parameters
are verified before sending credentials. Unlike TLS1.3, TLS1.2 client certificates
are transmitted before encryption begins. No requested compatible identity sends
an empty Certificate. Large chains fragment at16KiB. Server Finished must verify
before connect succeeds or application bytes can be delivered.

TLS1.2 server and client certificate chains are bounded to16 certificates,
256KiB each and512KiB aggregate. Exact handshake transcript storage is bounded
to1MiB, with reserved space for the client flight. AES-GCM records use independent
directional counters and explicit nonces; exhaustion fails rather than wrapping.
Tests cover primitive vectors, fragmented/malformed input, EMS/renegotiation,
signed parameters, downgrade, CCS/Finished/AEAD errors, real suites/mTLS,
active-once, ownership, truncation and deterministic blocked-flight timeout/cancel.
See the ledger for exact executed gates and remaining consumer work.

## Opt-in TLS 1.3 resumption and diagnostics

`session_tickets: :disabled | :auto` defaults to `:disabled`. Auto is supported
only with TLS 1.3-only versions and no configured client certificate/key. Mixed
versions, TLS 1.2, mTLS auto, manual ticket export/import, PSK-only exchange and
`early_data` return explicit option errors. Explicit WireProfiles must reserve
`{:psk_key_exchange_modes, [1]}` and a last `{:pre_shared_key, :deferred}` slot;
other extension ordering is preserved. A cache miss omits only the PSK slot.

Tickets are authenticated post-handshake messages and consume no application
active-once credit. Up to eight tickets per connection are processed; each PSK is
derived from its nonce. Retained entries are limited to 128 partitions, 4 MiB
aggregate, 256 KiB each, 16 KiB ticket bytes and seven days lifetime. Atomic
one-use checkout and a single expiry timer bound cache lifetime and concurrency.
Cache calls fail closed after 25 ms; a cache failure takes the full-handshake
path. There is no persistent state. Each checkout revalidates the saved chain
against current time, reference identity, loaded CA content, depth and certificate
signature policy. Partition digests also cover the concrete endpoint, hostname,
ALPN and ordered version/cipher/group/signature/profile policies.

Resumption requires fresh ECDHE, a valid binder, selected identity zero with a
compatible hash, unchanged selected ALPN, and authenticated Finished. HRR uses
the exact CH1 message-hash rewrite and recomputed CH2 binder; a hash-incompatible
PSK is removed. Server decline, including ticket-key rotation, follows the normal
full certificate flight on the same socket. Invalid binders/Finished never cause
reconnect or replay. Ticket bytes and secrets are excluded from runtime inspection
and diagnostics; authenticated peer DER is intentionally public through peercert.

Diagnostics return only the three keys listed above; ALPN remains available from
`negotiated_protocol/1`. Closed diagnostic calls return `{:error, :closed}` under
the existing public handle mapping. Local OTP28/OTP29 reference scenarios cover the
implemented return forms, not every OTP information key or full API parity.
Independent OpenSSL peers prove full/resumed exchanges, P384 HRR resumption,
server ticket-key restart, disabled mode and authentication-policy rejection.
The source-package consumer gate proves HTTP/1.1 resumption; HTTP/2/WSS/SSE
resumption is not separately certified by that gate.

## Naked ClientHello analysis

`SSL.Fingerprint` supports bounded direct/fragmented observation with explicit
TCP or QUIC provenance, ordered unknown IDs, JA3 raw/hash and JA4 raw components
and hash. It does not authenticate peers or constrain negotiation. See
[FINGERPRINTS.md](FINGERPRINTS.md) for the contract and pinned reference vectors.


## QUIC-TLS boundary validation

The experimental `SSL.QUIC` API retains its existing signatures and role scope.
Certificate/ECDHE offers require key_share/supported_groups presence; a legal
empty share vector can cause HRR. Client ServerHello/HRR processing enforces the
configured inbound extension budget before state advancement. EE and ticket
errors preserve shared-core TLS alert categories. TCP defaults, authentication,
resumption and fingerprint observation are unchanged. See
[the interface](QUIC_TLS_INTERFACE.md) for precise inbound/outbound limit scope
and [the ledger](QUIC_TLS_IMPLEMENTATION.md) for actual regression results.
