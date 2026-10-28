# TLS client compatibility

`ex_ssl` provides an experimental OTP `:ssl`-compatible client API for the
implemented subset below. Passing the repository tests is not a security
certification, and OTP `:ssl` remains the recommended default.

## Public API

| Surface | Supported behavior |
| --- | --- |
| `SSL.connect/2,3,4` | Authenticated TLS 1.3 and bounded TLS 1.2 client connections, passive binary/raw STARTTLS upgrades, and nested upgrades over an owned `SSL.Socket`. Connect succeeds only after peer signature and Finished validation. |
| `SSL.send/2` | Valid iodata of any logical size supported by available caller memory. Data is traversed without flattening the entire write and protected in records of at most 16,384 plaintext bytes. One logical write is admitted at a time; another caller receives `{:error, :busy}`. There is no automatic replay. An unfinished admitted send is settled promptly as `{:error, :closed}` after an authenticated peer closure makes further writes impossible; a send already acknowledged in full remains `:ok`. |
| `SSL.recv/2,3` | Passive raw binary receive. Length zero returns available plaintext; a positive length waits for exactly that many bytes. One passive receive is admitted, and the maximum requested/buffered plaintext is 1 MiB. |
| `SSL.setopts/2` | Validates the whole request for `active: false` or `:once`, send timeouts and the mutable TCP allowlist below. Invalid options reject before changes. Driver failures can partially apply TCP options; TLS state changes only after driver success. |
| `SSL.controlling_process/2` | Transfers the application owner and monitor. The connection process remains the TCP owner and sole owner of TLS state. Only the current application owner may transfer. |
| `SSL.negotiated_protocol/1` | Returns authenticated ALPN as `{:ok, binary}` or `{:error, :protocol_not_negotiated}`. |
| `SSL.connection_information/1,2` | Only `:protocol`, `:selected_cipher_suite`, and `:session_resumption`; explicit ordered key lists reject unknown/duplicate keys. No secret-bearing OTP keys. |
| `SSL.peercert/1` | Leaf DER from the completed peer handshake, including cached DER on resumption. Chain trust/identity is revalidated only in `verify_peer`; `verify_none` does not make a certificate trust claim. |
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
- `verify: :verify_peer | :verify_none` (default `:verify_peer`);
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
- `ex_ssl: [profile: :default | %SSL.ClientHello.WireProfile{}, reference_identity: {:ip, address} | {:dns_id, name}]` (either key may be supplied).

`honor_cipher_order` is a server-only option. This client returns
`{:error, {:option, :server_only, :honor_cipher_order}}` for any explicit value
except `:undefined`, which behaves as omission. Validation occurs before trust
loading or connection allocation. TLS12/TLS13 and mixed-offer reference runs
observe the error for both booleans; other values and `:undefined` follow the
installed OTP29 public option validation source and focused regression checks.

Explicit TCP `verify_none` skips certificate path/trust, validity and hostname
verification. It still bounds and decodes the peer certificate chain, extracts the
leaf public key with its key parameters, and requires valid CertificateVerify (TLS
1.3) or signed ECDHE ServerKeyExchange (TLS 1.2), Finished and record AEAD. A
successful handshake under this option does not establish the peer's identity or
certificate trust. `SSL.QUIC` rejects the `verify` option and always requires its
existing trust and identity checks.

With explicit `verify_none`, omitted CA options do not load system trust. Empty
`cacerts`, unused malformed CA entries and readable non-PEM CA files are admitted,
as in the executed OTP 29 references. An explicit unreadable CA file still fails;
`cacerts` retains precedence over `cacertfile`. Unsupported verification callbacks
remain explicit option errors. Supplied reference/SNI values retain their shape
validation even when hostname verification is disabled.

Packet modes, list mode, active true/active-N, arbitrary TCP
options outside the allowlist and `send_timeout_close: false` remain
unsupported. Unsupported or malformed options return a redacted
`{:error, {:options, reason}}`; supplied option data is not echoed.

An explicit `ex_ssl.reference_identity` selects certificate verification independently
of the TCP destination and `server_name_indication`. IP addresses accept valid IPv4/IPv6
tuples or address strings; DNS identities accept ASCII DNS names up to 253 bytes with
labels up to 63 bytes. Malformed, duplicate or unknown custom options fail before TLS
I/O. The explicit identity does not generate SNI: a supplied DNS SNI is preserved;
otherwise direct DNS dialing retains its inferred SNI, and IP dialing or socket
upgrade omits it. `server_name_indication: :disable` suppresses SNI while retaining
verification of the explicit identity. Without the custom option, the existing
reference-from-SNI or inferred-host behavior remains. Both reference identity and
SNI participate in the resumption cache partition.

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
parameters. With `verify_peer`, trust-anchor and self-signed signatures are
exempt, but normal PKIX trust/path/identity validation still runs. Explicit
`verify_none` skips this validated-chain policy as in the executed OTP 29
reference: a valid forced fallback chain outside `signature_algs_cert` completed
only in none mode. The advertised wire policy is preserved. This follows the
fallback-chain allowance in [RFC 9846 §4.5.1.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.5.1.2);
CertificateVerify still must use an offered scheme and a compatible leaf key.
Both modes require the leaf's `digitalSignature` usage when KeyUsage is present.
TLS 1.3 also requires X.509v3 for every presented Certificate entry, including a
transmitted root and cached peer chains. This check does not reject a locally
configured v1 trust anchor omitted from the wire. TLS 1.2 keeps its existing
certificate-version behavior; an independent OTP/OpenSSL v1 none-mode exchange is
covered by the compatibility test. A certificate failing the signing/v3 checks
requires a corrected or reissued signing-capable v3 credential. A locally trusted
v1 root can instead be omitted from the presented chain.
RSA PKCS1 SHA256/384/512 is supported for certificate signatures and TLS1.2
ServerKeyExchange/client CertificateVerify, with the required runtime padding
primitive. It is never accepted as a TLS1.3 CertificateVerify signature or a
QUIC handshake signature. TLS1.2 eligibility uses a separate capability registry.

The default profile and trust behavior remain unchanged when no certificate
signature policy is supplied. `signature_algs` restricts version-specific handshake signatures;
use `signature_algs_cert` to impose a validated-chain restriction in `verify_peer`. This explicit-policy
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
`buffer`, `tos`, `tclass` and `priority` accept nonnegative integers and are passed
to the native driver. Actual ranges, rounding and family/platform support are
established by that driver, not silently emulated by ex_ssl. On the current
macOS/OTP29 reference, buffer values 0, 65536 and 2^31 read back as 1, 65536 and 1;
IPv4 tos and IPv6 tclass apply, while priority returns :ok but reads zero. This is
not a claim of effective packet scheduling support on that platform.
`ip` accepts a local IPv4/IPv6 address tuple and `port` accepts 0..65535. Direct
`SSL.connect` accepts one bare `:inet` or `:inet6` family flag; literal remote or
local bind addresses infer the family when absent. Conflicting families reject.
DNS references and IP SAN references remain distinct; inferred IP literals do
not send SNI. Both textual and tuple IPv6 literals are supported.

All eight listed non-binding options are mutable. A complete `SSL.setopts`
request validates before I/O. Driver errors propagate; no stronger rollback
guarantee is made for partially applied driver settings. Virtual TLS options and
buffered delivery remain usable after raw TCP shutdown. Raw dial supplies a
16640-byte driver buffer only when the caller omitted it. STARTTLS preserves the
existing raw buffer when no replacement is supplied; explicit mutable options
are applied after ownership handoff. This retains existing ExSSL behavior. The
OTP29 reference ignores TCP replacements passed to existing-socket SSL.connect;
its explicit SSL.setopts applies them afterward. Bind/family requests cannot
change an existing connection and remain rejected during upgrade.

A driver rejection that exits initial gen_tcp.connect with :badarg becomes
`{:error, :badarg}`. OTP returns the same error class inside a formatted detail
tuple; that OTP-specific charlist is not synthesized. Other failures retain their
existing mapping. Live OS errors (including wrong-family :einval on this macOS
reference) propagate without committing virtual active-mode changes.

Raw active/packet ownership controls, arbitrary socket backends and unsafe linger
are unsupported. Driver buffer tuning cannot change the TLS record, handshake or
plaintext bounds. The private binary/raw/active-once configuration remains
controlled by the connection process.

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

The owner may explicitly opt in to `SSL.enable_duplex_reads/1` on an established
open connection with a finite send timeout. This idempotent operation permits
bounded inbound processing while one application output job is pending. The
handshake, control and shutdown barriers stay intact; mandatory inbound protocol
responses on an occupied writer fail closed with `:busy`. Infinite-timeout write
admission is rejected in this mode. The pending job is immutable and retains its
original deadline, including any automatic KeyUpdate bundled with its application
record; no epoch rollback, re-encryption or retransmission occurs.

`SSL.abandon_send/1` is a separate owner-only, one-way operation. It settles an
admitted logical send as `{:error, :write_abandoned}`, drops unsent plaintext and
its caller monitor/timer, and rejects future application sends. Only the existing
bounded protected job (up to 16,384 application plaintext bytes plus TLS and
optional KeyUpdate overhead) and already-buffered TCP bytes may remain. Reads
retain their bounds and may finish before that job; `SSL.close/1` aborts remaining
uncertain output. That abort intent survives completion of the retained native
job: final close skips close_notify and uses zero linger even when both the job
and inet driver queue are empty. Abandonment rejects a pending job without a finite output timer.
HTTP/1 streamed Fetch uploads use these operations under their original request
deadline; confirmed logical upload/source death is distinct from the surviving
bounded transport job.

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
An explicitly abandoned upload, pending writer output or a nonempty inet send
queue uses zero linger so the driver cannot retain a flushing port after the
connection exits. Empty-queue shutdowns after complete, unabandoned logical sends
retain ordinary graceful transport closure.
Passive reads and active-once delivery need not wait for reciprocal shutdown
before consuming authenticated response bytes.

## STARTTLS and security boundaries

STARTTLS callers must own a connected binary/passive/raw `:gen_tcp` socket and
fully consume and validate the positive upgrade reply, including plaintext held in
their own parser. With default `verify_peer`, they must also supply a DNS reference
through `server_name_indication` or an explicit IP/DNS reference through
`ex_ssl: [reference_identity: ...]`. Explicit IP and DNS references work without
SNI and require a trusted certificate matching that reference. Explicit
`verify_none` permits an upgrade without SNI or a reference identity and makes no
trust/identity claim. Queued or delivered TCP plaintext causes explicit
failure and owned-socket closure. A non-owner's TCP socket is not closed.

Profiles affect offered wire capabilities only. They cannot replace trust or
identity verification. Record, handshake, certificate, trust-store, and passive
plaintext bounds remain independently enforced. No traffic secrets, private
keys, or application payloads are exposed through public metadata or ordinary
inspection.

### Existing TLS carriers

`SSL.connect(outer_socket, inner_options, timeout)` and `SSL.connect_prepared/3`
can establish independently authenticated inner TLS over an owned passive
`SSL.Socket`. Each layer retains its own protocol, ALPN, trust, identity, record
keys, bounded buffers and writer. The inner connection becomes the outer
application owner; later transfers of the inner socket retain that relationship.
Peer/local addresses continue to identify the underlying connection endpoint.

Unread carrier plaintext, active delivery and occupied I/O reject the upgrade.
A foreign caller receives `:not_owner` without changing or closing the carrier.
After an owned upgrade attempt, failure closes the carrier. Inner close and owner
loss retire both sessions; carrier death also terminates the inner session. Inner
record writes carry their original absolute deadline through `SSL.send/3` on the
outer layer. Enabling duplex reads on the inner socket enables them on its
carrier, subject to the existing finite send-timeout requirement for each layer.

Independent OpenSSL peers and OTP public `cb_info` reference cases cover all
four TLS1.2/TLS1.3 combinations. Lifecycle-backed upgrades also accept an owned
`SSL.Socket`: the inner `:layer` receipt accounts Setup, Connection and Writer
without allocating or adopting TCP. The outer handle retains its independent
physical-socket obligation. Each handle needs its own confirmed `await/2` result;
the inner receipt alone never establishes outer TCP cleanup. Authentication
failure phase evidence remains separate from both cleanup receipts. Prepare,
owner transfer, adoption and TLS attachment retain their original deadline.

This layer support does not yet provide a combined transfer handle or enable
HTTP HTTPS-over-HTTPS routing. Those integrations and their consumer acceptance
remain required before default promotion or production OTP SSL removal.

## Prepared upgrade configuration

The project extensions `SSL.prepare_upgrade(options)` and
`SSL.connect_prepared(tcp, prepared, timeout \\ :infinity)` separate configuration
resolution from an existing-socket upgrade. They are not OTP `:ssl` APIs.
Preparation uses the same **upgrade** option context, including rejection of bind
IP/port and address-family options. It loads the effective trust source and client
certificate/key, validates the concrete profile, reference identity, SNI, versions
and ALPN, and returns an opaque, ordinarily redacted `SSL.PreparedUpgrade` snapshot.
A profile requiring connection SNI must have it; actual SNI bytes count toward the
existing extension-vector bound. Preparation allocates no socket, TLS connection
process or ephemeral keys.

Consumption uses that resolved snapshot without rereading files or resolving a
new profile. Later source-file replacement/deletion does not change the prepared
policy; call `prepare_upgrade` again to obtain a new snapshot. Deliberate snapshot
reuse is supported. Random ClientHello/session-ID values, ephemeral key pairs,
session-ticket selection and binders remain connection-dependent. Supported
explicit fixed session-ID/profile policies retain their existing meaning.
Deferred PSK material and runtime/handshake failures remain checked at attach.
Ownership, pending-plaintext rejection, timeout and owned-socket close-on-failure
semantics match ordinary existing-socket `connect`.

ExSSL HTTP CONNECT prepares after merging `defaults < ssl < socket_opts` and
applying the origin reference/SNI, before allocating the raw proxy TCP socket.
The CONNECT deadline starts before preparation. The same snapshot is consumed
only after the proxy response and plaintext boundary are validated. Supported
one-TLS-leg routes remain HTTPS origin through an HTTP proxy and HTTP origin
through an HTTPS proxy. Nested HTTPS-proxy plus HTTPS-origin routes remain
explicitly rejected before dialing.

A configuration snapshot is not a durable connection-attempt/adoption or cleanup
receipt. It does not enable managed/completion paths, establish cancellation or
resource-cleanup guarantees, or resolve the separate proxy-origin-port ticket
partitioning gate. Those lifecycle and acceptance gates remain open.

## Remaining limitations

The experimental `SSL.QUIC` record-free TLS integration has its own
[role/transport matrix](QUIC_TLS_IMPLEMENTATION.md) and
[public interface](QUIC_TLS_INTERFACE.md). It does not broaden TCP socket support.

TCP server TLS, DTLS, QUIC networking/HTTP/3, TLS 1.3 automatic mTLS resumption,
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
PKCS#8 private keys, and PEM through binary or charlist paths. One combined
certificate/key PEM is supported when `certfile` supplies both. Separate sources
cannot conflict or hide additional private keys. Encrypted PEM accepts byte
iodata or a zero-arity `password` callback through public `:public_key` decryption.
Legacy AES/3DES and PBES2 AES with SHA1/224/256/384/512 PRFs have local positive
evidence. Default local OTP provider discovery rejects ten DES/RC2 and PBES1
formats with fixed redacted errors. An isolated process configured with the
installed legacy provider passes all336 loader/password combinations and40
independent TLS12/TLS13 host/prepared mTLS exchanges for those ten formats,
including exact client identity, authenticated HTTP and TLS12 EMS. This local
version-specific configuration does not establish default-provider or platform
compatibility.
Full encrypted-key compatibility remains unaccepted. Hardware signers remain
unsupported. Ordinary `certs_keys` selection has independent TLS1.2/TLS1.3
evidence: explicit modern sources override legacy sources, each map owns its
password, and all candidates are validated before dialing. Selection respects
local/peer signature policy, certificate types and CA hints, including later
matching candidates and bounded local chain completion. Prepared identities
retain their snapshot across file changes. Fetch, EventSource and WebSocket
have independent authenticated exchanges; public lifecycle/cleanup and complete
P3 acceptance remain pending. See `docs/tls-migration-design.md` in the umbrella
for the explicit candidate, credential-byte and issuer-search limits.
Chain order and a scheme-specific signing/verification proof bind the key to the
leaf; the peer remains responsible for client certificate trust and validity.

File-backed PEM invokes a password callback once, including plaintext PEM;
typed DER and absent identities never invoke it. Normalization retains decoded
credentials only. Callbacks are trusted synchronous code and may outlast a
connect timeout; the original absolute deadline still applies afterward.
`prepare_upgrade/1` has no callback preemption or timeout guarantee. Passwords
are bounded to 1 MiB, 2,097,153 traversal nodes and nesting depth 64. Encoded KDF
iterations are bounded to 1,000,000 and conservative aggregate work to 2,000,000
units before decryption; PBES2 OCTET salts may be empty and are at most 65,536
bytes. These finite admission limits are not unrestricted OTP parity.

Bounds: 16 certificates, 256 KiB per DER certificate, 512 KiB aggregate DER,
1 MiB per PEM file or typed DER key. The chain bound leaves room for TLS record
and handshake overhead within the existing 1 MiB writer ceiling. Errors contain
only fixed reason atoms; ordinary identity inspection exposes only scheme IDs.
CertificateRequest CA-name and OID-filter vectors each allow at most 64 entries
within the existing bounded extension envelope.
Restricted PSS private keys and leaf constraints are both checked through the
shared signature verifier. Unsupported key/parameter combinations fail explicitly.

## Advanced certificate-policy boundary (Phase 3 audit)

Peer chains may include trailing cross-signed alternatives. Path selection
considers leaf-first prefixes terminating at an explicitly supplied trust anchor
or a certificate it issued. Each candidate still passes OTP `:public_key` PKIX
validation, including signature, validity, policy and depth checks. Hostname
verification remains required; certificate-signature policy applies to the
selected path. This does not reorder arbitrary peer chains or discover new
trust anchors. Bounds and certificate decoding cover the full presented chain.

This table describes the current optional-backend subset. The complete http_fetch
migration must preserve ordinary `verify_fun` and fully implement `partial_chain`,
CRL/OCSP, encrypted private keys and multiple client identities before OTP SSL
removal (user decision, 2026-10-23). Migration acceptance remains open; partial
support or current rejection does not satisfy the migration contract.

| Policy | Candidate support |
| --- | --- |
| `cacerts` / `cacertfile` | Explicit trust sources; no silent replacement with system trust |
| `depth` | Intermediate-CA bound, independent of parser/resource limits |
| SNI / reference identity | DNS identity or IP SAN verification; explicit `ex_ssl.reference_identity` is independent of SNI and destination, including socket upgrades |
| `customize_hostname_check: [match_fun: fun]` | Supported hostname matching customization; path validation remains required |
| `verify_fun` | Ordinary TCP supports tuple fun3/native-DER fun4, legacy fun1 and `:undefined`; prepared two-attach state-reset acceptance and final regression gates remain open |
| `partial_chain` | Rejected; no user callback can introduce an intermediate trust anchor |
| `crl_check` / `crl_cache` | Rejected; no revocation freshness or retrieval guarantee is claimed |
| `stapling` | Rejected; OCSP response validation and availability policy are not implemented |
| `cert_policy_opts` / `allow_any_ca_purpose` | Rejected; no implicit acceptance of policy overrides |

These names follow the [OTP 29 public option documentation](https://www.erlang.org/docs/29/apps/ssl/ssl.html).
Each supplied unsupported policy fails before network I/O, with its value
redacted. Implementing one requires a separate trust-semantics design and
negative/availability tests.

Ordinary verification callbacks receive a fresh initial state for each candidate
path and prepared attachment. Callback overrides apply to X.509 validation;
TLS1.3 certificate-version, signing-key usage, certificate-signature policy,
CertificateVerify/ServerKeyExchange, Finished and AEAD checks remain mandatory.
Callback failures expose fixed diagnostic classes. Configured callbacks force a
full certificate handshake, including with explicit automatic tickets, and bypass
ticket partition/cache access and insertion. Managed and QUIC callback support
remains excluded. Public cancellation and cleanup acceptance remains blocked by P2.

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
RSA-PSS, RSA-PKCS1 SHA256/384/512 and P256/P384 ECDSA. SHA1 and EdDSA cipher
authentication are not offered by the TLS1.2-only generated profile. Supplied
signature order is preserved; TLS1.3-only policies reject PKCS1 handshake schemes.

Extended Master Secret and a valid initial secure-renegotiation indication are
mandatory. Missing EMS fails explicitly. The repository's observed OTP28/OTP29
TLS1.2 reference-server configurations omit extension23; their rejection is
fixture-specific evidence, not a claim about every OTP server configuration.
Positive full/mTLS interoperability uses capable independent OpenSSL peers;
the [current ledger](EX_SSL_HTTP_FETCH_PROGRESS.md) records actual runtime and
provider versions separately from configured CI. Missing capable peers fail
the mandatory gate rather than weakening EMS or skipping positive scenarios.
Static RSA, CBC, RC4, compression, TLS1.0/1.1,
renegotiation and TLS1.2 session tickets remain unsupported. Generated TLS1.2-only
hellos use an empty session ID until an authenticated cached EMS session is selected;
mixed offers retain TLS1.3 compatibility behavior. An echoed ID without matching
saved authenticated material still rejects.

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

`session_tickets: :disabled | :auto | :manual` defaults to `:disabled`. Auto is
supported only with TLS 1.3-only versions, `verify: :verify_peer`, and no configured
client certificate/key. Auto with mixed versions, TLS 1.2 or mTLS, PSK-only
exchange and `early_data` return explicit option errors.
Explicit WireProfiles must reserve `{:psk_key_exchange_modes, [1]}` and a last
`{:pre_shared_key, :deferred}` slot; other extension ordering is preserved. A
cache miss omits only the PSK slot.

Manual mode delivers `{:ssl, :session_ticket, ticket}` to the current connection
owner. The ticket is a provider-owned map; only its `sni` key is public routing
metadata. Pass an unchanged ticket in `use_ticket: [ticket]` with manual mode to
attempt reuse. Up to eight candidates of at most 256 KiB each are accepted;
malformed or oversized lists return redacted option errors. An explicitly empty
candidate list is rejected; omit `use_ticket` for an initial full handshake.
Tickets contain secrets and must remain in memory; OTP ticket maps are not
interchangeable with ExSSL maps. Manual tickets bypass the automatic cache.

Manual mode supports configured client identities, explicit `verify_none`, and
mixed TLS 1.3/1.2 offers. A TLS 1.2 peer still performs a full handshake. Each
candidate is bound to the original endpoint, verification/trust policy, identity
configuration and ordered wire profile; changed policy and expired candidates
require a full authenticated handshake on the same connection. Callback,
partial-chain and revocation policies retain their full-handshake requirement and
do not deliver or select tickets. The independent OTP 29 reference demonstrates
manual mTLS reuse and ticket delivery without consuming active-once credit. OTP
29 returns `{:error, :no_peercert}` for manual resumed connections; ExSSL retains
its documented cached-DER result and revalidates that chain before reuse.

Tickets are authenticated post-handshake messages and consume no application
active-once credit. Up to eight tickets per connection are processed; each PSK is
derived from its nonce. Retained entries are limited to 128 partitions, 4 MiB
aggregate, 256 KiB each, 16 KiB ticket bytes and seven days lifetime. Atomic
one-use checkout and a single expiry timer bound cache lifetime and concurrency.
Cache calls fail closed after 25 ms; a cache failure takes the full-handshake
path. There is no persistent state. Each `verify_peer` checkout revalidates the
saved chain against current time, reference identity, loaded CA content, depth and
certificate signature policy. Auto rejects `verify_none`; ordinary `verify_none`
remains supported with `session_tickets: :disabled` or `:manual`. Partition digests
include verification mode, the concrete endpoint, hostname, client identity, ALPN and
ordered version/cipher/group/signature/profile policies.

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


## TLS1.2 EMS session-ID reuse

Explicit `reuse_sessions: true | false | :save` and `reuse_session: session_id`
or `reuse_session: {session_id, session_data}`
require TLS1.2 in the configured offer. The raw engine retains its previous
full-handshake default (`reuse_sessions: false`); enabling reuse is explicit.
`true` selects a compatible automatic session if available and saves newly
completed sessions. `false` neither selects automatically nor caches a newly
completed session until the caller explicitly requests `:session_data`. `:save`
starts a new full handshake and saves its session without selecting automatically.
An explicit saved ID selects that session independently of automatic selection,
including with `reuse_sessions: false`. Unknown, evicted or expired IDs continue
with one full handshake. The public ID is available through
`SSL.connection_information(socket, [:session_id])`; TLS1.3 returns an empty ID
through this additive query. The existing default diagnostic key list is unchanged.
Explicit `:session_data` returns a 40-byte ExSSL-owned opaque capability for use
as `{session_id, session_data}`. It is a credential, valid only in this VM and
the original authentication partition, cache retention and absolute lifetime.
It contains no master secret and is not portable OTP serialized session data;
foreign formats fail option validation, while a well-formed forged or evicted
capability takes one full handshake. Repeated exports remain stable while the
entry exists. Successful explicit reuse with `true` makes that session eligible
for later automatic reuse without renewing its lifetime; `false`/`:save` do not
demote an existing automatic session. TLS1.3 returns empty ID/data binaries and
continues using the separate ticket API.

The separate memory-only TLS1.2 cache retains at most128 sessions, four MiB total,
256 KiB per session, and an absolute ten-minute lifetime. Resuming does not extend
that lifetime. Cached binary material is copied, secret inspection/status is
redacted, and one tokened timer removes expired material. Cache unavailability
uses a bounded miss and a full handshake. TLS1.3 ticket storage is unchanged.

Partitions include the original ordered profile, requested host/origin, actual
TCP endpoint, reference identity, SNI, trust snapshot, verification mode/depth,
hostname policy, and complete configured client identities. Current PKIX validation
runs again before offering an ID. A changed configuration authenticates afresh;
advanced CRL/OCSP/partial-chain policies and `verify_fun` always take full
certificate handshakes and bypass session lookup/saving; `:session_data` then
returns `{:error, :no_session}`. `verify_none` retains
its explicit untrusted-certificate semantics and a distinct partition. A caller's
fixed profile session ID is never replaced with a different cached ID.

Only an EMS session with the saved cipher can resume. ALPN is negotiated afresh
from the current offer, including a different selection on resumption, as required
by RFC 7301 section 3.1. The live session records the current selection without
renewing its lifetime. true/save refresh cached metadata; false does not create
or revive cache entries to refresh informational ALPN. Changes to the configured
offer retain partition isolation.
Fresh connection randoms derive fresh record keys; the server Finished authenticates the exact
abbreviated transcript before client CCS/Finished is written and the public
connection succeeds. The server may decline an offered ID and select a full
handshake on that same connection. Failure never reconnects or replays application
bytes. Ordinary mTLS reuse retains the independently observed server-side identity;
a changed client credential selects a separate full handshake.

The focused native selection passes55 checks, including independent OpenSSL
full/resumed HTTP for all four suites, exact request digests, server-observed
mTLS identity, save/false/default controls, current PKIX/context isolation,
cache limits/expiry/privacy, independently computed SHA256/SHA384 vectors,
fragmentation and negative Finished/AEAD/EMS checks. Installed OTP29.0.2 public
references accept the controls and expose32-byte IDs; explicit public opaque
`{id, session_data}` resumes against OpenSSL, including exported false/save
sessions reused with true. Subsequent automatic reuse still performs a full
handshake. The same runtime's automatic and saved-ID cache references have not
resumed, including with valid server-observed mTLS identity and the documented
public cache callback; that reference gap and integrated candidate/platform acceptance
remain open. OTP documents automatic reuse as "if possible"; a full-handshake
fallback alone does not establish an ExSSL implementation failure. This evidence
does not promote the default HTTP provider or complete
migration/release gates.

Final source regression passes20 properties/3485 tests with integration included;
Core transport/source-pin checks pass27/27, strict compile and root formatting pass.
This does not replace the remaining candidate/package/platform and release gates.
