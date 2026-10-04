# ADR: opt-in TLS1.3 resumption and bounded diagnostics

Date: 2026-09-22. Status: accepted for implementation; no completed resumption
claim until independent peer and policy-isolation gates pass. Plan Phase5 may
proceed independently of the remaining Phase4 consumer gate.

## Public and authentication boundary

Implement OTP `session_tickets: :disabled | :auto`, disabled by default. Manual
export/import, early data, PSK-only exchange and persistence remain explicit option
errors. Initially require TLS1.3-only versions and no configured client identity
for auto; TLS1.2/mixed and mTLS resumption reject until their identity semantics
are separately proven. Every connection still uses a fresh ECDHE key share.

A server accepting PSK authenticates through the binder/Finished schedule. Bind
selected identity zero and selected suite hash to the offered ticket. The resumed
flight is EncryptedExtensions then Finished: no permissive bypass of the full
certificate/CertificateVerify flight. Declining PSK continues full authentication
on the same socket; no reconnect, fallback or replay of application bytes.
Derive the resumption master only after the transcript through client Finished.
Parse authenticated, bounded NewSessionTicket messages and derive a distinct PSK
from each nonce. 0-RTT is never offered. Explicit profiles reserve mode1 and a
last deferred PSK slot; dynamic materialization preserves all other ordering.
HelloRetryRequest recomputes the binder over exact message_hash(CH1), HRR and
truncated CH2. Incompatible HRR hash removes that PSK and continues full handshake.

## Cache and security-policy partition

Use one bounded supervised in-memory cache with atomic one-use checkout, at most
128 partitions and4MiB retained entry data, finite ticket lifetime/expiry, and
one cleanup timer. Retain no files or external secrets. A partition digest covers
endpoint host+port (or concrete STARTTLS peer), certificate reference identity,
ALPN offer, profile/version/suite/group/signature policies, loaded trust material,
depth, hostname customization function identity, and an implementation policy
schema version. Loaded PEM bytes and current system CA material are included,
not merely file paths. A changed trust/policy context cannot reuse an old entry.
Client identity is excluded by rejecting auto with credentials.

Retain the authenticated peer chain with a ticket and revalidate it using current
PKIX, time, reference identity and certificate-signature policy before offering
PSK. Bound entry bytes separately; oversized chains/tickets simply cannot be
cached. Bind resumed ALPN to the stored selection and compatible offered context.
Expired/rejected tickets cannot bypass verification. Cache misses/failures use the
normal full handshake; uncertainty in TLS/application writes never triggers retry.
All ticket/PSK/resumption-secret state is excluded from Inspect and diagnostics.

## Diagnostics and evidence

Only non-secret protocol, selected cipher suite, ALPN and resumption status are
eligible for connection_information. peercert returns authenticated server leaf
DER; peername/sockname report the live underlying addresses. Unsupported keys
fail explicitly. No traffic secrets, session ticket bytes or private identity
fields are exposed. Closed-socket behavior is documented and compared with OTP.

Required gates: deterministic binders including HRR, malformed/expired tickets,
cache bounds/isolation/concurrency, trust/identity/ALPN/policy changes, actual
independent-peer resumption and server-decline/restart full continuation, HTTP
exchanges and cleanup. Measure full/resumed handshake and transfer costs against
OTP under identical peers/configuration; no unmeasured performance claims.
Normative TLS1.3 source: RFC9846 sections4.2.11,4.4,4.7.1 and7. Public option
reference: https://www.erlang.org/docs/29/apps/ssl/ssl.html#client_option_tls13/0.
