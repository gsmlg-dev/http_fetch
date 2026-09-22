# TCP TLS consumer contract

Audited against PR #14 baseline `690258ac38e50b0d1a968d9d5e510c560f45f5d4`
and released ex_ssl 0.4.0 on 2026-09-22. OTP `:ssl` stays the default; ex_ssl
is explicitly selected. This inventory does not claim full OTP compatibility.

| Requirement | Status | Production boundary | Executable coverage |
| --- | --- | --- | --- |
| Connect, ownership, send, passive recv, active-once, ALPN, close | implemented | `http_core` transport behaviour and SSL/ExSSL adapters | `apps/http_core/test/http/tls_transport_test.exs` |
| Shared default and explicit per-call backend | implemented | `HTTP.TLSBackend`, fetch/WSS/EventSource option normalization | `apps/http_core/test/http/tls_backend_test.exs` and each client's option tests |
| Verified HTTP/1.1 fixed/chunked/close-delimited responses, large uploads, cancellation/deadline | implemented | `HTTP.SocketClient` | `apps/http_fetch/test/http/ssl_transport_test.exs` |
| Verified ALPN HTTP/2, streaming/flow control, early response with pending upload | implemented | shared HTTP/2 parser and socket owner | `apps/http_core/test/http/http2_test.exs`, `apps/http_fetch/test/http/socket_client_http2_test.exs` |
| Authenticated close during optional control writes | implemented | ex_ssl-only `:closed` classification, existing receive loop and deadline | deterministic cross-record tests in `socket_client_http2_test.exs` |
| HTTP/2 Content-Length completion and input bounds | implemented in this continuation | counted unpadded DATA, u64 decimal length, 16 KiB frames, 64 KiB compressed header blocks | core HTTP/2 and limits tests; real TLS cross-record buffered/streamed mismatch regressions |
| Redirect backend pinning | implemented | backend resolved before redirect lifecycle | `ssl_transport_test.exs` |
| Passive WSS Upgrade followed by active-once frames | implemented | `HTTP.WebSocket.Connection`, shared transport recv | `apps/http_web_socket/test/http/web_socket_test.exs`, `web_socket_tls_lifecycle_test.exs` |
| EventSource reconnect with pinned backend | implemented | `HTTP.EventSource.Connection` | `apps/http_event_source/test/http/event_source_test.exs` |
| Wrong CA/reference hostname and profile/ALPN conflicts | implemented | adapter forwards to verified ex_ssl options | `tls_transport_test.exs` (adapter-level evidence) |
| No automatic backend fallback | implemented | fixed adapter, explicit option/handshake errors | `tls_backend_test.exs`, TLS-1.2-only peer negative in `tls_transport_test.exs` |
| `socket_opts: [send_timeout: ..., send_timeout_close: true]` | implemented | ExSSL translates these two options; socket values override matching `ssl` values | `tls_transport_test.exs` |
| Safe TCP options, client certificates, TLS 1.2/mixed versions, ordered TLS policy | implemented in ex_ssl 0.4.0 | allowlisted adapter options and independent ex_ssl engine | packaged-source 47-test gate, published-dependency smoke, and scoped transport tests |
| Arbitrary TCP options, verify-none, early data, TLS 1.2 resumption | unsupported | explicit option/protocol errors | negative option and authentication tests |
| Introspection beyond negotiated ALPN, active-N, packet modes | not required by audited consumer | no production callsites | library roadmap; not a Phase 0 blocker |
| HTTP/3 and WebTransport | separate QUIC implementation | explicit TCP backend rejected; shared default ignored | fetch SSL transport tests and WebTransport option/TLS config tests |

Only `HTTP.Transport.SSL` calls OTP `:ssl` in production. TLS listen, accept,
handshake, and peer traffic in test support are reference-server operations.
QUIC calls in HTTP/3/WebTransport are outside this TCP TLS contract.

Public `ssl:` and `socket_opts:` containers remain backend-specific. The OTP
adapter preserves its existing option behavior. The ex_ssl adapter validates
keyword shape and duplicates and rejects unsupported socket options. No option
is dropped to make a connection succeed.

The cross-record fixture suspends the HTTP owner after it enters its receive
loop, proves its sole first plaintext delivery, releases later peer output, and
checks authenticated closure with retained plaintext before resuming. Its private
ex_ssl state probe is test-only, guarded to version 0.4.0, and checks exact byte
count plus passive mode. Larger streaming responses drain incrementally through
flow control before the final gated records; they do not require an oversized
passive TLS buffer.

Current validation is tracked in the ex_ssl repository's
`docs/EX_SSL_HTTP_FETCH_PROGRESS.md`. Historical PR validation remains in
[pr-14-validation.md](pr-14-validation.md). Commands must run from the umbrella
root. Adapter-level security tests do not establish per-client-family coverage
of every invalid option, and local OTP peers do not prove every server or runtime.

## Phase 1: algorithms in ex_ssl 0.4.0

ex_ssl 0.4.0 adds P-384 ECDHE/ECDSA, Ed25519 and RSA-PSS-PSS SHA-256/384/512.
The source smoke below records the pre-release cross-repository validation;
the current consumer dependency resolves the published 0.4.0 package.

Run `EX_SSL_SOURCE_DIR=/absolute/path/to/ex_ssl bash scripts/ex_ssl_source_smoke.sh`
from the umbrella root. This builds all five fresh package artifacts into a
temporary consumer and explicitly overrides ex_ssl there; repository manifests,
lockfiles and installed sources are unchanged. It is separate from the existing
five-package released-dependency smoke, which has no ex_ssl override.
Set `EX_SSL_DEP_MODE=published` with the same fixture source directory to run
the 47-test feature gate against the Hex release rather than the source override.

Seed 36 on OTP 28 / Elixir 1.18.5: 12 tests, zero failures (ten positive exchanges
cover each new signature over HTTP/1.1+P-384 HRR and HTTP/2+direct P-384; five
hostname-negative scenarios in one test; one OTP-default assertion). Both
transport modes retain peer verification. New fixture setup initially omitted
`http_version: :http2`, so five HTTP/2 cases failed; the corrected fixture sets
both HTTP mode and exact profile ALPN and waits for the SETTINGS acknowledgement.
No production workaround was added. Log: `/tmp/http-fetch-tls-plan-algorithms.log`.


## Phase 2: client identity in ex_ssl 0.4.0

ex_ssl 0.4.0 supports one bounded initial-handshake client identity
through `ssl: [certfile: ..., keyfile: ...]` or the documented in-memory forms.
It remains separate from the server's `cacerts`/`cacertfile` trust. Encrypted keys,
hardware signing and multiple identities remain unsupported. The library's
compatibility matrix documents CertificateRequest selection limits.

For `:ex_ssl` with any configured `cert`, `certfile`, `key` or `keyfile`, an
automatic redirect that changes scheme, case-insensitive hostname or effective
port returns `{:error, :client_identity_cross_origin_redirect}` before opening
the next connection. Same-origin redirects retain the identity. Use
`redirect: :manual` and issue a separate, deliberate request if another origin
is authorized to receive those credentials. OTP backend behavior is unchanged.
This policy also rejects a downgrade to plain HTTP. HTTP/3/WebTransport remain
on QUIC and do not use these credentials.

The source smoke includes required RSA/EC/large-chain HTTP/1.1 and HTTP/2
requests, exact server-observed client DER, optional auth, missing/wrong-CA/
expired/wrong-purpose/incompatible credentials, pre-I/O key mismatch and bad
server hostname. WSS verifies passive Upgrade, active-once frames and close;
EventSource verifies the identity across same-origin reconnects. Redirect tests
cover all three origin components, DNS casing, manual reuse and unchanged OTP.
These tests were first run against source and are now rerun against the published
0.4.0 dependency without modifying installed dependency sources.

## Phase 3: options in ex_ssl 0.4.0

The adapter forwards the safe TCP allowlist: `nodelay`, `keepalive`, `sndbuf`,
`recbuf`, local `ip`/`port`, plus the existing send deadline options. ex_ssl 0.4.0
validates values and supports mutable driver options. Keyword containers and duplicate
keys reject before fetch adds deadlines or ALPN, including improper lists.
Raw active/packet controls, linger and arbitrary socket backends remain rejected.

ex_ssl 0.4.0 accepts ordered TLS 1.3 `ciphers`, `signature_algs`,
`signature_algs_cert` and `supported_groups` through `ssl`. Generated profiles
preserve order; explicit profile conflicts fail before I/O. The certificate
signature policy is separate from handshake CertificateVerify. No supplied
`signature_algs_cert` preserves the earlier chain policy. See the library matrix
for supported names/maps and deliberate differences from OTP.

`scripts/ex_ssl_options_test.exs` exercises real packaged HTTP policy and TCP
selection, IPv6 local binding/DNS, raw option precedence/mutation, authentication
failures and pre-I/O rejection of malformed/unsafe/conflicting options. The same
shared adapter serves WSS and SSE. No TLS1.2 or default change is introduced here.

## Phase 4: TLS 1.2 in ex_ssl 0.4.0

ex_ssl 0.4.0 adds verified TLS 1.2 ECDHE AES-GCM to the shared adapter. The
independent OpenSSL packaged gate covers HTTP/1.1 and HTTP/2
with both TLS 1.2-only and mixed offers, mixed-offer TLS 1.3 selection, WSS
Upgrade/frame/close, and EventSource reconnect with pinned backend and
Last-Event-ID. All seven scenarios pass in the final 47-test source gate.
The expanded HTTP/2 fixture sends 262,144 bytes, honors connection/stream
flow control, and requires observed WINDOW_UPDATE frames; its seven-test gate
also passes. TLS 1.2 session resumption and full OTP option parity are not claimed.

## Phase 5: opt-in TLS 1.3 resumption in ex_ssl 0.4.0

`ssl: [versions: [:"tlsv1.3"], session_tickets: :auto]` enables bounded TLS 1.3
ticket reuse for a fresh connection to the same authenticated context. The
default is `:disabled`; auto rejects TLS 1.2/mixed offers and configured client
identity. Early data, persistent tickets, PSK-only key exchange, and automatic
reconnect/replay are unsupported. An unaccepted ticket follows normal full
handshake processing on the same socket.

`scripts/ex_ssl_resumption_test.exs` uses two packaged HTTP/1.1 fetches against
one Python/OpenSSL context and checks the peer's `session_reused` value is false
then true. Cache policy isolation and measured performance are
recorded in the library readiness report. This consumer check proves only the
HTTP/1.1 adapter path; HTTP/2/WSS/SSE resumption is not separately verified.

## Published 0.4.0 validation (2026-09-22)

The umbrella lock resolves Hex ex_ssl 0.4.0. The test-only cross-record buffer
probe was revalidated against its `closed`, `size`, and `active` fields and its
version guard advanced from 0.3.0 to 0.4.0. `MIX_ENV=test mix test
apps/http_fetch/test/http/socket_client_http2_test.exs --only cross_record`
passed 11 tests with 23 excluded. The full `MIX_ENV=test mix test` passed 185
`http_core`, 176 `http_fetch` plus 20 doctests, 33 WebSocket, 24 WebTransport,
and 26 EventSource tests, all with zero failures. `MIX_ENV=test mix compile
--warnings-as-errors`, `mix format --check-formatted`, `mix credo` (116 files,
no issues), and `mix dialyzer` (four existing ignored warnings, zero unnecessary
skips) passed.

The fresh five-package `bash scripts/external_consumer_smoke.sh` passed with a
transitive Hex ex_ssl 0.4.0 dependency and no source override. The broader
`EX_SSL_DEP_MODE=published EX_SSL_SOURCE_DIR=/absolute/path/to/ex_ssl bash
scripts/ex_ssl_source_smoke.sh` resolved ex_ssl from Hex and passed 47 tests;
the source directory supplies only test fixture builders in that mode. Neither
smoke modifies installed dependency sources. On the first published run, the
unit suite had two failures from obsolete 0.3.0 negative expectations for
TLS 1.2 and `nodelay: true`; the first external smoke failed its obsolete
`~> 0.3.0` metadata assertion. Those assertions were updated to test supported
and still-rejected values before the passing reruns. An earlier source-mode
47-test run had one intermittent large HTTP/2 `:econnreset`; the independent
test peer now holds its close until the client reads the complete response.
The final source-mode and published-mode 47-test runs each had zero failures.
