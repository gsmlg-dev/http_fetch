# TCP TLS consumer contract

Audited against PR #14 head `690258ac38e50b0d1a968d9d5e510c560f45f5d4`
on 2026-09-22. OTP `:ssl` stays the default; ex_ssl is explicitly selected.
This inventory separates implemented consumer requirements from planned library
features. It does not claim full OTP compatibility.

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
| Arbitrary TCP options, verify-none, client certificates, TLS 1.2/mixed versions | deliberately unsupported in ex_ssl 0.3.0 | explicit redacted option errors | `tls_transport_test.exs` |
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
ex_ssl state probe is test-only, guarded to version 0.3.0, and checks exact byte
count plus passive mode. Larger streaming responses drain incrementally through
flow control before the final gated records; they do not require an oversized
passive TLS buffer.

Current validation is tracked in the ex_ssl worktree's
`docs/EX_SSL_HTTP_FETCH_PROGRESS.md`. Historical PR validation remains in
[pr-14-validation.md](pr-14-validation.md). Commands must run from the umbrella
root. Adapter-level security tests do not establish per-client-family coverage
of every invalid option, and local OTP peers do not prove every server or runtime.
