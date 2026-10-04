# http_fetch opt-in transport integration

## Current reproducible candidate check

Run `timeout 900 bash scripts/downstream_candidate.sh` from the ex_ssl root.
It fetches the verified full-SHA consumer pin
`6a6c93e5c852e2e2bbffcc2186bef9bf34a79cac` into a temporary checkout and calls
the existing consumer smoke script from the umbrella root with explicit source
mode. It prints both revisions and verifies the loaded ex_ssl source/path/version,
then removes its temporary checkouts, overrides and builds. The same command
checks the standalone candidate package/startup boundary without publishing.
No edits to a companion checkout are required. See the
[evidence map](SECURITY_REVIEW_EVIDENCE.md) and
[current ledger](EX_SSL_HTTP_FETCH_PROGRESS.md) for executed results and gates.
Source-candidate integration does not prove a published Hex artifact contains it.

## Historical integration and release context

Release note: the Phase 1–5 capabilities below ship in ex_ssl 0.4.0. Consumers
must depend on `~> 0.4.0` to use them. References to the 0.3.0 dependency and
source-candidate gates record the historical validation boundary; they are not
the current installation requirement. OTP remains the default consumer backend.


The opt-in integration exists in `gsmlg-dev/http_fetch` PR #14 at
`690258ac38e50b0d1a968d9d5e510c560f45f5d4` (open, unmerged on 2026-09-22).
Its adapter serves HTTPS fetch, WSS, and EventSource while OTP remains the
default. The library fixture proves the transport lifecycle; consumer tests
prove real HTTP exchanges. Current execution evidence and remaining gates are
recorded in [EX_SSL_HTTP_FETCH_PROGRESS.md](EX_SSL_HTTP_FETCH_PROGRESS.md).

## Audited consumer contract

The relevant consumer entry points are:

- `apps/http_core/lib/http/transport.ex`: the transport callbacks `connect/4`,
  `controlling_process/2`, `send/2`, `setopts/2`, `close/1`, and
  `normalize_message/2`;
- `apps/http_core/lib/http/transport/ssl.ex`: OTP implementation, trust defaults,
  depth, active message normalization, and ALPN lookup;
- `apps/http_fetch/lib/http/socket_client.ex`: `connect_in_worker/7`,
  `transfer_connected_socket/5`, task-based `send_request/4`,
  `activate_socket/2`, and protocol selection;
- `apps/http_fetch/lib/http/fetch_options.ex`: public transport option
  conversion;
- `apps/http_web_socket/lib/http/web_socket/connection.ex`: passive HTTP Upgrade
  receive followed by active-once WebSocket delivery.

`HTTP.SocketClient` connects in a short-lived worker with `active: false`, sends
the socket handle to the long-lived request process, waits for authorization,
calls `controlling_process/2`, and exits. Separate supervised tasks call
`send/2`. The request process selects a protocol from authenticated ALPN and
repeatedly calls `setopts(active: :once)` while processing response bytes.

The fixture in `test/ssl/http_fetch_transport_contract_test.exs` reproduces
that ownership/send/ALPN/active-once/abort pattern against a generated local OTP
TLS peer. It is transport-contract evidence only.

## ex_ssl adapter rules

An opt-in adapter may call these implemented functions directly:

```elixir
SSL.connect(host, port, tls_options, connect_timeout)
SSL.controlling_process(socket, owner)
SSL.send(socket, iodata)
SSL.setopts(socket, active: :once)
SSL.negotiated_protocol(socket)
SSL.recv(socket, length, timeout)
SSL.close(socket)
```

It must normalize active messages exactly as the OTP adapter does:

```elixir
{:ssl, socket, data}          -> {:data, data}
{:ssl_closed, socket}         -> :closed
{:ssl_error, socket, reason}  -> {:error, reason}
```

Map `{:error, :protocol_not_negotiated}` to the consumer's `nil` ALPN result.
Keep protocol choice in http_fetch: `h2` selects HTTP/2; an absent or
`http/1.1` selection follows the requested HTTP mode. ex_ssl does not implement
HTTP framing.

Keep `versions: [:"tlsv1.3"]` as the ex_ssl adapter default. The source candidate
also accepts caller-selected TLS1.2-only or mixed lists under its mandatory EMS
policy; the released0.3.0 dependency still rejects them. Preserve `depth: 4`, peer
verification, CA overrides, SNI, and hostname checking.

The consumer currently places `send_timeout` and `send_timeout_close` in its
transport `socket_opts`. The ex_ssl adapter must translate the supported values
to ex_ssl's top-level connection options; it must reject remaining arbitrary TCP
options instead of dropping them. `send_timeout_close` must be `true`.

For custom profiles, apply the ALPN precedence rules in
[COMPATIBILITY.md](COMPATIBILITY.md). In particular, an explicit profile and
top-level HTTP ALPN list must match exactly, including order.

## Ownership, deadlines, and backpressure

Transfer ownership while still passive, before the connect worker exits. Do not
attempt to migrate active messages already delivered to the worker mailbox.
After `:ok`, worker exit is safe and new-owner death closes the connection.

One logical send is admitted at a time. A competing send returns `:busy`; the
adapter should treat that as a request failure, close, and never replay an
uncertain body. The logical send deadline is captured when admission begins.
Consumer request deadline/abort handling must still call `SSL.close/1`; this
interrupts blocked or infinite-timeout writes and cleans up the helper.

Application-passive mode does not disable internal TLS processing. Plaintext is
bounded to 1 MiB and raw reads pause near that boundary. Repeated active-once
delivery drains the buffer and resumes progress, permitting responses larger
than the bound without increasing it.

Internally, received TCP data and EOF/error events are held in arrival order in
a bounded FIFO whenever an output record is pending. After each bounded writer
completion, ex_ssl drains older input and safely rearms raw TCP before producing
the next application record. A several-MiB request therefore does not starve
response bytes or peer-requested KeyUpdate traffic, while a control response
still cannot overtake already-protected application ciphertext. Consumer calls
must not use repeated `setopts/2` as a polling mechanism for TLS progress.

All TLS output paths share the same connection-owned asynchronous writer.
Handshake deadlines include ClientHello/retry/client-Finished transport output;
logical send deadlines are not restarted by interleaved input or control
traffic. If an output is blocked and its result is uncertain, abort closes the
transport without replay rather than attempting to append close_notify behind
it.

An authenticated peer close that makes further application writes impossible
settles an unfinished admitted `SSL.send/2` promptly as `{:error, :closed}`.
This outbound settlement is independent of preserved inbound plaintext
drainage: a passive consumer may await the send result without calling `recv`,
then consume the response exactly once, followed by `{:error, :closed}`; an
active-once consumer receives buffered data before its terminal closure event.
The connection cancels the send timer, releases admission, demonitors the
sender, and discards the cursor and retained write state for that operation, so
an infinite or long send timeout does not delay the closure result and stale
completion messages cannot reply twice. A logical send already fully acknowledged
by the transport remains `:ok`; uncertain or partial bytes are not retried or
replayed. Abrupt transport failure keeps its existing error classification rather
than being converted to authenticated closure. Once authenticated closure is
accepted, failure of the reciprocal close-notify writer does not discard the
buffered response or reclassify the terminal state.

The consumer may drain that response immediately, even while reciprocal
close-notify output is pending. The connection retains its existing bounded
shutdown deadline after the last byte is delivered; it does not enter a blocking
TCP flush in its termination callback. A concurrent or subsequent `SSL.close/1`
can abort remaining output, including with `send_timeout: :infinity`. This
teardown rule applies to both passive receive and active-once delivery.

The existing Manifold passive direct-TLS and STARTTLS subset remains supported.
This work does not weaken its verification, plaintext-boundary, close, or
receive-timeout behavior.

## Implemented consumer integration

PR #14 implements explicit backend selection, TLS-1.3-specific ex_ssl options,
transport-neutral ALPN and passive WebSocket receive, socket ownership handoff,
and adapter error propagation. It preserves backend selection through redirects
and EventSource reconnects. HTTP/3 and WebTransport retain the QUIC path and
reject an explicit TCP TLS backend.

The existing HTTP/2 close fix permits drainage only after an ex_ssl optional
control write returns `:closed`. Response completion still requires END_STREAM
and complete header blocks. A completed early response stops unsent upload DATA;
an unfinished upload alone does not invalidate the response. Truncation, actual
required-write failures, other transport errors, cancellation, and the original
operation deadline remain errors. No request bytes are replayed.

The Phase 0 continuation adds HTTP/2 Content-Length validation, bounded
frame/header accumulation, and exact-once completion checks. Its core and real
TLS regressions are recorded in the progress ledger alongside the preserved
closure/early-response evidence.

## Consumer acceptance checklist

Keep OTP as default while running both backends through the same scenarios.

HTTP/1.1:

- verified request with absent ALPN and with `http/1.1` selected;
- fixed-length, chunked, close-delimited, streaming, and several-MiB bodies;
- connect-worker transfer, task send, active-once response rearming;
- hostname/CA/depth failures, TLS 1.2-only peer, timeout, abort, and cleanup;
- WebSocket passive Upgrade receive followed by active-once frames.

HTTP/2:

- a real request/response with `h2` negotiated, not only an ALPN assertion;
- SETTINGS, flow-control, multiplexing, response streaming, and large-body
  behavior through the existing HTTP/2 implementation;
- cancellation and connection teardown with no replay or leaked task/socket.

Consumer tests establish the tested HTTP integration subset. The ex_ssl
fixture separately establishes the transport lifecycle contract. Neither suite
establishes full OTP parity, release readiness, or all server/runtime combinations.

## Candidate algorithm validation

The Phase 1 source candidate adds P-384 ECDHE/ECDSA, Ed25519, and
RSA-PSS-PSS SHA-256/384/512. These changes are not in the published 0.3.0
dependency. The consumer's `scripts/ex_ssl_source_smoke.sh` builds fresh HTTP
package artifacts and uses an explicit `EX_SSL_SOURCE_DIR` override only in a
temporary consumer project. It tests every new signature over HTTP/1.1 with
P-384 HRR and HTTP/2 with a direct P-384 share, plus hostname rejection. The
separate `external_consumer_smoke.sh` validates released dependency metadata
without that override. No installed dependency sources are modified.


## Candidate client authentication

The Phase 2 source candidate supports one initial-handshake client identity.
These options use the existing HTTP transport's `ssl:` path:

```elixir
HTTP.fetch("https://service.example/resource",
  tls_backend: :ex_ssl,
  ssl: [
    cacertfile: "/etc/service/server-ca.pem",
    certfile: "/etc/service/client-chain.pem",
    keyfile: "/etc/service/client-key.pem"
  ]
)
```

Client identity and server trust remain separate. The key must match the leaf
certificate; files must be unencrypted. Peer acceptance is observed through the
HTTP result, because TLS 1.3 permits a client-identity rejection after the local
client Finished write. No retry, backend fallback or weakened verification is
performed. See the compatibility matrix for input forms, chain bounds and
CertificateRequest selection constraints. For automatic ex_ssl redirects, a
configured identity remains within its original scheme, case-insensitive hostname
and effective port. A change returns `:client_identity_cross_origin_redirect`
before connecting. `redirect: :manual` followed by a new, deliberate request
permits broader reuse. OTP redirect behavior is unchanged.

The P2.3 source gate verifies RSA/EC/large-certificate mTLS over HTTP/1.1 and
HTTP/2, required/optional failures, same-origin/manual redirects, and WSS and
EventSource reconnects with exact peer-observed client identities. The released
0.3.0 dependency does not contain this feature. Source-candidate validation is
separate from released-dependency packaging evidence.

## Source candidate option gate (Phase 3)

The source candidate supports ordered suite/group/handshake-signature and
certificate-signature policies plus safe TCP nodelay/keepalive/sndbuf/recbuf/local
ip/port. The consumer adapter forwards only the tested allowlist; keyword
containers and duplicate keys fail before fetch modifies ALPN or deadlines.
IPv6 literals infer family and IPv6 local binds select IPv6 DNS. Raw active/packet
controls and unsafe linger remain private/unsupported. The released0.3.0 package
has not gained these features. See COMPATIBILITY.md for exact forms and limits.

## Source candidate dual-version and resumption gates (Phases 4–5)

The source candidate supports explicit TLS 1.2-only and mixed offers through the
same shared adapter, retaining TLS 1.3-only as the library default and OTP as the
consumer default. Independent OpenSSL package tests cover required mTLS HTTP/1.1,
HTTP/2 ALPN with a 262,144-byte response crossing both flow-control windows, WSS
and pinned EventSource reconnects. A capable mixed-version peer selects TLS 1.3.
The safe TLS 1.2 subset requires EMS and secure-renegotiation indication; see the
compatibility matrix for its four ECDHE AES-GCM suites and exclusions.

`ssl: [versions: [:"tlsv1.3"], session_tickets: :auto]` enables the optional bounded
TLS 1.3 cache without client credentials. Two fresh packaged HTTP/1.1 fetches
prove actual OpenSSL session reuse. It does not change request retry semantics,
backend selection, credentials across redirects, or the QUIC path. The published
0.3.0 dependency remains separate from these unreleased source-candidate features.
