# Internal QUIC consumer mapping

This is a mapping to frozen upstream interfaces, not another QUIC protocol
specification. This adapter does not implement HTTP/3, QPACK or WebTransport.

## Authority and source combination

- ex_quic G-T: [`5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb`](https://github.com/gsmlg-dev/ex_quic/tree/5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb),
  [consumer contract](https://github.com/gsmlg-dev/ex_quic/blob/5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb/docs/consumer-contract.md),
  [I/O contract](https://github.com/gsmlg-dev/ex_quic/blob/5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb/docs/io-contract.md),
  [acceptance](https://github.com/gsmlg-dev/ex_quic/blob/5f1b8a13b6be8cd38db0fc62b8490b3f1fc3f8bb/docs/phase1-acceptance.md).
- ex_ssl G-S: [`f1327e0bb7fb2093b8dc2b07e72b26233a739963`](https://github.com/gsmlg-dev/ex_ssl/tree/f1327e0bb7fb2093b8dc2b07e72b26233a739963),
  [TLS interface](https://github.com/gsmlg-dev/ex_ssl/blob/f1327e0bb7fb2093b8dc2b07e72b26233a739963/docs/QUIC_TLS_INTERFACE.md),
  [acceptance](https://github.com/gsmlg-dev/ex_ssl/blob/f1327e0bb7fb2093b8dc2b07e72b26233a739963/docs/phase1-acceptance.md).
- Optional joint fixture only: Abyss G-A
  [`50e121fce66daeb9cb25a2f5dc93050ca37efc5d`](https://github.com/gsmlg-dev/abyss/tree/50e121fce66daeb9cb25a2f5dc93050ca37efc5d),
  [public service](https://github.com/gsmlg-dev/abyss/blob/50e121fce66daeb9cb25a2f5dc93050ca37efc5d/docs/quic-service.md).
  Abyss is not a production dependency.

Both direct http_core and transitive ex_quic declarations use the exact same
ex_ssl Git URL and SHA. No override hides a conflicting requirement. The pinned
ex_ssl project version is 0.7.1; the source SHA, rather than that version string,
identifies G-S. The ex_quic pin identifies v0.2.1. These source dependencies are
not a claim that a new http_core Hex package can be published unchanged.

## Adapter mapping

`HTTP.QUIC.ExQuic` is internal (`@moduledoc false`). Its normal driver is `QUIC`;
the final optional driver argument is a strict contract-test seam. No production
HTTP route selects it. Neither existing `HTTP.Transport` (one TCP/TLS socket)
nor `HTTP.WebTransport.Transport` (HTTP/3 application sessions and datagrams)
represents this raw stream interface correctly.

| Consumer call | Frozen upstream operation / local responsibility |
| --- | --- |
| `client(host, tls, endpoint_options)` | Normalize credentials/options, then `QUIC.client(tls: normalized, ...)`; default owner remains the calling process |
| `local(endpoint)` | `QUIC.local/1` |
| `connect(endpoint, remote, options)` | `QUIC.connect/3`; remote is an IP/port, DNS resolution is the caller's responsibility |
| `attach`, `ready`, `info` | Same public upstream operations; readiness remains distinct from HTTP/session success |
| `open_stream` | `QUIC.open_stream/3`, bidi or uni; retains opaque handles unchanged |
| `send_stream` | `QUIC.send_stream/4`; binary, at most 16 KiB; returns admission reference, never a delivery receipt |
| `read` | `QUIC.read/3`; explicit positive limit at most 16 KiB |
| `events` | `QUIC.events/3`; positive limit at most 128, default 32 |
| `reset_stream`, `stop_stream` | Same public operations; one send/receive half, not the connection |
| `close` | `QUIC.close/4`; preserves application code, opaque reason and terminal errors |
| `operation_status` | `QUIC.operation_status/2`; connection or endpoint plus the original operation reference |
| `capabilities` | `QUIC.capabilities/0`, including `http3: false` |
| `stop_endpoint` | Standard bounded OTP endpoint shutdown; distinct from stream cancellation |
| `normalize_message` | Accepts only ready/closed notifications for the exact connection handle, including its generation; unrelated/late generations return `:unknown` |

No new adapter process or application byte queue is introduced. The application
must serialize operations through the attached owner. Upstream pull queues,
stream limits, coalesced notifications, operation-result retention and ownership
monitors provide their documented bounds; arbitrary local producers can still
fill a BEAM mailbox. Endpoint options are limited to stream limits, maximum
connections, event limit and operation limit; callers cannot replace normalized
TLS, I/O, owner or diagnostic delivery through this container.

`:blocked` means definite non-admission; `{:unknown, ref}` does not. Unknown
writes, reads, event pulls or opens retain the original result and reference.
Resolve via `operation_status`; cache eviction or process death may leave the
outcome unknown permanently. The adapter never retries, changes references,
turns unknown into not-sent, or falls back to the legacy library. The real test
harnesses have finite deadlines and retry only definite blocks.

## TLS normalization

`HTTP.QUIC.TLSOptions.normalize/2` runs before endpoint creation and before TLS
feed. Explicit `cacerts` (DER list/PEM bundle) or `cacertfile` is required; sources
cannot conflict. Client `cert`/`key` or `certfile`/`keyfile` are loaded and validated
through the existing identity loader. File reads are bounded and errors redact
paths and credential contents. No credentials are loaded in a feed callback.

The default reference identity derives from the host: DNS or a parsed numeric
IPv4/IPv6 address. An explicit `reference_identity` replaces it. Optional
`server_name_indication` maps to upstream `server_name`; absent SNI does not
remove identity verification. Only `verify_peer` is accepted. Unsupported legacy
TCP options, duplicate/malformed options and `verify_none` fail explicitly.

`alpn` is an opaque binary list; the internal default is `ex-quic-phase1`.
HTTP/3 ALPN is rejected in this preparatory interface. Ordered numeric `ciphers`,
`groups` and `signature_algorithms` must be available according to public
`SSL.QUIC.capabilities/0`. `depth`, hostname checking and a record-free
`SSL.ClientHello.WireProfile` are supported. Upstream construction validates the
profile's exact ALPN and engine-supplied local transport parameters; the adapter
never manufactures transport parameters for validation. Invalid profiles or
TLS authentication still fail at the frozen public TLS boundary.

## Existing production backends and startup audit

- `apps/http_core/mix.exs` declares ex_ssl/ex_quic as normal runtime dependencies.
  Existing `quic ~> 1.6` remains `runtime: false` there; it provides the shared
  `HTTP.HTTP3` module's legacy implementation.
- `apps/http_fetch/mix.exs` and `apps/http_web_transport/mix.exs` retain runtime
  `quic`; the other children depend on http_core transitively.
- `HTTP.HTTP3` calls `:quic_h3` and ensures `:quic` starts before connecting.
  Fetch's `http_version: :http3` route remains there.
- `HTTP.WebTransport.Transport.QUIC` calls both `:quic_h3` and `:quic`, including
  its existing application session/stream operations and startup.
- `HTTP.H3.Frame`, `Settings`, `Varint` and `WebTransport` remain codecs/helpers;
  no QPACK or HTTP/3 client-session implementation is added.
- OTP `:ssl` remains the default. Explicit TCP TLS selection for QUIC remains
  rejected by `HTTP.TLSBackend`. There is no new production HTTP/3 selector.

See [acceptance](phase1-acceptance.md) for executed commands and limits. G-F is
independent of G-A; the Abyss raw-handler combination is a separate G-P1 item.
Abyss supplies a general service, while application servers own HTTP/3 or DoQ.
