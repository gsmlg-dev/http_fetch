# QUIC service

Abyss hosts UDP I/O and binds application consumers to `elixir_quic` connections.
The QUIC engine owns connection IDs, TLS, streams, flow control, recovery and
packetization. Applications own their protocols. DNS/DoQ and HTTP/3/QPACK are
permanently outside Abyss; raw stream examples do not implement either.

## Dependencies

Ordinary `Abyss.start_link/1` UDP usage does not load or require elixir_quic. A QUIC
application explicitly adds both Abyss and the engine to its dependencies:

```elixir
def deps do
  [
    {:abyss, "~> 0.10.0"},
    {:elixir_quic, "== 0.21.17"}
  ]
end
```

The published engine uses OTP application `:elixir_quic` and facade `Quic`;
its source is `gsmlg-dev/http_fetch` under `apps/elixir_quic`. It requires Hex `ex_ssl`
`0.21.17`, whose TLS facade remains `SSL.QUIC`. Abyss does not provide a legacy
`QUIC` alias or fall back to an older engine. The examples pin these published
packages and use `ABYSS_PATH` only to select the Abyss checkout under test.
Do not set `runtime: false` on these runtime dependencies.

These versions match the repository's independent QUIC examples. The core
Abyss package does not declare either engine or TLS package as a dependency.
The examples require Elixir 1.18; check the selected engine's runtime requirements
separately from Abyss's declared Elixir requirement.

## Start a listener

Implement `Abyss.QUIC.Handler` and add the listener to your supervisor:

```elixir
{Abyss.QUIC,
 name: MyApp.QUICListener,
 ip: {127, 0, 0, 1}, port: 4433,
 alpn: ["my-stream-protocol-v1"],
 tls: [cert: certificate_der_chain, key: {key_type, key_der}],
 handler: {MyApp.QUICHandler, handler_options},
 max_connections: 128,
 quic_options: [retry: true, streams: [max_data: 16_384, max_stream_data: 16_384]]}
```

Certificate material uses the public ex_ssl/elixir_quic TLS contract. `alpn` is a
nonempty list of distinct opaque identifiers (each 1–255 bytes). TLS negotiates
one; Abyss does not inspect application payloads or route protocols on the same socket.
Readiness/ALPN is not application authorization. The documented service uses
server certificates; it does not provide a client-identity authorization layer.
Bind a concrete address; wildcard destination metadata is unsupported upstream.
`local/1` returns `{:ok, {address, bound_port}}`; `stop/2` stops a listener.
Startup errors are explicit; no QUIC option silently activates ordinary UDP.
Credential structure is checked using the public `SSL.QUIC.new/2` API before
starting the listener. Actual connection transcripts are created by elixir_quic.

## Configuration

Listener options, besides `name`, `handler`, `alpn` and `tls`, are:

| Option | Default | Meaning |
| --- | --- | --- |
| `ip`, `port` | `{127, 0, 0, 1}`, `0` | Concrete bind address; zero chooses a port |
| `max_connections` | 128 | Endpoint and consumer ceiling |
| `init_timeout` | 5000 ms | Attachment and handler initialization bound |
| `callback_timeout` | 5000 ms | One event batch and its callbacks |
| `shutdown_timeout` | 1000 ms | Total cooperative worker drain bound |
| `poll_interval` | 10 ms | Consumer event/credit polling interval |
| `event_batch` | 32 | Engine events per poll, range 1–128 |
| `writer_timeout` | 1000 ms | Local writer operation timeout |
| `writer_max_queue` | 128 | Queued plus in-flight datagrams |
| `writer_max_bytes` | 1,048,576 | Queued plus in-flight payload bytes |
| `quic_options` | `[]` | Supported engine limits and timers |

All host limits/timeouts are finite positive integers. Supported engine options
are `retry`, `retry_ttl` (microseconds), `retry_limit`, `event_limit`,
`operation_limit`, `handshake_timeout`, `idle_timeout`, `closing_timeout`,
`draining_timeout` (engine timers in milliseconds), and `streams`. Stream limits
are `max_data`, `max_stream_data`, `max_stream_data_bidi_local`,
`max_stream_data_bidi_remote`, `max_stream_data_uni`, `max_streams_bidi`,
`max_streams_uni`, `max_buffer`, `max_ready_bytes`, `max_stream_records` and
`max_recv_ranges`. Unknown options and overrides of engine I/O, TLS or ownership
are rejected. `_backend` is a private host-test seam, not a supported engine plugin API.

`child_spec/1` uses transient restart: an explicit normal `stop/2` stays stopped;
host failures restart under the application's supervisor with fresh generations.
Choose the `stop/2` call timeout and supervisor child shutdown timeout longer than
`shutdown_timeout`. A stop-call timeout does not confirm listener termination.

## Idle policy and keepalive

With `elixir_quic` 0.21.17, set `quic_options: [idle_timeout: :infinity]` to
disable the local connection idle limit. Positive integer values retain their
finite millisecond meaning; `0` is rejected. Omitting the option retains the
engine's finite default. Only the idle limit supports `:infinity`: handshake,
closing, draining, host initialization, callbacks, writes and shutdown keep
their independent finite bounds.

The engine advertises a zero `max_idle_timeout` transport parameter for this
disabled local policy. A peer's finite idle limit still applies. QUIC selects
the smaller nonzero advertised limit and applies its three-PTO minimum; neither
endpoint can override the peer's policy. `Abyss.QUIC.info(connection)` exposes
`idle_timeout` metadata with `local_ms`, `peer_ms`, `negotiated_ms` and
`effective_ms`; disabled values are reported as `:infinity`. Avoid contradictory
raw idle transport parameters in TLS options: the engine rejects them.

For a peer with a finite limit, an application can call
`Abyss.QUIC.ping(connection, timeout: 1000)` on its own bounded schedule.
This delegates to the engine's public PING operation, with finite operation
deadlines and its normal admission and result accounting. There is no automatic
keepalive timer. An admitted PING is not proof of peer receipt; handle blocked,
unknown and error results as for other writes, and do not blindly replay an
unknown operation. Keepalive cannot guarantee network or peer availability.

The listener passes the selected policy unchanged to its endpoint. Newly
accepted connections and supervised listener replacements use the same
configuration; existing connections are not resumed after a host restart.

## Application callbacks

A listener owns its socket, one blocking receive process, writer and endpoint.
A persistent worker per accepted connection attaches through the public engine
API and executes application callbacks. There is no process per packet or stream.
Initialization/binding precedes data callbacks. Peer stream-open precedes data
readiness. Before attachment, the engine retains bytes and events within its
finite limits; overflow terminates the connection rather than silently dropping
application events. The attached worker alone reads and drains events.

`init(connection, metadata, options)` returns `{:ok, state}` or `{:error, reason}`.
Metadata includes peer/local addresses and negotiated ALPN. `handle_event(event,
state)` returns `{:ok, state}` or `{:stop, reason, state}`. An optional
`terminate(reason, state)` handles local teardown. Application code runs outside
shared reception and writing. Use bounded application queues, and choose read
credit deliberately. A slow consumer must not accumulate arbitrary data in its
own state after removing it from the engine's bounded buffers.
The worker also delivers `:tick` after each bounded event batch; this lets a
consumer resume partial reads or definitely blocked writes. Polling applies to
consumer events, not UDP reception, which uses a blocking receive loop. Callbacks
share one aggregate deadline per batch, including the engine event call and
`:tick`; the next poll is scheduled after that batch completes. Attachment,
metadata lookup and initialization likewise share `init_timeout`.
Failed initialization, attachment,
crashes and callback timeout close only that connection. Teardown callbacks are
best effort; forced termination can skip them.
`{:closed, reason}` is delivered once when the worker processes its matching
engine close notification. It can describe transport/TLS/engine termination,
and is not guaranteed during worker crashes or forced shutdown. Use process
ownership/monitors for lifecycle observation that must survive callback failure.

Listener shutdown stops ingress first, notifies its workers, waits for at most
the configured drain interval, then terminates remaining host components and
closes its socket. Writer/endpoint/receiver failure fails the listener closed.
Existing connections are not resumed across restart. Watchdogs run in the service
process; suspending that process delays watchdog enforcement and new binding,
while already attached consumers and the writer continue to progress.

## Byte streams

Connection handles carry engine generations; streams embed their connection
handle and stream ID. Treat them as opaque. The facade delegates `ready`, `info`,
`events`, `open_stream`, `read`, `send_stream`, `reset_stream`, `stop_stream`,
`close`, `ping` and `operation_status` to public engine operations. No endpoint-private
connection enumeration is part of the consumer API.
The event vocabulary is `{:ready, metadata}`, `{:stream_open, stream, :bidi | :uni}`,
`{:readable, stream}`, `{:stopped, stream, code}` and `:writable`, followed by
the worker's `:tick`. Only the attached worker may read or drain events. Normal
handlers consume the supplied events rather than calling `events/3` again.
Serialize other application work through a bounded queue; arbitrary concurrent
local callers are not given bounded BEAM mailboxes by this API.

A read consumes at most 16 KiB and returns ordered `{:data, id, bytes}`,
`{:fin, id}` or `{:reset, id, code, final_size}` items. A write admits at most
16 KiB and can split into many UDP datagrams. Neither write nor callback boundaries
are message boundaries. FIN closes only that sending direction: receiving may
continue. Reset and stop are directional stream operations. Closing one connection
does not close the listener socket or other connections.

## Backpressure and errors

`send_stream` returns an operation reference on admission, `{:blocked, reason}`
when no admission occurred, or an error. `{:unknown, ref}` means a call timed out
and its operation may have happened. Use `operation_status/2` where possible;
never blindly retry with a new reference. The engine caches a bounded number of
operation results; eviction or process death can make an outcome unresolvable.
Admission is not local UDP completion and neither is a peer acknowledgement.
No public per-write peer-delivery receipt is supported.
Unknown outcomes also apply to destructive reads and event pulls, not only writes.
Resolve their cached result before issuing another operation. Pass the connection
handle to `operation_status/2`, including for references returned by stream
operations; a stream handle is not an operation-status target. Options `:ref`,
`:timeout` and `:deadline` follow the engine's public consumer contract.

Stream consumption advances transport receive credit. Engine limits are supplied
under `quic_options[:streams]`; callbacks decide how many bytes to consume. Engine
readable/writable events coalesce. A handler must retain at most its chosen bounded
pending output when blocked and wait for progress before retrying definite blocks.
Admission is all-or-nothing for each write. For small peer windows, choose chunks
smaller than the remaining credit: a full 16 KiB pending write can otherwise wait
indefinitely when the peer replenishes credit only after consuming half its
window. The echo example uses 1 KiB echo chunks and separately demonstrates one
initial 16 KiB write. The collection example hashes bounded reads incrementally.

Transport, TLS and local application-worker failures retain their distinct reason
terms. Application close/reset/stop codes are opaque 62-bit integers passed
unchanged to elixir_quic; bounded binary reasons are not mapped to HTTP or DNS errors.
The independent writer contract is documented in [dispatcher.md](dispatcher.md).

## Examples

The independent [echo](https://github.com/gsmlg-dev/abyss/tree/main/examples/quic_echo)
and [collection](https://github.com/gsmlg-dev/abyss/tree/main/examples/quic_collect)
projects each have their own application supervisor, handler and custom ALPN.
Copy either
project to another directory and set `ABYSS_PATH` to this repository (or replace
the path dependency with a reviewed package). Set `QUIC_CERT`, `QUIC_KEY` and
optionally `QUIC_PORT`, then run `mix deps.get` and `mix run --no-halt`. Credentials
are PEM files converted to DER by the example application. Test fixtures are
not deployment credentials. Echo demonstrates bounded pending output; collection
hashes bounded reads incrementally. The
[UDP echo](https://github.com/gsmlg-dev/abyss/tree/main/examples/udp_echo)
application verifies ordinary UDP integration without a QUIC engine.

## Service limits and validation

This service exposes QUIC v1 certificate-based 1-RTT bidi/uni byte streams.
It does not expose engine DATAGRAM configuration or operations, external client
endpoints, resumption/0-RTT, migration, or wildcard/ancillary local-address
metadata. The pinned engine has its own DATAGRAM API; that does not activate
DATAGRAM support through `Abyss.QUIC`. HTTP/3/QPACK, DoQ and WebTransport remain
application-layer integrations outside this service. Finite stream tombstones
can exhaust the lifetime stream-record budget. Recorded acceptance is scoped
interoperability evidence, not a full conformance or production security audit.

Current release validation is recorded in the
[UDP runtime acceptance archive](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/udp-runtime/acceptance.md).
The [published-engine regression](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/published-quic-acceptance.md)
and [original QUIC acceptance](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/phase1-acceptance.md)
retain their historical dependency versions, commands and gate status.
Unit/fake-backend tests verify host regressions; independent peer transfers
provide the network evidence.

The current idle-policy gate uses the locked published engine, real TLS and
loopback UDP. It checks idle negotiation, quiet persistence against actual
finite-expiry control connections, PING operation results, listener recreation
and independent handshake expiry. Run it from either QUIC example:

```sh
mix deps.get
mix run --no-start ../../scripts/phase1/idle_policy.exs
```

This gate runs on OTP 27 and 28 in CI and before release publication.
