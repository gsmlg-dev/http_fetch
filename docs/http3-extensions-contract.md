# HTTP/3 extension contract — Task C

Source contract, 2026-11-08; WebTransport live wiring updated 2026-11-09.
Explicit WebSocket/H3 is implemented and locally verified. WebTransport draft-17
is wired end to end on an exclusive owner (see "Live WebTransport owner
contract"); independent interoperability acceptance is BLOCKED, so
`HTTP.WebTransport.Profile.supported?/0` and every WebTransport capability flag remain false.
See `http3-websocket-validation.md` for acceptance evidence and its limits.

## Caller-owned extended CONNECT

`QuicHttp3.Session.extended_connect(session, protocol, fields, opts \\ [])`
uses the existing resumable session operation/result shapes. The implemented
network protocols are `"websocket"` and, on a session created with
`webtransport: true`, `"webtransport-h3"`. Without that option the latter fails
with `:webtransport_not_enabled`. The pooled relay `HTTP.HTTP3.Stream` still
refuses `"webtransport-h3"` with `:webtransport_requires_exclusive_owner`.

Fields contain exactly `:method=CONNECT`, `:scheme=https`, nonempty `:authority`
and an absolute `:path`, followed by ordinary fields. The function adds the one
selected `:protocol`; callers must not supply it. Host, content-length,
connection-specific headers and H1 WebSocket key/accept fields are rejected.
Ordinary `Session.request/4` rejects `:protocol` with
`:protocol_requires_extended_connect`.

Before peer SETTINGS, the result is
`{:blocked, unchanged_session, :peer_settings_pending}`: no bidi stream or native
operation has been allocated. A definitive SETTINGS set without CONNECT=1 returns
`:extended_connect_not_supported`. The original absolute operation deadline is
checked even while SETTINGS is pending. Existing native blocked/unknown operation
references are retained for reconciliation; an unknown operation is never replayed.

Accepted 2xx responses enter a tunnel phase, leave upload open and ignore ordinary
content-length/bodyless response semantics (including 204/205). Tunnel trailing
HEADERS are rejected. Informational/rejected responses retain ordinary HTTP
validation. DATA cannot be sent before acceptance. Remote FIN is a receive
half-close; the local half remains available for a Close reply until local FIN or
explicit cancellation retires the session request.

## Sole live owner and WebSocket relay

`HTTP.HTTP3.ConnectionOwner` remains the only QUIC event consumer. Open admission
carries `purpose: :extended_connect, protocol: "websocket"`. The owner queues opens
until peer SETTINGS, polls control progress and enforces the original opening
deadline/cancellation. Accepted tunnel headers preserve upload. STOP_SENDING fails
only the affected tunnel. Other Fetch/EventSource requests retain their behavior.

Owner notifications are `{:http3, generation, request_ref, event}`; tunnel events
include `{:headers, status, fields}`, `{:data, bytes}`, `:done` (remote FIN), and
`{:error, reason}`. DATA is charged until relay ACK/removal, within an aggregate
262144-byte extension budget. `ConnectionOwner.status/1` reports
`extension_bytes`; unknown request ACKs do not release credit. Ordinary owner
read/operation limits still apply.

`HTTP.HTTP3.Stream.start(request, subscriber, purpose: :extended_connect,
protocol: "websocket", ...)` returns `{:ok, relay_pid, generation}`. Opening and
write timeouts must be positive finite milliseconds (defaults 5000); default
`max_write_bytes` is 16777230. There is one admission attempt for a tunnel;
GOAWAY does not silently reconnect/replay it. Pool identity includes optional
`extension_policy`; origin, trust, profile and ownership identity still partition
reuse. A WebSocket can share an eligible owner with ordinary H3 requests.

Relay envelopes reuse `{:http_runtime, generation, relay_pid, event}`:

- `{:opened, %{owner: owner_pid, ref: request_ref, protocol: :h3}}` is admission,
  before the successful response; it is not the public WebSocket Open event.
- `{:headers, [{":status", decimal_status} | ordinary_fields], []}` carries
  informational/final headers for the existing WebSocket handshake validator.
- `{:data, bytes, [], receipt}` carries bounded DATA. Call
  `HTTP.Runtime.Stream.acknowledge(relay, receipt)` after parser admission.
- `:remote_end` is receive FIN, after preceding DATA credit is settled.
- `{:write, ref, {:progress, accepted_bytes}}`, `{:write, ref, :done}` and
  `{:write, ref, {:error, reason}}` report local write admission; `{:error, reason}`
  is terminal. They do not certify peer application receipt.

Use existing `HTTP.Runtime.Stream.write(relay, bytes, fin?)`, `half_close/1` and
`close/1`: their message protocol is shared by the H3 relay. One bounded write
may be outstanding; excess admission returns `:write_busy`. Writes use chunks of
at most 16384 bytes under one original deadline, checked between chunks and
while the mailbox remains busy. Timeout reports
`{:indeterminate_operation, public_write_ref}`, cancels the request and releases
the relay lease; uncertain bytes are never replayed. Application WebSocket ACKs
are separate from relay parser ACKs.

Public selection is `HTTP.WebSocket.new(wss_url, protocols,
http_version: :http3, ssl: verified_quic_options)`. Existing framing, masking,
Close/Ping/Pong, limits and delivery APIs are reused. H1 remains default; there
is no H3 fallback. TCP backend, address pin and infinite opening timeout options
are rejected for H3. `http3_profile` and `http3_reuse` select the existing runtime
policies.

`HTTP.ClientCompletion.await(HTTP.WebSocket.completion(socket), timeout)` is a
supported H3 barrier; its exact meaning is defined in the next section. A clean
Close event remains WebSocket handshake evidence only.

## WebSocket/H3 completion receipt

Design, 2026-11-09. The public receipt reuses the existing client/attempt
`HTTP.RequestLifecycle` trackers; no new public type or engine API was added.

Evidence chain:

1. A tunnel relay started with `request_lifecycle` (every `HTTP.WebSocket`
   H3 attempt) is registered under the lifecycle's proof-bearing worker kind.
   Tracker cancellation reaches it as a graceful `:abort`; death before a
   normal return (kill, crash) is sticky uncertainty. Untracked tunnels and all
   Fetch/EventSource relays keep their original `:http3_relay` kind and code.
2. Before returning, the relay asks its owner
   `ConnectionOwner.settle(owner, relay, refs, timeout)`. The owner rejects any
   queued open by that relay, removes the relay's demux entries, enqueues
   native `Session.cancel` (RESET_STREAM + STOP_SENDING + request removal) and
   replies `:settled` only when no demux entry, no native session request among
   the tracked refs and no queued, pending or suspended action for the relay or
   those refs remains. Otherwise it replies `{:pending, refs}`; the relay polls
   within a 5 s bound. An owner observed down also settles the stream: that
   process held the only demux and native session state for it.
3. With `http3_reuse: false` (exclusive owner) the relay supplies its own
   `quic_cleanup` callback, creating a `Quic.Cleanup` scope it owns. After
   lease release and stream settlement it calls `Quic.Cleanup.retire/2` and
   requires `{:ok, %{cleanup: :confirmed}}`: the exclusive endpoint,
   connection, IO actor and UDP Port were joined. Caller-supplied
   `quic_cleanup`/`cleanup` descriptors are never retired by the relay.
   Since `4c1bf8f`, lease release no longer retires the exclusive owner's
   scope directly: the pool sends `:http3_retire`, and the owner first sends
   CONNECTION_CLOSE with H3_NO_ERROR (only when no request remains) under its
   watchdog-guarded `operation_timeout` (default 1 s), then retires. The
   receipt therefore follows the owner's guarded close, and confirmation can
   take up to that bound longer.
4. Missing proof (owner alive but unsettled at the bound, native scope pending
   or unconfirmed, relay killed) calls `RequestLifecycle.unconfirmed/1`; the
   public result is `{:error, :cleanup_unconfirmed}`. Lifecycle-registered
   exclusive owner/watchdog/connector processes must also go DOWN.

What `:ok` proves: the WebSocket connection process, its relay and (exclusive)
owner processes terminated; the CONNECT stream was retired from its owner,
natively cancelled or finished; and, for an exclusive owner, native QUIC
cleanup was confirmed. Clean Close, peer Close+FIN, peer stream reset, opening
cancellation/deadline, refusal and owner death all reach this check.

What it does not prove: peer application receipt; the peer's view of stream
closure; for a shared pooled owner, closure or native reclamation of the QUIC
connection, endpoint or UDP Port, which stay open for siblings by design (no
shared-owner native receipt exists); kernel or allocator memory reclamation.

## Pure draft-17 codecs

- `HTTP.H3.Settings.wt_enabled/0` retains historical `0x2c7cf000`.
  `wt_enabled_draft17/0` is `0x20b8933b`; the engine facade delegates both.
  Draft-17 section 7.1 uses this versioned codepoint itself, without an extra
  invented negotiation setting or legacy substitution.
- `HTTP.H3.WebTransport.Draft17.client_settings/0` advertises draft-17, H3
  Datagram and zero initial WT limits; it does not advertise server-only CONNECT.
  `validate_server_settings/1` requires draft-17, Datagram and CONNECT all equal 1.
  This pure check does not establish negotiated QUIC Datagram/reliable reset.
- `Draft17.prefix(:uni | :bidi, connect_stream_id)` returns `{:ok, bytes}` or an
  error. `decode_prefix(kind, bytes)` returns `:more`,
  `{:ok, connect_stream_id, tail}` or an error. IDs must be client bidi IDs
  (multiples of 4). Prefixes are 0x54/0x41 respectively; an incomplete prefix
  retains at most 15 bytes.
- `Draft17.application_error/1` and `decode_application_error/1` map the draft's
  application error space and reject reserved/out-of-range values.
  `close_capsule/2` and `decode_capsule/1` validate Close/Drain payloads, including
  a finite UTF-8 Close reason.
- `HTTP.H3.Datagram.encode(connect_stream_id, payload, max_bytes)` and
  `decode(bytes, max_bytes)` enforce the wire limit including quarter-stream
  association overhead. Empty and duplicate application datagrams remain valid.
- `HTTP.H3.Capsule.new(opts)`, `feed(state, bytes)` return incremental
  `{:ok, state, [{:capsule, type, payload}]} | {:error, reason}`. Defaults cap
  capsule length at 65536; known types are Close 0x2843 and Drain 0x78ae.
  Unknown payload is skipped without retention. `finish/1` rejects truncation;
  `retained_bytes/1` supports owner accounting. Flow-control capsule types are
  ignored in the initial zero-limit profile.

## Pure association router

`QuicHttp3.WebTransportRouter.new(opts)` returns `{:ok, state}` with positive
finite byte/item/stream/datagram limits (defaults 262144/128/32/1200; aggregate
bytes cannot exceed 262144). `register(state, actual_connect_stream_id)` reserves
one pending session; `accept(state, id)` releases pending deliveries only after
acceptance. `stream_data(state, key, :uni | :bidi, bytes, fin?)` incrementally
associates prefixes; `datagram(state, wire_bytes)` uses quarter-stream association.

Mutation results are `{:ok, state, actions}` or an error. Delivered actions are
`{receipt, {:stream, session_id, key, kind, bytes, fin?}}` and
`{receipt, {:datagram, session_id, payload}}`. `acknowledge(state, receipt)` releases
retained bytes; unknown receipts error. Pending and exposed events consume the
same finite byte/item budget, including empty datagram items. Excess streams
return `{:reset, key, code}` actions; excess datagrams are dropped whole.
`close(state, id)` clears retained state and emits resets; repeated close is safe.
`local_stream(state, key, kind)` registers a locally opened stream of an accepted
session (no receive prefix). A FIN delivery releases the stream entry;
`reset(state, key, code)` emits `{nil, {:reset, session_id, key, code}}` (no
credit) for an associated stream and silently discards an unassociated one;
`forget(state, key)` drops an entry after local abandonment. Only peer-initiated
entries count toward `max_streams`. Delivered credit stays charged until its
receipt is acknowledged.

This module performs no IO; `QuicHttp3.Session` is its only owner.

## Live WebTransport owner contract

`QuicHttp3.Session.new(webtransport: true | [max_bytes:, max_items:, max_streams:])`
adds `Draft17.client_settings/0` to the local SETTINGS. `extended_connect/4` with
`"webtransport-h3"` sends nothing unless, in order: the session has no WT
CONNECT yet (else `:webtransport_session_capacity`); peer SETTINGS pass
`validate_server_settings/1` (`:webtransport_draft17_not_enabled`,
`:h3_datagram_disabled`, `:extended_connect_disabled`); and transport `info/1`
reports `reliable_reset: %{draft: 11, local: true, peer: true, negotiated: true}`
(`:reliable_reset_not_negotiated`) and `datagram.send_max_bytes > 0`
(`:quic_datagram_not_negotiated`). The CONNECT stream ID registers the router.
A 2xx accepts it and releases pending deliveries; any other final status, FIN,
reset or stream error closes it. CONNECT DATA is parsed as capsules: Close and
Drain become events, unknown capsules are skipped, malformed ones are a stream
error `0x10e`.

Peer bidi streams (refused with `:peer_bidirectional_stream` without WT) and
uni streams of type `0x54` are associated through the router; malformed or
foreign session IDs reset/stop only that stream (`0x101`, or
`WT_BUFFERED_STREAM_REJECTED` for a foreign session/overflow). `:datagram_readable`
reads up to 32 QUIC DATAGRAMs per event; datagrams for other sessions, oversize
or undecodable ones are dropped. A WT stream is read only while the router keeps
16384 bytes and one item of headroom, so reliable bytes are backpressured
through QUIC flow control instead of rejected. Peer data preceding a reliable
reset is delivered before the reset. A peer STOP_SENDING closes the local send
side; the engine itself answers with RESET_STREAM (see validation report).

Poll events: `{:wt, connect_ref, ev}` with `ev` in `{:stream, key, :uni | :bidi,
bytes, fin?, receipt}`, `{:datagram, payload, receipt}`, `{:reset, key, code}`,
`{:stopped, key, code}`, `{:close, code, reason}` and `:drain`. `key` is the QUIC
stream ID; codes are decoded draft-17 application codes or `{:http3_error, code}`.
`webtransport_acknowledge/2` releases credit; unknown receipts error.
Operations (resumable, never replayed, under the caller's absolute deadline):
`webtransport_open/3` (prefix sent first; returns `{:ok, session, key}`),
`webtransport_send/5` (raw bytes, FIN), `webtransport_reset/4`
(`RESET_STREAM_AT` with `reliable_size` = this stream's WT prefix length, mapped
code), `webtransport_stop/4` (mapped STOP_SENDING), `webtransport_datagram/3`
(quarter-stream association; payload limit `webtransport_info/1`
`max_datagram_payload` = QUIC send limit minus association bytes) and
`webtransport_close/4` (Close capsule in DATA with FIN). The QUIC transport
behaviour gains `reset_stream_at/4`.

`HTTP.HTTP3.ConnectionOwner` remains the sole QUIC consumer. Its CONNECT
subscriber receives `{:http3, generation, ref, {:wt, ev}}` and is the only
process allowed to call `ConnectionOwner.webtransport(owner, ref, op, timeout)`
(`{:open, kind}`, `{:send, key, bytes, fin}`, `{:reset, key, code}`,
`{:stop, key, code}`, `{:datagram, bytes}`, `{:close, code, reason}`, `:info`);
others get `:unknown_webtransport_session`. Operations join the owner's single
action queue, continuations and watchdog; an expired deadline is
`:operation_timeout` without native admission. `webtransport_ack/3` returns
credit. `ReceiveBudget` with `webtransport: true` reserves receive windows for
16 peer bidi and 16 peer WT uni streams (in addition to the three H3 streams);
ordinary owners keep peer bidi at 0. Retained WT bytes stay within the router
budget (at most 262144), the owner's extension budget.

`HTTP.WebTransport.Transport.QUIC` starts one inert exclusive owner
(`max_streams: 1`) with a session-owned `Quic.Cleanup` scope, activates it, sends
exactly one CONNECT and never falls back. `close/2` sends the Close capsule,
lingers up to `quic: [close_linger: ms]` (default 500) for the peer's FIN, stops
the owner and returns `:ok` only when the cleanup receipt is `:confirmed`.
The owner's guarded H3_NO_ERROR close (bounded by `operation_timeout`,
default 1 s) runs before it retires the scope, so the receipt follows it.

Known gaps: blocked writes hold the session
process until admission or deadline. The session's terminal-stream ledger caps a
connection at 1024 retired streams. No keepalive is sent; the QUIC idle timeout
applies.

## Client migration (beta)

Long-lived exclusive HTTP/3 sessions may move their QUIC connection to a new
local address: `HTTP.WebSocket.migrate(socket, local: {ip, port}, timeout: ms)`
for an open `http_version: :http3` WebSocket created with `http3_reuse: false`,
and `HTTP.WebTransport.migrate(session, local: {ip, port}, timeout: ms)` (a
WebTransport session always owns its connection). `ip` must be concrete; port
`0` selects an ephemeral port. `timeout` (default 5000) is one absolute deadline
for admission and the engine's path validation. Both calls return
`{:ok, %{local: actual}}` after the engine reports the validated, selected path,
or `{:error, reason}`. If no outcome is known one second after the deadline the
call returns `{:error, {:indeterminate_operation, ref}}`; nothing is replayed.
A failed migration keeps the original path, and the session stays usable.

Chain: the public call reaches the owner's sole CONNECT subscriber (the
WebSocket relay `HTTP.HTTP3.Stream.migrate/4`, or the WebTransport session
through `HTTP.WebTransport.Transport.QUIC.migrate/3`), which calls
`ConnectionOwner.migrate(owner, ref, local, timeout)`. The owner admits only
when it is `:ready`, `exclusive?`, dialled on its own endpoint (no shared
resumption endpoint), and the caller is the subscriber of `ref`, the owner's
only request; at most one migration is outstanding. Refusals are explicit:
`:not_ready`, `:not_exclusive_owner` (pooled/shared connections, including
Fetch and EventSource owners and pooled WebSockets), `:shared_endpoint`,
`:unknown_request`, `:migration_busy`. Admitted calls join the owner's single
action queue under the watchdog and run `QuicHttp3.Session.migrate/3`, which
forwards through the optional `QuicHttp3.Transport.migrate/2` callback to
`Quic.migrate(connection, local: local, ref: ref, deadline: {:abs_ms, d})`. The
production adapter refuses a connection whose endpoint it does not own with
`:shared_endpoint`; an unknown admission is reconciled through
`Quic.operation_status/2` with the same ref (cleanup operation kind
`:migrate`). The owner, as the sole QUIC event consumer, routes
`{:migration, ref, outcome}` to that subscriber as
`{:http3, generation, request_ref, {:migration, ref, outcome}}`; stale or
foreign outcomes are dropped. Engine refusals (`:invalid_local_address`,
`:peer_disabled_migration`, `:no_unused_connection_id`,
`:handshake_not_confirmed`, `:unchanged_local_address`, `{:bind_failed, r}`,
`:validation_timeout`) are returned unchanged. The WebSocket API refuses
before forwarding with `:invalid_state`, `:migration_requires_http3` or
`:not_exclusive_owner` for a pooled tunnel.

Evidence: in-repo Quic server integration tests migrate a WebSocket tunnel and
a WebTransport session to a new loopback port and then exchange a WebSocket
message both ways, and a WebTransport bidi stream with FIN plus DATAGRAMs both
ways; the peer observes the new remote address. Source-IP migration needs a
loopback alias not present on macOS by default. The independent HTTP-level
gate `scripts/http3_migration/gate.py` runs an exclusive WebSocket/H3 tunnel
against unmodified quic-go/http3 v0.65.0 (pinned by the committed `go.mod` and
`go.sum`; the harness adds only RFC 6455 framing over the RFC 9220 extended
CONNECT stream). After `migrate/2` to a new loopback port, the peer reports the
post-migration text and 96 KiB binary messages with exact bytes on the same
connection and CONNECT stream, its connection `RemoteAddr()` equal to the
client's new address, and its per-source datagram counters attribute the large
message to the new path; the echoes return, and the tunnel closes with Close +
FIN. A pooled WebSocket refuses with `:not_exclusive_owner` and keeps
exchanging. Port migration passes locally and in CI; source-IP migration to 127.0.0.2
(`--ip`) passes in the CI `independent-http3-migration` job (first green on
`17bd1c8`), which adds the alias. When the owner retires the connection it sends
CONNECTION_CLOSE with H3_NO_ERROR (0x100) before cleanup (`4c1bf8f`); the gate
requires the peer to observe it. aioquic 1.2.0 is not used: it
does not answer a padded probe on the new path (see
`docs/quic/client-features-validation.md`, M2). WebTransport migration has no
independent peer. `Quic.capabilities().migration.local` is `[:client]`: the
engine's M2 positive and negative matrices pass in CI against unmodified
quic-go v0.62.0 and quinn 0.11.11 (`docs/quic/client-features-validation.md`).
That is an engine capability; this HTTP API stays beta, and WebTransport
migration still has no independent peer.
