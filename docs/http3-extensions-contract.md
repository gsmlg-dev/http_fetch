# HTTP/3 extension contract — Task C

Source contract, 2026-11-08. Explicit WebSocket/H3 is implemented and locally
verified. WebTransport support below consists of pure codecs and a pure router;
there is no live WT owner API or network adapter. Capability flags remain false.
See `http3-websocket-validation.md` for acceptance evidence and its limits.

## Caller-owned extended CONNECT

`QuicHttp3.Session.extended_connect(session, protocol, fields, opts \\ [])`
uses the existing resumable session operation/result shapes. The implemented
network protocol is `"websocket"`. `"webtransport-h3"` is recognized but fails
with `:webtransport_network_not_ready`; it cannot admit an unsupported session.

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

## Pure association router; WT network boundary unavailable

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
Tracked terminal stream handles remain bounded until session close.

This module performs no IO. A future owner must validate all negotiation before
registration, charge these retained bytes to its aggregate budget and execute
reset actions through reliable-prefix-aware transport operations. It is not
wired to live peer uni/bidi streams or datagrams. Direct QUIC reads by
WebTransport would violate sole ownership and must not be added as a workaround.
There is no live WT stream/datagram API, so Task D's network adapter remains
blocked. Task A's reliable-reset API alone does not complete this integration.
A matching independent draft-17/reliable-reset peer is also still unavailable;
see `webtransport-peer-profile.md` and `webtransport-validation.md`.
