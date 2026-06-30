# HTTP WebTransport App Design

## Goal

Add a sibling Mix child app named `:http_web_transport` that exposes a
browser-like WebTransport client API for Elixir.

The public module should be `HTTP.WebTransport`. It should follow the browser
`WebTransport` surface where that maps cleanly to Elixir:

- constructor-style session start
- `ready`, `closed`, and `draining` promise-like accessors
- `close/1` and `close/2`
- datagram read/write APIs
- outgoing unidirectional streams
- outgoing bidirectional streams
- incoming unidirectional and bidirectional stream queues
- `reliability`, `congestion_control`, `response_headers`, and `protocol`
  accessors
- connection and datagram stats

The first implementation should be client-only. A server-side WebTransport API
can be designed later as a separate surface because the browser API is
client-oriented.

## Standards Baseline

Use the current WebTransport API as the compatibility target and WebTransport
over HTTP/3 as the first wire protocol target.

Primary references:

- W3C WebTransport Working Draft, 18 June 2026:
  <https://www.w3.org/TR/webtransport/>
- IETF WebTransport over HTTP/3 draft:
  <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-15>
- QUIC transport, RFC 9000:
  <https://datatracker.ietf.org/doc/html/rfc9000>

Key compatibility points:

- Constructor URLs must use `https`; fragments are invalid.
- Construction starts connecting immediately and returns a transport object
  after synchronous validation.
- `ready` resolves when the session is established and rejects when
  establishment fails.
- `closed` resolves with close info on graceful close and rejects on abrupt
  failure.
- State is one of `:connecting`, `:connected`, `:draining`, `:closed`, or
  `:failed`.
- HTTP/3 WebTransport support requires HTTP/3 extended CONNECT, WebTransport
  settings, HTTP datagrams, QUIC datagrams, streams, and TLS-backed QUIC.
- HTTP/3 WebTransport reports `reliability` as `"supports-unreliable"`.
- HTTP/2 WebTransport is not part of the MVP. If added later, it reports
  `"reliable-only"` and has different datagram semantics.

## Important Protocol Decision

Do not implement browser-compatible WebTransport as raw UDP.

QUIC runs on UDP, so a pure Elixir QUIC implementation may use `:gen_udp`
internally. That is different from exposing raw UDP as `HTTP.WebTransport`.
Browser WebTransport requires the full stack:

```text
HTTP.WebTransport API
  WebTransport over HTTP/3
    HTTP/3 extended CONNECT + settings + QPACK + HTTP datagrams
      QUIC streams + QUIC datagrams + flow control + congestion control
        TLS 1.3 for QUIC
          UDP socket, such as :gen_udp
```

If the app skips QUIC and sends raw datagrams with `:gen_udp`, it will not
interoperate with browser WebTransport servers and should not use the
`HTTP.WebTransport` name.

Recommended approach:

1. Define a narrow internal transport behaviour for QUIC/WebTransport
   operations.
2. Back the MVP with an existing QUIC-capable library.
3. Keep a future pure-Elixir `:gen_udp` backend possible behind that behaviour,
   but treat that as a QUIC implementation project, not a small app feature.

## App Boundary

Create a new child app:

```text
apps/http_web_transport/
  .formatter.exs
  mix.exs
  lib/http_web_transport.ex
  lib/http_web_transport/application.ex
  lib/http/web_transport.ex
  lib/http/web_transport/options.ex
  lib/http/web_transport/session.ex
  lib/http/web_transport/transport.ex
  lib/http/web_transport/transport/quic.ex
  lib/http/web_transport/promise.ex
  lib/http/web_transport/close_info.ex
  lib/http/web_transport/error.ex
  lib/http/web_transport/datagram_duplex_stream.ex
  lib/http/web_transport/datagrams_writable.ex
  lib/http/web_transport/send_group.ex
  lib/http/web_transport/send_stream.ex
  lib/http/web_transport/receive_stream.ex
  lib/http/web_transport/bidirectional_stream.ex
  lib/http/web_transport/stream_queue.ex
  lib/http/web_transport/stats.ex
  lib/http/web_transport/telemetry.ex
  test/http/web_transport_test.exs
  test/http/web_transport/options_test.exs
  test/http/web_transport/datagram_duplex_stream_test.exs
  test/http/web_transport/stream_test.exs
  test/http/web_transport/telemetry_test.exs
```

`http_web_transport` should depend on `http_fetch` in the umbrella so it can
reuse:

- `HTTP.Headers`
- shared browser-like naming and docs conventions
- optionally `HTTP.Blob`, if a future stream write API accepts blob data

Do not route WebTransport through `HTTP.fetch/2`. WebTransport requires a
long-lived HTTP/3 CONNECT stream and QUIC stream/datagram ownership. `fetch/2`
is response-oriented and currently HTTP/1.1-oriented.

## Public API

Use `HTTP.WebTransport` as the browser-facing module.

```elixir
transport =
  HTTP.WebTransport.new("https://example.com/transport",
    protocols: ["chat.v1"],
    require_unreliable: true
  )

:ok =
  transport
  |> HTTP.WebTransport.ready()
  |> HTTP.WebTransport.Promise.await()

datagrams = HTTP.WebTransport.datagrams(transport)
writable = HTTP.WebTransport.DatagramDuplexStream.create_writable(datagrams)
:ok = HTTP.WebTransport.DatagramsWritable.write(writable, <<1, 2, 3>>)

{:ok, stream} = HTTP.WebTransport.create_bidirectional_stream(transport)
:ok = HTTP.WebTransport.SendStream.write(stream.writable, "hello")
{:ok, data} = HTTP.WebTransport.ReceiveStream.read(stream.readable)

:ok = HTTP.WebTransport.close(transport, close_code: 0, reason: "done")
```

### Constructor

```elixir
@spec new(String.t() | URI.t(), keyword() | map()) :: t() | {:error, term()}
def new(url, init \\ [])
```

Browser parity:

- starts connecting immediately
- accepts only `https` URLs in browser-compatible mode
- rejects fragments
- returns `{:error, reason}` for invalid constructor input instead of raising a
  browser exception
- stores `ready`, `closed`, and `draining` promise-like objects immediately
- fails the session if `require_unreliable` is true and the backend cannot
  establish unreliable datagram support
- does not follow redirects

Browser init options, using Elixir names:

- `:allow_pooling` - default `false`
- `:require_unreliable` - default `false`
- `:headers` - default `[]`
- `:server_certificate_hashes` - default `[]`
- `:congestion_control` - `:default`, `:throughput`, or `:low_latency`
- `:anticipated_concurrent_incoming_unidirectional_streams` - default `nil`
- `:anticipated_concurrent_incoming_bidirectional_streams` - default `nil`
- `:protocols` - default `[]`
- `:datagrams_readable_type` - default `:default`; `:bytes` can be accepted
  only if the backend can preserve datagram boundaries

Elixir extensions:

- `:owner` - process receiving optional diagnostic messages, defaults to
  `self()`
- `:backend` - internal backend module, default `HTTP.WebTransport.Transport.QUIC`
- `:connect_timeout` - default `30_000`
- `:idle_timeout` - default from backend
- `:ssl` - TLS verification options passed to the backend
- `:quic` - QUIC transport parameters passed to the backend
- `:socket_opts` - UDP socket options, only for backends that expose them
- `:max_incoming_datagrams` - default implementation-defined value
- `:max_outgoing_datagrams` - default implementation-defined value
- `:max_datagram_size` - optional local guardrail; backend remains authoritative

Keep options flat, matching `HTTP.fetch/2`, `HTTP.WebSocket.new/3`, and
`HTTP.EventSource.new/2`. Do not add `options:`, `opts:`, or `client_opts:`
buckets.

### Accessors

Expose browser-style values using Elixir naming:

```elixir
HTTP.WebTransport.ready(transport)
HTTP.WebTransport.closed(transport)
HTTP.WebTransport.draining(transport)
HTTP.WebTransport.datagrams(transport)
HTTP.WebTransport.incoming_bidirectional_streams(transport)
HTTP.WebTransport.incoming_unidirectional_streams(transport)
HTTP.WebTransport.reliability(transport)
HTTP.WebTransport.congestion_control(transport)
HTTP.WebTransport.response_headers(transport)
HTTP.WebTransport.protocol(transport)
HTTP.WebTransport.state(transport)
HTTP.WebTransport.supports_reliable_only?()
```

`ready/1`, `closed/1`, and `draining/1` return
`%HTTP.WebTransport.Promise{}`. This app should define its own generic promise
type rather than reusing the current `HTTP.Promise`, because `HTTP.Promise`
is documented around `HTTP.Response` and `Task` chaining for fetch.

Provide convenience awaiters for common Elixir usage:

```elixir
HTTP.WebTransport.await_ready(transport, timeout \\ :infinity)
HTTP.WebTransport.await_closed(transport, timeout \\ :infinity)
HTTP.WebTransport.await_draining(transport, timeout \\ :infinity)
```

### Closing

```elixir
HTTP.WebTransport.close(transport)
HTTP.WebTransport.close(transport, close_code: 0, reason: "")
```

Rules:

- if state is `:closed` or `:failed`, return `:ok`
- if state is `:connecting`, fail the session and reject `ready`
- if state is `:connected` or `:draining`, terminate the WebTransport session
  through the backend
- `close_code` defaults to `0`
- `reason` defaults to `""`
- truncate or reject reasons longer than 1024 UTF-8 bytes; prefer rejecting
  with `{:error, :close_reason_too_long}` so callers do not lose information
  silently

## Datagram API

Browser WebTransport models datagrams as a duplex stream. Elixir should expose a
small stream-like API rather than raw process messages.

```elixir
datagrams = HTTP.WebTransport.datagrams(transport)

HTTP.WebTransport.DatagramDuplexStream.max_datagram_size(datagrams)
HTTP.WebTransport.DatagramDuplexStream.incoming_max_age(datagrams)
HTTP.WebTransport.DatagramDuplexStream.set_incoming_max_age(datagrams, 1_000)
HTTP.WebTransport.DatagramDuplexStream.outgoing_max_age(datagrams)
HTTP.WebTransport.DatagramDuplexStream.set_outgoing_max_age(datagrams, 1_000)

writable =
  HTTP.WebTransport.DatagramDuplexStream.create_writable(datagrams,
    send_group: nil,
    send_order: 0
  )

:ok = HTTP.WebTransport.DatagramsWritable.write(writable, <<1, 2, 3>>)
{:ok, bytes} = HTTP.WebTransport.DatagramDuplexStream.read(datagrams, timeout: 5_000)
```

Rules:

- datagrams are message-oriented binaries
- zero-length datagrams should be rejected or dropped consistently and tested
- datagrams larger than `max_datagram_size` resolve as sent/dropped without
  closing the session, matching browser semantics
- incoming and outgoing queues have independent max-age and max-buffered-count
  settings
- incoming datagrams may arrive out of order
- writes while connecting may be queued
- writes after closed or failed return `{:error, :invalid_state}`
- backpressure should be count-based, not byte-stream-based

Payload sends should not move large binaries through the session GenServer when
the backend can send directly. The session process should validate state and
queue policy; the backend should own the high-throughput packet path.

## Stream API

Browser WebTransport streams are byte streams. They do not preserve application
message boundaries. Applications that need messages must add framing.

### Outgoing Bidirectional Streams

```elixir
{:ok, stream} =
  HTTP.WebTransport.create_bidirectional_stream(transport,
    send_group: nil,
    send_order: 0,
    wait_until_available: false
  )

:ok = HTTP.WebTransport.SendStream.write(stream.writable, data)
:ok = HTTP.WebTransport.SendStream.close(stream.writable)
{:ok, data} = HTTP.WebTransport.ReceiveStream.read(stream.readable)
:ok = HTTP.WebTransport.ReceiveStream.cancel(stream.readable, code: 0)
```

`%HTTP.WebTransport.BidirectionalStream{}` should contain:

- `:readable` - `%HTTP.WebTransport.ReceiveStream{}`
- `:writable` - `%HTTP.WebTransport.SendStream{}`
- `:transport` - parent `HTTP.WebTransport` struct

### Outgoing Unidirectional Streams

```elixir
{:ok, stream} =
  HTTP.WebTransport.create_unidirectional_stream(transport,
    send_group: nil,
    send_order: 0,
    wait_until_available: false
  )

:ok = HTTP.WebTransport.SendStream.write(stream, data)
:ok = HTTP.WebTransport.SendStream.close(stream)
```

### Incoming Streams

Map browser `ReadableStream` properties to queue structs:

```elixir
bidi_queue = HTTP.WebTransport.incoming_bidirectional_streams(transport)
uni_queue = HTTP.WebTransport.incoming_unidirectional_streams(transport)

{:ok, bidi_stream} = HTTP.WebTransport.StreamQueue.read(bidi_queue, timeout: 5_000)
{:ok, recv_stream} = HTTP.WebTransport.StreamQueue.read(uni_queue, timeout: 5_000)
```

Rules:

- reads may return partial bytes
- writes may be split or coalesced by the transport
- `write/2` returns `:ok` after bytes are accepted by the local backend, not
  after peer delivery
- `close/1` on a send stream sends FIN
- `abort/2` on a send stream maps to QUIC stream reset
- `cancel/2` on a receive stream maps to stopping receive
- stream creation should return `{:error, :quota_exceeded}` if no stream credit
  is available and `wait_until_available` is false

## Events And Messages

Unlike WebSocket and EventSource, browser WebTransport is not primarily an
`EventTarget`; it exposes promises and streams. The Elixir API should therefore
prefer explicit await/read/write functions.

The session may still send optional diagnostic messages to `init[:owner]` for
observability and tests:

```elixir
{HTTP.WebTransport, transport, {:state, :connected}}
{HTTP.WebTransport, transport, {:state, :draining}}
{HTTP.WebTransport, transport, {:state, :closed, close_info}}
{HTTP.WebTransport, transport, {:error, error}}
```

Do not execute user callbacks inside the session process. Slow or crashing user
code must not take down a transport session.

## Process Architecture

One process per WebTransport session is justified because it owns mutable
session state:

- connection establishment state
- readiness, draining, and closed promises
- negotiated protocol
- response headers
- reliability mode
- datagram queues
- incoming stream queues
- active stream registry
- close/failure cleanup

Application supervision:

```elixir
children = [
  {DynamicSupervisor, strategy: :one_for_one, name: HTTP.WebTransport.SessionSupervisor},
  {Registry, keys: :unique, name: HTTP.WebTransport.Registry}
]
```

Session children should use `restart: :temporary`. A restart would create a new
logical WebTransport session without the caller asking for it.

Keep the high-throughput payload path out of a single bottleneck process when
the backend supports direct operations. The session process should serialize
state transitions and queue bookkeeping, while the backend handles QUIC packet
IO, stream flow control, retransmission, congestion control, and datagram send.

## Internal Transport Behaviour

Define a behaviour that represents the capabilities `HTTP.WebTransport` needs,
not the full QUIC implementation.

```elixir
defmodule HTTP.WebTransport.Transport do
  @callback connect(URI.t(), HTTP.WebTransport.Options.t()) ::
              {:ok, session_ref(), transport_info()} | {:error, term()}

  @callback close(session_ref(), HTTP.WebTransport.CloseInfo.t()) :: :ok | {:error, term()}
  @callback get_stats(session_ref()) :: {:ok, HTTP.WebTransport.Stats.t()} | {:error, term()}

  @callback open_bidirectional_stream(session_ref(), keyword()) ::
              {:ok, stream_ref()} | {:error, term()}

  @callback open_unidirectional_stream(session_ref(), keyword()) ::
              {:ok, stream_ref()} | {:error, term()}

  @callback send_datagram(session_ref(), binary(), keyword()) :: :ok | {:error, term()}
  @callback recv_stream(stream_ref(), timeout()) :: {:ok, binary()} | :fin | {:error, term()}
  @callback send_stream(stream_ref(), iodata(), keyword()) :: :ok | {:error, term()}
  @callback close_send_stream(stream_ref()) :: :ok | {:error, term()}
  @callback abort_send_stream(stream_ref(), non_neg_integer()) :: :ok | {:error, term()}
  @callback cancel_receive_stream(stream_ref(), non_neg_integer()) :: :ok | {:error, term()}
end
```

The backend should report asynchronous session events to the session process:

```elixir
{:webtransport_connected, session_ref, info}
{:webtransport_draining, session_ref}
{:webtransport_closed, session_ref, close_info}
{:webtransport_failed, session_ref, reason}
{:webtransport_datagram, session_ref, bytes}
{:webtransport_incoming_bidi_stream, session_ref, stream_ref}
{:webtransport_incoming_uni_stream, session_ref, stream_ref}
{:webtransport_stream_data, stream_ref, bytes}
{:webtransport_stream_fin, stream_ref}
{:webtransport_stream_error, stream_ref, reason}
```

This lets the public app remain stable if the backend changes from a NIF-backed
QUIC library to a pure Erlang `:gen_udp` QUIC implementation later.

## Backend Choice

There are two practical backend routes:

- Use a mature QUIC implementation with Erlang/Elixir bindings. This is the
  practical MVP route if browser interoperability matters soon.
- Build a pure Elixir/Erlang QUIC and HTTP/3 stack on `:gen_udp`. This gives
  dependency control, but it is a large protocol project: TLS 1.3 for QUIC,
  packet protection, loss recovery, congestion control, stream flow control,
  HTTP/3 control streams, QPACK, extended CONNECT, HTTP datagrams, and
  WebTransport session demux.

Recommended MVP decision:

- Design the public app and tests around `HTTP.WebTransport.Transport`.
- Implement a fake backend for deterministic unit tests.
- Spike one real QUIC backend separately before committing to dependency and
  API promises.
- Only claim browser-compatible WebTransport after an interoperability test
  passes against a known WebTransport server and a browser-compatible server
  accepts the same URL/protocol behavior.

## Telemetry

Use the prefix `[:http_web_transport, ...]`.

Events:

- `[:http_web_transport, :connect, :start]`
- `[:http_web_transport, :connect, :stop]`
- `[:http_web_transport, :connect, :exception]`
- `[:http_web_transport, :session, :draining]`
- `[:http_web_transport, :session, :closed]`
- `[:http_web_transport, :session, :exception]`
- `[:http_web_transport, :datagram, :sent]`
- `[:http_web_transport, :datagram, :received]`
- `[:http_web_transport, :stream, :opened]`
- `[:http_web_transport, :stream, :received]`
- `[:http_web_transport, :stream, :sent]`
- `[:http_web_transport, :stream, :closed]`

Metadata should include:

- `:url`
- `:scheme`
- `:host`
- `:port`
- `:protocol`
- `:reliability`
- `:stream_id` when applicable
- `:direction` when applicable
- `:close_code` when applicable
- `:error` for exception events

Measurements should include:

- `:duration`
- `:bytes`
- `:queue_length`
- `:datagram_size`

## Testing Strategy

Start with tests that do not require a real QUIC stack:

- constructor URL validation
- option normalization
- promise state transitions with fake backend events
- datagram queue age and buffer limits
- datagram max-size handling
- stream queue reads and timeout behavior
- close/failure cleanup
- telemetry event emission

Then add integration tests behind tags:

- `@tag :quic_backend`
- real session establishment
- negotiated protocol
- datagram send/receive
- unidirectional stream send
- bidirectional stream echo
- remote close info
- failure on missing WebTransport HTTP/3 settings

Keep e2e tests opt-in until the QUIC backend and test server are stable.

## MVP Cut

MVP should include:

- app skeleton and supervision
- `HTTP.WebTransport.new/2`
- URL and option validation
- session state machine
- generic promise implementation for `ready`, `closed`, and `draining`
- datagram duplex stream API
- stream structs and queue API
- transport behaviour
- fake backend tests
- telemetry helpers
- one real backend spike branch or feature flag

Do not include in MVP:

- HTTP/2 WebTransport fallback
- connection pooling
- server API
- send groups beyond carrying `send_group` and `send_order` through to the
  backend
- custom certificate hash verification unless the selected backend exposes the
  certificate chain cleanly
- full `export_keying_material/4` unless the backend exposes a TLS exporter

## Open Questions

- Which QUIC backend should be the first supported backend?
- Is a NIF dependency acceptable, or must this repo stay pure Erlang/Elixir?
- Should the app expose browser-like camelCase aliases, or keep only Elixir
  snake_case like `HTTP.WebSocket` and `HTTP.EventSource`?
- Should `server_certificate_hashes` be unsupported at first, returning
  `{:error, :unsupported_server_certificate_hashes}` when non-empty?
- Should datagram writes after local queue overflow return `{:error, :backpressure}`
  or block until queue credit is available?
