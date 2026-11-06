# Datagram dispatcher and writer

The legacy dispatcher gives a protocol callback persistent state and generic
routes. Its independent writer also supplies the generation-scoped send
capabilities used by the [UDP runtime](udp-runtime/design.md) and
[QUIC service](quic-service.md).

## Selecting a dispatcher

Configure `datagram_dispatcher: Module` or `{Module, options}` on a listener with
`broadcast: false`. The module implements `Abyss.DatagramDispatcher`; no dummy
`handler_module` is needed. Do not combine it with `datagram_handler`.

```elixir
{:ok, server} = Abyss.start_link(
  datagram_dispatcher: {MyApp.Dispatcher, protocol_options},
  port: 49_000,
  num_listeners: 1,
  transport_options: [ip: {127, 0, 0, 1}],
  dispatcher_max_queue: 128,
  dispatcher_max_queue_bytes: 1_048_576
)
```

Each listener has one dispatcher and one writer. `dispatcher_options` supplies
callback options; options in `{Module, options}` override it. The two writer
limits above are also their defaults. New applications needing runtime-managed
execution and input bounds can use `Abyss.DatagramHandler` with `:per_datagram`,
`:endpoint` or `:keyed` execution; see the [migration guide](udp-runtime/migration.md).
QUIC applications use `Abyss.QUIC` for application binding and lifecycle.

## Callback state and routes

The dispatcher runs separately from the socket control owner. `init(context,
options)` returns `{:ok, state}` or `{:error, reason}`. The initialization context
contains `local_info`, `generation`, `send` and `send_fun`.

`handle_datagram(remote, bytes, received_at, context)` receives a peer
`{address, port}`, complete binary payload, monotonic receive timestamp, and a
context containing the last callback `state`, `routes`, `generation`, `send`,
`send_fun` and dispatcher PID in `local`. Available `ancillary` and `local_info`
fields are preserved. Empty payloads are valid datagrams.

Return `{:ok, state}` or `{:drop, reason, state}` to update application state.
Callbacks can register generic routes via `{:new, keys, pid, state}` or
`{:route, keys, pid, state}`. Replacing routes removes displaced monitors;
process death removes only that process's routes. Route entries contain the PID,
remote, generation and monitor. The callback decides how to forward datagrams;
registration does not automatically route later packets. Optional
`terminate(reason, state)` performs callback cleanup.

QUIC services do not install a second CID registry here: `Quic.Endpoint` remains
authoritative for QUIC routing and protocol state.

## Writer capability and outcomes

The callback context provides `send`, a generation-scoped
`Abyss.Dispatcher.SendCapability`, and `send_fun.(remote, binary)`, which waits
for local completion. A capability authorizes only this listener's writer.
Neither a callback nor a connection may close the shared socket.

- `Abyss.Dispatcher.send(capability, remote, bytes, timeout)` reserves both one
  item and its bytes, then atomically hands the payload to the writer through
  an independent admission process. `{:ok, send_ref}` means admission only.
- `Writer.await(writer, capability, send_ref, timeout)` returns
  `{:ok, completed_at}` after the socket send, in monotonic microseconds, or a
  transport error. `Abyss.Dispatcher.send_receipt/4` composes admission and this wait.
- A submitted-call or receipt timeout returns `{:unknown, send_ref}`. It is not
  cancellation; do not blindly retry. The capability retains the generation.
- Reservation timeout returns `{:error, :writer_timeout}` before any payload
  submission, and sends an ordered cancellation of the control-only reservation.
- Unknown/expired references return `{:error, :unknown_send}`; a stale generation
  returns `{:error, :stale_generation}`. Writer/gate death rejects admission.

Credits include queued **and in-flight** work, including payloads awaiting writer
mailbox processing. They are released exactly once by completion, unused
reservation cancellation/death, or writer teardown. A caller dying after payload
handoff does not free credit prematurely. The writer performs socket sends itself,
with no task per packet and no synchronous listener call.

The independent gate remains responsive while the writer is blocked. At most one
waiter per reference is admitted; another receives `:already_awaiting`. Waiters
have deadlines and process monitors and are removed on timeout/death/completion.
Results have a finite count (default 256) and lifetime (default 5 seconds),
including idle expiration. Eviction/expiration makes the outcome unresolvable;
it never proves the datagram was not sent. These are local socket receipts, not
peer ACKs. The host receives generation-tagged completion notifications.

A QUIC external sender must return completion, not a reference. The service
converts an unknown writer outcome into an explicit error with the generation
and reference; elixir_quic terminates the uncertain connection without reusing packet
numbers. No automatic retry is added by Abyss.

## Failure ownership

Writer/admission death makes the dispatcher fail closed and invokes callback
cleanup. Callback initialization failure reaps its writer even if transport send
is blocked. The admission companion observes owner death and kills a blocked
writer; writer death resolves waiters, invalidates its lookup and stops the gate.
The owning QUIC service drains its workers within a configured deadline and then
terminates its host components and closes its socket. One connection close never
closes that socket. Stale or late completion cannot refund a different generation.

## Compatibility and limits

The dispatcher is unavailable with `broadcast: true` or the Broadcast transport.
Multicast memberships with `broadcast: false` remain supported. Direct native
sockets require `Abyss.DatagramHandler`. See the
[eligibility matrix](udp-runtime/migration.md#legacy-dispatcher-and-transport-helpers).
Omitted QUIC/dispatcher configuration does not load or require elixir_quic. Callers must use
the capability API rather than forging internal GenServer messages. Application
code is responsible for its own bounded input queues; this contract bounds
admitted writer payloads, not arbitrary messages sent by hostile local processes.

Source-linked historical validation is retained in the
[UDP runtime acceptance archive](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/udp-runtime/acceptance.md).
