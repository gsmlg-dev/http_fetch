# UDP datagram runtime

The datagram API separates application state from socket ownership, admission,
execution deadlines, and egress. Applications implement `Abyss.DatagramHandler`
and start an `Abyss.Endpoint`; the existing Abyss supervision tree owns the
runtime. See the [migration guide](migration.md) for configuration and examples.

## Ownership and data flow

Each datagram endpoint has one receive socket and one listener. Multiple
listeners and dynamic receive scaling are rejected for `datagram_handler`.

| Component | Responsibility |
|---|---|
| `Abyss.Endpoint` | Public startup, inspection, membership, send, and lifecycle API |
| `Abyss.Listener` | Sole socket owner; receive activation, metadata requirements, and membership changes |
| [Abyss.DatagramRuntime](https://github.com/gsmlg-dev/abyss/blob/main/lib/abyss/datagram_runtime.ex) | Input queues, route helpers, workers, managed timers, action validation, and watchdogs |
| [Abyss.DatagramWorker](https://github.com/gsmlg-dev/abyss/blob/main/lib/abyss/datagram_worker.ex) | Application initialization, state transitions, and optional termination |
| [Abyss.UDPAdmission](https://github.com/gsmlg-dev/abyss/blob/main/lib/abyss/udp_admission.ex) | Shared input credits and protected work accounting |
| `Abyss.Dispatcher.Writer` / `Admission` | Bounded egress and generation-scoped send receipts |
| [Abyss.TableOwner](https://github.com/gsmlg-dev/abyss/blob/main/lib/abyss/table_owner.ex) | Durable membership intent and monitored retirement of owned runtime processes |

The listener normalizes a complete packet into `Abyss.Datagram`, checks packet
size and required metadata, then submits it to the runtime. Admission reserves
item and byte credits before application work starts. The runtime selects a
worker, runs its callback, validates the entire action list, and submits effects
through the original socket's writer. Routing, callbacks, and send helpers run
outside the socket owner and have separate deadlines.

## Received datagrams

`Abyss.Datagram` carries immutable packet context. Unavailable fields are `nil`;
the runtime does not infer addressing information from configured memberships.

| Field | Meaning |
|---|---|
| `payload` | Complete binary UDP payload, including an empty payload |
| `peer` | Observed sockaddr map with family, address, port, and IPv6 scope when available |
| `local_endpoint` | Bound address and port; wildcard binds remain wildcard |
| `destination` | Packet destination from receive controls |
| `interface_index` | Observed ingress interface |
| `local_address` | Usable local unicast address for source-controlled replies |
| `hop_limit`, `traffic_class` | Receive TTL/hop limit and TOS/traffic class when available |
| `ancillary`, `flags` | Original bounded receive controls and flags |
| `endpoint_id`, `generation` | Logical endpoint identity and current socket generation |
| `received_at` | BEAM monotonic microseconds when receive processing occurs |

`received_at` is not a kernel arrival timestamp. Telemetry sampling does not
change datagram contents. The native adapter drops truncated payloads; control
truncation keeps unsafe derived metadata unavailable. Receive sub-binaries are
copied when needed to avoid retaining larger parent buffers.

## Handler transitions

`init(options, context)` returns `{:ok, application_state}` or `{:error, reason}`.
The options come from `handler_options`. Context contains `endpoint_id`,
`generation`, and an immutable `send` capability; it contains no raw socket.

`handle_datagram(datagram, state)` returns one of:

```elixir
{:ok, state, actions}
{:stop, reason, state, actions}
{:error, reason, state}
```

Persistent policies can also implement `handle_event/2` with the same transition
contract. Managed events are `{:timer, token, value}` and
`{:send_outcomes, generation, input_token, outcomes}`. Events share the worker's
serialized queue with datagrams and are subject to admission limits. Outcome
events do not recursively produce further outcome events.

Optional `terminate(reason, state)` receives the last returned application
state, including a state returned with a stop/error transition or invalid
actions. Forced callback death cannot recover unreturned state and can prevent
termination from running. Cleanup itself has a watchdog.

## Execution policies

| Policy | Application state and ordering |
|---|---|
| `:per_datagram` (default) | One initialization, datagram callback, and cleanup per admitted packet |
| `:endpoint` | One lazily initialized state serializes datagrams and managed events for the current endpoint generation |
| `:keyed` | Explicit `route_key` selects an opaque application key; each key has one serialized worker |

Keyed routing accepts a unary function or `{module, function}`. It runs serially
in local admission order under `route_timeout`, outside listener and control
processes. Keys have finite serialized-size and count limits. Different active
keys can execute concurrently. The runtime neither parses protocols nor creates
implicit peer sessions, and local serialization does not guarantee wire order.

Only `:keyed` retires idle workers after the finite `idle_timeout`; later work
initializes fresh state. Pending managed timers do not pin an idle key, and
eviction cancels its timers. Status inspection and stale timers do not extend
key lifetime.

Endpoint state and managed timers survive ordinary inactivity and pause/resume
within one generation. Retaining state does not retain completed input or send
credit. Stop, generation replacement, an application stop/error, or genuine
callback failure can retire state. This is not durable storage or recovery of
unreturned callback state. Failed invocations and queued work retired with a
failed worker are not replayed.

## Bounds and watchdogs

Input credit covers queued, routing, initializing, and executing work. Byte
accounting includes serialized datagram/event metadata. `num_connections` is the
shared service item ceiling; `runtime_options` supplies endpoint and worker
item/byte limits, key limits, timer limits, and deadlines. Overload drops new
work before allocating a rejected packet's worker. Timer and outcome events
also use input credit and can be rejected under overload. Their rejections
are counted separately from network datagram loss.

Action count and total payload bytes are bounded. Managed timer token/value
size and delay are validated, and timers are available only for persistent
policies. Application state and arbitrary messages sent to application workers
remain the application's responsibility; these quotas are not a whole-VM
memory guarantee.

Watchdogs run in the coordinator, separately from application callbacks. Each
init, callback, effects and cleanup arm has its own identity, phase and absolute
monotonic deadline. Expiry must match the worker, invocation and generation as
well as that arm; cancelling a timer alone does not invalidate an already
emitted message.
Completed effects retire their watchdog only after a terminal result and the
helper's actual normal `DOWN`. Input credit stays reserved until worker
settlement or protected work retirement. `TableOwner` monitors descendants so
forced retirement cannot refund input credit while protected work remains
alive. Accepted egress retains its own accounting until writer completion.

See [configuration defaults](migration.md#configuration-and-limits) for exact
option names and values.

## Actions and send outcomes

The complete action vocabulary is:

```elixir
{:reply, binary}
{:reply, binary, :strict}
{:send, sockaddr, binary}
{:timer, token, delay_ms, value}
{:cancel_timer, token}
```

The entire list is validated before any effects begin. Once valid actions are
submitted, they are not a transaction: some effects can succeed while others
fail. Ordinary reply uses the observed peer and normal routing. Strict reply
requires actual local-source/interface metadata and native per-message
controls on the original socket; missing metadata or unsupported controls
produce explicit errors. A reply action requires a datagram callback; an event
callback can use `{:send, sockaddr, binary}` for a saved destination.

`Endpoint.send(capability, destination, payload, timeout)` returns `{:ok, ref}`
when egress is admitted. `Endpoint.await(capability, ref, timeout)` reports:

| Result | Meaning |
|---|---|
| `{:ok, monotonic_microseconds}` | Local socket send completed |
| `{:error, reason}` | Definite local failure |
| `{:unknown, ref}` | No definite result is available within this wait |

Supported GenUDP and native transport instrumentation records each actual local
socket result once, including empty sends. Payload bytes exclude addressing
controls. Validation/admission rejections and receipt waits or reads do not
record socket outcomes. Custom transports retain their own contracts.

Local completion does not prove delivery. Timeout does not cancel accepted
work or justify a blind retry. Send references have finite result retention.
The endpoint separately retains action outcome receipts, including outcomes
from workers that have exited, and exposes them through `Endpoint.info/1`.
Persistent handlers can receive outcomes through `handle_event/2`; receipt
inspection remains useful when an outcome event is dropped.

## Drop accounting

For the datagram API, public `Endpoint.info/1` and `status/1` report current
generation `received` and known network `dropped` counts. `drop_counts` exposes
non-overlapping `ingress` and `runtime` components whose sum is `dropped`.
Ingress validation/pause, runtime input admission and deferred route/key/queue
rejection each count a network input once at the definitive decision. An
admitted packet awaiting completion is not a drop.

`internal_events_rejected` separates `timer` and `send_outcomes` rejection.
Callback failure, socket-send failure and queued work discarded during teardown
do not enter the network admission-drop total. Unknown kernel receive loss is
not measurable here. Network drop bytes are observed payload bytes; internal
event rejection bytes remain serialized admission bytes.

Generation replacement resets public counts. Telemetry retains logical-server
lifetime until service deletion; compare matching interval deltas. Fixed counter
names avoid metric cardinality based on arbitrary keys or peers. Legacy listener
statistics retain their existing contracts. See [operations](../operations.md)
for counters and events.

## Pause, drain, and restart

`Endpoint.pause/1` establishes a barrier for admission of received datagrams
while retaining the socket. Accepted callbacks, egress, and managed runtime
events can continue. Pause does not flush the kernel queue.

`Endpoint.stop/2` uses one absolute drain deadline across ingress, application
work, egress, and forced cleanup. Drain cancels outstanding managed timers and
stops new input admission. Deadline expiry forces retirement; accepted send
outcomes can remain unknown.

Capabilities, timer instances, and receipts belong to a socket generation.
Old capabilities cannot submit to a replacement writer. Listener restart
restores desired memberships from `TableOwner`; an ephemeral port can change.
Logical service deletion removes stored membership intent.

## Backends and compatibility

`io_backend: :gen_udp` uses the effective `inet_backend: :inet | :socket` driver.
`io_backend: :socket_native` uses direct public OTP `:socket` APIs and Linux
receive/send control encodings. It never treats a GenUDP descriptor as a native
socket. Native startup requires the datagram API, Linux, and OTP 27 or newer;
the verified native runtime versions are OTP 27 and 28.

`Endpoint.capabilities/1` reports adapter/driver identity, family, platform,
runtime, and each capability's supported/enabled status and unavailable reason.
`required_capabilities` rejects startup when a requirement is unavailable;
`required_metadata` rejects individual packets missing selected fields.
Membership success alone does not prove interface isolation. See the
[backend matrix](migration.md#backend-and-capability-matrix).

Legacy `Abyss.Handler`, custom `start_link/1` handlers, and
`Abyss.DatagramDispatcher` remain separate interfaces. A datagram handler
cannot be combined with a legacy handler or dispatcher. Dispatcher writer and
receipt infrastructure is reused internally, without adopting legacy
dispatcher callback queues. QUIC keeps its existing service and engine-owned
connection state.
