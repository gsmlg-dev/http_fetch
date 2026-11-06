# Architecture

Abyss is a supervised UDP service host. It owns sockets, bounds admitted work, and separates network I/O from application callbacks. Datagram handlers, legacy handlers and protocol dispatchers share the host, but have different execution contracts.

## Application and service supervision

The `:abyss` application starts a long-lived table owner. Each call to `Abyss.start_link/1` or `Abyss.Endpoint.start_link/1` starts a separate service supervisor.

```text
Abyss.Supervisor                         one_for_one
└── Abyss.TableOwner                     shared tables and monitored accounting

Abyss.Server                            rest_for_one; one per service
├── Abyss.ListenerPool                   one_for_one
│   └── Abyss.Listener                  socket owner(s)
├── DynamicSupervisor                   legacy handler children
├── Task                                activates listeners
├── Abyss.ListenerPoolScaler            only when dynamic_listeners is enabled
└── Abyss.ShutdownListener               drain and service cleanup
```

`TableOwner` keeps listener caches, desired memberships, telemetry scopes and admission accounting alive independently of individual listeners. Its monitors clean up registrations and protected work when owners or runtime components die.

The listener pool restarts a failed listener independently. The service supervisor uses `:rest_for_one`, so the order of its children matters: loss of an earlier child also restarts later children. Runtime workers and writer components are linked or monitored by their owners; they are not additional top-level server supervisor children.

## Socket ownership and topology

`Abyss.Listener` opens and owns the socket, arms reception, normalizes packets, manages memberships, and coordinates pause and drain. Application callbacks do not execute in the socket owner.

| Service configuration | Receiving sockets |
| --- | --- |
| Datagram handler | Exactly one; multiple or dynamic listeners are rejected |
| Legacy ephemeral port (`port: 0`) | One |
| Broadcast, multicast transport, or configured startup memberships | One |
| Fixed-port legacy unicast | Configurable pool, default 100 listeners |

Dynamic scaling is limited to eligible legacy fixed-port unicast services. Increasing listener count is not a universal throughput improvement. The shared `num_connections` ceiling applies to the logical service across listeners.

GenUDP reception uses active-once credits. The direct native adapter uses OTP `:socket` receive readiness through the existing owner. Both paths keep complete datagram boundaries and preserve empty payloads.

## Datagram runtime flow

```text
UDP socket
  → Listener: normalize Datagram, validate size and required metadata
  → DatagramRuntime: reserve bounded input, select execution key
  → DatagramWorker: initialize state and invoke handler callback
  → validate complete action list
  → bounded effects: timers or Admission → Writer → original socket
  → local send outcomes become managed events for persistent state
```

The runtime coordinator tracks input items/bytes, workers, routing helpers, timers and receipts. Input accounting includes queued and in-flight work. It retains protected quotas until the actual helper or worker exits, rather than treating a logical completion notification as reclamation.

`Abyss.DatagramHandler` receives immutable `Abyss.Datagram` values and returns finite actions. Its execution policy controls state ownership:

| Policy | State lifetime and ordering |
| --- | --- |
| `:per_datagram` | Initialize, process and terminate for each admitted datagram |
| `:endpoint` | One lazily initialized serialized state for the current socket generation |
| `:keyed` | Application-defined route key; same-key work serialized, different keys may progress concurrently |

Routing, initialization, callbacks, termination and effects have configured deadlines. Persistent workers can receive timer and send-result events. Managed events also consume input quota and can be dropped under overload. Local serialization does not imply UDP delivery or wire ordering. See the [runtime contract](udp-runtime/design.md) for the precise actions and bounds.

## Legacy handlers and dispatchers

The legacy path reserves a service-wide input slot, asks a fixed starter to initialize a handler, validates the startup token and deadline, then delivers `{ip, port, payload}`. The default handler runs as a `DynamicSupervisor` child. A `{:continue, state}` result retains that invocation process; later packets from the same peer create new invocations. Broadcast handling is one-shot. Overload drops new work without spawning a task for every rejection.

A configured `Abyss.DatagramDispatcher` instead keeps one protocol callback state per listener. It can register generic routes to application processes and uses the bounded independent writer. Its application-owned input queues do not gain the datagram runtime's bounds. Broadcast dispatching and native direct sockets are rejected for this legacy API. See the [dispatcher guide](dispatcher.md).

## Backend and optional dependency boundaries

`io_backend: :gen_udp` selects GenUDP and resolves its `:inet` or `:socket` driver. `io_backend: :socket_native` selects direct OTP `:socket`; it is a different adapter, not the GenUDP socket driver. Native operation is tested on Linux OTP 27/28 and requires the datagram API. It provides destination/interface metadata and strict original-source replies. Portable GenUDP does not provide these guarantees.

`Abyss.QUIC` owns a separate service host using the dispatcher writer machinery. The optional `elixir_quic` engine owns QUIC connections, CIDs, recovery and TLS integration; ordinary UDP does not load it. The UDP runtime does not parse QUIC or implement stream semantics. See the [QUIC guide](quic-service.md).

The core package does not compile Rust. DHCP raw-socket functionality is supplied only by an explicitly installed `abyss_raw` package. `Abyss.DhcpSocket.Native` is a lazy facade and reports a missing optional dependency when it is absent. Installation details are in the [migration guide](udp-runtime/migration.md).

## Lifecycle and failure boundaries

A logical endpoint has a stable service identity and a replaceable socket generation. Send capabilities, receipts and timers belong to that generation; old-generation operations fail rather than acting on a replacement socket. Restart can change an ephemeral port. Desired memberships are restored by the replacement owner and removed when the logical service is deleted.

Pause stops admission and keeps the socket available for accepted replies. It does not flush the kernel receive queue. Stop uses one overall drain deadline, then forces remaining cleanup and closes I/O. Datagram runtime draining, legacy handler completion and QUIC application draining have distinct contracts; see [operations](operations.md).

A writer or admission failure invalidates that generation and fails its host closed. Callback failures remain bounded by worker and watchdog ownership. Send admission is separate from local socket completion; an unknown outcome must not trigger a blind retry. None of these contracts guarantees remote receipt, total application memory bounds, or immediate native reclamation from a logical counter alone.
