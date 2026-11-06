# UDP broadcast and multicast

Abyss receives complete UDP datagrams, including empty payloads, and sends from
the endpoint's socket. Broadcast and multicast addressing are independent of
callback execution policy. Local send completion does not acknowledge network
delivery, and ordinary UDP requires no QUIC engine.

## Start an endpoint

The datagram API is available in Abyss 0.8. Implement `Abyss.DatagramHandler`
and return bounded actions; the runtime owns the socket and executes the sends.
The following examples use unprivileged ports. Replace `test0` with an existing
test interface and select the destination from your actual network configuration.

```elixir
defmodule DatagramEcho do
  @behaviour Abyss.DatagramHandler

  @impl true
  def init(_options, _context), do: {:ok, 0}

  @impl true
  def handle_datagram(datagram, count) do
    {:ok, count + 1, [{:reply, datagram.payload}]}
  end
end

{:ok, broadcast_endpoint} = Abyss.Endpoint.start_link(
  datagram_handler: DatagramEcho,
  execution: :endpoint,
  port: 49_001,
  transport_module: Abyss.Transport.UDP.Broadcast,
  transport_options: [ip: {0, 0, 0, 0}],
  num_connections: 32
)

{:ok, multicast_endpoint} = Abyss.Endpoint.start_link(
  datagram_handler: DatagramEcho,
  execution: :endpoint,
  port: 49_002,
  transport_module: Abyss.Transport.UDP.Multicast,
  transport_options: [
    ip: {0, 0, 0, 0},
    add_membership: {{239, 255, 42, 1}, "test0"},
    add_membership: {{239, 255, 42, 2}, "test0"},
    multicast_if: "test0",
    multicast_loop: true,
    multicast_ttl: 1
  ],
  num_connections: 32
)

{:ok, {address, port}} = Abyss.Endpoint.local_endpoint(multicast_endpoint)
```

`{:reply, payload}` sends a unicast reply to the observed peer and source port.
A group reply requires an explicit `{:send, sockaddr, payload}` action, such as
`{:send, %{family: :inet, addr: {239, 255, 42, 1}, port: 49_002}, payload}`.
Broadcast permission, receive membership and outgoing interface selection are
separate socket settings; a sender does not need to join a group.

Choose `:per_datagram` for independent invocations, `:endpoint` for one serialized
state, or `:keyed` with an explicit application `route_key`. Each datagram
endpoint has one receiver. Callback execution has finite item, byte and deadline
bounds; see the [runtime contract](udp-runtime/design.md) and
[migration guide](udp-runtime/migration.md) for actions, timers and configuration.

## Memberships

```elixir
:ok = Abyss.Endpoint.join(multicast_endpoint, {{239, 255, 42, 3}, "test0"})
Abyss.Endpoint.memberships(multicast_endpoint)
:ok = Abyss.Endpoint.leave(multicast_endpoint, {{239, 255, 42, 3}, "test0"})
```

Membership APIs stay responsive without incoming packets. Memberships are
canonicalized; duplicate joins and absent leaves are idempotent. The same group
on different interfaces remains distinct. Desired memberships are bounded to 64
entries, updated only after a successful OS operation, and restored on listener
restart. Pause retains existing joins; stop closes all socket memberships.
Startup applies membership operations individually after opening the socket and
closes the temporary socket if a join fails.

IPv4 selectors are local IPv4 addresses, interface names, `:any`, or
`{0, 0, 0, 0}`. Interface names must exist and be up; invalid addresses and family
mismatches fail explicitly. An explicitly selected missing interface returns
`{:error, :enodev}`. `multicast_if` selects outgoing traffic independently of the
receiving `add_membership` interface.

## IPv6 and scope

IPv6 has no broadcast. Use an IPv6 binding and an existing positive interface
index or interface name:

```elixir
group6 = {0xFF02, 0, 0, 0, 0, 0, 0, 42}
{:ok, endpoint6} = Abyss.Endpoint.start_link(
  datagram_handler: DatagramEcho,
  execution: :endpoint,
  port: 49_003,
  transport_module: Abyss.Transport.UDP.Multicast,
  transport_options: [
    :inet6,
    {:ip, {0, 0, 0, 0, 0, 0, 0, 0}},
    {:add_membership, {group6, "test0"}},
    {:multicast_if, "test0"},
    {:multicast_ttl, 1},
    {:multicast_loop, true}
  ]
)

Abyss.Client.broadcast(group6, 49_003, "ipv6",
  interface: "test0", inet_backend: :inet, hop_limit: 1, loopback: true)
```

Link-local sends require an explicit scope, selected by `interface: "test0"` or
`interface: index, scope_id: index`. Conflicting or missing scope fails rather
than discarding it. GenUDP's `:inet` driver uses OTP's scoped sockaddr API;
GenUDP's `:socket` driver returns
`{:error, {:unsupported_capability, :scoped_sockaddr_send, :socket}}` on the tested
OTP 27/28 runtimes. Client helpers reject this configuration before socket open.
The direct native backend supports scoped endpoint sends on Linux OTP 27/28;
it is distinct from the GenUDP socket driver.

IPv6 multicast interface, hop and loopback controls use tested Linux socket
options. Other platforms return an unsupported-capability error. Runtime or
backend limitations are reported explicitly; no alternative route is selected.

## Client queries and subscriptions

```elixir
Abyss.Client.broadcast({255, 255, 255, 255}, 49_001, "limited",
  interface: "test0", source: {192, 0, 2, 1})

# Supply the directed broadcast address derived from the actual subnet.
Abyss.Client.broadcast({192, 0, 2, 255}, 49_001, "directed",
  interface: "test0", source: {192, 0, 2, 1})

# An ephemeral sender collects replies addressed to its source port.
Abyss.Client.multicast_query({239, 255, 42, 1}, 49_002, "query", 500,
  interface: "test0", source: {192, 0, 2, 1},
  reply_mode: :unicast, max_responses: 32, max_response_bytes: 65_536)

# Collect group replies by binding the group port and joining before sending.
Abyss.Client.multicast_query({239, 255, 42, 1}, 49_002, "query", 500,
  interface: "test0", membership_interface: "test0",
  reply_mode: :multicast, bind_port: 49_002, loopback: true)

Abyss.Client.subscribe_broadcast({239, 255, 42, 1}, 49_002, 500,
  membership_interface: "test0", with_metadata: true,
  on_ready: fn endpoint -> IO.inspect(endpoint, label: "subscription ready") end)
```

Queries default to unicast replies; choosing multicast collection does not change
how a server replies. Subscription/group-reply sockets bind wildcard by default;
`membership_interface` selects reception, while `interface` selects egress.
`source` binds outbound queries. `ttl` / `hop_limit` defaults to 1 and `loopback`
to true. No application-specific TTL is imposed.

Explicit unicast/broadcast device selection uses Linux `bind_to_device`. OS
permission and backend errors are returned. Other platforms reject explicit
device binding. Multicast egress uses the OS multicast interface setting.

Single-response helpers return `{:ok, binary}` or `{:error, reason}`.
`multicast_query` returns `{:ok, [{peer, port, payload}]}`; actual ancillary fields
extend each tuple to `{peer, port, ancillary, payload}`. Subscriptions return
binaries by default, or peer tuples with `with_metadata: true`.

Collectors use one absolute finite response deadline and default to at most 256
responses and 1,048,576 payload bytes. Empty payloads consume an item. Bounds must
be positive integers; infinite or negative collection timeouts are invalid.
Overflow returns `{:error, {:response_limit, :count | :bytes}, partial}` without
retaining the overflowing packet. Socket errors return `{:error, reason, partial}`;
deadline expiry returns `{:ok, collected}`. Temporary sockets close on every exit,
including callback exceptions. Send failure is checked before waiting for replies.

## Pause, stop and send outcomes

`Abyss.Endpoint.pause(endpoint)` stops admission while accepted work can reply
from the existing socket. It does not flush the kernel queue: queued packets may
be received after `resume/1`. Desired memberships survive pause and restore on
listener restart. `Abyss.Endpoint.stop(endpoint, timeout_ms)` shares one absolute
deadline across ingress, accepted work, sends and forced cleanup.

Capabilities and receipts belong to one socket generation. `Endpoint.send/4`
returns `{:ok, ref}` for admission; `Endpoint.await/3` reports local completion,
definite error or an unknown outcome. A timeout does not cancel accepted sends or
authorize retry. Results expire after finite count/time bounds. Writer limits
include queued and in-flight work; UDP provides no network backpressure or peer
acknowledgement. OS receive-queue drops cannot be counted reliably.

## Metadata and backend capabilities

Wildcard `sockname` identifies the binding, not a packet's destination or ingress
interface. GenUDP preserves only peer/ancillary fields actually returned by OTP.
It does not infer metadata from membership lists. The native backend exposes
observed destination, interface and usable local-source metadata; strict replies
require this metadata and per-message source controls.

Use `Abyss.Endpoint.capabilities/1` to inspect the actual adapter and driver.
`required_capabilities` rejects an incapable endpoint at startup, while
`required_metadata` rejects individual inputs missing selected fields. Details
and all capability names are in the [migration guide](udp-runtime/migration.md).

| Capability | GenUDP inet | GenUDP socket | Direct native |
| --- | --- | --- | --- |
| IPv4 broadcast/multicast | Supported | Supported on Linux | Linux OTP 27/28 |
| IPv6 scoped endpoint send | Supported | Explicitly unsupported on OTP 27/28 | Linux OTP 27/28 |
| Strict original-source/interface reply | Unavailable | Unavailable | Linux OTP 27/28 |
| Strict IPv4 group filtering | Linux explicit option | Unavailable | Linux explicit option |
| Strict interface receive filtering | Unavailable | Unavailable | Unimplemented |

Enable `strict_group_filter: true` only with a supported backend. GenUDP's inet
implementation uses Linux `IP_MULTICAST_ALL=0` for IPv4. IPv6 strict group filtering
is unsupported. Basic OS membership can deliver traffic for groups joined by
another socket; membership alone does not promise per-interface receive isolation.
Payload bytes are never used to deduplicate legitimate deliveries.

Transport option normalization keeps the first scalar user value. Conflicting
family or mode aliases fail; membership operations and raw options preserve
meaningful ordering. Linux GenUDP multicast controls/memberships use explicit OS
option mappings where generic OTP options do not represent the requested IPv4 or
IPv6 behavior. Untested platform/backend combinations return capability errors.

## Legacy compatibility

`Abyss.start_link(handler_module: Module, ...)` and the `Abyss.join/leave/memberships`
APIs retain their contracts. Legacy handlers receive `{peer, port, payload}` and
send through their configured transport; they must not close the shared socket.
Legacy broadcast callbacks remain one-shot, including cleanup with returned
application state. In ordinary legacy mode `{:continue, state}` retains that
invocation; it does not route the next packet from the peer back to it.

Legacy broadcast/multicast and ephemeral endpoints also use one receive socket;
automatic socket scaling is rejected. The [legacy dispatcher](dispatcher.md)
supports multicast memberships with `broadcast: false`, but rejects Broadcast
transport, `broadcast: true` and direct native sockets. New datagram execution
supports broadcast/multicast with each of its three policies.

Legacy admission uses drop-new limits shared by reserved starts and live handlers.
Reception uses one `active: :once` credit and a complete datagram buffer before
checking `max_packet_size`. Idle deadlines advance only on explicit handler
progress; stale timer tokens are ignored. Handler memory sampling reports bytes
but cannot provide a strict whole-VM memory bound.

Supported transport sends report local outcomes and byte counts per server;
direct `:gen_udp.send` bypasses this accounting. Handler termination does not
establish that a reply was sent.

## Validation records

Current implementation and release checks are retained in the
[UDP runtime acceptance archive](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/udp-runtime/acceptance.md).
The [UDP hardening archive](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/udp-hardening-acceptance.md)
and [OTP multicast defect notes](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/udp-otp-multicast-defects.md)
record historical gate results and reproductions. Portable loopback tests verify
library paths; isolated independent-peer fixtures provide interface, hop-limit,
loopback and source-selection evidence. Historical results apply to their
recorded source and environments.
