# UDP datagram API migration

The datagram API is opt-in. Existing raw-socket handlers, transport calls,
memberships, dispatcher capabilities, and optional QUIC services keep their
contracts. This guide explains how to adopt `Abyss.DatagramHandler` and the
configuration boundaries of the current runtime. See [runtime design](design.md)
for ownership and lifecycle details.

## Start an endpoint

```elixir
defmodule Echo do
  @behaviour Abyss.DatagramHandler

  @impl true
  def init(_options, _context), do: {:ok, 0}

  @impl true
  def handle_datagram(datagram, count) do
    {:ok, count + 1, [{:reply, datagram.payload}]}
  end
end

{:ok, endpoint} = Abyss.Endpoint.start_link(
  datagram_handler: Echo,
  execution: :endpoint,
  port: 0,
  transport_options: [ip: {127, 0, 0, 1}]
)

{:ok, {address, port}} = Abyss.Endpoint.local_endpoint(endpoint)
```

Pass application options using `handler_options`; they become the first
argument to `init/2`. Its context contains endpoint identity, socket generation,
and the send capability. Callbacks receive a normalized `Abyss.Datagram` and
return application state and actions instead of owning the socket.

The runtime selects one listener automatically. Setting `num_listeners` to
anything other than `1`, enabling dynamic listeners, or combining
`datagram_handler` with `handler_module` or `datagram_dispatcher` is rejected.

## Choose state lifetime

| Execution | Use when |
|---|---|
| `:per_datagram` (default) | Each packet is independent; initialize and clean up for each admitted input |
| `:endpoint` | One application state should serialize datagrams and managed events throughout a socket generation |
| `:keyed` | Application-selected keys need independent serialized states |

For keyed execution, supply `route_key: fn datagram -> application_key end` or
`route_key: {Module, :function}`. For example, `fn datagram -> datagram.peer end`
explicitly chooses the complete peer sockaddr as the key. The runtime does not
create implicit peer sessions. Routing has a separate watchdog; different
active keys can progress concurrently, and same-key work is locally serialized.
This does not imply wire ordering or delivery.

Since the post-0.8.0 hardening patch, `:endpoint` state is initialized lazily and
persists through ordinary inactivity and pause/resume in the same generation.
`idle_timeout` governs only keyed eviction. This corrects 0.8.0, where endpoint
idleness could silently reset state and cancel long-delay timers.

Keyed workers still expire after `idle_timeout`; the next packet initializes
fresh state. Pending timers do not pin an idle key and are cancelled on
eviction. Endpoint stop/replacement, explicit handler stop/error, or callback
failure can retire state. Store durable data outside workers when it must
survive these events; failed callbacks do not recover unreturned state.
Legacy `{:continue, state}` keeps its invocation process alive; it
does not route subsequent peer packets back to that process. Legacy broadcast
processing remains one-shot.

## Configuration and limits

Top-level datagram options are:

| Option | Default | Purpose |
|---|---|---|
| `datagram_handler` | `nil` | Select the application-state API |
| `execution` | `:per_datagram` | Select state lifetime and routing |
| `route_key` | `nil` | Required for `:keyed`, rejected for other policies |
| `io_backend` | `:gen_udp` | Select GenUDP or direct native socket I/O |
| `runtime_options` | `[]` | Override finite runtime limits below |
| `required_capabilities` | `[]` | Require enabled adapter capabilities at startup |
| `required_metadata` | `[]` | Require observed fields on each received datagram |

`runtime_options` accepts only these finite positive integer overrides:

| Option | Default |
|---|---:|
| `max_queue`, `max_keys`, `max_timers` | 128 |
| `max_queue_bytes`, `max_action_bytes` | 1,048,576 bytes |
| `max_key_queue` | 32 |
| `max_key_queue_bytes` | 262,144 bytes |
| `max_key_bytes` | 1,024 bytes |
| `max_actions` | 32 |
| `init_timeout`, `callback_timeout`, `route_timeout` | 1,000 ms |
| `terminate_timeout`, `send_timeout` | 100 ms |
| `idle_timeout` (keyed eviction only) | 60,000 ms |

`num_connections` remains the shared service input ceiling (default 16,384).
The endpoint's `max_queue` and worker's `max_key_queue` count in-flight work as
well as queued work. Byte quotas include serialized datagram/event metadata.
Key-worker limits apply to all execution policies, including per-datagram
workers. Full admission drops new work.

The listener also applies `max_packet_size` (default 8,192 payload bytes).
`dispatcher_max_queue` (128) and `dispatcher_max_queue_bytes` (1,048,576) bound
queued and in-flight egress, including structured addressing controls. These
writer limits also apply to datagram handlers without a legacy dispatcher.

Timer token/value serialized size is at most 4,096 bytes; delay is an unsigned
32-bit millisecond value. Application state and arbitrary local mailbox
messages are application responsibilities; runtime quotas are not a whole-VM
memory guarantee.

## Return actions and handle events

Callbacks return `{:ok, state, actions}`, `{:stop, reason, state, actions}`, or
`{:error, reason, state}`. Supported actions are:

| Action | Effect |
|---|---|
| `{:reply, binary}` | Reply to the current datagram's observed peer using normal routing |
| `{:reply, binary, :strict}` | Require the original local source/interface through native send controls |
| `{:send, sockaddr, binary}` | Send to an explicit sockaddr map |
| `{:timer, token, delay_ms, value}` | Create or replace a managed timer for this worker |
| `{:cancel_timer, token}` | Cancel this worker's managed timer |

All actions are validated before effects begin. Multiple valid effects are not
atomic. Timer actions require a persistent policy. A managed event has no
current datagram, so its callback must use `{:send, sockaddr, binary}` instead
of `{:reply, binary}`.

Optional `handle_event/2` receives `{:timer, token, value}` and
`{:send_outcomes, generation, input_token, outcomes}`. These events use the same
input credit and worker queue as datagrams; overload can drop them. Outcome
events do not recursively generate outcome events. `Endpoint.info/1` retains
action receipts independently of worker lifetime, up to 256 entries for five
seconds within the current generation.

## Send outside a callback

Use the capability returned by `Endpoint.capability/1` or supplied to `init/2`:

```elixir
{:ok, capability} = Abyss.Endpoint.capability(endpoint)
{:ok, peer_socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
{:ok, {_peer_address, peer_port}} = :inet.sockname(peer_socket)
destination = %{family: :inet, addr: {127, 0, 0, 1}, port: peer_port}
{:ok, ref} = Abyss.Endpoint.send(capability, destination, "hello", 100)
result = Abyss.Endpoint.await(capability, ref, 100)
{:ok, {_address, _port, "hello"}} = :gen_udp.recv(peer_socket, 0, 1_000)
:gen_udp.close(peer_socket)
```

`{:ok, ref}` means admission. Await returns local completion
`{:ok, monotonic_microseconds}`, definite failure `{:error, reason}`, or
`{:unknown, ref}`. Local completion does not prove delivery. Timeout does not
cancel accepted sends and must not cause blind retries. Writer results are also
retained for up to 256 references/five seconds; expiry does not establish that
a packet was unsent. Supported GenUDP and Linux native sends (including strict
replies) now share actual local-outcome counters and send events. Native sends
were missing that instrumentation in 0.8.0. Wait timeouts, receipt reads and
pre-send validation/admission rejection do not add send counts.

## Inspect drops

The post-0.8.0 hardening patch corrects public drop totals: deferred routing,
key and queue rejection remains visible, and synchronous rejection counts once.
`Endpoint.info/1` and `status/1` expose current-generation `received`, `dropped`
and `drop_counts: %{ingress: count, runtime: count}`. `dropped` is their sum.
`internal_events_rejected: %{timer: count, send_outcomes: count}` records
managed-event overload separately from network loss.

Network-drop byte telemetry uses payload length, excluding serialized metadata.
Internal rejection has its own counters/event and retains serialized event bytes.
Callback failure, socket-send failure, teardown discard and unknown kernel queue
loss are separate from these network admission drops. Counts survive graceful
and forced drain while that generation remains inspectable. Public counters reset on
generation replacement; telemetry retains logical-server lifetime. Compare
matching interval deltas and see [operations](../operations.md) for event names.
Legacy listener statistics keep their prior contract.

## Pause, stop, and socket replacement

`Endpoint.pause/1` stops admission of received datagrams while accepted work,
managed events, and egress can continue. It retains the socket and does not
flush its kernel receive queue. `Endpoint.resume/1` resumes receiving.

`Endpoint.stop/2` shares one absolute deadline across input work, egress, and
cleanup. Drain cancels outstanding managed timers; deadline expiry forces
retirement. Accepted outcomes can remain unknown. Socket replacement
invalidates old capabilities and timers, and an ephemeral port can change.
Desired memberships restore through `TableOwner`; logical service deletion
removes them.

## Backend and capability matrix

The default `io_backend: :gen_udp` has a separate driver selected through
`transport_options: [inet_backend: :inet]` or `:socket`. If absent, the resolver
uses the node's boot-time default and then the OTP default. Already-opened
sockets retain their actual driver identity.

`io_backend: :socket_native` uses direct OTP `:socket` APIs. Do not combine it
with `inet_backend`. Native sockets require a datagram handler, Linux, and OTP
27 or newer; native traffic/control validation covers OTP 27 and 28.

| Linux OTP 27/28 capability | GenUDP inet | GenUDP socket | Direct native |
|---|---|---|---|
| Complete/empty IPv4 UDP and ordinary IPv6 UDP | Supported | Supported | Supported |
| IPv4 broadcast/multicast | Supported | Supported | Supported |
| IPv6 scoped multicast | Verified | Unavailable | Verified |
| Destination, ingress interface, local address metadata | Unavailable | Unavailable | IPv4/IPv6 receive controls |
| TTL/traffic metadata | When enabled and supported | Runtime dependent | Enabled by default |
| Strict original-source/interface reply | Unavailable | Unavailable | IPv4/IPv6 per-message controls |
| Strict IPv4 group filter | Linux explicit option | Unavailable | Explicit option |
| Strict interface receive filter | Unavailable | Unavailable | Unimplemented |
| Legacy raw-socket handlers/dispatcher | Supported | Supported | Rejected |

Native receive buffers are 65,535 payload bytes and 4,096 control bytes; the
listener's `max_packet_size` still applies. Payload truncation drops the packet.
Control truncation leaves unsafe metadata `nil`, causing strict reply failure
or admission rejection when required fields are missing. IPv4 packet
destination, usable local source, and interface are distinct. For IPv6 group
traffic the local source is selected from the observed ingress interface,
preserving scope.

`Endpoint.capabilities/1` reports adapter, driver, family, platform/runtime,
and each capability's `supported`, `enabled`, and unavailable `reason`.
`required_capabilities: [:destination, :source_control]` rejects startup unless
enabled. `required_metadata: [:destination, :interface_index, :local_address]`
drops each packet missing these fields with a measurable reason. Membership
alone never proves interface isolation. Route reply uses the peer; strict reply
uses the original socket's source/interface controls. Group replies require an
explicit destination.

The declared Elixir requirement remains `~> 1.13`; the validated runtime
matrix uses Elixir 1.18 with OTP 27/28. Portable GenUDP macOS coverage does not
imply native macOS support. See the archived
[acceptance record](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/udp-runtime/acceptance.md)
for release validation and its exact platform scope.

## Legacy dispatcher and transport helpers

| Configuration | Legacy dispatcher | Datagram API |
|---|---|---|
| UDP/Unicast, `broadcast: false` | Supported | Supported |
| Multicast memberships, `broadcast: false` | Supported | Supported |
| Broadcast transport or `broadcast: true` | Rejected | Supported |
| Direct native socket | Rejected | Supported |

Legacy dispatcher callback-owned input queues are outside the handler runtime's
bounds; its writer/admission/outcome contracts remain independent. See
[dispatcher guidance](../dispatcher.md). QUIC retains its existing service and
engine-owned protocol state; UDP execution policies do not replace QUIC
application draining.

Unicast request/response helpers reject responses from a wrong resolved
address/port under one absolute response deadline. DNS/socket setup remains
outside that response budget. Broadcast/multicast helpers retain
multi-responder behavior. Directed broadcast requires subnet context; select
an explicit response policy for ambiguous one-to-many use. See
[broadcast and multicast guidance](../udp-broadcast-multicast.md).

## Optional DHCP dependency

Ordinary core installation does not compile Rust or load a native artifact.
The former `Abyss.DhcpSocket.Native` facade was removed. Without the optional
package `AbyssDhcpSocket.Native` is not loaded; guard with
`Code.ensure_loaded?(AbyssDhcpSocket.Native)`.

DHCP and raw ARP users explicitly install the add-on at the shared release version:

```elixir
{:abyss, "~> 0.9.0"},
{:abyss_raw, "~> 0.9.0"}
```

The standalone source package is `packages/abyss_raw` from the monorepo root
(`../../packages/abyss_raw` relative to this app). Its manifest and Hex
archive contain everything needed to build it without the parent checkout.
Core declares neither this dependency nor Rustler, and the add-on does not
depend on core.

Call `AbyssDhcpSocket.Native` (Rust crate `dhcp_socket`) directly. There is one
NIF loader; its OTP application and `priv/native` artifact belong to
`:abyss_raw`. `open/2` returns the opaque resource directly, and owner messages
carry that resource as their second element: `{:dhcp_rx, socket, binary}`,
`{:arp_rx, socket, binary}`, `{:dhcp_socket_down, socket, reason}`,
`{:arp_socket_down, socket, reason}`.
The package requires Cargo/Rust and the existing platform-specific raw ARP
and interface-bind capabilities. See the
[package guidance](https://github.com/gsmlg-dev/http_fetch/blob/main/packages/abyss_raw/README.md)
and [coordinated release policy](../releases.md).
