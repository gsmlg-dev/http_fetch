# Abyss

[![release](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml)
[![Hex.pm](https://img.shields.io/hexpm/v/abyss.svg)](https://hex.pm/packages/abyss)
[![Documentation](https://img.shields.io/badge/documentation-gray)](https://hexdocs.pm/abyss)

Abyss is a supervised Elixir UDP service library. It provides socket ownership, bounded admission, pluggable handlers, broadcast/multicast support and lifecycle control. The core package does not require Rust, TLS or a QUIC engine.

## Installation

Requires Elixir 1.18 or later and Erlang/OTP 27 or later.

```elixir
def deps do
  [
    {:abyss, "== 1.0.0-rc.4"}
  ]
end
```

QUIC applications explicitly install `elixir_quic` and its engine dependencies. DHCP and raw ARP users explicitly add `{:abyss_raw, "== 1.0.0-rc.4"}`. Both packages share each release version; core does not depend on the add-on. See the [QUIC guide](docs/quic-service.md) and [DHCP migration](docs/udp-runtime/migration.md).

## Datagram echo

Use the datagram API for immutable packet values and finite reply/send/timer actions. This example keeps one serialized endpoint state:

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
  port: 1234,
  transport_options: [ip: {127, 0, 0, 1}]
)

{:ok, {address, port}} = Abyss.Endpoint.local_endpoint(endpoint)
```

From another terminal:

```sh
printf 'hello' | nc -4 -u -w1 127.0.0.1 1234
```

Choose `:per_datagram` (the default) for a fresh state per input, `:endpoint` for serialized endpoint state, or `:keyed` with an explicit `route_key` for application-defined state partitions. Broadcast and multicast addressing are independent of execution policy. Endpoint state persists for its socket generation; keyed state is subject to idle expiry. Both retain configured work limits.

A reply action uses the original endpoint socket. Send admission and local completion are distinct; neither establishes peer receipt. See [migration and backend capabilities](docs/udp-runtime/migration.md) and the [runtime contract](docs/udp-runtime/design.md).

## Existing handler API

Legacy handlers continue to receive `{ip, port, payload}` and access the shared socket through their state:

```elixir
defmodule LegacyEcho do
  use Abyss.Handler

  @impl true
  def handle_data({ip, port, payload}, state) do
    :ok = Abyss.Transport.UDP.send(state.socket, ip, port, payload)
    {:close, state}
  end
end

{:ok, server} = Abyss.start_link(
  handler_module: LegacyEcho,
  port: 1235,
  num_listeners: 1,
  transport_options: [ip: {127, 0, 0, 1}]
)
```

Each accepted packet gets a separate invocation. `{:continue, state}` keeps that invocation alive without routing subsequent peer packets to it. Stateful protocols can use the [datagram API](docs/udp-runtime/migration.md), or retain an existing [dispatcher](docs/dispatcher.md).

## Documentation

The [documentation guide](docs/README.md) is the entry point for:

- [Architecture](docs/architecture.md): supervision, ownership and data flow.
- [UDP addressing and lifecycle](docs/udp-broadcast-multicast.md): clients, memberships, pause and drain.
- [Datagram runtime](docs/udp-runtime/design.md) and [migration](docs/udp-runtime/migration.md): callbacks, bounds, effects and backends.
- [Dispatcher and writer](docs/dispatcher.md): routing, send capabilities and receipts.
- [QUIC service](docs/quic-service.md): optional engine and application handlers.
- [Operations and development](docs/operations.md): inspection, telemetry and scoped checks.
- [Coordinated releases](docs/releases.md): version policy, package boundaries and publication recovery.

Source-attributed plans, diagnostics and release evidence are separated in the [historical archive](https://github.com/gsmlg-dev/abyss/tree/main/docs/archive). Current guides describe behavior; historical measurements do not imply a universal throughput improvement.

## Development

```sh
mix deps.get
mix docs --warnings-as-errors
mix format --check-formatted
```

Use [scoped verification commands](docs/operations.md) for the changed area. Independent network and optional-package gates are documented with their fixture prerequisites.

## License

[MIT](https://github.com/gsmlg-dev/http_fetch/blob/main/apps/abyss/LICENSE).
