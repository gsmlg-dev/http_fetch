# Hell

[![CI](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/ci.yml)
[![Tests](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml/badge.svg)](https://github.com/gsmlg-dev/http_fetch/actions/workflows/test.yml)

Hell is a fork of [Thousand Island](https://github.com/mtrudel/thousand_island),
originally developed by Mat Trudel and contributors. The initial identity
migration, based on upstream commit `e3eb2a7a05f98d79436abcefd8c954da2f8b05c0`,
preserved upstream runtime behavior. Hell `0.1.1` adds a narrow shutdown fix that
waits for acceptor cleanup before pool teardown; see [MIGRATION.md](MIGRATION.md)
for its shutdown latency implications. Hell `0.1.2` fixes supervisor recovery,
socket handoff cleanup, TLS upgrade timeouts and transport option handling.
Hell `0.1.3` adds public owner-side read-idle timeout transitions for persistent
connections through `Hell.Handler.set_read_timeout/2`.
Existing handler and required transport callbacks remain compatible. The Elixir
namespace is `Hell`; the OTP
application and Hex package are `hell`; the repository is
[`gsmlg-dev/http_fetch/apps/hell`](https://github.com/gsmlg-dev/http_fetch/tree/main/apps/hell).

The standalone source was imported from `gsmlg-dev/hell` at
`4fb5d53a1b2acfb5afc9b1ceba65fdc52d61ef83` (version `0.1.3`).
The library implementation and public API are preserved. `Hell.Transports.SSL`
now runs on the umbrella `ex_ssl` engine (TLS 1.3 only) instead of OTP `:ssl`;
see the changelog for the breaking differences.
From the umbrella root, run `mix test apps/hell/test --include integration`
for the complete Hell suite; default tests exclude real socket integration.
See the root migration report for current validation and release tooling.
`RELEASE.md` and `VERIFICATION.md` retain the standalone repository history.

The upstream baseline version is `1.5.0`; Hell `0.1.0` was published to Hex
by the fork maintainer. Subsequent versions use a gated manual workflow for publication.
Hell requires Elixir `>= 1.18.0`. No historical
Thousand Island release is being relabeled as a Hell release. See
[MIGRATION.md](MIGRATION.md) before replacing an existing Thousand Island dependency.

Hell is a modern, pure Elixir socket server, inspired heavily by
[ranch](https://github.com/ninenines/ranch). It aims to be easy to understand
and reason about, while also being at least as stable and performant as alternatives.
Upstream's informal tests placed ranch and Thousand Island at roughly the same
level of performance and overhead; this fork preserves that implementation.

Hell is written entirely in Elixir, and is nearly dependency-free (the
only library used is [telemetry](https://github.com/beam-telemetry/telemetry)).
The application strongly embraces OTP design principles, and emphasizes readable,
simple code. The hope is that as much as Hell is capable of backing
the most demanding of services, it is also useful as a simple and approachable
reference for idiomatic OTP design patterns.

## Usage

Hell is implemented as a supervision tree which is intended to be hosted
inside a host application or a higher-level protocol library. Upstream Thousand
Island is used by libraries such as [Bandit](https://github.com/mtrudel/bandit);
those integrations require an explicit migration to use Hell. Aside from
supervising the Hell process tree, applications interact with Hell primarily via the
[`Hell.Handler`](lib/hell/handler.ex) behaviour.

### Handlers

The [`Hell.Handler`](lib/hell/handler.ex) behaviour defines the interface that Hell
uses to pass [`Hell.Socket`](lib/hell/socket.ex)s up to the application level; together they
form the primary interface that most applications will have with Hell.
Hell comes with a few simple protocol handlers to serve as examples;
these can be found in the [examples](https://github.com/gsmlg-dev/http_fetch/tree/main/apps/hell/examples)
folder of this project. A simple implementation would look like this:

```elixir
defmodule Echo do
  use Hell.Handler

  @impl Hell.Handler
  def handle_data(data, socket, state) do
    Hell.Socket.send(socket, data)
    {:continue, state}
  end
end

{:ok, pid} = Hell.start_link(port: 1234, handler_module: Echo)
```

For more information, please consult the [`Hell.Handler`](lib/hell/handler.ex) documentation.

### Starting a Hell Server

Hell servers exist as a supervision tree, and are started by a call
to
[`Hell.start_link/1`](lib/hell.ex).
There are a number of options supported; for a complete description, consult the
[Hell
docs](lib/hell.ex).

### Connection Draining & Shutdown

The `Hell.Server` process is just a standard `Supervisor`, so all the
usual rules regarding shutdown and shutdown timeouts apply. Immediately upon
beginning the shutdown sequence the `Hell.ShutdownListener` will cause
the listening socket to shut down, which in turn will cause all of the `Acceptor`
processes to shut down as well. At this point all that is left in the supervision
tree are several layers of Supervisors and whatever `Handler` processes were
in progress when shutdown was initiated. At this point, standard Supervisor shutdown
timeout semantics give existing connections a chance to finish things up. `Handler`
processes trap exit, so they continue running beyond shutdown until they either
complete or are `:brutal_kill`ed after their shutdown timeout expires.

The `shutdown_timeout` configuration option allows for fine grained control of
the shutdown timeout value. It defaults to 15000 ms.

### Logging & Telemetry

As a low-level library, Hell purposely does not do any inline
logging of any kind. The [`Hell.Logger`](lib/hell/logger.ex) module defines a number of
functions to aid in tracing connections at various log levels, and such logging
can be dynamically enabled and disabled against an already running server. This
logging is backed by telemetry events internally.

Hell emits a rich set of telemetry events including spans for each
server, acceptor process, and individual client connection. These telemetry
events are documented in the [`Hell.Telemetry`](lib/hell/telemetry.ex) module.

## Implementation Notes

At a top-level, a `Server` coordinates the processes involved in responding to
connections on a socket. A `Server` manages two top-level processes: a `Listener`
which is responsible for actually binding to the port and managing the resultant
listener socket, and an `AcceptorPoolSupervisor` which is responsible for managing
a pool of `AcceptorSupervisor` processes.

Each `AcceptorSupervisor` process (there are 100 by default) manages two processes:
an `Acceptor` which accepts connections made to the server's listener socket,
and a `DynamicSupervisor` which supervises the processes backing individual
client connections. Every time a client connects to the server's port, one of
the `Acceptor`s receives the connection in the form of a socket. It then creates
a new process based on the configured handler to manage this connection, and
immediately waits for another connection. It is worth noting that `Acceptor`
processes are long-lived, and normally live for the entire period that the
`Server` is running.

A handler process is tied to the lifecycle of a client connection, and is
only started when a client connects. The length of its lifetime beyond that of the
underlying connection is dependent on the behaviour of the configured Handler module.
In typical cases its lifetime is directly related to that of the underlying connection.

This hierarchical approach reduces the time connections spend waiting to be accepted,
and also reduces contention for `DynamicSupervisor` access when creating new
`Handler` processes. Each `AcceptorSupervisor` subtree functions nearly
autonomously, improving scalability and crash resiliency.

Graphically, this shakes out like so:

```mermaid
graph TD;
  Server(Server: supervisor, rest_for_one)-->Listener;
  Server-->AcceptorPoolSupervisor(AcceptorPoolSupervisor: dynamic supervisor);
  AcceptorPoolSupervisor--1...n-->AcceptorSupervisor(AcceptorSupervisor: supervisor, rest_for_one)
  AcceptorSupervisor-->DynamicSupervisor
  AcceptorSupervisor-->Acceptor(Acceptor: task)
  DynamicSupervisor--1...n-->Handler(Handler: gen_server)
  Server-->ShutdownListener;
```

Hell does not use named processes or other 'global' state internally
(other than telemetry event names). It is completely supported for a single node
to host any number of `Server` processes each listening on a different port.

## Contributing

Contributions to Hell are very much welcome! Before undertaking any substantial work, please
open an issue on the project to discuss ideas and planned approaches so we can ensure we keep
progress moving in the same direction.

All contributors must agree and adhere to the project's [Code of
Conduct](https://github.com/gsmlg-dev/http_fetch/blob/main/apps/hell/CODE_OF_CONDUCT.md).

Security disclosures should be handled per Hell's published [security policy](https://github.com/gsmlg-dev/http_fetch/blob/main/apps/hell/SECURITY.md).

## Installation

For the `0.1.3` release, add the Hex package `hell` to your dependencies:

```elixir
def deps do
  [
    {:hell, "~> 0.1.3"}
  ]
end
```

Releases use workflow validation and the explicit publication gates in
[RELEASE.md](RELEASE.md). For local development, use a checkout:

```elixir
def deps do
  [
    {:hell, path: "../hell"}
  ]
end
```

A Git dependency can use
`{:hell, github: "gsmlg-dev/hell", ref: "<reviewed commit SHA>"}`. Replace the ref
with a reviewed fork commit, or use `tag: "v0.1.3"`. Historical upstream releases
remain documented in
[CHANGELOG.md](CHANGELOG.md) and retain their upstream identity.

[Hell 0.1.3 documentation](https://hexdocs.pm/hell/0.1.3/) accompanies the release.
Build documentation locally
with `mix docs` and open `doc/index.html`. [Source documentation](lib/hell.ex) and the [consumer migration guide](MIGRATION.md)
are available in this checkout.

## License

MIT. The [license](LICENSE) retains the original copyright notice for Mat Trudel
and all MIT terms. Hell fork contributions are copyright (c) 2026 GSMLG Limited.
Hell is derived from Thousand Island; historical upstream releases and contributor
credits remain in [CHANGELOG.md](CHANGELOG.md).
