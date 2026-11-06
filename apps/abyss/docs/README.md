# Documentation guide

These guides describe Abyss 0.9 and the architecture in the current source tree. Start with the [project README](../README.md) for installation and a runnable UDP echo.

See the [monorepo migration notes](monorepo.md) for source provenance, shared
build paths and explicit current-engine verification.

## Choose an API

| Application | API | Guide |
| --- | --- | --- |
| Stateless UDP or explicit persistent application state | `Abyss.DatagramHandler` and `Abyss.Endpoint` | [Datagram API and migration](udp-runtime/migration.md) |
| Existing raw-socket UDP handlers | `Abyss.Handler` and `Abyss.start_link/1` | [UDP addressing and lifecycle](udp-broadcast-multicast.md) |
| Existing protocol routing callbacks | `Abyss.DatagramDispatcher` | [Dispatcher and writer](dispatcher.md) |
| QUIC streams and application sessions | `Abyss.QUIC` with optional `elixir_quic` | [QUIC service](quic-service.md) |

Broadcast and multicast are addressing choices. The datagram API's execution policy is a separate choice: one worker per input, one persistent endpoint state, or application-defined keyed state.

## Read by topic

| Topic | Document |
| --- | --- |
| Supervision, ownership, data flow and failure boundaries | [Architecture](architecture.md) |
| Immutable datagrams, callbacks, effects, bounds and generations | [UDP runtime contract](udp-runtime/design.md) |
| New and legacy usage, backend capabilities and DHCP migration | [Datagram API and migration](udp-runtime/migration.md) |
| Unicast, broadcast, multicast, clients and memberships | [UDP addressing and lifecycle](udp-broadcast-multicast.md) |
| Admission, send receipts and protocol routing | [Dispatcher and writer](dispatcher.md) |
| Optional QUIC engine, handlers, stream I/O and draining | [QUIC service](quic-service.md) |
| Inspection, telemetry, shutdown and scoped verification | [Operations and development](operations.md) |
| Shared versions, package artifacts and publication recovery | [Coordinated releases](releases.md) |

Module and function details are available in the [API reference](https://hexdocs.pm/abyss).

## Documentation conventions

Use one descriptive level-one title, followed by a short explanation and level-two sections. Use `elixir` or `sh` fenced examples, relative links between current guides, and tables for defaults or capability comparisons. Examples should use loopback and unprivileged ports unless they explicitly require an isolated network fixture.

Describe shipped behavior separately from measurements and limitations. Defaults must match `Abyss.ServerConfig`; capability claims must identify the backend and tested platform. A successful local send is not a peer acknowledgement, a timeout is not cancellation, and sampled resource counts are not whole-VM bounds.

Keep current guides in this directory and `udp-runtime/`. Release evidence and diagnostic transcripts belong in the [historical archive](https://github.com/gsmlg-dev/abyss/tree/main/docs/archive), which is excluded from the Hex package and generated user guides. The archive retains source attribution and failed attempts; its statuses are historical.
