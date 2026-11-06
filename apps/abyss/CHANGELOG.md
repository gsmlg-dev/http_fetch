# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2026-10-25

### Added

- Accept `idle_timeout: :infinity` in QUIC engine options, with finite peer
  timeout negotiation still applying. Handshake, callback, closing and draining
  deadlines remain independently bounded.
- Expose `Abyss.QUIC.ping/2` for caller-managed QUIC keepalive with bounded
  operation accounting and deadlines. Applications explicitly install
  `elixir_quic` 0.21.17 or newer for these engine capabilities.

### Changed

- Release `abyss` and `abyss_raw` together at 0.10.0; ordinary UDP consumers
  retain the core package's Rust-free and optional-QUIC dependency boundary.

## [0.8.1] - 2026-10-14

### Fixed

- Isolate each init, callback, effects and cleanup watchdog arm so stale expiry
  cannot terminate a later execution phase.
- Preserve endpoint application state and managed timers for the socket
  generation; keyed idle eviction remains finite and unchanged.
- Record actual native ordinary/strict send outcomes once, including empty
  datagrams, without counting admission rejection or receipt reads as sends.
- Report non-overlapping ingress/runtime network drops in public endpoint
  statistics, retain counts through drain, and track rejected internal events
  separately. See `docs/udp-runtime/post-release-fixes.md` for evidence.

## [Unreleased]

### Added

- **New configuration options for enhanced control**:
  - `connection_telemetry_sample_rate` (default: 0.05) - Configure sampling rate for connection telemetry events
  - `handler_memory_check_interval` (default: 10_000ms) - Interval for handler memory monitoring
  - `handler_memory_warning_threshold` (default: 100 MB) - Memory threshold for warnings
  - `handler_memory_hard_limit` (default: 150 MB) - Hard memory limit triggering termination

- **Modular UDP transport architecture**:
  - `Abyss.Transport.UDP.Core` - Core UDP socket operations
  - `Abyss.Transport.UDP.Unicast` - Unicast-specific functionality
  - `Abyss.Transport.UDP.Broadcast` - Broadcast-specific functionality

- **Enhanced telemetry metrics**:
  - Rolling window rate calculations for accepts_per_second and responses_per_second
  - Atomic ETS operations for concurrent metric updates
  - Response time tracking with per-request measurements

### Changed

- **Improved listener scaling algorithm**: Changed `calculate_optimal_listeners/2` to use 1:100 ratio (1 listener per 100 connections) instead of 1:1000, providing better granularity for low to medium loads
- **Adaptive timeout calculation**: Now consistently uses milliseconds throughout, improving accuracy and preventing time unit bugs
- **Telemetry sampling**: Connection telemetry events now respect configurable sampling rate from ServerConfig

### Fixed

- **Critical ETS race condition**: Fixed race condition in telemetry metrics table creation when multiple processes initialize simultaneously using try/catch pattern
- **Time unit inconsistency**: Fixed adaptive timeout calculation that was incorrectly mixing native time units with milliseconds in bounds checking
- **Socket leak**: Fixed resource leak in `Abyss.Transport.UDP.Unicast.send_recv/3` by ensuring socket cleanup in all code paths
- **Telemetry rate calculation**: Improved rolling window rate calculations with proper atomic operations and window expiration handling
- **Configuration validation**: Added comprehensive validation for all new configuration options with clear error messages

### Improved

- **Test coverage**: Increased from ~40% to 62%+ coverage
- **Test cleanup**: Removed 5 skipped/placeholder tests for a cleaner test suite (237 tests, 0 failures, 0 skipped)
- **Code quality**: Addressed all critical and medium priority code quality issues
- **Documentation**: Updated CLAUDE.md with comprehensive development guidelines
- **Memory management**: Configurable memory monitoring with graceful degradation

### Technical Details

#### Telemetry Improvements

The telemetry system now uses atomic ETS operations to prevent race conditions:

```elixir
# Before: Non-atomic read-modify-write
count = :ets.lookup_element(table, :accepts_in_window, 2)
:ets.insert(table, {:accepts_in_window, count + 1})

# After: Atomic increment
:ets.update_counter(table, :accepts_in_window, {2, 1})
```

#### Adaptive Timeout Fix

Fixed time unit handling in adaptive timeout calculations:

```elixir
# Before: Mixing native and millisecond units
avg_time_native = Enum.sum(times) / length(times)
timeout = round(avg_time_native * 3)
timeout |> max(div(base_timeout, 2)) |> min(base_timeout * 2)

# After: Consistent millisecond units
avg_time_native = Enum.sum(times) / length(times)
avg_time_ms = System.convert_time_unit(round(avg_time_native), :native, :millisecond)
timeout_ms = round(avg_time_ms * 3)
timeout_ms |> max(div(base_timeout, 2)) |> min(base_timeout * 2)
```

#### Listener Scaling Enhancement

Improved scaling granularity for better performance under varying loads:

```elixir
# Before: 1 listener per 1000 connections
base_listeners = max(div(current_connections, 1000), 1)

# After: 1 listener per 100 connections
base_listeners = max(div(current_connections, 100), 1)
```

## [0.8.0] - 2026-10-14

### Added

- Public `Abyss.Datagram`, `Abyss.DatagramHandler`, and `Abyss.Endpoint` APIs with per-datagram, endpoint, and keyed execution policies.
- Bounded input and action accounting, generation-scoped send receipts, managed events, callback watchdogs, and observed worker/helper cleanup.
- Linux native UDP metadata and strict source/interface-correct replies, with independent IPv4/IPv6 multicast and scoped-send fixtures.
- Runtime design, migration, resource/performance measurements, and reproducible G0–G10 evidence in `docs/udp-runtime/`.

### Changed

- DHCP/ARP Rust support moves to the explicitly installed `packages/abyss_dhcp_socket` package. The legacy facade remains; ordinary UDP builds without Rust or QUIC. The optional package is not published in this release.
- Optional QUIC examples pin the fixed published `elixir_quic`/`ex_ssl` 0.21.6 and retain their concurrent workload and deadlines.

### Fixed

- UDP one-peer exchanges reject wrong IP/port replies without extending the absolute response deadline.
- Public UDP paths resolve the effective boot/default backend consistently.
- Completed effects retire their watchdog after actual helper completion; stop handles expected runtime deadline retirement while draining.

### Performance

- Controlled legacy sequential throughput is approximately 6.9% below the 0.7.0 baseline. New execution policies incur additional action/receipt coordination costs; measurements and limits are documented.

## [0.6.1] - 2026-09-29

### Fixed

- Use the published `elixir_quic` engine's `Quic` namespace for optional engine
  detection, service hosting and public stream operations (internal request #5).
- Pin independent QUIC consumers to Hex `elixir_quic` 0.2.2 and `ex_ssl` 0.7.2,
  with published-package provenance and real network/release regression checks.
  Ordinary UDP remains independent of the engine; no legacy alias or fallback
  is introduced.

## [0.6.0] - 2026-09-28

### Added

- Public `Abyss.QUIC` listener and `Abyss.QUIC.Handler` application service using
  the explicitly activated ex_quic engine, with isolated connection consumers,
  negotiated ALPN metadata, generation handles and bounded byte-stream operations.
- Independent echo, collection and ordinary UDP consumers, pinned-peer QUIC
  acceptance scripts, and outside-checkout production release checks.
- Service, ownership, backpressure and capability documentation in
  `docs/quic-service.md` and the Phase 1 acceptance report.

### Fixed

- Writer item/byte admission before payload mailbox entry, bounded receipt/waiter
  retention, explicit unknown outcomes and generation-safe completion handling.
- Bounded listener draining and cleanup after writer, endpoint or consumer failure.

### Scope

- Ordinary UDP remains independent of ex_quic. DNS/DoQ and HTTP/3/QPACK belong to
  application servers and are not implemented by Abyss. DATAGRAM, 0-RTT, migration
  and server mTLS are outside the supported subset.

## [0.5.0] - 2025-10-14

Published to Hex through the repository release workflow.

## [0.4.0]

Initial stable release with core UDP server functionality, telemetry support, and security features.
