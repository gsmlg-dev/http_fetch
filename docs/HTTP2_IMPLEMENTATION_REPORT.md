# HTTP/2 Implementation Report

## Baseline

Review baseline: `b4ad2f5ef003415941b97f5e0cc78c21dcc94296` (v0.13.0).

## Delivered in this revision

- Strict versioned `WireProfile` validation and stable digest.
- Ordered SETTINGS/header serialization with native and two synthetic test
  profiles.
- Pure connection/stream state modules for stream reservation and flow-control
  bookkeeping.
- Long-lived `ConnectionOwner` and bounded profile-keyed `Pool` runtime modules,
  with focused fake-transport tests for multi-stream writes, cancellation,
  upload DATA/EOF/backpressure, inbound DATA flow-control replenishment,
  GOAWAY drain, and inbound HPACK continuation.
- Bounded, redacted wire observation and structured diff.
- Flat fetch option validation for `http2_profile`, `http2_reuse`,
  `http2_scope`, and `http2_priority`.

## Verification

Focused core profile/fingerprint/connection tests pass, runtime/body bridge
 tests pass (13), PoolKey tests pass (9), and fetch tests pass (198 tests plus
20 doctests), full fetch application tests pass, and core tests pass except one existing
platform-sensitive TLS assertion (`:eaddrnotavail` instead of
`:econnrefused`), and root compilation with warnings-as-errors passes after
pinned pre-existing bitstring matches. Fresh warnings-as-errors compilation,
format, and diff checks pass. Credo
currently crashes in its token-position checker on an existing sigil under
Elixir 1.20; Dialyzer exits 2 after a Dialyxir `Protocol.UndefinedError` while
rendering warnings. `mix docs` completes with existing hidden-module and stale
file-reference warnings.

## Explicitly not verified

The profile-aware Pool and ConnectionOwner exist as explicit runtime modules,
but they are not yet wired into the default `HTTP.fetch/2` socket path, so
actual multi-request socket reuse and response adaptation are not verified.
Explicit HTTP/2 options therefore remain on the existing per-request socket
path; the default remains HTTP/1.1. Runtime upload behavior is verified only
at the owner/bridge boundary, not through `HTTP.fetch/2`. Independent mature
implementation interoperability, h2c end-to-end wire tests, and a captured
browser profile also remain pending.
