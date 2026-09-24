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
20 doctests). The full HTTP/2 socket regression suite passes (35 tests), the
full fetch application tests pass, and core tests pass except one existing
platform-sensitive TLS assertion (`:eaddrnotavail` instead of
`:econnrefused`). Fresh warnings-as-errors compilation, format, and diff
checks pass. Credo
currently crashes in its token-position checker on an existing sigil under
Elixir 1.20; Dialyzer exits 2 after a Dialyxir `Protocol.UndefinedError` while
rendering warnings. `mix docs` completes with existing hidden-module and stale
file-reference warnings.

## Explicitly not verified

Explicit `http2_profile` requests now use `ConnectionOwner` for socket
ownership, ordered request submission, and response HEADERS/DATA adaptation;
the full HTTP/2 socket regression suite passes. The default HTTP/1.1 path and
HTTP/2 requests without an explicit profile retain the legacy per-request
adapter for compatibility. The Pool is not yet used for cross-request socket
reuse, so three-request reuse and concurrent shared-socket evidence remain
pending. Explicit-profile streaming upload now uses `BodyBridge` through the
owner and is covered by an h2c socket test; requests without an explicit
profile retain the legacy path. Independent mature implementation
interoperability, shared Pool reuse, and a captured browser profile remain
pending.
