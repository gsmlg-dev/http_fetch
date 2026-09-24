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
- Explicit-profile h2c requests can reuse a profile-keyed `ConnectionOwner`
  across sequential fetches; reservations release after each stream while the
  owner remains pooled.

## Verification

Focused core profile/fingerprint/connection tests pass, runtime/body bridge
tests pass (13), PoolKey tests pass (9), and fetch tests pass (203 tests plus
20 doctests). The full HTTP/2 socket regression suite passes (37 tests),
including sequential h2c reuse on one accepted socket with streams 1 and 3.
The full fetch application tests pass, and core tests pass except one existing
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
explicit-profile h2c requests also reuse an existing owner when
`http2_reuse` is enabled. The default HTTP/1.1 path and
HTTP/2 requests without an explicit profile retain the legacy per-request
adapter for compatibility. Three-request and concurrent shared-socket evidence
remain pending. Explicit-profile streaming upload now uses `BodyBridge`
through the owner and is covered by an h2c socket test; requests without an explicit
profile retain the legacy path. Independent mature implementation
interoperability and a captured browser profile remain pending.
