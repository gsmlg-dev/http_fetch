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
- HPACK decoder dynamic-table capacity updates now preserve the configured
  maximum, allowing legal shrink-and-restore sequences without stale indexes.
- Profile-selected HPACK output now supports static/dynamic exact indexing,
  incremental indexing, sensitive never-index, and RFC 7541 Huffman strings;
  numeric SETTINGS IDs also update directional core state.
- GOAWAY marks pooled owners draining so new reservations select a fresh owner
  while existing streams continue to drain.
- Pool reservations arm a configurable idle timeout after the last stream is
  released; a new reservation cancels it.
- ConnectionOwner enforces a GOAWAY drain deadline and closes immediately once
  all active streams are released.
- Legacy profiles serialize a legal PRIORITY frame before HEADERS; RFC 9218
  profiles emit a `Priority` header from validated per-request metadata without
  mixing legacy signaling.
- RFC 9218 `PRIORITY_UPDATE` is registered as frame type `0xF` and accepted by
  the owner only with a zero frame stream ID, a non-zero target stream, and a
  bounded field value; malformed updates are rejected.
- `HTTP.HTTP2.ProfileCapture` now builds and validates provenance manifests,
  including a digest computed from fixture bytes and explicit cold/reused
  context and evidence source fields.
- Flow-controlled upload chunks now remain pending per stream until a valid
  WINDOW_UPDATE restores credit; the bridge is acknowledged only after DATA is
  serialized, with a runtime zero-window/resume regression test.
- `BodyBridge.status/1` reports current and peak buffered bytes, while
  `ConnectionOwner.status/1` reports the writer queue peak and configured
  limit; focused tests assert both peaks stay within their budgets.
- Core DATA effects now split payloads at the peer MAX_FRAME_SIZE and preserve
  END_STREAM on the final fragment, with explicit frame-size and window tests.
- Pending upload streams are selected through a bounded round-robin scheduler
  during connection-level credit recovery; scheduler rotation has pure tests.
- Explicit profiled HTTPS h2 now participates in the same pool path as h2c,
  with `:h2` pool keys preserving TLS backend, verification, scope, and profile
  isolation. OTP `:ssl` and `:ex_ssl` HTTP/2 socket regressions both pass.
- Fingerprint observations now preserve a validated evidence source and reject
  oversized input or frame-count limits before parsing.
- Capture manifest import accepts JSON-style keys and documented string
  evidence labels through a finite normalization table; unknown fields never
  become atoms.

## Verification

Focused core profile/fingerprint/connection tests pass, runtime/body bridge
tests pass (18), PoolKey tests pass (9), and fetch tests pass (215 tests plus
20 doctests). The full HTTP/2 socket regression suite passes (41 tests),
including 20 sequential h2c churn requests with varying path payload sizes,
sequential h2c and HTTPS h2 reuse, three overlapping requests, and
simultaneous cold-start coalescing on one accepted socket with streams 1, 3,
and 5. The churn server asserts one TCP accept and monotonically advancing
stream IDs; it does not claim a long-duration memory benchmark.
The full fetch application tests pass, and the full core test suite now passes
(`209 passed`). The unsupported-options test uses a kernel-assigned closed
port, so its refusal assertion is stable across platforms. Fresh
warnings-as-errors compilation, format, and diff checks pass. Credo currently
crashes in its token-position checker on an existing sigil under Elixir 1.20;
this is an environment/tooling limitation, not a passed CI-version Credo run.
Dialyzer passes with narrow, documented contracts for the intentionally
structural public observation APIs. `mix docs` completes with existing hidden
module/type reference warnings; linked validation extras are included.

An independent `hyper-h2` 4.2.0 cleartext server accepted the client's
prior-knowledge preface, SETTINGS, HPACK request headers, and stream, then
returned `200`, `x-peer: hyper-h2`, and `independent:/independent`. The
reproducible fixture is `scripts/http2_hyper_h2_server.py`, pinned by
`scripts/requirements-http2-interop.txt`; run
`PYTHON_BIN=/path/to/python scripts/http2_hyper_h2_interop.sh` after installing
that requirement. The verified run produced:

```text
200|hyper-h2-4.2.0|independent:/independent
```

The same peer also accepted `synthetic_test_v1` with Huffman-encoded request
headers and its larger advertised header-table capacity. This remains a
single-peer interoperability smoke check, not a complete RFC or stress
matrix.

## Explicitly not verified

Explicit `http2_profile` requests now use `ConnectionOwner` for socket
ownership, ordered request submission, and response HEADERS/DATA adaptation;
explicit-profile h2c requests also reuse an existing owner when
`http2_reuse` is enabled, including overlapping streams after the first owner
is established. The default HTTP/1.1 path and
HTTP/2 requests without an explicit profile retain the legacy per-request
adapter for compatibility. Broader concurrent queue/drain evidence remains
pending.
Explicit-profile streaming upload now uses `BodyBridge`
through the owner and is covered by an h2c socket test; requests without an explicit
profile retain the legacy path. Broader interoperability and a captured
browser profile remain pending.
