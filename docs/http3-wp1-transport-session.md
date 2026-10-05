# WP1 transport and resumable session evidence

Worktree: `.trees/http3-completion`. Investigation baseline:
`6e33bcba7dae9acee1924af744c766b8e1d6147d`. WP0 was committed by the
coordinator during implementation; the handoff HEAD is
`bc63a24a1c93447efedf402e14fdbc71b680641d`.

## Implemented contract

- Adapter connections retain endpoint ownership, native generation handle,
  consumer and original connect reference. An unknown connect retains its
  endpoint for status reconciliation. Known native connections are attached
  before successful composition; attachment timeout retains context and retries
  only the same consumer attachment. Definitive attachment failure retains
  connection state for cleanup.
- Opened streams, drained events and recovered open/event results all use the
  same adapter wrapper around native generation handles. Stale generation events
  and mismatched native read stream IDs are rejected explicitly.
- Session mutation failures return `{:error, session, reason}`,
  `{:blocked, session, reason}` or `{:unknown, session, operation_ref}`.
  Existing success shapes remain. `resume/1` retains the admitted stream,
  outstanding operation arguments/ref/deadline, unwritten chunks and the
  unprocessed drained event batch. Cached completed reads/events are processed
  exactly once. Unknown or evicted outcomes never trigger transport replay;
  unresolved expiration is `{:indeterminate_operation, original_ref}`.
- Native `:deadline` is a remaining admission duration, derived from an absolute
  session budget. Definitely blocked operations use fresh references on explicit
  resume; admitted prefixes are not resent.
- Native receive resets preserve application code and final size. Cancellation
  independently admits RESET_STREAM and STOP_SENDING with H3_REQUEST_CANCELLED
  (`0x10c`); a timeout of the second half does not repeat the first half.
- `poll/3` accepts `paused: MapSet.new(request_refs)` and
  `max_read_batches: 1..128`. Runnable readable streams survive partial reads
  and demand pauses, without requiring another wire notification. Control and
  unpaused siblings remain eligible. A poll consumes at most 16 KiB of stream
  bytes; retained native event batches are limited to 128 and read batches to
  16 KiB. Unknown peer bidirectional streams are explicit errors.
- Client trust/identity/key/algorithm normalization uses shared HTTP core
  primitives while the companion supplies its own exact `h3` ALPN policy.
  Original DNS/IP reference identity and SNI are independent of resolution.
  Compiled client profiles include SNI when configured. Insecure verification
  and incompatible TCP TLS backend options are rejected. Readiness additionally
  requires negotiated `h3`, completed TLS, authenticated peer and valid peer
  parameters.
- Close shuts down owned endpoints, including when the native connection already
  terminated or an unknown connect was subsequently rejected. Native nil-handle
  close is safe. `abort/1` terminates owned transport resources without replaying
  pending work and retains abandoned operation identity in the returned session;
  it does not claim an indeterminate request was unsent.
- Raw PID endpoint injection is rejected. `Transport.Quic.client/1` accepts
  `host:` plus TLS/transport options and returns an adapter-managed shared
  descriptor binding normalized original host, TLS, profile and operations
  module. Borrowed connections require that same immutable configuration.
  Shared endpoints are preserved by ordinary connection close. An unresolved
  shared connect cannot be aborted by stopping a shared endpoint.
- Cancellation removes the stream from the runnable set and retains its exact
  generation-aware handle in a bounded set of 1024 terminal tombstones. Only
  late notifications for those retired handles are ignored; unknown/stale stream
  failures remain explicit. Tombstone exhaustion fails explicitly instead of
  evicting generation history.

## Verification

Initial regression red: 11 tests failed for missing attachment, inconsistent
handles, lost pending state, cleanup and readiness contracts. Additional tests
were added red before implementing operation result limits, native stream ID and
peer stream validation, independent SNI, terminal cleanup and attachment recovery.

Final focused command, executed from the umbrella root:

```sh
MIX_ENV=test mix test \
  apps/elixir_quic_http3/test/quic_http3_wp1_test.exs \
  apps/elixir_quic_http3/test/quic_http3_native_session_test.exs \
  apps/elixir_quic_http3/test/quic_http3_session_test.exs \
  apps/elixir_quic_http3/test/quic_http3_transport_quic_test.exs --seed 0
```

**PASS: 41 tests, 0 failures.** This command excludes the coordinator's prepared
WP2 control/response tests. The 29 WP1 deterministic tests use Session + the
real adapter with native generation/result shapes, rather than replacing the
adapter with a simplified incompatible session transport. Two additional tests
use actual local UDP, real Quic endpoints and the real adapter/session: a request
with empty body, framed response through partial bounded reads, native two-half
cancellation and owned endpoint termination; and certificate reference mismatch
that fails before opening HTTP streams. Native reads explicitly drain through
FIN; they do not assume all UDP packets have arrived with the first readable
notification. Tests use bounded public event/read polling without sleeps.

**PASS:** `MIX_ENV=test mix compile --warnings-as-errors`; explicit formatter
check of all eight owned source/test files; `git diff --check` of owned files.
**PASS:** positional-file `mix credo suggest` over those eight files checked
234 modules/functions and reported no issues.

An earlier full companion snapshot passed **62 tests** while the coordinator's
WP2 control/response changes were also present. Further WP1 regressions were
added afterward; the focused 41-test result above is the final WP1 evidence.
An attempted strict Credo command with `--files-included` unexpectedly checked
410 umbrella files and failed on strict baseline suggestions and owned style
findings. Only owned findings were repaired. The successful final Credo command
used explicit positional file paths and the repository's normal priority gate.
No unrelated strict findings were changed.

Sol repair rounds: 2, both subsequently passed validation. No Astra repair.
All worker commands completed; no commits, pushes or publication performed.

## Review regressions repaired

Review found cancellation runnable/tombstone races, loss of pending identity when
recovered rejection remains blocked or attachment remains unknown, unverified
shared endpoint configuration, and nil-handle/indeterminate cleanup. Six added
regressions initially failed for these contract gaps. They now pass in the
41-test focused suite. Cancellation races retain sibling progress; recovered
unknown work retains its original reference; shared configuration mismatches are
rejected; terminal owned-resource abort performs no application write replay.

## Explicit remaining boundaries

- Query calls (`ready`, `info`, `operation_status`) and synchronous DNS still
  have their native timeout bounds. A session admission budget does not establish
  a shorter strict wall-clock DNS/query deadline.
- Shared endpoint descriptors bind adapter-created immutable TLS configuration.
  Runtime pool identity must additionally prevent cross-origin/trust/identity/
  profile endpoint reuse. The descriptor is an in-process capability, not an
  authorization boundary against malicious local code with raw Quic access.
- WP1 has one pending mutation per caller-driven session. A definitely blocked
  upload currently prevents another Session mutation/poll until resumed. WP2/WP3
  must introduce bounded detached blocked continuations merged into the current
  session to preserve control/sibling fairness. Unknown continuations cannot be
  detached/replayed as definitely blocked work.
- Pending unknown admission must be reconciled or reported indeterminate before
  normal cancellation/close. `abort/1` supplies terminal owned-endpoint teardown
  without replay. An evicted unknown connect on a shared endpoint remains the
  shared endpoint owner's responsibility and returns an explicit abort failure.
- Outgoing body DATA framing, complete response semantics/terminal request
  cleanup, dynamic QPACK policy, critical stream completion and GOAWAY admission
  belong to WP2. Public Fetch integration, pooling, streaming producer demand,
  connection rotation and sustained interop/load acceptance belong to later
  packages. This evidence does not enable the public HTTP/3 selector or change
  capability reporting.
