# WP3 HTTP/3 runtime

The runtime owns native HTTP/3 sessions independently of Fetch and EventSource.
`HTTP.HTTP3.Stream` exposes the same outer relay envelope as the existing runtime:

```elixir
{:ok, stream, generation} = HTTP.HTTP3.Stream.start(request, subscriber, options)
# {:http_runtime, generation, stream, {:headers, status, fields}}
# {:http_runtime, generation, stream, {:data, bytes, delivery_ref}}
HTTP.HTTP3.Stream.acknowledge(stream, delivery_ref)
HTTP.HTTP3.Stream.close(stream)
```

Informational responses and trailers carry their regular field lists. Final
`:done` and `{:error, reason}` follow all previously delivered DATA settlements.
Headers and other control deliveries settle internally. Runtime modules do not
call Fetch response or producer modules; upload producers use `:read_chunk`,
`:stream_chunk`, `:stream_chunk_ack`, `:stream_end`, and `:stream_error` messages.

## Ownership and admission

The owner executes Session calls itself, retaining the native consumer identity.
A task outside the owner bounds synchronous native operations, including DNS and
query calls. A stalled owner is terminated. Owned endpoints are linked to the
owner; borrowed, verified endpoint descriptors survive owner shutdown. Graceful
termination aborts the owned connection and pending application work without
replaying it. If a watchdog terminates reconciliation of an unknown operation,
the original operation reference is preserved in the relay error when available.

Unknown outcomes remain pending and query the original native operation reference.
Only definitely blocked work can detach into a continuation. Detached work runs
again after a `:writable` event or its deadline; it does not retry on every poll.
Scheduling alternates runnable continuations and newly queued actions. Subscriber
death during opening reconciles the original admission and cancels that stream.
Cancellation acknowledges the local cancellation intent; native cleanup follows
serialized outstanding work and does not establish that an unknown request was
unsent.

GOAWAY drains the owner and rejects admitted native IDs at or above the cutoff
with `:request_rejected`. Queued opens fail before admission. The runtime never
replays a request automatically. Default rotation starts at 960 native allocations,
including the local control stream, and keeps existing streams until they finish.
The static-only QPACK profile does not allocate local QPACK instruction streams.
Custom native lifetime record limits cap that rotation at the effective local
record capacity. The native stream constructor derives local capacity by
subtracting permitted peer bidi/uni records from the aggregate record limit.
A budget that cannot reserve all concurrent requests plus the local control
stream fails before opening with `:http3_stream_record_budget_too_small`;
an incompatible explicit rotation fails with `:http3_rotation_budget_mismatch`.

The pool uses monitored leases and connector reservations, bounded FIFO waiters,
and owner monitoring. Duplicate owners and wrong connector/key identities are
rejected. Pool shutdown terminates its owners; owner death releases corresponding
leases. Stream acquisition failures release leases and stop newly created owners.
A request's absolute deadline starts before acquisition. EventSource may use
`:infinity` for the established relay while retaining a finite opening deadline.
Failure before verified HTTP/3 readiness is distinguished as
`{:http3_not_established, reason}`.

An expired established request cancels its native request and releases its pool
lease even if the consumer has not acknowledged previously delivered DATA. Its
relay retains bounded DATA delivery and the ordered timeout terminal until the
consumer settles that DATA, aborts, or exits. Byte/event retention stays within
the configured delivery limits; retained time depends on consumer demand. No
further native reads or upload admission occur for that relay. Deadline checks
run before processing queued relay messages, so mailbox activity cannot extend
the absolute request budget.

## Bounds and reuse

Defaults are 32 requests per owner, 128 pending pool waiters, two connections per
key, 20 total owners/connectors, and 100 active keys.
The pool records each registered owner's configured concurrent request limit.
An explicit pool stream limit additionally caps that owner's admitted leases;
exhausted owners cause connector reservation or bounded waiting.
The owner action queue and blocked-continuation retention are bounded at 128.
Native receive windows reserve
65,536 bytes for each admitted request and three peer unidirectional streams:
`(32 + 3) * 65_536 = 2_293_760` bytes for the default connection. The same finite
value bounds `max_data`, `max_ready_bytes`, and the configured reorder buffer.
Server-initiated bidirectional streams are disabled. Tighter explicit buffers
that cannot reserve every stream window fail with
`:http3_receive_budget_too_small`. Concurrency is limited to 128 and individual
receive windows to 65,536 bytes; custom peer-unidirectional admission is 3..16.
Borrowed endpoints expose immutable effective stream budgets. Missing, different
or insufficient borrowed budgets fail with
`:http3_endpoint_receive_budget_mismatch`; no override is pretended to apply.
The descriptor also carries effective aggregate/local lifetime record capacity;
legacy descriptors missing these fields are rejected before connection reuse.
Idle owners stop 30 seconds
after their last request activity. Established active streams prevent idle exit.

Each upload bridge retains at most 64 KiB from its producer and admits at most
16 KiB per native write. The producer ACK occurs only after every slice is
admitted. Cancellation and early final response do not manufacture an ACK.
Final response headers are relayed after send-half reset is settled when upload
reset is required. Definitely blocked upload work can be abandoned; unknown work
must reconcile first. Response delivery defaults to 64 KiB and 128 events. A
DATA delivery pauses the request before its next native read, preserving QUIC
receive-credit backpressure while sibling requests continue. Overflow terminal
errors also wait for earlier DATA settlements.

Reuse identity covers HTTPS origin, normalized trust/reference identity, QUIC
profile, verified endpoint descriptor and runtime/flow settings. Unsafe TLS
callback identity or `http3_reuse: false` creates a unique key. Raw TLS options
are forwarded once to the adapter, retaining ordered profile settings. TCP TLS
backends, Unix sockets, proxies, nonempty TCP socket options, and HTTP/2 profile
selectors fail explicitly.

## Verification evidence

Initial scoped red: four tests failed with `UndefinedFunctionError` for absent
runtime modules. Initial implementation passed four tests with seed zero.
Subsequent native relay tests and deterministic operation tests passed. The
first independent 32-stream run with 31 demand-paused consumers timed out after
15 seconds: all uploads completed, but the native default shared receive window
of 262,144 bytes was smaller than the sum of per-stream windows. Parent-approved
finite window reservation repaired that demonstrated fairness defect. Sol repair
round 1 passed both concurrent and majority-paused independent consumers.

The checkpoint command below passed **75 tests, zero failures**, including the
existing runtime compatibility suite and 16 new HTTP/3 tests:

```bash
MIX_ENV=test mix test apps/http_runtime/test --seed 0
```

The new HTTP/3 coverage includes 32 native requests on one connection, demand
pause with a progressing sibling, terminal ordering, producer admission ACKs,
unknown-write reconciliation without replay, blocked-open fairness, blocked
initialization, watchdog bounds, GOAWAY cutoff, allocation rotation, idle
accounting, early response, shared endpoint lifetime and connector validation.

Final scoped validation passed **78 runtime tests** and **six companion adapter
tests**, all with seed zero. The HTTP/3 subset contains **19 tests**. Strict
root test-environment compilation and explicit owned-file formatter checks pass.
Normal Credo passes across all 423 files. The earlier resolved upstream TODO
finding was removed only after the parent-approved upstream fix was verified.

Pinned `aioquic==1.2.0` independent runtime gates pass with 32 native streams and
61,725-byte streamed binary uploads and downloads per stream. Both a concurrent
consumer and a serial consumer leaving 31 siblings demand-paused pass body
integrity, verified peer identity (`x-connection`), single-connection reuse,
terminal relay exit and zero retained pool leases. The independently running
peer is always terminated and waited after the gate. Reviewable scratch gate
inputs are `/tmp/http3-wp3-runtime-gate-concurrent.exs`,
`/tmp/http3-wp3-runtime-gate.exs`, and `/tmp/http3-wp3-runtime-gate.py`; the parent
owns permanent acceptance orchestration.

```bash
MIX_ENV=test mix compile --warnings-as-errors
MIX_ENV=test mix test apps/http_runtime/test \
  apps/elixir_quic_http3/test/quic_http3_transport_quic_test.exs --seed 0
MIX_ENV=test mix credo
uv run --python 3.12 --with aioquic==1.2.0 python /tmp/http3-wp3-runtime-gate.py
```

Root test-environment Dialyzer passes with five existing intentional skips and
no new warnings. Repair round 2 matched the timer cancellation return and removed
an unreachable core-header error clause; the final run passed after finite budget
validation assertions. Both cumulative Sol repair rounds succeeded. All worker
commands and independent peer processes completed or were terminated and waited.
Long-duration canary, 10,000-request rotation, Caddy interoperability,
release publication and published-only consumer gates belong to later parent
acceptance steps. WP3 alone does not claim those gates passed.

The final worker baseline is `5f801df93472aebe7f304be008851843fae1dc99` on
`codex/http3-completion`. Parent-owned version reconciliation preserved all source
edits. No worker commit, push, publication, or companion scheduler edit occurred.

## Independent review repairs

The subsequent review reproduced three scoped defects before editing: a timed
out demand-paused request retained its native request and lease; a one-request
owner received a second lease from the default-capacity pool; custom native
lifetime record limits did not constrain rotation. The first red run reported
three expected failures. Additional boundary assertions reproduced omitted
borrowed record metadata and an explicit pool limit overridden by a larger owner
capacity.

The repaired scoped command passes **82 runtime tests** and **six adapter tests**
with seed zero. Four added runtime tests cover actual native deadline cleanup
with terminal ordering, actual one-request-owner lease queuing, explicit pool
limits, and owned/borrowed record budgets and rotation. Strict test-environment
compilation, formatting, diff checks and configured scoped Credo pass. During
validation, the enlarged registration branch exceeded Credo's complexity limit;
private capacity/connector predicates resolve it. A compiler clause-grouping
warning from their first placement was corrected before the final strict gate.

The independent pinned aioquic 32-request gate also passes after these repairs:
61,725-byte binary uploads/downloads, 31 demand-paused siblings, progress of the
active consumer, one verified connection, relay exit and zero retained leases.
Its peer process was terminated and waited. The repair does not change the
public execution facade; the parent stages that integration separately.

This review checkpoint did not rerun Dialyzer, public Fetch acceptance, remote
CI or release publication. The earlier worker's Dialyzer evidence above belongs
to its earlier checkpoint.
