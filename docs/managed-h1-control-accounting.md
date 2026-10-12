# Managed H1 control accounting: resolution attempt for #97

Status: **HARDENING_COMPLETE_NATIVE_CONTRACT_UNRESOLVED**. The changes reduce
allocation churn and strengthen logical correctness; they do not establish a
native memory budget. Keep #97 open and Gaoxy managed numerical production
activation disabled. No arbitrary-history leak has been demonstrated.

## Accounting target and immutable premises

The target includes library terms and externally visible native control objects,
including TLS caller, delivery and tracking metadata. Private TLS/crypto heaps,
kernel socket memory and allocator/OS return are separate quantities. An object
being unreachable, freed, or its carrier returned are three different events.

The original workload remains four charged outer generation slots, including
retiring/uncertain generations; per scope two connections, 32 request slots and
zero pending pool waiters; explicit HTTP/1, OTP TLS, manual redirects, raw streamed
responses, bounded nil/PID uploads, immutable finite deadlines, and buffer,
recbuf and sndbuf 8192. Public operation/snapshot callers have fixed counts;
there is no retry fanout or unbounded diagnostic input. There is **no cumulative
request/chunk limit**. Concurrent-request capacity and lifetime-history limits
are not interchangeable.

[The audit manifest](managed-h1-accounting/profile.json) records exact source
hashes and separates the requested runtime from the validation host. The library
baseline is 0.21.3, `ceecbf2df62ca80c361597c7303f65a153f2ce3c`, retaining #98–#100.
The runtime source tag OTP-28.5.0.7 resolves to commit
`09fb046150ab94104e03ee816b95c8b7e6b04683`. Local tests use Elixir 1.18.5,
OTP 28.5.0.5 / ERTS 16.4.0.5 / SSL 11.6.0.4, Linux x86_64, eight normal
schedulers; this is **not certification** for OTP 28.5.0.7 / ERTS 16.4.0.6 /
SSL 11.6.0.6 with two normal schedulers.

The manifest is a proof-status inventory, **not a certificate**. Build options,
ABI/layout, allocator flags, dirty/aux scheduler configuration and the consumer's
exact input limits remain uncertified. A source hash/version match alone must
not authorize a number. Missing or mismatched certification keeps numerical
activation disabled; no library API added here grants native-budget authority.

The requesting branch/evidence was not available in this checkout. No local
`h1-complete-ledger` files were found under the workspace, and its 72 rows and
187 hashes have not been independently recomputed. This blocks consumer
certification, but does not block the source audit or independent functional fixes.

## Source-backed conservative envelope attempt

Use, without evaluating it until every term is proved:

```
B_included <= B_fixed + sum_i(K_i * S_i) + B_copy_overlap + B_TLS_metadata
```

`K_i` covers live, queued and retired-but-unreclaimed objects, including objects
removed from Elixir maps. `S_i` includes the actual build's term/struct layout,
headers and bounded payload. If allocator carriers/fragmentation are included,
add their separate reserve; object size alone cannot bound them. Below, a live
logical count is not a certificate for `K_i`. Unknown is not zero.

All source line references below are to the pinned OTP commit. The sizes named
by `sizeof` require native ABI certification; no measured structure size or
portable Elixir payload charge is substituted for it.

| Included family / creation operation | Producer, target, executor, ownership | Population and size premises | Release evidence; failure/timeout behavior; proof status |
| --- | --- | --- | --- |
| Scope configuration, ingress, gate, durable latch and request preparation terms | Caller claims an ETS row before preparing; scope owns tables; tracker owns admitted work | Four generations, 32 rows/scope, frozen policy <=1 MiB, metadata <=64 KiB/256 fields, buffered body <=1 MiB. Multiple representations and preparation overlaps require separate reserves | Tracker termination releases the row logically; uncertain generations remain externally charged. BEAM heap/ETS layout, collection delay and copy overlap are uncertified |
| Request/stream/tracker/connector process controls, heap fragments and completion evidence | Caller, supervisors, scope and tracker create/monitor bounded current resources; ERTS owns process exit/signal handling | Concurrent resource maps are bounded by admitted requests/connections and bounded source actors; cumulative retired processes are not counted by those maps. Process control blocks and term overhead need build/layout proof | `DOWN` is logical termination evidence; it does not inventory remaining signal/monitor/process references or allocator carriers. Historical native reserve unresolved |
| Managed H1 response writer lease and chunk control messages | One fixed socket owner and stream establish reciprocal process monitors once; one owner holds atomic credit; reader grants chunk ACK | One writer/session, one in-flight chunk/ref, one credit cell; no helper per chunk, ordinal counter or history map. References use runtime reference layout. Existing total-byte telemetry counters and arbitrary-history integer growth require a separate term-cost premise | Timeout/abort/deadline permanently close writer credit, leave at most that admitted chunk owned until stream consumes stop or terminates, and prevent a retry through the same session. Wrong owner/stale token cannot replace credit. A late ACK can leave one terminal reply. Session teardown/native monitor reserve remains unproved |
| Legacy/public upload chunk monitors and reader switching | Public `chunk/3` caller monitors stream per chunk; stream monitors its selected reader | Existing public/non-managed contract retained. Caller-created upload input is excluded, but repeated upload control monitors remain included. Payload/credit bounds do not bound retired native monitor history | ACK/demonitor-flush settle the application chunk, not native retirement. Stable response lease does not certify upload monitors or change the public upload producer model; unresolved |
| H1 pool logical expiration entries, prepare-owner monitors and maintenance timer | Owner prepares pending entry; pool owns entry after socket handoff; timer service expires tick; pool validates timer ref | At most min(2,16) entries/scope in original profile (global non-managed cap 256). One logical maintenance timer per pool after first prepare; no per-entry timer/cancel/recreate on reuse. Entry terms and local monitors have fixed shapes | Pending handoff deadline 1s and idle expires_at enforced at activation/checkout independently of maintenance delay. Dirty/expired socket discarded. Native prior ticks, canceled timer objects and prepare-owner monitor retirement remain unresolved |
| Scope reconciliation and request/deadline/receive timers | Scope schedules one ref-matched reconciliation successor after callback; request owners/ERTS schedule finite waits | One logical reconciliation tick; fixed admitted request/caller counts bound current waits, not completed timer allocations. Timer wheel/high-level structs and message fragments require build/layout sizes | Stale/duplicate refs cannot start additional maintenance chains. Self-rescheduling still allocates over time. `cancel_timer(false)` neither consumes expiry nor acknowledges reclamation; residual reserve unresolved |
| Finite call aliases, caller/target monitors and unacknowledged requests | Pool, lifecycle, scope and public callers send; target consumes; ERTS handles alias/monitor signals | Fixed concurrently waiting callers and small request shapes are insufficient to bound all calls after timeout/retry. No pre-enqueue operation-slot certificate exists for all these APIs | gen.erl:251–280 deactivates timed-out alias without canceling target request. Timed-out work must remain owned/uncertain; a later call from another sender is not an all-sender barrier. Full finite pre-admission/ack settlement remains unresolved |
| Monitor allocations, demonitor signals, signal queue/buffer arrays and references | Participating caller/stream/tracker/pool/TLS processes; ERTS signal receiver, normal/dirty threads and aux work | `erl_monitor_link.c:877–914` allocates local monitor storage with two references; destruction at :1113 requires final zero. Buffer arrays use sizeof(ErtsSignalInQueueBufferArray) and fixed slot layout, but number of retired arrays is not bounded here | `erl_proc_sig_queue.c:10589–10660` deinstalls and schedules later refcount decrement; .h:1957–1976 only frees at final reference zero. Demonitor/flush and thread progress alone do not certify callback execution/all reference drops; unresolved |
| Expired/canceled native timers, message fragments and deferred destroy work | Timer executor marks state, queues target message, canceling thread queues remote cleanup, timer owner decrements refs | `erl_hl_timer.c:247–248` cancellation processing limits are service limits (100/5), not queue-admission limits; timer/control layouts still need ABI evidence | :1098–1126 sets TIMED_OUT before message allocation/enqueue; :1881–1883 queues cross-scheduler cancellation; :1023–1063 schedules destruction at final timer reference. One logical active timer is not one allocated native timer; unresolved |
| Thread-progress later-op and miscellaneous auxiliary work | Native timer/signal/process paths append; scheduler/aux executor runs callbacks after required progress | erl_process.c:2280–2370 boosts callback service by list_len/8 and enqueues by incrementing list_len. :1687–1698 cleanup-size threshold requests wakeup. Neither site rejects/backpressures further creation or certifies a fixed backlog | Thread progress governs visibility/access safety; actual callback execution and remaining dirty references are further edges. No guaranteed reclamation delay plus enforceable creation-rate bound established; unresolved |
| TLS caller, sender/receiver, delivery and ownership tracking metadata, including failed setup | Dial helper/owner calls OTP SSL; TLS connection tree/sender/receiver and controlling user exchange calls/signals; tracker/scope monitor returned inventories | Two connection slots limit current transports, but unsuccessful setup may return no socket inventory. Frozen SSL policy bounds payload, not all TLS caller queues/aliases/delivery metadata. Private crypto heaps remain separate exclusions | tls_gen_connection.erl:78–123 creates sender/receiver tree; ssl_gen_statem.erl:297–339 handshake calls; :821–825 changes user monitor; :1304 calls gen_statem. Known returned receiver/sender are independently tracked. Failure without inventory preserves cleanup_unconfirmed and retires generation. Required visible TLS metadata reserve remains unresolved |
| Mailbox snapshots, binary/term copy overlaps, allocator retained carriers | Pool observes messages for dirty-socket correctness; caller snapshots and BEAM GC/allocators own copies/carriers | `Process.info(:messages)` may copy the entire observed mailbox; fixed producer/input premises are required to bound that copy. Binary refcounts, heap overlap and carrier policies need separate certified costs | Observation consumes nothing and supplies no native frontier. Dirty-socket scan remains for socket reuse safety. RSS/carrier plateau is empirical, not an object population/OS return theorem; unresolved |

### Smallest remaining proof obligations

1. Prove a history-independent maximum backlog for each retired timer, monitor,
   alias, signal buffer, process control/reference and later-op family, including
   the TLS paths. Alternatively supply an explicitly supported runtime-owned
   reclamation acknowledgement for those same families. Wakeups, increasing
   service loops, ordinary fairness, wall-clock deadlines and observed latency
   do not by themselves supply this maximum.
2. Certify native/term layouts, all retained and overlap payload shapes, build,
   flags and allocator treatment for the exact original profile. The workload
   supplies concurrent counts, not all ABI sizes or lifetime counter costs.
3. Give every included control sender finite pre-enqueue admission and target
   settlement ownership, including timeout/lost-evidence cases. Current request
   ingress retains a request lease through tracker death; it is not a universal
   control-operation gate. Fixed public caller counts alone do not cover
   repeated timed-out requests to a delayed target.
4. Independently requalify the consumer's actual ledger on the published cohort.

These are missing edges, not a proof that a bound is impossible. No arbitrary
history leak trace has been established. Adding a receipt from application
snapshots would not answer any of these obligations.

## Independently justified hardening and limits

Managed H1 response delivery uses one fixed producer-to-stream writer session
with reciprocal monitors and one admitted chunk. Reader ACK remains the credit
boundary; receiving bytes into the stream mailbox does not grant another write.
The writer handle is held in request state, not a process dictionary. It cannot
be used by another producer; a timeout/abort/deadline closes its credit for the
rest of the session. It does not silently recycle the uncertain chunk. Stream
failure releases the pending application write; producer death before finish
reports an error (the reason can be `:noproc` if the owner died before monitor
initialization), while an already finished/failed unread response keeps its
terminal result for a late reader. No new unbounded tombstones are retained.
`HTTP.Stream.chunk/3` and non-managed behavior remain unchanged.

H1 pending ownership still has its original one-second deadline. Activation is
restricted to the pending owner; the lifecycle tracker validates the pending
deadline before releasing socket/TLS monitors. That accepted transaction is the
activation frontier. A reply delayed beyond the deadline does not undo an
already accepted transfer. An expired or lost tracker does not certify handoff. Checkout checks deadlines around socket validation/transfer and retains
the queued-socket-event check. A maintenance tick can be delayed without granting
an expired lease. Logical expiry records stay bounded by the pool entry cap;
maintenance ticks are reference matched. Scope reconciliation likewise accepts
only the current timer reference and schedules its successor after reconciliation.
These reduce churn/duplicate chains; remaining native tick retirement is unknown.

`HTTP.RequestCompletion.await/2` success now also requires tracker termination,
matching its documented tracked-resource contract. A settled latch with a live
tracker returns cleanup_pending at the finite deadline. Failure evidence remains
cleanup_unconfirmed. Whole-generation `await_retired/2` already included
coordinator termination and keeps that behavior. Neither barrier proves native
reclamation, allocator/OS return or remote byte receipt.

### Control-operation audit

Pool checkout/prepare/activate currently use finite GenServer.call waits;
activation's existing lifecycle handoff waits synchronously. If a caller deadline
expires while a target retains the operation, alias deactivation is not target
settlement. In particular a delayed checkout may transfer to a still-live caller
that has stopped waiting. Current generation resource tracking is not a receipt
acknowledging that caller consumed the lease. Preventing that race completely
needs pre-admitted operation slots and an explicit offer/accept/cancel protocol
spanning pool, request tracker and owner, with uncertain transfers retained.
No claim of such a protocol is made by this timer/stream patch.

Lifecycle deadline_call aborts its tracker after timeout; existing scope ingress
keeps admitted/canceling requests charged until tracker termination. Scope
connect_start may allocate before its caller receives a token; tracker DOWN
marks and prunes empty connection slots, while independently tracked resources
continue to hold their slot. Snapshot timeout does not cancel the queued
snapshot, and retire timeout does not establish whether retire was consumed.
Fixed caller counts do not constitute pre-enqueue admission of these operations.
No new infinity timeout, monitored helper per chunk, cross-sender fake barrier or
native refund is introduced. A full control protocol would be a separate focused
change with its own finite slot/admission/closure proof; this unresolved obligation
continues to forbid a numerical activation budget.

## Validation and release-note draft

Deterministic logical tests cover 500 acknowledged chunks with one writer monitor,
closed credit on timeout/abort/deadline, wrong writer and stale token, producer or
stream termination, a settled latch with a live tracker, repeated pool reuse,
expired/delayed handoff and checkout, dirty socket events, owner death, retirement,
and stale maintenance refs. They establish library protocol behavior for those
traces, **not ERTS C-object reclamation**. Existing parser/trailer, early/late reader,
cancellation, retirement races and failed OTP TLS setup tests remain required.

Before publication run warnings-as-errors compile, formatter, full umbrella
unit suite, Credo, Dialyzer and the workflow's wire/E2E/candidate-package gates.
Record actual runtime, commands, seed, exclusions and failures in the release
evidence. Repeated reuse and long-stream sampling must label process/port,
mailbox/binary/allocator/RSS counts as empirical observations. A zero snapshot or
plateau is not universal arbitrary-history boundedness.

Release note: reduce managed H1 response monitor churn with a stable writer;
coalesce H1 pool expiry and reference-match scope reconciliation; enforce expired
handoff/lease checks and tracker termination for logical completion. **Native
accounting remains uncertified; #97 stays open.**

## Gaoxy requalification checklist

- Resolve all nine packages at the new exact coordinated published version;
  verify Hex identities/checksums/dependency edges and source/tag parity.
- Reproduce the exact original runtime/build/profile, certifying ABI/layout and
  scheduler/allocator flags independently of version strings.
- Re-run the actual 72-row ledger, parser/cancellation/late-reader cases, H1 reuse,
  ownership timeout races, failed TLS setup and retiring/uncertain generations.
- Recompute every native/control reserve using proved populations and costs;
  charge all four outer slots until the required frontier is established.
- Missing or mismatched proofs leave numerical managed production disabled.
  Functional tests can pass independently; do not close #97 on hardening/release.
