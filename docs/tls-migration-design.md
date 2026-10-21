# TLS migration design and compatibility contract

Status: P0 in progress; design proposals below are not implemented or accepted test results.
Execution baseline: `main`, `6b69bde3f43f2270317c38fbe68d5ac9635d3b36`, all nine packages
`0.21.14`, initially clean worktree, 2026-10-21 (Asia/Shanghai).
Local toolchain: Elixir 1.20.1 / Erlang OTP 29 (ERTS 17.0.2).

## Goal and ownership

Make this umbrella's `apps/ex_ssl` the only production TLS provider while retaining
supported HTTP contracts. A minimal production consumer release must work with OTP
SSL absent from its code path. `:crypto`, `:public_key`, the public `SSL` facade,
`ssl:` options and compatibility message atoms remain valid.

| Owner | Responsibility |
| --- | --- |
| `ex_ssl` | TLS protocol, verification, record/writer ordering, provider resources and public lifecycle evidence |
| `http_core` | Effective TLS policy, transport adapter and request-level evidence integration |
| `http_runtime` | Dialing, pools, managed generations, capacity and ownership transfer |
| Fetch / EventSource / WebSocket | Existing public request, streaming, cancellation and protocol APIs |
| QUIC / HTTP3 | Separate public `SSL.QUIC` integration; preserve supported explicit H3 beta |

No server/DTLS expansion, TLS-over-TLS proxy support, new H3/WebTransport support,
0-RTT, hidden provider fallback or uncertain request replay is part of this work.
The historical standalone ex_ssl repository is provenance, not the implementation.

## Compatibility inventory

Classification: **supported** means source and authored coverage exist, not that this
execution has validated the whole operation. **required** needs implementation.
**decision** is an unresolved public compatibility decision and blocks promotion.
Test paths below are relative to the repository root.

| Public operation / option | Current OTP behavior | Current ExSSL behavior | Required target / classification | Owner | Acceptance source | Release blocker |
| --- | --- | --- | --- | --- | --- | --- |
| Unspecified backend | OTP default | Explicit selector works | Preserve OTP until P4 passes; consistent ExSSL default only in P5 (required) | core, clients | `apps/http_core/test/http/tls_backend_test.exs` | P5 gate |
| Default TLS versions | 1.3 + 1.2 | HTTP adapter and engine default 1.3 | HTTP default 1.3 + supported 1.2 in one ClientHello; explicit 1.3 remains (required) | core | `apps/http_core/test/http/tls_transport_test.exs`, `scripts/ex_ssl_tls12_test.exs` | Yes |
| TLS 1.2 endpoint profile | OTP policy | ECDHE AES-GCM, EMS, initial secure renegotiation | Independent peer coverage; decide PKCS1 SHA256+ handshake support separately from TLS1.3 (decision) | ex_ssl | `apps/ex_ssl/test/ssl/tls12_interop_test.exs` | Yes |
| CA precedence / reference identity | System roots unless explicit CA; origin verification | Explicit cacerts, then file, then roots; DNS/IP identity and SNI | Preserve system/custom trust, pinned and tunnel-origin identity (supported subset) | core, ex_ssl | `tls_transport_test.exs`, `reference_identity_interop_test.exs` under respective app tests | Additional route matrix |
| `verify_none` | Public adapter passes through; managed allows | Rejects | Faithful implementation or explicit versioned compatibility change (decision); keep verify_peer default | ex_ssl, core | `tls_transport_test.exs`, `apps/ex_ssl/test/ssl/certificate_policy_options_test.exs` | Yes |
| Verification callbacks, partial chain, CRL/OCSP, encrypted keys, identities | OTP public options available | Bounded verified subset, explicit unsupported errors | Inventory actual required contract and decide each incompatibility; no whole-OTP claim (decision) | ex_ssl | `certificate_policy_options_test.exs`, mTLS candidate groups | Yes until classified |
| Safe TCP/send options | OTP options | Adapter allowlist; defaults < ssl < socket options | Preserve explicit precedence and mutation/binding rules (supported) | core, ex_ssl | `scripts/ex_ssl_options_test.exs` | Required matrix |
| Managed H1/H2 | OTP only | Rejected before dial | Enable after provider lifecycle and policy are complete (required) | runtime, core | `apps/http_fetch/test/http/managed_otp_tls_lifecycle_test.exs` adapted to ExSSL | Yes |
| Managed internal `buffer: 65_536` | Injected into socket options | Adapter and engine reject | Implement faithful driver buffer support or document/test equivalent bounded internal policy; never discard caller value (required) | runtime, core, ex_ssl | `apps/ex_ssl/test/ssl/tcp_options_test.exs` plus managed tests | Yes |
| Explicit tos/tclass/priority/reuse_sessions/middlebox_comp_mode/honor_cipher_order/manual tickets | Managed policy accepts | Unsupported controls rejected | Per-option implementation or versioned compatibility decision (decision) | runtime, ex_ssl | Add independent positive/negative option matrix | Yes |
| Ordered ClientHello profiles | Backend-specific | Exact version/ALPN/policy matching | Preserve wire order; resolve TLS1.3 profiles against future mixed HTTP default without silently rewriting them (decision) | core, ex_ssl | `scripts/ex_ssl_options_test.exs`, engine options/profile golden tests | Yes |
| Tickets / resumption | OTP behavior | Disabled default; auto only TLS1.3 and no identity | Preserve explicit TLS1.3 opt-in; do not ignore auto under mixed default (decision) | core, ex_ssl | `scripts/ex_ssl_resumption*_test.exs` | Yes |
| Completion / failed setup cleanup | Current barrier, conservative unconfirmed setup failures | Explicitly unsupported | Public provider evidence before allocation; preserve pending/unconfirmed semantics (required) | ex_ssl, core, Fetch | `apps/http_fetch/test/http/*request_completion_test.exs` | Yes |
| H1 handoff / H2 cancellation | Managed ownership and capacity invariants | Managed path disabled | Handoff transfers cancellation rights; one H2 stream cancel preserves others (required) | runtime, core | Managed and pooled completion tests | Yes |
| Busy writer + inbound control | OTP handles its implementation | Control output can fail `:busy` | Bounded pending output; preserve ciphertext, epoch and absolute deadline (required) | ex_ssl | Reproduce with independent KeyUpdate/upload and close races | Yes |
| Fetch / SSE / WSS | Existing supported H1/H2 APIs | Explicit ExSSL ordinary paths exist | Preserve streaming, reconnect pinning, Upgrade, timeouts, abort and proxies (supported subset) | clients, runtime | Existing client suites + feature candidate groups | Full integrated acceptance |
| Explicit H3 / QUIC | Separate path | Public SSL.QUIC path | Preserve current explicit static/literal QPACK beta; no new support claim | ex_ssl, QUIC, H3 | Existing QUIC/H3 source and candidate gates | Shared-core regression |
| Production dependency closure | Five HTTP manifests include ssl | Independent engine itself needs crypto/public_key | Remove adapter/dispatch/private assumptions and five app dependencies in P6; isolate test peers (required) | all, release tooling | New actual production release + BEAM/boot/closure gate | Yes |

### Effective configuration facts

`HTTP.Transport.SSL` supplies mixed TLS versions and default trust. The ExSSL
adapter supplies TLS1.3-only and lets the engine resolve trust. The runtime also
injects send timeout/close behavior and ALPN; comparisons must use these effective
options, not raw engine defaults. Managed policy freezes CA/client identity
snapshots, policy hash and generation pools and currently freezes OTP backend.
It injects send_timeout, buffer, recbuf, sndbuf and send_timeout_close.

Changing only the ExSSL version default also changes explicit profile and auto-ticket
interactions. The adapter test currently expects unspecified ExSSL versions to reject
a TLS1.2-only peer: replace that expectation deliberately while preserving an explicit
TLS1.3-only negative. Existing candidate TLS1.2 tests supply versions explicitly and
do not establish unspecified-default or managed behavior.

## Provider lifecycle boundary (requirements; API still to be finalized)

The current `HTTP.RequestLifecycle` extracts two private OTP socket layouts.
`HTTP.RequestCompletion` rejects ExSSL. ExSSL's opaque socket and connection
information do not provide a cleanup receipt, and connection termination requests
writer exit without waiting for observed writer DOWN. `SSL.close == :ok` is not a
resource barrier. No HTTP inspection of `%SSL.Socket{}`, private state or guessed
writer PIDs may replace these gaps.

The proposed public boundary must provide:

1. An opaque attempt handle before dial, TCP allocation, TLS process or writer
   creation, including STARTTLS upgrade. Failed setup retains the same evidence.
2. Provider-owned enrollment/monitoring of connection, writer, TCP and setup workers.
   Enrollment acknowledgment precedes work; cancellation cannot miss a child.
3. Distinct setup/handshake outcome, logical closure and observed cleanup state.
   Retry safety separately requires proof about submitted HTTP bytes.
4. Finite cancellation/await using the existing absolute monotonic deadline; timeout
   is pending, observer/evidence loss is unconfirmed, never success.
5. Terminal evidence readable after observer/connection death, settling once only
   after provider resource DOWN. Live observer and receipt retention are bounded;
   handles held by callers may retain a small immutable/atomic terminal receipt.
6. Stable connection evidence across owner transfer, with acknowledged cancellation
   authority transfer. An old request cannot cancel a connection accepted by a pool.

Request completion releases/hands off request resources and reservations; a healthy
pooled connection remains alive. Generation retirement waits for provider cleanup.
Keep pure state/policy logic separate from monitoring and socket ownership. The
concrete API, enrollment protocol and handoff authorization require review before
P1/P2 workers modify shared interfaces. A minimal candidate is `SSL.Lifecycle.new/1`
returning a stable read handle plus a revocable control lease, a namespaced
`ex_ssl: [lifecycle: {handle, lease}]` connect option, and public status/cancel/await/
handoff functions. Existing synchronous connect return forms can remain intact.
Names and shapes are provisional; the invariants above are authoritative.

Enrollment needs an explicit allocation fence. An observer cannot declare success
merely because its current resource set is empty while an allocator can still create
a TCP port or writer. Setup allocators must be observed before launch and resource
adoption acknowledged before use. Abrupt connection death must not rely on its
terminate callback to kill an already-enrolled blocked writer. Receipt settlement
requires both closed enrollment and observed termination of all enrolled resources.

Pool handoff must serialize cancellation authority with the existing publication
points: H1 prepare/controlling_process/activate and H2 handoff before register/dispatch.
A stale old lease cannot cancel after a committed transfer; an accepted cancel must
prevent transfer. Delayed acknowledgments cannot let an old owner close an already
accepted connection. H2 request cancellation remains stream-scoped; connection
control stays with the pool/owner, and retirement retains the provider dependency.

## Source/dependency inventory and evidence boundaries

Run `python3 scripts/tls_migration_inventory.py` for a bounded JSON inventory of
production libraries and manifests, including SHA256 of matched files and HEAD.
Its dynamic dispatch matches are review candidates, not resolved targets. It excludes
test/support/e2e/docs/scripts deliberately; audit generated `.app` files, BEAM imports,
dynamic dispatch and release boot/closure separately in P6.

Current executable OTP calls/types live in the temporary OTP adapter and shared
transport type. Private tuple assumptions live in RequestLifecycle. Backend literals
also occur in client options and managed policy. Five HTTP manifests list `:ssl`;
ex_ssl lists it only in the test environment. Reference test peers and historical
documentation are classified separately and are not evidence of runtime dependency.

See [execution ledger](tls-migration-validation.md) for actual commands, failures and
limits. Existing historical consumer counts remain scoped to their original versions.

## Performance and acceptance budgets

P0 still needs comparative measurements of handshake/request tail latency,
upload/download throughput, process/port counts, long-lived memory and cleanup
latency using the same peers/runtime/workloads. The existing engine resumption
benchmark is useful preliminary evidence but is not the HTTP/managed workload matrix.
Define and record numeric regression budgets from the baseline before P5 candidate
results are used for promotion. No performance acceptance is claimed yet.
