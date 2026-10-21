# TLS migration design and compatibility contract

Status: P0 baseline/interfaces recorded; v1 targets below are not implemented public APIs
or accepted migration test results.
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
| Default TLS versions | 1.3 + 1.2 | HTTP ordinary default now mixed; raw engine default 1.3 | One ClientHello; explicit versions and concrete profile order retained, auto tickets/explicit cipher policy keep existing 1.3 context absent versions (implemented adapter slice) | core | [version-policy tests](../apps/http_core/test/http/ex_ssl_version_policy_test.exs) | Broader P1 compatibility/consumer gates remain |
| TLS 1.2 endpoint profile | OTP policy | ECDHE AES-GCM, EMS, initial secure renegotiation | Independent peer coverage; decide PKCS1 SHA256+ handshake support separately from TLS1.3 (decision) | ex_ssl | `apps/ex_ssl/test/ssl/tls12_interop_test.exs` | Yes |
| CA precedence / reference identity | System roots unless explicit CA; origin verification | Explicit cacerts, then file, then roots; DNS/IP identity and SNI | Preserve system/custom trust, pinned and tunnel-origin identity (supported subset) | core, ex_ssl | `tls_transport_test.exs`, `reference_identity_interop_test.exs` under respective app tests | Additional route matrix |
| `verify_none` | Public adapter passes through; managed allows | Rejects | Faithful implementation or explicit versioned compatibility change (decision); keep verify_peer default | ex_ssl, core | `tls_transport_test.exs`, `apps/ex_ssl/test/ssl/certificate_policy_options_test.exs` | Yes |
| Verification callbacks, partial chain, CRL/OCSP, encrypted keys, identities | Ordinary OTP backend accepts backend-specific options; managed policy explicitly excludes callbacks/revocation/encrypted keys | Bounded verified subset, explicit unsupported errors | Classify ordinary escape hatches separately; verify_fun has actual HTTP tests and special pool treatment; no whole-OTP claim (decision) | ex_ssl | `certificate_policy_options_test.exs`, `apps/http_fetch/test/http/tls_setup_evidence_test.exs`, mTLS candidate groups | Yes until individually resolved |
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

## Compatibility decision direction (source-reviewed; implementation gates remain)

- Preserve explicit `verify_none` for TCP HTTP as an implementation requirement,
  keeping verify_peer default and all handshake signature/Finished/AEAD checks.
  Fetch's real self-signed success test and the managed validator establish this
  public behavior; current optional ExSSL rejection does not preserve it globally.
- Preserve explicit driver buffer/tos/tclass/priority semantics through actual inet
  options where the OS supports them. Check driver values, precedence, upgrade and
  mutation phases against OTP; never equate driver buffer with TLS parser limits.
- Keep concrete explicit WireProfile versions authoritative when caller versions are
  absent. Preserve existing explicit auto-ticket callers as TLS1.3-only when versions
  are absent; ordinary unprofiled/disabled-ticket defaults can become mixed. Explicit
  conflicting versions/profile and explicit mixed+auto remain errors until implemented.
  This contextual-default proposal needs positive and negative adapter/candidate tests;
  an existing H2 resumption fixture omits versions and must continue working.
- Implement TLS1.2 PKCS1 SHA256/384/512 with version-specific scheme resolution and
  independent forced-scheme peers, never by widening TLS1.3 CertificateVerify.
- Resolve managed controls individually. Client honor_cipher_order may be inert only
  after differential OTP evidence. middlebox_comp_mode affects actual wire behavior.
  reuse_sessions is TLS1.2 resumption, distinct from H1 pooling/TLS1.3 tickets. Manual
  ticket enum acceptance is public policy but does not imply HTTP ticket socket APIs.
- Ordinary OTP verify_fun has real setup/cancellation tests and a non-reusable pool
  key rule; preserve its behavior or explicitly version its removal. Managed policy
  already excludes it. CRL/OCSP/partial_chain/encrypted-key/multiple-identity escape
  hatches have no equivalent independent engine implementation: removal must be a
  named versioned incompatibility with actionable errors and migration notes, not a
  quiet claim that current optional ExSSL rejection settles the overall contract.

These directions do not accept a breaking removal or establish completed support.
Any narrowed ordinary OTP escape hatch remains a release blocker until its exact
boundary and migration behavior are resolved and documented.

### Effective configuration facts

`HTTP.Transport.SSL` supplies mixed TLS versions and default trust. The ExSSL
adapter now supplies mixed versions for ordinary calls and lets the engine resolve
trust. Explicit versions win; a concrete profile supplies its own version order.
Auto tickets and explicit cipher policies retain the previous TLS1.3 context when
versions are absent. This preserves existing ExSSL cipher callers without guessing
versions from cipher spellings; broader OTP cipher-policy parity still needs a
separate acceptance decision. The raw SSL facade default remains TLS1.3. The runtime also
injects send timeout/close behavior and ALPN; comparisons must use these effective
options, not raw engine defaults. Managed policy freezes CA/client identity
snapshots, policy hash and generation pools and currently freezes OTP backend.
It injects send_timeout, buffer, recbuf, sndbuf and send_timeout_close.

Changing only the ExSSL version default also changes explicit profile and auto-ticket
interactions. The adapter test currently expects unspecified ExSSL versions to reject
a TLS1.2-only peer: replace that expectation deliberately while preserving an explicit
TLS1.3-only negative. Existing candidate TLS1.2 tests supply versions explicitly and
do not establish unspecified-default or managed behavior.

## Public routes and effective policy (source-reviewed)

Backend retention and effective-policy snapshots are different contracts. Fetch,
SSE and WS resolve/pin the provider; an ordinary fresh redirect/reconnect dial still
resolves defaults/roots/files again. Existing pooled sockets retain their established
policy. Only managed freeze explicitly materializes CA/identity/system-root snapshots.
Do not describe ordinary raw options, or H3's key/connect double normalization, as
an immutable managed policy.

| Public route | Actual sequence and TLS peer | Scope / acceptance owner |
| --- | --- | --- |
| Fetch direct H1/H2 | [fetch](../apps/http_fetch/lib/http.ex#L328) → options/completion/task → SocketClient → [Dialer](../apps/http_runtime/lib/http/runtime/dialer.ex#L411) → adapter/ALPN → protocol owner | Provider pinned through redirect; fresh-hop route, trust and deadline resolution; core/runtime/client suites |
| Pinned HTTPS | dial connect_address, retain origin authority/Host and default identity/SNI; explicit SNI/reference override remains an independent option | [connect-address scenarios](../apps/http_fetch/test/http/connect_address_test.exs); core/runtime; no proxy/Unix/H3 or automatic redirect combination |
| HTTP via HTTP proxy | TCP to proxy, absolute-form HTTP request, origin Host; no TLS or CONNECT | [proxy](../apps/http_core/lib/http/proxy.ex#L112); core; no origin fallback |
| HTTPS via HTTP proxy | TCP to proxy → CONNECT origin → strict plaintext boundary → adapter.upgrade using origin identity → H1/H2 | [CONNECT](../apps/http_core/lib/http/proxy.ex#L123); core/runtime; raw phase must join provider lifecycle; option conflicts currently normalize after proxy I/O |
| HTTP via HTTPS proxy | TLS to proxy identity, forced http/1.1 → absolute-form HTTP | [HTTPS proxy](../apps/http_core/lib/http/proxy.ex#L106); core/runtime; trust/client identity belong to proxy; HTTPS origins reject, no TLS-over-TLS |
| Unix Fetch/SSE/WS H1 | [Unix](../apps/http_core/lib/http/transport/unix.ex#L7) precedes scheme selection; gen_tcp local-domain connection with plain HTTP/Upgrade | Core/clients; HTTP/ws Unix supported, H2/H3/proxy combinations reject; https/wss currently also selects plaintext, requiring the explicit security correction below |
| EventSource | [Connection](../apps/http_event_source/lib/http/event_source/connection.ex#L265) → H1 adapter worker or runtime H2/H3 relay | Backend/raw options retained across reconnect; cross-origin credentials stripped, HTTPS downgrade and client-identity redirects rejected; protocol-only H1 fallback; no supported forward-proxy plumbing |
| WebSocket | [H1](../apps/http_web_socket/lib/http/web_socket/connection.ex#L463) connects/validates Upgrade before acknowledged transfer; [H2](../apps/http_web_socket/lib/http/web_socket/connection.ex#L420) uses runtime extended CONNECT | Provider/options/deadline retained; one capability-only H1 fallback; no authentication fallback, redirect/reconnect or H3; mode:proxy means frame forwarding, not HTTP proxy routing |
| Explicit H3 Fetch/SSE | [relay](../apps/http_runtime/lib/http/http3/stream.ex#L21) → key/owner/session → [QUIC](../apps/elixir_quic_http3/lib/quic_http3/transport/quic.ex#L61) → TLSDriver → SSL.QUIC | Separate TLS1.3 beta, explicit CA, origin reference distinct from SNI; global TCP backend ignored, explicit backend/proxy/Unix/socket options reject; no TCP fallback |
| WebTransport | [default adapter](../apps/http_web_transport/lib/http/web_transport/transport/quic.ex#L4) always returns webtransport_not_supported_by_elixir_quic_http3 | Preserve unsupported boundary and selector isolation; public module wording now matches this result, with no new transport implementation |

Explicit DNS SNI may also set ordinary ExSSL's DNS certificate reference unless
ex_ssl.reference_identity supplies the independent reference; pinned-IP handling
forces the origin-IP reference. Default origin identity must not be confused with
an unconditional prohibition on the caller's supported identity overrides.

The following newly traced boundaries remain named release blockers:

- **Secure Unix correction (core/clients):** reject https/wss with unix_socket before
  local-socket I/O; preserve plain HTTP/ws. Add direct, redirect-to-secure and WS/SSE
  negative scenarios beside [HTTP Unix coverage](../apps/http_fetch/test/http_unix_socket_test.exs).
  Current plaintext selection does not establish TLS-over-Unix support.
- **Fetch client-identity redirects (core/clients):** [candidate coverage](../scripts/ex_ssl_mtls_redirects_test.exs#L78)
  deliberately allows OTP cross-origin identity forwarding while ExSSL/H3 reject.
  Promotion therefore needs a named versioned compatibility change and migration
  guidance: use manual redirect and choose origin-specific identity explicitly.
  Target automatic cross-origin identity isolation, retain same-origin behavior,
  and separately test unchanged HTTPS-proxy TLS identity when the HTTP origin changes;
  comparing URI origin alone can be too conservative for that proxy route.
- **CONNECT preflight (core/runtime):** normalize conflicting TLS profile/version/ALPN
  and unsupported options before contacting proxy. [Direct conflict coverage](../scripts/ex_ssl_options_test.exs#L60)
  does not prove zero proxy accepts; add an independent listener scenario.
- **SSE/WS proxy options (clients):** endpoint options are not retained by these
  clients. Explicitly reject unsupported supplied proxy endpoints before an origin
  dial, with an unreachable-proxy/no-origin-contact test; do not imply Fetch proxy
  support extends to them or conflate WS frame-proxy mode with HTTP routing.
- **Policy boundaries (core/runtime):** retain ordinary fresh-dial file/default
  semantics and managed immutable snapshots; mutation tests must establish each
  declared behavior. H3 key materialization followed by raw-option re-normalization
  is a separately tracked consistency gap, not evidence of frozen trust.

Completion eligibility remains narrower than ordinary requests: [RequestCompletion](../apps/http_fetch/lib/http/request_completion.ex#L40)
excludes ExSSL, automatic protocol/redirect, Unix and H3 today. H1 prepare/ownership/
activate and H2 handoff-before-registration are existing publication points; the
provider authority commit below must join them rather than infer transfer from a cast.

## Provider lifecycle boundary (v1 implementation contract; runtime not implemented)

The internal [ResourceLedger](../apps/ex_ssl/lib/ssl/lifecycle/resource_ledger.ex)
now models five fixed resource roles, acknowledged allocation permits, exact
monitor identity matching, adoption scope and bounded proof masks. Lost creators
leave their permit tokens registered: late identities must enroll with stop and
remain pending until exact DOWN; identity loss stays sticky. An unresolved lost
permit cannot settle a proof. This is pure bookkeeping, not real monitor evidence,
a public receipt, a Lease/Transfer authority reducer or an observer seal. It is
not wired into SSL.connect or HTTP completion yet.

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
Keep pure state/policy logic separate from monitoring and socket ownership.
The reviewed v1 shape below is the implementation target. These APIs do not exist
yet. Implement the pure transition/receipt model before changing engine topology;
HTTP integrations must consume public evidence rather than copy these internals.

```elixir
SSL.Lifecycle.new(controller: pid, deadline: {:abs_ms, integer} | :infinity)
# {:ok, handle, lease} | {:error, reason}
SSL.connect(host, port, [..., ex_ssl: [lifecycle: {handle, lease}]], timeout)
SSL.connect(tcp, [..., ex_ssl: [lifecycle: {handle, lease}]], timeout)
# Existing connect return forms; one attempt may bind once only.
SSL.Lifecycle.status(handle)
# {:pending, snapshot} | {:terminal, receipt} | {:unconfirmed, reason}
SSL.Lifecycle.cancel(lease, {:abs_ms, integer})
# :ok means accepted, never cleanup confirmed; stale_lease is explicit.
SSL.Lifecycle.await(handle, {:abs_ms, integer})
# {:ok, receipt} | {:pending, snapshot} | {:unconfirmed, reason}
SSL.Lifecycle.offer(lease, %{controller: pid, owner: pid}, {:abs_ms, integer})
# {:ok, transfer} | {:error, reason}
SSL.Lifecycle.accept(transfer, {:abs_ms, integer})
# {:ok, replacement_lease} | {:error, reason}
```

Handle is stable read authority: attempt identity, observer identity and a bounded
shared terminal receipt. Lease is a separate epoch/capability; never embed it in
the stable socket, active messages or Handle. Transfer is latest-nonce/epoch-bound,
names its accepting controller and intended application socket owner, and has a
finite expiry. Controller and application owner are deliberately separate roles
(e.g. request tracker vs socket task, or pool vs H2 connection process). They may
coincide for H1. Possession of the Lease authorizes control; accept additionally
requires the named controller as caller.

`new` returns before provider data resources can be allocated. Monitor controller
before reply. A fresh unbound reservation expires after at most 30 seconds or its
earlier finite setup deadline; binding consumes it immediately. An explicit
infinite setup deadline remains supported after binding. `await`, cancel and
transfer use finite absolute deadlines in the same VM monotonic clock; status is
read-only. Never restart the original budget on repeated waits. A timed-out
control call has unknown acceptance; reconcile status/epoch instead of treating
it as rejection or blindly closing a socket after a transfer might have committed.

Snapshot and fixed-size receipt dimensions remain separate: setup
not_started/pending/connected/failed/cancelled, logical open/closing/closed, and
cleanup pending/confirmed/unconfirmed. Live snapshots also expose current authority
epoch and the latest bounded transfer outcome/nonce for acknowledgment recovery.
Preserve the raw connect error only in the
existing connect result, not in retained evidence. Terminal data uses finite setup
failure categories and fixed resource-role/proof/loss masks, never arbitrary peer
errors, PID lists, stacks, payloads, transfer histories or TLS keys. Publish all
terminal fields before a final seal operation. Seal once; late messages cannot
rewrite terminal evidence. Reader trust is provider attestation under cooperative
API use, not protection against hostile same-VM memory inspection or mutation.

Cancellation and transfer acceptance serialize in one authority reducer. Accepted
cancel closes allocation/use admission and prevents acceptance. Committed accept
increments epoch, revokes all old Lease copies, verifies application-owner transfer
acknowledgment, replaces the controller monitor, and returns the new Lease to the
recipient. Repeating the latest nonce from the same recipient recovers a lost reply
without rotating twice; no unbounded historical nonce set. Expired/uncommitted offer
never implies acceptance. In lifecycle-enabled sockets, destructive public calls
must enforce current application ownership/authority, including close and owner
transfer. Merely revoking Lifecycle.cancel while retaining unrestricted Socket.close
would let stale requests destroy pooled connections. Ordinary compatibility mode
retains its existing public behavior; opted-in lifecycle mode documents/tests this
authority rule before HTTP adopts it.

Enrollment needs an explicit allocation fence. An observer cannot declare success
merely because its current resource set is empty while an allocator can still create
a TCP port or writer. Setup allocators must be observed before launch and resource
adoption acknowledged before use. Abrupt connection death must not rely on its
terminate callback to kill an already-enrolled blocked writer. Receipt settlement
requires both closed enrollment and observed termination of all enrolled resources.

Public gen_tcp.connect creates/connects a port internally before returning its
identity. Observing an allocator before launch does not create a matching PORT DOWN
for an unreported port. v1 must conservatively mark loss during an unresolved
allocation permit as unconfirmed, even when the allocator has died. Never substitute
allocator DOWN for unknown port DOWN. The ordinary acknowledged path monitors the
returned port before ownership transfer/TLS use and retains that monitor through
teardown. Improving uncertain allocation cancellation requires an explicit public
socket-allocation boundary or separately established ownership proof; it cannot be
claimed by polling private state. Scope shared runtime DNS helpers separately.

STARTTLS adopts/monitors the caller-owned socket before consuming or mutating it;
foreign/not-owned sockets remain untouched. Its receipt certifies adopted-resource
cleanup, not that existing socket's birth. CONNECT paths need an earlier attempt
and raw-dial integration to cover pre-upgrade resources. Inert setup/Connection/writer
startup, provider enrollment acknowledgment and allocation permits must cover late
arrivals and creator death. Unknown late allocation means unconfirmed, never empty
set success. Observer independently kills/monitors the writer even if Connection is
killed without terminate; writer's own owner monitor cannot interrupt a native send.

The observer seals only after matching ref/type/object DOWN for each enrolled data
resource and a closed allocation fence. It is outside that data-resource set and
must terminate after publishing. await also observes observer termination within its
own deadline. A late reader may use an already sealed attestation plus current
observer absence; it must not interpret :noproc as a historical successful exit
reason. Observer death with unsealed evidence is unconfirmed. This contract proves
local provider-resource termination, not remote delivery/close-notify receipt,
retry safety, secret zeroization, kernel reclamation or VM-global helper shutdown.

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

The measured H1 diagnostic baseline and full samples are recorded in
[tls-migration-validation.md](tls-migration-validation.md) and
[tls-migration-p0-http-baseline.json](tls-migration-p0-http-baseline.json). They do not
cover the entire target matrix. The following v1 engineering budgets are promotion
targets, established before lifecycle/provider changes are accepted. Changing them
requires a recorded rationale and fresh comparative evidence; do not relax a
threshold merely to make a candidate pass.

Use the same host, runtime, peer, verification/cipher policy, payload, pool limits,
concurrency and warm state for OTP and candidate. Bracket candidate trials with OTP
runs; if the OTP reference drifts over 20%, investigate the environment and rerun.
For direct verified H1/H2 on TLS1.2 and TLS1.3, run cold small requests, reused small
requests, separate 1 MiB upload/download and cancellation under blocked output at
concurrency 1/8/32. Use at least 1,000 measured requests after warmup in each of three
independent trials; each trial must meet the applicable budget. Report raw samples,
p50/p95/p99, failures and effective options. Other routes keep mandatory correctness
coverage; do not extrapolate direct-path performance to proxies or H3.

| Metric | Required promotion budget |
| --- | --- |
| Request latency | candidate p50 ≤ 2 × OTP p50 + 2 ms; p95 ≤ 2.5 × OTP p95 + 5 ms; p99 ≤ 3 × OTP p99 + 10 ms |
| 1 MiB application upload/download | each direction ≥ 70% of matched OTP goodput, with identical payload checks and no failed exchanges |
| Known-resource cleanup | public confirmed receipt after explicit close/cancel, p99 ≤ 500 ms and every wait ≤ 1,000 ms; close-return/unsupported/pending/unconfirmed are not successful ordinary cleanup samples |
| Per-connection live resources | no more than matched OTP + 2 provider processes; one underlying TCP socket per connection; bounded observer/allocation roles independently enumerated |
| Retired resources | zero surviving enrolled data-resource monitors after confirmed await; observer also terminated; all ports returned after retirement |
| Reuse/soak resources | 30-minute H1/H2 reuse soak, both fixed single connection and 100 live connections, at least 1,000 completed cycles; no accumulating provider process/port/generation count |
| Memory during matched soak | p95 process memory ≤ 1.5 × OTP + 8 MiB; p95 binary memory ≤ 2 × OTP + 2 MiB; report actual live connection count and VM allocations separately from RSS |
| Memory after full retirement | after a fixed 2-second observation, binary allocation ≤ warmed baseline + 8 MiB, global process count ≤ warmed baseline + 2, no surviving provider-owned resources; repeated cycles must plateau |

Monitor-loss and unresolved-allocation adversarial cases must explicitly return
unconfirmed; they are separate negative tests, not samples relabeled as successful
cleanup. Global VM counts and memory observations complement provider receipts;
they cannot replace them. No forced global GC may manufacture an ordinary cleanup
pass. TLS1.2/resumption/H2/managed/other supported runtimes, soak measurements and
stable tails remain unexecuted. The current 30-sample H1 script is a diagnostic
baseline, not the full P5 load/soak validator. No performance acceptance is claimed.
