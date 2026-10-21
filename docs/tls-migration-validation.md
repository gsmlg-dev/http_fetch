# TLS migration execution ledger

## Execution identity and limits

Date: 2026-10-21 (Asia/Shanghai). Source: `main@6b69bde3f43f2270317c38fbe68d5ac9635d3b36`,
all nine packages `0.21.14`, initially clean worktree. The first P0 checkpoint
(`d7442ef`) added documentation and a bounded source inventory. Subsequent local
changes remove compiler warnings and add diagnostic peers/benchmarks; TLS defaults
and provider behavior remain unchanged. An unsuccessful shutdown experiment was
reverted, as recorded below.
Runtime: Elixir 1.20.1 / OTP 29 / ERTS 17.0.2, macOS Intel. OpenSSL 3.6.5.
This does not establish the configured Elixir 1.18/OTP28 or 1.19/OTP28 results.

Use the umbrella root for all Mix commands. Existing local `_build` metadata reports
`http_core` and `elixir_quic_http3` as `0.14.0` despite current manifests `0.21.14`.
The original `MIX_ENV=test unbuffer mix deps.get` failed dependency convergence.
Changing only the build directory made dependency preparation pass without changing
manifests or lockfile. Preserve the original cache; use the isolated path below.

```bash
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build unbuffer mix deps.get
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build unbuffer mix compile --warnings-as-errors
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build unbuffer mix test --seed 36
```

## Baseline results

| Check | Executed result | Scope / next action |
| --- | --- | --- |
| HEAD, worktree, versions | Baseline confirmed; initially clean | New P0 changes uncommitted |
| Isolated dependency preparation | Exit 0, locked versions unchanged | Stale default build cache avoided |
| Strict test compilation | Initial exit 1; after two narrow repairs exit 0 | Inline the identity-only socket_resource callers after wrapper-specific clauses; pin the outer bitstring size. No provider behavior/default change |
| Default umbrella test suite, seed 36 | Stopped with SIGTERM after failures were captured | Missing h2 prerequisite caused repeated startup failures; no final aggregate success claimed. Loopback and ExSSL upload cleanup failures also observed |
| Focused H2 trailers + HTTPS early upload, pinned peer environment | Exit 2: 55/61 passed, 6 failed | All six failures belong to ExSSL early upload timeout/cleanup cases; H2 trailer startup failures disappear with the pinned Python dependencies |
| Nine candidate archives + metadata | Passed | Built from unchanged production source, all nine identities/internal exact requirements validated |
| Isolated external candidate consumer | Passed, `external consumer smoke passed` | Existing fixture includes OTP SSL; not production removal evidence |
| Direct candidate feature invocation | Failed before test execution: EX_SSL_FIXTURE_DIR missing | Invocation did not prepare fixtures; use the existing wrapper below |
| Candidate feature wrapper | Initial exit 127 resolved; rerun exit 0, 68 tests passed in nine groups | coreutils gnubin + pinned venv; Hex.SCM source archives, not published or OTP-free proof |
| Source inventory | Exit 0 | 35 production files matched; category counts: 15 OTP calls/types, 20 private socket matches, 90 backend selections, 7 dynamic-dispatch candidates, 9 application declaration lines; overlapping categories and comments/types are included |
| Existing engine benchmark | Exit 0, 24 exchanges | Preliminary TLS-only evidence below, not HTTP/managed performance acceptance |
| `git diff --check` | Passed for changes so far | Repeat before stage commit |

The default test invocation excludes `:integration` by repository configuration.
Completed portions observed: ex_ssl 469 passed (20 properties + 449 tests), 194
excluded; elixir_quic 249 passed; http_core 381 passed, 3 skipped;
elixir_quic_http3 113 passed; http_runtime 149 passed. These partial results are
not a full successful gate. Mandatory independent coverage still needs explicit execution.

Observed source-suite failures include `:eaddrnotavail` for second loopback bindings,
pinned-address/refusal timeouts, write-idle/trailer and H2 scripted peer timing,
and Python H2 peer startup failure (`ModuleNotFoundError: h2`). Distinguish actual
platform assumptions from product failures with focused reproduction. At that first
checkpoint no production fix, assertion change or skip was applied. The pinned HTTP2
peer requirements were
successfully installed in `/tmp/http-fetch-tls-migration-p0-venv` (h2 4.2.0,
hpack 4.1.0, hyperframe 6.1.0, wsproto 1.2.0, h11 0.16.0). This changes test
prerequisites, not runtime package dependencies.

Focused reproduction after supplying those prerequisites:

```bash
PATH=/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix test apps/http_fetch/test/http/http2_request_trailers_test.exs \
  apps/http_fetch/test/http/https_early_upload_test.exs --seed 36
```

Result: 55/61 passed, six failures, exit 2. Four failures time out waiting two
seconds for ExSSL `send_timeout` cases (HTTP auto/H1, 4000/infinity). Two peer
assertions report `HTTPS socket remained open after confirmed request cleanup`
(ExSSL auto buffered infinity and H1 streamed infinity). These reproduce without
the missing H2 dependency and need lifecycle/writer diagnosis; do not dismiss them
as missing prerequisites or claim their root cause is already proven.

`brew install coreutils` completed successfully (9.12_1). With its gnubin path
and the pinned peer venv available, the unchanged candidate feature wrapper exited 0.
The report at `/tmp/http-fetch-tls-migration-p0-feature-results/ex_ssl_feature_gate-candidate.txt`
records Hex.SCM, runtime `hex-candidate/0.21.14`, fixture 0.7.2 at
`fb47051355c9d0a29caee046fa060a745ad0ce5b`, seed 36, all nine discovered groups,
and 68 passed tests (12/5/2/11/9/6/8/8/7 respectively), with no skips or zero-test
groups. These archives still contain the original production baseline, not subsequent
local repairs, and the fixture includes OTP SSL. This is candidate feature evidence,
not published package or OTP-free production release evidence.

## Follow-up timeout diagnosis and compiler repairs

A bounded non-secret probe captured explicit send_timeout=600 and changing logical
write tokens with fresh original deadlines every approximately 200–500 ms. The
previous 20 ms stable output token did not prove a single logical write remained
blocked for 600 ms. Forwarding was intact; no timeout-forwarding production change
was made. The temporary probe and logging were removed.

For native send-timeout cases only, the upload matrix now uses an independent
Python/OpenSSL peer with no background reads after request headers. Listener and
accepted sockets both receive the small receive-buffer policy. A 150 ms per-send
deadline fits the observed blocked interval rather than allowing each progressing
64 KiB logical send to complete under the old 600 ms deadline. Existing two-second
Promise wait, error classification, one-second request/source/writer cleanup bound,
and peer EOF/reset assertions remain. `tls_outcome` permits focused execution; the
external peer must report actual closure and exit successfully before acknowledgment.
All eight backend × H1/auto × finite/infinite send-timeout cases passed after the
shutdown experiment was reverted, including final peer-exit acknowledgment.

The earlier combined follow-up run passed all 469 ExSSL base checks (194 integration
checks excluded), and 78/81 selected Fetch checks. Three ExSSL peer-open failures
remained: H1 buffered/4000, auto cancel/4000, H1 streamed/infinity. Adding
write_abandoned? to zero-linger selection did not eliminate them and was reverted;
this is not a proven root cause or shipped fix. Next probes must distinguish provider
connection/writer termination, raw port disappearance, and remote TLS receiver state.

Strict compilation now exits 0 after removing the unreachable socket helper branch
without changing either identity path and pinning the external binary size in
HTTP1.IdleTimeout. A separate final run of completion, pooled completion and H2
trailers passed all 54 checks with the pinned peer PATH (see command). Existing H2 test-source
bitstring pin warning remains; it is distinct from production strict compilation.

```bash
PATH=/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix test apps/http_fetch/test/http/request_completion_test.exs \
  apps/http_fetch/test/http/pooled_request_completion_test.exs \
  apps/http_fetch/test/http/http2_request_trailers_test.exs --seed 36
PATH=/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix test apps/http_fetch/test/http/https_early_upload_test.exs \
  --only tls_outcome:send_timeout --seed 36
```

## Reproducible candidate commands

Baseline archives are retained locally at
`/tmp/http-fetch-tls-migration-p0-candidate-20261021/archives` for follow-up gates.
They precede P0 documentation edits. Never publish these baseline archives as new work.

```bash
python3 scripts/release/stage.py build 0.21.14 \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/stage \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/archives
elixir scripts/release/archives.exs 0.21.14 \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/archives
python3 scripts/release/consumer_gate.py 0.21.14 \
  /tmp/http-fetch-tls-migration-p0-candidate-20261021/archives --mode external
PATH=/usr/local/opt/coreutils/libexec/gnubin:/tmp/http-fetch-tls-migration-p0-venv/bin:$PATH \
  PYTHONDONTWRITEBYTECODE=1 EX_SSL_DEP_MODE=candidate \
  EX_SSL_CANDIDATE_ARCHIVE_DIR=/tmp/http-fetch-tls-migration-p0-candidate-20261021/archives \
  EX_SSL_RESULTS_DIR=/tmp/http-fetch-tls-migration-p0-feature-results \
  EX_SSL_TEST_SEED=36 bash scripts/ex_ssl_source_smoke.sh
```

Stage/build commands must use a fresh stage destination when retaining old evidence.
The wrapper prepares pinned historical fixture builders; actual TLS runtime in
candidate mode must resolve this umbrella's nine archives through Hex.SCM. Fixture
provenance and runtime source are distinct. Candidate feature acceptance requires
all discovered groups, no failures/skips/zero tests, and independent peer results.

## Preliminary comparative TLS measurement

Executed from root:

```bash
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix run apps/ex_ssl/scripts/resumption_benchmark.exs
```

Independent OpenSSL peer, TLS_AES_128_GCM_SHA256, TLS1.3-only, ALPN http/1.1,
1 MiB echo payload, one warmup + five measured exchanges per backend/mode.
Peer-observed resumption is false for all full exchanges; resumed modes report
false for warmup then true for all five measured exchanges.

| Backend / mode | Handshake median µs (range) | Combined transfer median µs (range) |
| --- | --- | --- |
| OTP / full | 4,355 (3,874–6,338) | 8,321 (6,687–15,644) |
| OTP / resumed | 3,005 (2,524–3,902) | 7,547 (5,964–10,098) |
| ExSSL / full | 5,565 (4,555–12,977) | 14,029 (13,200–19,944) |
| ExSSL / resumed | 3,977 (3,419–22,319) | 13,722 (11,306–17,519) |

Other baseline jobs were active, sample count is small, and transfers combine upload
and download. These values are diagnostic only: no tail latency, resource/cleanup
budget, independent throughput budget or production readiness claim follows.
Run isolated comparable HTTP workloads and set promotion budgets before P5.

## HTTP baseline measurements

The public-API benchmark and independent control peer are
`scripts/tls_migration_benchmark.exs` and `scripts/tls_migration_benchmark_peer.py`.
Full samples, 213 runtime-source/manifest hashes, tracked-patch digest, script/cert
hashes, runtime settings, peer exchanges and resource observations are retained in
[tls-migration-p0-http-baseline.json](tls-migration-p0-http-baseline.json).
The raw stdout SHA256 is included; only redundant intermediate handshake histories
were replaced with counts, with the full final history retained.

```bash
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-tls-migration-p0-build \
  unbuffer mix run --no-compile scripts/tls_migration_benchmark.exs
```

Actual run exited 0, with no concurrent project tests. Source `d7442ef` plus the
recorded local compiler repairs and scripts. Python 3.15.0 / Python-linked OpenSSL
4.0.3 (the earlier standalone benchmark used OpenSSL CLI 3.6.5). Both providers
negotiated verified TLS1.3, AES256-GCM, ALPN http/1.1, disabled peer tickets, no
resumption; client nodelay enabled. Each workload used three warmups and 30 measured
samples, concurrency one, OTP then ExSSL. Cold requests used distinct connections;
upload/download/reuse each proved the same connection ID through an explicit final
close response. All payloads and lengths were checked. Peer totals: 270 requests,
72 accepted/closed connections, zero active connections, zero peer errors,
69,206,016 uploaded bytes including warmups.

| Backend / workload | Request p50 / p95 / p99 (µs) | Measured goodput (MiB/s) |
| --- | --- | --- |
| OTP / cold small | 12,768 / 21,867 / 22,147 | — |
| ExSSL / cold small | 12,027 / 22,171 / 25,751 | — |
| OTP / 1 MiB upload | 13,048 / 25,758 / 29,224 | 60.77 |
| ExSSL / 1 MiB upload | 22,558 / 54,714 / 63,151 | 39.93 |
| OTP / 1 MiB download | 12,026 / 25,977 / 30,061 | 66.49 |
| ExSSL / 1 MiB download | 15,311 / 44,483 / 83,746 | 41.81 |
| OTP / paced reused small | 16,141 / 23,253 / 25,461 | — |
| ExSSL / paced reused small | 5,296 / 20,133 / 20,855 | — |

Cold server handshake p50/p95/p99 µs: OTP 8,969/18,266/18,486; ExSSL
7,320/10,969/21,181. This measures the peer's wrap_socket duration including client
scheduling, not isolated client handshake latency. Cold request timing includes
connect/TLS/HTTP/body verification. Goodput is sequential application transfer,
including response/body checks; it is not raw TLS bandwidth.

At post-workload observations approximately 304–387 ms after final close, both
providers had 165 VM processes, four ports including the still-live external peer,
and zero peer connections. During reused workloads OTP had 168 processes/five ports,
ExSSL 167/five. Download live binary allocations were approximately 5.10 MB OTP and
9.40 MB ExSSL, returning to approximately 3.72 MB and 3.65 MB respectively in these
observations. These are noisy global BEAM allocations, not RSS or provider cleanup
receipts; no forced global GC or plateau/leak proof is claimed.

Every OTP request's public completion returned :ok; every ExSSL request returned
`{:error, {:unsupported_completion, :tls_backend}}`. OTP measured completion wait
p50/p95/p99 µs: cold 29/49/99, upload 27/73/94, download 30/72/88, reuse 28/45/53.
The ExSSL unsupported-return duration is recorded but does not establish cleanup.
The paced reuse interval was one second, not a production long-duration soak.

Thirty observations make the reported nearest-rank p99 equal to the maximum; these
are reproducible diagnostic baselines, not stable tail acceptance. Other supported
runtimes, TLS1.2, resumption, H2/H3, concurrent loads, managed completion, long soaks
and performance acceptance remain pending. See the later v1 engineering targets;
do not infer acceptance from these ExSSL results or present the run as P5 evidence.

## Formatting and static-analysis checkpoint

Root `mix format --check-formatted` exited 0. Root `mix credo` then exited 1 while
checking 513 files: pinned Credo 1.7.13 crashes in Credo.Code.Token.position/1 on
Elixir 1.20 sigil tokens. The installed matcher for seven-element sigil tuples
requires `{line, column, nil}` metadata; actual tokens contain an ending-position
tuple instead. Failures occur in unchanged HTTP3/options/response/setup-test files,
not a lint finding in the migration edits. No dependency code was patched and no
check was disabled. Compatible supported-toolchain execution or a verified upstream
tooling update remains required; this is not a successful Credo gate.

## Expanded source, tooling and route checkpoint

Credo was upgraded alone in the lockfile from 1.7.13 to 1.7.19; existing manifest
ranges already permit it and no transitive dependency changed. The tagged upstream
[changelog](https://github.com/rrrene/credo/blob/v1.7.19/CHANGELOG.md) records final
Elixir 1.20 compatibility. Complete analysis exposed 20 existing depth-4 nesting
findings. Small helper extractions/ordered rejection checks preserve original error,
transcript/record, stream accounting and ownership-effect order. No check, threshold,
protocol policy or default was disabled/changed. Lead reviewed both disjoint worker
diffs. Final root formatting, warnings-as-errors compilation, Credo (513 files,
54 checks, no issues), and git diff --check all exit 0.

The first full post-extraction umbrella run completed, exit 2:

| App | Passed | Failed | Excluded / skipped |
| --- | ---: | ---: | --- |
| ex_ssl | 469 (including 20 properties) | 0 | 194 integration excluded by default |
| elixir_quic | 249 | 0 | 0 |
| http_core | 381 | 0 | 3 opt-in real QUIC adapter scenarios |
| elixir_quic_http3 | 113 | 0 | 0 |
| http_runtime | 149 | 0 | 0 |
| http_fetch | 1,193 (including 20 doctests) | 33 | 0 |
| http_web_socket | 138 | 0 | 0 |
| http_web_transport | 24 | 0 | 0 |
| http_event_source | 75 | 0 | 0 |

The three initially skipped real QUIC adapter scenarios were then explicitly run
with HTTP_QUIC_PHASE1_REAL=1: all three passed, exit 0 (35.2 seconds). This exercises
authenticated raw streams and negative readiness through the public adapter; it is
not independent H3 interoperability or a new capability claim. A test-only bitstring
pin warning remains visible.

Fetch failures were retained and classified: 13 depended on unavailable 127.0.0.2
binding/refusal semantics on this macOS host; 13 intentionally hit the private
buffer-probe source-hash guard after Connection source changed; six failed remote
upload closure observation; one failed cleanup while observing an earlier timed-out
request Task still present in the shared supervisor. Noninteractive sudo permission
is unavailable, so no loopback alias was installed. These platform cases are not
successful acceptance and still require a prepared host/CI run.

The Connection extraction was reviewed against unchanged closed/size/active fields,
application-data buffering, peer-close and drain transitions. The hash guard remains
enabled and now pins reviewed SHA256
7c891a11c6ea595fcaff9d99767b4d1294a7ec0e876675422c86eff93e6342ae.
All 45 SocketClient H2 plus failed-open cleanup scenarios then passed in a fresh VM,
exit 0. Test-only bitstring pin warnings remain visible; they are distinct from
passing strict production compilation. This targeted result does not turn the
previous complete umbrella run into a green run.

With integration explicitly included, all 663 ex_ssl checks ran: 659 passed, four
failed, exit 2. Three reference-identity scenarios dial unavailable 127.0.0.2. The
remaining connection_backpressure scenario could not establish its expected
KeyUpdate queued-behind-output state. Keep this as an ex_ssl/P2 blocker; the result
proves neither correct occupied-writer control ordering nor a protocol regression
introduced by extraction. The same invocation ran all 24 WebTransport checks
successfully. Its module documentation now correctly describes the unsupported
default network backend. Independent TLS1.2 Python/OpenSSL 4.0.3 RSA/ECDSA AES-GCM
and mTLS exchanges executed in the integration suite; no blanket endpoint claim.

## Local teardown versus remote closure

The upload test now captures exact Connection/writer monitors and raw TCP identity
during the existing test-only stable-output probe. After request/source/upload
termination it requires matching Connection and writer DOWN plus absent raw port
before permitting peer drain. These local checks passed even in scenarios failing
remote closure. No HTTP production code gained private ExSSL inspection or public
cleanup claims.

Repeated seed-36 whole-upload runs yielded 41/44 and 43/44, including an OTP remote
closure failure. Bounded peer diagnostics showed no receiver/sender mailbox backlog,
no server send queue, and receive buffers around 420–485 KiB despite the intended
1 KiB listener setting. Setting accepted-socket recbuf explicitly did not stabilize
the result and was reverted. A temporary close probe observed selected zero linger
returning :ok with pending output, but its eight streamed scenarios did not reproduce
the failure; the probe was removed. No close-predicate change is retained or proved.

The independent no-background-reader peer now has a two-second absolute drain
budget inside the parent's three-second observation. Timeout emits a distinct
bounded drain_timeout event with byte count/receive-buffer size and exits nonzero;
it cannot count as closure. Final native send-timeout selection passed all eight
scenarios, exit 0, with 36 unrelated upload cases excluded. Remote closure remains a
release blocker even when local resources are gone; neither observation is a public
provider receipt and kernel/peer termination is outside a local receipt's proof.

## One-minute reuse observation and v1 acceptance targets

The extended bounded H1 runner preserves default one-second pacing but permits up
to 60 seconds, requiring request intervals at most two seconds. Both providers
completed a separate approximately 60-second fixed-connection reuse interval,
three warmup plus 30 measured requests, concurrency one. Full samples, source hashes,
settings and counters are in [reuse evidence](tls-migration-p0-http-reuse-baseline.json).
As in the original artifact, only repeated intermediate handshake arrays are replaced
by counts; final history and raw-stdout SHA256 remain.

| Observation | OTP | ExSSL |
| --- | --- | --- |
| Reuse duration | 60.272 s | 60.143 s |
| One connection ID across all 33 requests | 36 | 72 |
| Live processes / ports | 168 / 5 throughout | 167 / 5 throughout |
| Live binary allocation range | 3,719,104–3,757,232 bytes | 3,640,072–3,665,216 bytes |
| Reused request p50/p95/p99 | 2,332 / 23,409 / 41,633 µs | 2,145 / 10,870 / 22,993 µs |
| After all workloads, processes / ports | 165 / 4 | 165 / 4 |

Across all rerun workloads the peer verified 270 requests and 69,206,016 upload
bytes, accepted/closed all 72 connections, and reported zero active/errors. Every
OTP public completion returned :ok; every ExSSL completion remained unsupported.
These are BEAM allocation observations without forced GC, not RSS, local receipt
proof, stable tails or the required 30-minute load/soak gate. Numeric v1 promotion
budgets are now recorded in the design before provider implementation/promotion;
they are engineering targets, not acceptance inferred from 30 samples.

Source review completed the public route matrix in the design: origin/proxy TLS
identity, plaintext CONNECT versus unsupported TLS nesting, secure-scheme Unix
plaintext selection, SSE/WS forwarding-option gaps, backend pinning versus trust
snapshots, explicit QUIC/H3, unsupported WebTransport, and provider-dependent Fetch
client-identity redirects. Each remaining difference has an owner/acceptance target.
The reviewed lifecycle v1 API separates stable evidence, revocable control and
recipient-bound handoff; lost unreported allocation must be unconfirmed. None of
those APIs or topology guarantees is implemented by documenting the contract.

## Remaining implementation and release gates

- ex_ssl/P2 owns occupied-writer KeyUpdate, cancellation/teardown, allocation fences,
  durable public evidence and stale-owner authority; retain current failing cases.
- Core/runtime/clients own the version/option, CONNECT preflight, secure Unix,
  redirect/proxy identity and managed/completion boundaries in the design.
- Prepared-host full regression, independent H3/package acceptance, stable tails,
  30-minute load/soak, other supported runtimes, Dialyzer and remote CI remain gates.
- No P1–P7 acceptance, changed default, production OTP removal or publication is
  established. Historical validation remains scoped to its original execution.

## P1 contextual versions and P2 resource foundation (round 4)

The HTTP ExSSL adapter now offers TLS1.3 plus bounded TLS1.2 in one ordinary
handshake. Explicit versions remain exact; concrete WireProfile versions retain
order and GREASE handling. Auto tickets retain TLS1.3 when versions are absent.
An initial mixed-default patch exposed a real regression for explicit TLS1.3-only
ciphers: the unchanged cipher policy worked through OTP and through explicit
ExSSL TLS1.3 but failed when versions were omitted. The regression was retained,
then fixed by preserving the previous ExSSL TLS1.3 context for explicit cipher
policies absent versions/profile. No inference from cipher spellings or mutation
of caller policy was introduced. Broader OTP cipher-option parity remains open.

All 22 [version-policy scenarios](../apps/http_core/test/http/ex_ssl_version_policy_test.exs)
passed, including independent OTP TLS1.3 and Python/OpenSSL TLS1.2 byte exchanges,
direct/upgrade paths, profile/ticket conflicts before direct TCP accepts and an
explicit TLS1.3 rejection against the same EMS-capable OpenSSL TLS1.2-only peer.
The unchanged reverse-order mixed profile works against OpenSSL TLS1.2 and 1.3;
local OTP TLS1.3 rejected that hello with illegal_parameter. OTP28/29 TLS1.2 without
EMS is separately rejected, consistent with the existing bounded engine profile.
Neither peer distinction is fixed or hidden by rewriting profiles/weakening EMS.

The internal ResourceLedger is the first P2 slice, not a public lifecycle API.
Its ten tests cover fixed resource bounds, permit fences, exact ref/type/object
DOWN matching, idempotence, stale tokens, late enrollment, adoption scope and
bounded evidence without arbitrary reasons. Independent read-only review found
that deleting permits on creator death lost late identities. The correction keeps
bounded original tokens, requires late enrollment to stop, keeps proof pending
until exact resource DOWN, and retains irreversible loss. An unresolved lost permit
cannot settle; no matching allocator DOWN substitutes for unknown TCP identity.
Actual monitors, allocator/runtime topology, authority epochs, transfer, terminal
seal and observer exit remain unimplemented.

Final shared formatting, strict compilation and Credo passed (516 source files,
54 checks, 8,594 modules/functions at that invocation). The complete seed-101 root
run then executed all nine apps, exit 2:

| App | Result |
| --- | --- |
| ex_ssl | 479 passed including 20 properties; 194 integration excluded |
| elixir_quic | 249 passed |
| http_core | 402 passed; three real-QUIC opt-ins skipped |
| elixir_quic_http3 | 113 passed |
| http_runtime | 149 passed |
| http_fetch | 1,210/1,226 passed; 16 failed |
| http_web_socket | 138 passed |
| http_web_transport | 24 passed |
| http_event_source | 75 passed |

This full run contains the first 21 policy tests; the additional independent
explicit-version negative was then included in the separate 22-pass run. Fetch
failures were 13 unavailable-127.0.0.2 scenarios, one known remote-upload closure
observation, one raw-stream listener accept returning einval, and one OTP ordinary
reuse fixture unable to observe its expected in-flight send. All source-hash H2
buffer probes passed. A fresh targeted rerun of the two newly failing Fetch files
passed 57/58: stream mismatch passed, OTP reuse again could not establish the
blocked-writer precondition. Keep that reproducible fixture/result open for P2
investigation; this does not establish a production policy regression or green
umbrella acceptance. No assertion/deadline was relaxed to hide it.

The global backend is still OTP; managed and public ExSSL completion remain guarded.
No P1/P2 exit, P4 acceptance, default promotion or publication is claimed.

## P1 native TCP options and P2 authority core (round 5)

Added buffer/tos/tclass/priority to the engine and HTTP adapter allowlists. Real
OTP/raw inet references distinguish effective driver behavior from acceptance:
on this macOS/OTP29, buffer 0/65536/2^31 reads 1/65536/1; IPv4 tos and IPv6 tclass
apply; priority accepts but reads zero. Initial duplicate buffer defaults actually
overrode the caller's 65536 with 16640. Fixed raw dial to supply its default only
when absent, and removed the attach default so STARTTLS preserves existing TCP
buffer state. Explicit ExSSL mutable upgrade settings still apply; OTP instead
retains the old raw settings and requires subsequent setopts. Both paths are
covered, with the distinction documented rather than reported equivalent.

Native wrong-family live setopts returns einval here. The test compares the
actual platform reference, including platforms that permit a setting, and checks
virtual active mode remains unchanged on driver failure. Initial raw connect
exits badarg; a narrow exit clause now returns ExSSL {:error, :badarg}. OTP adds a
formatted detail tuple; ex_ssl does not synthesize that implementation text.
All 16 mandatory TCP tests executed, no skip. Worker root-scoped core/runtime
acceptance passed 406 and 149 tests respectively (three real-QUIC opt-ins were
still skipped in that particular invocation). Core tests include exact buffer
precedence at direct and upgrade boundaries.

Added internal Authority with single-use binding, exact attempt/epoch/capability
validation, cancel/accept serialization, named recipients, exact owner ack,
monitor generations, bounded latest-nonce recovery and idempotent committed replay.
A read-only review caught missing nonce correlation in live snapshots; corrected
and covered pending/accepted/cancelled/expired/replaced outcomes. Thirteen authority
and ten resource-ledger tests passed together. These remain pure models, not a
public API or proof that real monitors/socket ownership were established.

Reviewed Connection diff (only native attach buffer defaults) and renewed the
existing test-only H2 source guard to SHA256
`e3a397587a5b137236afed3210b775f30590a067f3963ffdf4a9410e8964aac2`.
Plaintext closed/size/active state and drain ordering are unchanged; native chunk
sizes can differ. All 43 targeted H2 tests passed without bypassing the guard.
The new core driver probe also pins that audited source and coordinated app
versions; its final transport file passed all 25 tests. Final Credo remained clean.

Strict compilation and Credo passed: 518 files, 54 checks, 8629 modules/functions,
zero issues. Added full umbrella Dialyzer: its first run found one contract_supertype
warning on ResourceLedger.proof's broad map return. Added explicit finite snapshot
and proof types (scope/admission/cleanup enums and 0..31 role masks), without runtime
behavior changes or ignore-list edits. All 23 lifecycle tests passed again and the
second Dialyzer run passed: zero errors/skips; four existing unnecessary-ignore
notices retained per repository instruction.

Full root `mix test --include integration --seed 101` with the pinned
Python environment and HTTP_QUIC_PHASE1_REAL=1 exited 2:

| App | Result |
| --- | --- |
| ex_ssl | 688/692 passed, including all 20 properties; four failed |
| elixir_quic | 249 passed |
| http_core | 409 passed; three real QUIC opt-ins executed, no skips |
| elixir_quic_http3 | 113 passed |
| http_runtime | 149 passed |
| http_fetch | 1208/1226 passed; 18 failed |
| http_web_socket | 138 passed |
| http_web_transport | 24 passed |
| http_event_source | 75 passed |

All 3075 checks executed, 3053 passed and 22 failed; no excluded integration or
skipped opt-ins in this run. The existing real QUIC tests are self-implementation
coverage and do not replace an independent H3 peer/package gate.

The four ExSSL failures remain three unavailable-127.0.0.2 identity scenarios and
the existing KeyUpdate/backpressure pending-input queue assertion. Fetch failures
were 13 unavailable-address cases, the OTP reuse blocked-writer precondition, and
four remote upload closure observations. Local matching Connection/writer DOWN
and Port absence checks passed before those remote failures. One was the Python
native-timeout peer's explicit drain_timeout (16384 bytes, receive buffer491904);
three were OTP peers still waiting after local cleanup. This is failed remote
observation, not a successful closure result. Assertions, two-second Python drain
budget and public deadlines were not relaxed. No newly observed assertion category
is attributed to the option patch without causal evidence; all remain acceptance
blockers. Raw-stream listener einval from round4 did not recur.

P1 verification/signature/advanced-policy decisions and P2 runtime observer,
allocation/use enforcement, immutable terminal seal, socket authority and duplex
control-output handling remain open. Managed/completion gates and OTP default stay
in place. Candidate/release/publication acceptance has not been executed for this
implementation slice.

## Private terminal storage and TCP verification policy (round 6)

Added provider-internal Receipt and Reader, not SSL.Lifecycle or a runtime observer.
Receipt stores eight unsigned atomic words, validates fixed setup/failure/mask/epoch
metadata, restricts publication to its creating observer, and publishes once after
all payload writes. It accepts only a settled, closed-admission ledger; the future
observer must still establish/authenticate the real resource evidence. Terminal
maps retain no TLS material, raw errors, PID/port lists or capability history.

Reader requires observer absence plus a valid final seal for successful await.
Sealed/live is pending; unsealed death is unconfirmed regardless of normal/killed
exit. Late noproc establishes current absence only. A sealed resource-loss receipt
remains readable but await returns unconfirmed. Finite waits retain their original
absolute deadline, match exact monitor/type/PID, and flush their waiter monitor.

Root-scoped lifecycle tests passed 38/38 (23 existing + 15 new) with seed101.
New cases use actual process and port monitors/DOWN, a late identity after creator
loss, adopted-port scope, wrong publisher, immutable repeated seal, invalid metadata,
fixed native storage size, interrupted publication including ALL payload words
written before death, sealed/live and late readers, unsealed normal/killed death,
100 publication/monitor races, 32 waiters, expired deadlines and caller mailbox /
monitor cleanup on timeout and fast terminal/loss/error returns. A read-only
adversarial source review found no concrete defect; it did not execute tests.

Actual observer supervision, inert TLS births, authenticated enrollment/owner ACKs,
allocation-with-no-resource completion, bounded unknown-identity retention and public
socket/HTTP integration remain open. No actual TLS cleanup claim follows from these
private foundations alone.

Explicit TCP `verify: :verify_none` now skips PKIX path/identity policy; omitted
verification remains `:verify_peer`. It still decodes bounded presented credentials,
preserves SPKI/PSS key restrictions, and verifies negotiated CertificateVerify or
TLS1.2 signed ServerKeyExchange, Finished and AEAD. Existing-socket none mode permits
absent SNI/reference without inventing an identity. Unused CA anchors need not be
normalized or system-loaded; explicit CA file read errors remain errors. QUIC still
rejects none mode and uses the shared core's peer-verification default.

The protocol peer boundary checks digitalSignature when leaf keyUsage is present
and rejects duplicate keyUsage in both trust modes. RFC9846 4.5.1.2 requires X.509v3
for ALL presented TLS1.3 certificate entries: both modes and cached peers enforce it,
including a transmitted root. Locally configured v1 anchors omitted from the wire
remain allowed. TLS1.2 uses explicit protocol context and retains its certificate
version policy; generic PKIX verify/decode primitives remain unchanged. Real
OpenSSL TLS1.2 v1 none-mode traffic also passes with OTP as independent client.

An independently constructed, valid TLS1.3 server flight forces a certificate-chain
signature outside the client's actual advertised cert schemes, with offered CV
scheme and valid CV/Finished/CCS. Both OTP and ExSSL none mode connect; peer mode
rejects the chain policy. This distinguishes intentionally skipped PKIX chain policy
from mandatory handshake authentication. RFC9846 4.5.1.2 permits fallback chains and
signature-algorithm exemptions; 4.5.2 still requires offered CV schemes. Ticket
policy partition v2 includes verification mode, and cached credentials revalidate
under current mode/protocol. Actual OpenSSL full/resumed none sessions pass while
default-peer crossover rejects the untrusted peer. Legacy VerifiedPeer is explicitly
documented as a credential container, not a standalone proof of trust. An independent
read-only security review checked mode propagation, default/QUIC trust, unconditional
handshake/record authentication, SPKI restrictions and ticket isolation without
finding a concrete introduced defect; that review ran no tests or network activity.

Final policy-focused gate passed 45/45. Three-app regression executed every new
scenario: ex_ssl 724/728 passed, core 408 passed/3 real opt-ins skipped, runtime149
passed. ExSSL failures were the same three unavailable-127.0.0.2 identity cases and
the KeyUpdate pending-input assertion. Isolated reproduction passed all eight
backpressure cases but reproduced the three address timeouts, so scheduling-sensitive
KeyUpdate acceptance remains open. A raw TCP wildcard-listener probe connected to
127.0.0.1 but timed out on 127.0.0.2 without TLS; no OS network changes or weakened
identity assertions were made. This scoped run is not full acceptance.

Strict compilation and formatting passed. Configured Credo checked523 files /
8695 modules-functions with54 checks and zero issues. Optional `credo --strict`
reported200 style/design suggestions (158 design,30 readability,12 refactoring);
that additional check is not reported green. First Dialyzer found one opaque-type
contract error in Receipt.new: declared reference() did not preserve OTP's opaque
atomics_ref(). Corrected the cell type to :atomics.atomics_ref() without runtime
changes. Rerun passed with zero errors/skips and four preserved pre-existing ignore
notices. No ignore-list entries were removed.

Final full root regression used the pinned Python environment,
`HTTP_QUIC_PHASE1_REAL=1` and `mix test --include integration --seed 101`:

| App | Result |
| --- | --- |
| ex_ssl | 725/728 passed (20 properties executed); three failures |
| elixir_quic | 249 passed |
| http_core | 411 passed; all three real opt-ins executed |
| elixir_quic_http3 | 113 passed |
| http_runtime | 149 passed |
| http_fetch | 1210/1226 passed; sixteen failures |
| http_web_socket | 138 passed |
| http_web_transport | 24 passed |
| http_event_source | 75 passed |

All3113 checks executed,3094 passed,19 failed; no excluded integration or skipped
real opt-ins. New none/protocol/receipt tests passed. Existing43 H2 tests were
included without failure. Connection's production diff is only forwarding the
validated verify mode: TCP/closed/size/active/plaintext-drain layout is unchanged.
Both test-only probes were re-audited and pinned to SHA256
`96628c634cb07f924f54bc67d6f9e6e014092d65e47e88ed778c3519efa9d5b5`;
coordinated app-version guards remain in place.

The19 failures are16 unavailable-127.0.0.2 scenarios, the OTP reused-writer test's
unobserved in-flight-send precondition, an early_data raw-stream listener/accept
`:einval`, and one ExSSL streamed4000 upload peer still open after local cleanup.
That peer reported recv_oct102032 / recbuf485936. Matching local Connection/writer
DOWN and Port absence assertions passed before remote drain; remote closure is
still failed evidence. The raw-stream einval category was seen in round4, absent
in round5, and recurred here. KeyUpdate passed this full run but failed the earlier
three-app run; it remains an ordering/scheduling acceptance issue until causally
resolved. Other upload closure cases passing this run do not resolve earlier
failures. No timing/buffer/identity assertions or two-second peer-drain limits were
relaxed. Full source acceptance is not green.

A read-only proxy contract audit confirmed HTTPS-proxy plus HTTPS-origin nested
TLS is explicitly rejected today. Supported CONNECT and HTTPS-proxy forwarding
have one TLS leg, targeting origin and proxy identity respectively. Corrected stale
Fetch option documentation about supported ExSSL IP-origin CONNECT. The next P1
slice needs provider-owned prepared upgrade policy before raw proxy dial, exact
upgrade-context validation and zero-proxy-accept negatives; full trust/key/profile
resolution must not independently change later in the same attempt. Existing bind
option rejection and the nested-route rejection remain explicit. Public provider
attempt/adoption, managed/completion, platform/runtime/package/performance/CI and
release/publication gates remain open; OTP remains the default backend.

## Round7 — private observer and prepared CONNECT policy

Private observer/runtime foundation now executes under a separate DynamicSupervisor
with temporary children. Isolated all-lifecycle run passed58 checks; root focused
run after the final bootstrap corrections passed59 (38 prior +21 observer cases).
Actual helper processes and native owned ports cover foreign-port preservation,
independent exact DOWN, late delegated identity/creator loss, duplicate objects,
replayed permits, fixed role graph, distinct controller/owner death, original finite
deadlines, infinite setup, large native timers, unknown call acceptance and
nonextendable1000ms grace. Unknown permits leave unsealed evidence rather than
inferred cleanup. No native TLS Connection or public lifecycle integration is claimed.

Independent source review found and corrected two initial runtime defects: setup
helper completion could leave pending infinite setup without a result producer;
and synchronous public DynamicSupervisor admission could exceed the start budget.
Setup completion now rejects pending outcome and its actual unexpected DOWN retires
failed/internal. A disposable monitored control proxy bounds admission, preserves
the original finite budget, uses reply aliases, waits actual normal worker DOWN
before successful publication, and leaves late unbound reservations with their
original expiry. Follow-up review identified a parent-death window before caller
installed the proxy kill timer, plus budget origin sampled after validation. Timer
installation/cancellation moved inside the worker BEFORE blocking admission, and
control budget origin moved to API entry. Regression suspends the supervisor and
kills the caller after public process-spawn tracing identifies its actual proxy;
three trials observe independent bounded proxy death. Tests use no private OTP
supervisor messages or fabricated data-resource DOWN.

Initial standalone harness exited its linked supervisor before ExUnit autorun;
fixed the harness to run ExUnit while its parent is alive. The one subsequent race
was a test assuming kill implied the observer had already processed creator DOWN;
changed the test barrier to wait real snapshot evidence with one original deadline.
Production evidence requirements were not weakened.

Prepared-policy work is under exact nine-file scope: public provider-owned immutable
configuration snapshot before raw CONNECT allocation, consume the same snapshot at
upgrade, preserve fresh per-connection keys/randomness/binders and upgrade-context
option rejection. Current focused run passed lifecycle, fresh ClientHello,
context bounds and actual full+two-resumed prepared-upgrade references. The two
TLS1.2 failures were isolated with public legacy-upgrade/prepared/direct comparisons,
combined and explicit TLS1.2 offers: all six fail identically. Public ServerHello
wire contains renegotiation/EC-point-format/ALPN extensions but no EMS(23); OTP29
client accepts that peer, while ExSSL correctly enforces its documented bounded
ECDHE/EMS subset. This is a fixture mismatch, not a prepared-snapshot regression.
The new positive CONNECT fixtures are being changed to the existing independent
OpenSSL EMS-capable peer behind a byte bridge, preserving combined client versions,
CA/identity/ALPN/option-precedence assertions and mandatory integration execution.
No production certificate/CV/version/EMS checks are relaxed. Final combined focused
run passed133/133 with ZERO exclusions/skips, --include integration and pinned Python
PATH: ex_ssl66 (59 lifecycle +7 prepared), http_core34 (27 existing transport +7 proxy),
Fetch33. Both mandatory new OpenSSL TLS1.2 positives executed with combined offers;
real IPv6 SAN negative, malformed reference zero-accept, source-file replacement/
deletion, wire freshness and full+two-resumed policy reuse passed. Strict root compile
and scoped formatting13 code paths passed. Configured Credo ran54 checks over530
files /8811 modules-functions with no issues. Initial Dialyzer reported two discarded
timer-cancellation return values in Observer; explicit `_ =` acknowledgments preserve
behavior. Final Dialyzer:0 errors,0 skipped; four prior unnecessary-ignore notices
remain untouched. Full source regression used pinned Python PATH and
HTTP_QUIC_PHASE1_REAL=1, --include integration, seed101. Exit2:3153 checks,
3131 passed,22 failed, no exclusions/opt-in skips. The40 new checks all passed.

| App | Full source result |
| --- | --- |
| ex_ssl | 752/756, including20/20 properties |
| elixir_quic | 249/249 |
| http_core | 418/418, all three real opt-ins included |
| elixir_quic_http3 | 113/113 |
| http_runtime | 149/149 |
| http_fetch | 1213/1231, including20/20 doctests |
| http_web_socket | 138/138 |
| http_web_transport | 24/24 |
| http_event_source | 75/75 |

All16 unroutable127.0.0.2 scenarios remain (3ExSSL +13 Fetch). Six other failures:
ExSSL requested KeyUpdate was not observed queued behind output (seen in prior
round6 scoped run too); OTP reuse could not establish in-flight bounded send;
a raw request-stream length-mismatch listener accept returned :einval; and THREE
ExSSL remote peers remained open after proven local cleanup (auto/buffered/infinity,
http1/cancel/infinity, http1/buffered/infinity). Remote counters were103979/101008
bytes, recbuf483984/486960. Exact local Connection/writer DOWN and native Port absence
passed BEFORE remote drain; those observations do not prove remote closure. The
prior early_data fixture and streamed4000 case passing this run do not causally
resolve their earlier failures. Additional failure isolation ran the backpressure file plus request-stream line160:
7/8 backpressure cases passed, queued-KeyUpdate failure reproduced; all3 selected
length-mismatch cases passed (28 other stream cases deliberately excluded by line
filter). That rerun does not resolve the full-run raw-accept :einval. Final configured
Credo again found0 issues; whole-root `mix format --check-formatted` passed.

No full acceptance is claimed. Read-only task-9 portability design keeps identity
proof nonvacuous by dialing routable127.0.0.1 with a dedicated certificate that has
SAN127.0.0.2/::2 but excludes actual dial1. True destination-isolation/refusal/
saturation cases require separate127.0.0.1 and IPv6-only::1 listeners at the SAME
port, reserved before clients. Preserve Host/:authority/pool scope/first-connection
reuse, exact refusal, independently proven saturation and no-fallback/no-replay
accept queues. No OS aliases, skips or weaker negative assertions are proposed.
 Pre-existing auto-ticket partition for CONNECT uses
proxy peer IP:port plus origin identity/profile/trust, lacking target origin port;
this remains a separate explicit P1 cache-isolation gate, with tickets disabled by
default. Preparation does not establish adoption or cleanup and does not enable
managed/completion/default promotion.

## Round8 — portable pin fixtures and authenticated KeyUpdate progress

Task9 changed seven existing test/support paths and three explicit Fetch PEM/key
fixtures. Physical test endpoints use127.0.0.1 and IPv6-only::1; logical certificate
references127.0.0.2/::2 remain. Optional ClientAuthFixtures server_sans defaults are
unchanged and the original mTLS suite still executes. Dedicated ExSSL certificates
have SANexssl.test,127.0.0.2,::2 and EXCLUDE actual dial1; direct/upgrade, IP tuple/
string, DNS, disabled/unrelated SNI, exact peercert, wrong CA and trusted wrong-dial
reference tests are retained. Independent TLS1.2 positives/negatives use the
mandatory EMS-capable OpenSSL peer. Fetch's new test leaf has ONLY SAN127.0.0.2,
excludes127.0.0.1/::1, matches its private key and serverAuth purpose, and expires
2036-10-18T14:09:43Z. Only public test CA/server cert and server key enter the repo;
the generating CA private key stayed in a disposable external directory.

Pin H1/H2 isolation/reuse/refusal/retry tests reserve both actual families at the
SAMEport before dialing. Preserve identical URL/Host/:authority/pool scope; prove
first-v4 ->second-v6 ->first-v4 connection reuse, exact refused pin, complete
mutation body and empty extra/fallback accept queues. Native saturation initially
failed honestly: backlog0 accepted64 bounded probes on this kernel, while backlog1
accepted1 then timed out. Fixture uses explicit backlog1 and requires TWO native
timeout probes with fill sockets still alive before HTTP's unchanged100ms connect
budget/overall deadline and explicit caller retry. No OS alias, skips or relaxed
negative assertions. String-host raw/proxy/redirect refusal controls instead use
separately reserved/closed IPv4 ports, retaining the live origin/first mutation and
original1271 Host. This is endpoint refusal evidence, not same-port pool isolation.

Focused85/85 (ExSSL17 +Fetch68) passed with --include integration, seed101 and pinned
Python PATH, zero exclusions/skips. Includes all six changed test modules plus the
unchanged-default ClientAuthInterop suite. Worker strict compile and scoped format
passed. Separate observed gap: literal IPv6 string hosts without explicit family
options can return:nxdomain through the existing TCP/OTP adapters; tuple-pin tests
infer family. Adding inet6 to a shared option set made literal IPv4 controls fail,
so the tests do not silently adopt such an invalid fallback control. Production
IPv6 string-family resolution is not fixed or claimed here.

KeyUpdate original line9 repro failed on current production source. Three metadata
probes also failed. Public OTP send_oct1386->1413 immediately after update_keys
proved27 update bytes emitted; an application marker raised it to1452. Client
recv_oct matched but raw input_size stayed0, nativeactive:once/packet0 and correct
controller remained. A public raw inet record-sized blocked-writer control still
delivered5 reverse bytes with send_pend16644; optional socket-backend counter
inspection stalled and was stopped, with no socket-backend support claim. Finally,
the ORIGINAL marker-free failure showed read_generation1/write_generation1 despite
input_size0 and a still-blocked application writer. The update had already been
authenticated between native output jobs of the SAME logical write. Waiting only
for a transient raw-input queue was an incorrect test oracle, not an engine failure.

The corrected oracle accepts queued bytes OR both epochs incremented, reasserts
real TCP writer blockage BEFORE resuming the proxy, retains exact16MiB payload/no
replay, asserts final read/write generation+1, and makes the independent OTP peer
authenticate a distinct12-byte client marker AFTER the complete payload/update ACK
before returning its recovery response under the new server key. This strengthens
end-to-end update evidence. Backpressure/input-ordering/lifecycle/abandonment:
48/48 passed, integration included, zero exclusions/skips. Independent read-only
review found no blocker to the broad recovery/no-replay contract. Raw queued bytes
alone do not authenticate KeyUpdate identity or prove deferral behind the SAME
immutable native job; final epoch/independent-marker assertions establish actual
update/ACK, and separate gated ordering tests cover exact job deferral. All DEBUG-ku8 diagnostics
were removed; production Connection/Writer, private-layout pins and policy/defaults
are unchanged. Strict compile and whole-root formatting passed. Initial configured
Credo found one unused final HPACK decoder return in the new repeated H2 fixture;
explicit `_decoder = Enum.reduce(...)` preserves decoder threading and acknowledges
the final state. Final configured Credo:54 checks,530 files,8819 mods/functions,
zero issues. Dialyzer:0 errors,0 skipped; four existing unnecessary-ignore notices
remain unchanged.

Final full source used pinned Python PATH, HTTP_QUIC_PHASE1_REAL=1,
--include integration, seed101. Exit2:3155 checks,3153 passed,TWO failed,
zero exclusions/opt-in skips. All16 formerly unroutable address cases and the
corrected requested-KeyUpdate case passed. Both newly added trusted wrong-dial
reference negatives passed. These are executed improvements, not a full gate pass.

| App | Full source result |
| --- | --- |
| ex_ssl | 757/757, including20/20 properties |
| elixir_quic | 249/249 |
| http_core | 418/418, including all three real opt-ins |
| elixir_quic_http3 | 113/113 |
| http_runtime | 149/149 |
| http_fetch | 1230/1232, including20/20 doctests |
| http_web_socket | 138/138 |
| http_web_transport | 24/24 |
| http_event_source | 75/75 |

Remaining actual failures:
- TLSSetupEvidenceTest early_data negative: raw listener accept returned:einval
  (line182); linked task MatchError, previously observed full-suite fixture race.
- HTTP1WriteIdleWireTest ExSSL cancellation after an OBSERVED blocked upload:
  `finish/3` did not receive peer_closed within its EXISTING8000ms bound. This is
  remote-close observation, NOT failure to establish the blocked-send precondition.

The prior three HTTPS-early-upload remote2s failures, OTP in-flight-send
precondition failure and request-stream raw-accept race passed this run without
production changes; they are NOT causally fixed by fixture portability or the
KeyUpdate oracle. Keep them as unresolved regression history. Read-only analysis
found an abort-intent boundary to test next: begin_shutdown/close_transport inspect
current output/driver send_pend but ignore retained write_abandoned?. Driver queue
empty does not prove kernel queue empty or remote acknowledgement. Pending task10
requires a deterministic abandoned-vs-completed first-hop RST/FIN test, retained
response reads, exact local DOWN/Port absence <=1s BEFORE remote2s drain, and original
failure reruns before any remote-failure fix claim. No production fix is made here.
Full P0–P7, public/native lifecycle integration, managed completion, default
promotion, production OTP dependency removal and package publication remain open.