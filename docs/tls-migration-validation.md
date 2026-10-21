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
