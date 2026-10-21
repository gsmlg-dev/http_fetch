# TLS migration execution ledger

## Execution identity and limits

Date: 2026-10-21 (Asia/Shanghai). Source: `main@6b69bde3f43f2270317c38fbe68d5ac9635d3b36`,
all nine packages `0.21.14`, initially clean worktree. P0 adds documentation and a
bounded source inventory only; production code/defaults remain unchanged.
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
| Strict test compilation | Exit 1 | Existing unreachable `socket_resource/1` clause at `apps/http_core/lib/http/request_lifecycle.ex:200` on Elixir 1.20; subsequent non-strict compilation also reports bitstring-size warning in `apps/http_fetch/lib/http/http1/idle_timeout.ex:22` |
| Default umbrella test suite, seed 36 | Stopped with SIGTERM after failures were captured | Missing h2 prerequisite caused repeated startup failures; no final aggregate success claimed. Loopback and ExSSL upload cleanup failures also observed |
| Focused H2 trailers + HTTPS early upload, pinned peer environment | Exit 2: 55/61 passed, 6 failed | All six failures belong to ExSSL early upload timeout/cleanup cases; H2 trailer startup failures disappear with the pinned Python dependencies |
| Nine candidate archives + metadata | Passed | Built from unchanged production source, all nine identities/internal exact requirements validated |
| Isolated external candidate consumer | Passed, `external consumer smoke passed` | Existing fixture includes OTP SSL; not production removal evidence |
| Direct candidate feature invocation | Failed before test execution: EX_SSL_FIXTURE_DIR missing | Invocation did not prepare fixtures; use the existing wrapper below |
| Candidate feature wrapper | Initial attempt exit 127: timeout executable absent | Install required coreutils and rerun unchanged wrapper; not acceptance |
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
platform assumptions from product failures with focused reproduction. No production
fix, assertion weakening or skip was applied. The pinned HTTP2 peer requirements were
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

`brew install coreutils` was started to provide the standard feature wrapper's
required `timeout`. It is building from source on this Intel macOS host; installation
and candidate wrapper rerun are pending at this checkpoint.

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
EX_SSL_DEP_MODE=candidate \
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

## Open P0 work and release blockers

- Finalize baseline results, supply pinned independent peer dependencies and rerun
  affected scenarios; retain strict-compilation and platform failures visibly.
- Execute required integration, H2/H3 and candidate feature gates with prerequisites.
- Finalize lifecycle interface and public option decisions listed in the design.
- Record HTTP workload/resource baselines and numeric promotion budgets.
- No P1–P7 acceptance, changed default, OTP removal, remote CI or publication is
  established by this ledger. Historical validation remains historically scoped.
