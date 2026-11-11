# Abyss and Hell repository migration

## Source and scope

Imported on 2026-11-06 into the existing `main` checkout, whose starting commit
was `f5c1b50e56c5e110fa8a68b3bb1a8eef5917f0b4` (`1.0.0-rc.3`). All three
repositories were clean before migration. Source repositories were read-only;
only tracked source files were eligible for import. No Git history was rewritten,
and no branch, worktree, commit, push, merge, publication, deployment, repository archival or
old-repository removal was performed.

| Source URL | Imported commit | Source version | Destination | License |
| --- | --- | --- | --- | --- |
| https://github.com/gsmlg-dev/abyss | `89f6879edd163ff023d8bcb44b9686175dca0109` | `abyss 0.10.0` | `apps/abyss` | MIT |
| https://github.com/gsmlg-dev/abyss | `89f6879edd163ff023d8bcb44b9686175dca0109` | `abyss_raw 0.10.0` | `packages/abyss_raw` | MIT |
| https://github.com/gsmlg-dev/hell | `4fb5d53a1b2acfb5afc9b1ceba65fdc52d61ef83` | `hell 0.1.3` | `apps/hell` | MIT |

Each package retains its original license/copyright. The machine-readable
[import inventory](server-migration-import.json) records source hashes and local
differences. Existing public test credentials are retained only as documented
local TLS fixtures. No dependency trees, build output, PLTs, caches, secret
configuration or historical validation logs were imported.

## Directory and dependency boundaries

The umbrella now contains eleven OTP applications. HTTP Fetch, EventSource,
WebSocket, WebTransport, their shared HTTP primitives/runtime, and the HTTP/3
companion remain client packages. `hell` owns TCP/TLS servers and still uses OTP
`:ssl`. `abyss` owns UDP servers and opt-in QUIC services. `elixir_quic` and
`ex_ssl` provide the protocol engines; their presence does not enable an
application protocol automatically.

`abyss_raw` stays in `packages/` because it has its own Mix/Rustler/Cargo build.
Putting it in `apps/` would make umbrella compilation load its NIF and require
Rust even for ordinary UDP or HTTP users. Its existing Linux DHCP/ARP platform
and privilege requirements remain unchanged. The native module names remain
`AbyssDhcpSocket.Native` and Rust crate `dhcp_socket` (with the existing
`Abyss.DhcpSocket.Native` facade).

| Consumer | Runtime Hex dependency closure, excluding OTP |
| --- | --- |
| Plain UDP | `abyss`, `telemetry`, `telemetry_metrics` |
| TCP/TLS server | `hell`, `telemetry` |
| QUIC server | Explicit `abyss` + `elixir_quic` + `ex_ssl`, plus telemetry/metrics |
| Native DHCP/ARP | Explicit `abyss_raw`; Rustler compiles the native component |

There is no permanent or optional runtime engine/raw dependency in Abyss's
manifest. QUIC consumers select the engine explicitly. The independent QUIC
candidate gate resolves the target engine pair at `1.0.0-rc.3`; the source example
locks at `0.21.17` remain available for historical compatibility checks.
No DATAGRAM, 0-RTT, migration, HTTP/3 server or public transport abstraction was
added. Source runtime implementation and supervision files are byte-identical.

Local changes are limited to umbrella build/dependency/lock paths; package and
ExDoc source links; explicit current/candidate engine selection in examples;
fixture/script paths; root-compatible integration tags; imported documentation;
and replacing standalone release tooling with version-group tooling. The imported
automatic `test --cover` alias was replaced with an explicit `test.coverage`
full-suite alias: root unit-only runs cannot enforce full-module coverage. The
original 40% threshold is unchanged and a dedicated complete-suite CI job
requires it (final measured coverage: 86.29%). Automatic
sibling `ex_dns`/`ex_dhcp` path detection was removed in favor of their existing
Hex constraints. Abyss ExDoc now runs only in development/test, matching the
umbrella tools; root ExDoc includes test to match Hell's existing declaration.

Root lock additions retain the Abyss source pins for all newly introduced
packages. Existing root pins are unchanged. A first floating resolution selected
Machete 0.3.13, which fails OTP 28 compilation while escaping a regex reference;
using the imported 0.3.12 lock restores the source baseline. This is a tooling
resolution difference, not a runtime change or dependency-cache patch.
The nine-package no-OTP release proof's lock hash was refreshed only after
checking every original lock entry and every reviewed runtime source unchanged.
That proof still covers the original nine packages. Hell's TLS server transport
now runs on `ex_ssl` and Hell no longer uses OTP `:ssl` in production; `abyss` and
`hell` are audited for direct `:ssl` imports as a separate group (see
[the no-OTP release audit](no-otp-release-audit.md#server-package-group)).
OTP `:ssl` remains only in test and reference peers.

Release ordering: Hell pins `{:ex_ssl, "== VERSION"}`, so `ex_ssl` must be
published before (or together with) Hell. The unified `release.yml` publishes the
portable packages in dependency order from one version; an independent or partial
Hell publication ahead of `ex_ssl` would not resolve on Hex.

## Versions, packaging and CI

The unified `release.yml` now prepares one version for all twelve packages,
including prereleases such as `1.0.0-rc.N`. Eleven portable packages (the original
nine plus Abyss and Hell) are compiled, archived and published in its main job.
Before packaging, the workflow runs only `mix deps.get` and `mix compile`;
tests, static analysis, protocol interop and consumer acceptance belong to
their dedicated CI workflows or explicit validation commands.
`abyss_raw` retains its separate Mix/Rustler/Cargo build and publishes in a
following asynchronous job at the same immutable `vVERSION` source tag. Its
failure does not undo or gate the completed eleven-package publication. The
native job verifies that the exact Abyss archive has already been published,
then runs `mix deps.get` and `mix compile` before packaging and publication.
It retains immutable artifact checks but does not run tests, Clippy or consumer
acceptance. Its result is reported separately.

`versions.exs prepare|validate VERSION` covers the root and all twelve manifests.
Existing released tags and package bytes remain immutable: historical RC3 does
not include the imported servers and cannot be reused as a unified release.
The source manifests are aligned to the current development version; this is
not a claim that the new server RC artifacts have been published. Use a new RC
version and matching changelog section for the next release.

`stage.py` defaults to the eleven-package `release` group; `--group core` retains
the original nine-client/engine proof boundary, and `--group native` selects
only `abyss_raw`. `--package` still supports scoped CI builds. The original nine
retain exact internal requirements. Abyss, Hell and the native package do not
gain new runtime engine or sibling dependencies merely because their release
versions are coordinated. Portable manifests remove umbrella-only paths.

Server `build`, `audit`, `validate`, `docs` and `preflight` helpers remain in
`scripts/release/server_packages.py`. Independent server `prepare` and portable
server publication are rejected; use the unified workflow. Native publication
requires the shared tag, a clean checkout, matching published Abyss bytes and
unchanged native archive rebuilds. Documentation source links use `vVERSION`.
No helper commits, tags or pushes outside the authorized release workflow.

If an immutable release has completed every portable build and publication
gate but failed only while publishing documentation, `release-complete.yml`
can finish documentation and the native lane without republishing portable
packages. Supply `version` and `source_run`, the failed `release.yml` run at the
exact tag SHA. The completion workflow rejects missing or deferred gates and
unrelated failures, then checks all eleven published Hex/GitHub archives against
the tagged sources and checksums. It uses current documentation tooling with
the tagged lockfile; release package sources and tags remain immutable. Portable
docs and the unchanged native publication lane run independently after that
verification. Their results must both be checked before calling the full
twelve-package release complete.

Examples (candidate validation only):

```sh
elixir scripts/release/versions.exs validate 1.0.0-rc.3
python3 scripts/release/stage.py build 1.0.0-rc.3 /tmp/release-stage /tmp/release-archives
elixir scripts/release/archives.exs 1.0.0-rc.3 /tmp/release-archives
python3 scripts/release/server_consumer_gate.py /tmp/release-archives --mode all
```

The no-OTP-SSL validation still selects the original nine clients/engines and
explicitly excludes Hell's consumer gate. Hell's TLS server transport now runs on
the `ex_ssl` TCP TLS 1.3 server (see `apps/ex_ssl/README.md` and
`docs/ex-ssl-consumer-contract.md`). Explicit HTTP/3 remains beta with finite
static/literal QPACK support, and WebTransport connection support remains
unimplemented. A package or ALPN name alone is not application acceptance.

The new consumer gate builds a signed local Hex registry from candidate archives
and checksum-verified external dependencies. Consumers start with independent
registry/cache/build directories and no inherited umbrella code paths. They
assert exact Hex.SCM versions/closures and BEAM locations before real traffic.
Plain UDP and Hell do not install engines, Rustler or the native package.

Existing app selection, formatter, changed-app detection and test closures include
Abyss/Hell. Engine changes also select Abyss's explicit QUIC acceptance consumer.
The new `servers.yml` retains Hell's OS/OTP matrix, Abyss UDP execution/backend
namespace matrix, current-engine QUIC gates, Linux native checks, and standalone
minimum-Elixir consumer jobs. Native checks run in a separate job with Rust;
ordinary package jobs do not install a Rust toolchain. The E2E workflow also runs
selected server candidate consumers. Manual existing shared workflows select all
eleven applications. Remote workflows were not dispatched in this migration.

## Verification ledger

This ledger records the original import results. The dated follow-up below
records subsequent CI repairs without replacing that history.

Commands below run from the destination root unless stated otherwise. Source
baselines were made with `git archive`/tracked-file copies in `/tmp`, without
building inside either source checkout. Detailed local diagnostics are under
`/tmp/http-fetch-server-migration/evidence` and `/tmp/http-fetch-abyss-*.log`;
these temporary logs are not package inputs. Results are recorded below as checks
finish; `NOT RUN` is not a passing gate.

| Gate | Command / evidence | Result |
| --- | --- | --- |
| Target pre-import strict compile | Isolated source snapshot: `MIX_ENV=test mix compile --warnings-as-errors` | PASS |
| Target pre-import units | Snapshot: `MIX_ENV=test mix test` | PASS; original nine suites, exclusions retained |
| Hell baseline | Isolated source copy: strict compile, format, `mix test` | PASS; 166 tests |
| Abyss baseline | Isolated source copy: strict compile and full tests | Compile PASS; tests FAIL: 693 + 3 doctests, one existing 100ms writer-death assertion; focused diagnostic rerun passed |
| Original engine baseline | Source example lock `0.21.17`, `idle_policy.exs` | PASS; 5 tests |
| Umbrella compile | `MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-server-migration/build mix compile --warnings-as-errors` | PASS |
| Imported Hell suite | Portable imported source and final root `HTTP_FETCH_CI_APP=hell ... mix test apps/hell/test --include integration --max-cases 1 --seed 28092026` | PASS; 166 tests in each |
| Imported Abyss suite and coverage | `HTTP_FETCH_CI_APP=abyss MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-abyss-integrated-build mix test apps/abyss/test --include integration --include slow` | PASS; 693 tests + 3 doctests, explicit full coverage 86.29% against unchanged 40% |
| Independent Hex consumers | `python3 scripts/release/server_consumer_gate.py /tmp/http-fetch-server-migration/archives --mode all --keep` | PASS; actual UDP, Hell 24 tests, idle policy 5 tests, exact current-engine closure |
| QUIC examples / independent TLS/UDP | Original imported network gate, exact candidate Hex engines, pinned aioquic peer | PASS; concurrent two 1MiB echo + collect, Retry echo, close-isolation surviving traffic |
| Native package independently | Raw `mix test`, `bash scripts/test_arp.sh`, `cargo clippy --locked --all-targets -- -D warnings` | PASS; 3 native + 5 ARP harness tests, Clippy clean |
| Native/plain-UDP package consumers | `cd apps/abyss && python3 scripts/udp/p5_consumers.py --no-wire` | PASS; extracted packages, UDP without Rust, raw/combined consumers, native release, legacy facade |
| Original nine isolated Hex consumers | Existing `consumer_gate.py 1.0.0-rc.3 ... --mode all` | PASS; nine independent Hex projects compiled and started |
| Formatting | Root `mix format --check-formatted` | PASS |
| CI tooling | `elixir scripts/ci/test_app_closures.exs`; Python CI unittest discovery | PASS; 4 + 45 tests |
| Core and server archives | Default core stage, server build/audit, checksum/source/dependency/minimum metadata validation | PASS; nine core + three server archives |
| Server tooling | Python `test_server_*.py` | PASS; 16 tests |
| All release-tooling regression | Python release unittest discovery | PASS; 269 tests |
| Default root unit regression after coverage fix | `mix test --seed 955225` | FAIL; 2 existing Runtime HTTP/3 timing assertions (100ms observation / opening deadline); all other suites pass; full integration Runtime suite passed all 290 |
| All source unit/integration regression | `mix test --include integration --include slow --seed 28092026` with provisioned peer venv | FAIL; all eleven suites completed: 12 failed, 190 invalid, 3 existing skipped cases; see diagnostics below |
| Credo | Root `mix credo` | FAIL; imported findings retained; source Abyss strict baseline has 83 findings |
| Dialyzer | Root test analysis with isolated PLT; original snapshot analyzed separately | FAIL; 7 unignored imported Abyss test-support findings. Original nine-package snapshot PASS with its 2 existing ignores |
| Root/package documentation | Root `mix docs`; grouped server `docs all` with `--warnings-as-errors` | PASS; root retains existing warnings; all three server package docs build strictly |
| Source and user-change preservation | Git status/HEAD plus import hashes and unchanged runtime-source comparison | PASS; both sources clean at original SHAs, target remains on original `main` HEAD; no initial user changes |
| Remote CI, platform/minimum-version matrices | GitHub CI/Test/Integration/E2E/Servers workflows | NOT RUN; no push or workflow dispatch authorized |
| Privileged DHCP/ARP namespace traffic | Dedicated CI namespace fixture | NOT RUN locally |

## CI and unified-release follow-up (2026-11-07)

Credo's positional path filter now scopes each CI app job correctly. Imported
Abyss/Hell findings were fixed without adding check exclusions, and Abyss test
support now satisfies Dialyzer's callback and return-value contracts. Logger
includes Abyss's structured event metadata; the original nine-package no-OTP
proof was rebound only for that configuration hash, with its source census and
review inputs unchanged.

The QUIC regression observes deadline termination before making any query that
requires a live process. Hell's outgoing-traffic regression observes the actual
read-timeout callback, termination reason and exact sent/received byte count,
instead of assuming a platform-specific send rate. Abyss's writer-death test
installs its monitor before termination. The isolated consumer tool copies both
legacy and versioned Mix rebar3 installation layouts.

| Gate | Result |
| --- | --- |
| Strict root compilation and locked dependencies | PASS; isolated build directory |
| Root Credo and all eleven scoped app checks | PASS; root inspected 834 files, zero findings |
| Root test Dialyzer | PASS; only the same two intentional ignores |
| QUIC complete app tests | PASS; 317 tests |
| Hell complete tests | PASS; 166 tests |
| Abyss complete tests and coverage | PASS; 694 tests + 3 doctests, 86.35% coverage against unchanged 40% |
| CI tooling | PASS; 45 Python tests and 4 app-closure checks |
| Release tooling | PASS; 280 Python tests, including 10 unified-release cases |
| Eleven portable archives | PASS; actual builds, metadata/source audit and byte-identical rebuilds |
| Independent candidate server consumers | PASS; UDP, 24 Hell cases, 5 QUIC idle cases and real 1 MiB network scenarios |
| Native candidate consumers | PASS; extracted Rust build/NIF load, UDP without Rust, combined native consumer and packaged Mix release |
| Workflow syntax, formatting and twelve-package version validation | PASS |
| Complete root integration/slow regression | FAIL / INCOMPLETE; prerequisite failures and one Runtime assertion, stopped during WebSocket |
| Remote CI, macOS/minimum-Elixir matrices, published RC consumers | NOT RUN; no push, dispatch or publication performed |
| Privileged DHCP/ARP namespace traffic | NOT RUN locally; retained as a native workflow gate |

Evidence is under `/tmp/http-fetch-ci-20261107.DKNLBG`. Verification uses an
isolated build directory because the checkout's existing build metadata still
contains version 0.18.0. Neither lockfile was changed. Source version alignment
to 1.0.0-rc.3 is preparation only; the historical published RC3 is immutable.

The complete regression finished Hell, Abyss, QUIC, Core and HTTP/3 with zero
failures. ExSSL finished 3,547 tests plus 20 properties with nine failures and
77 invalid cases: the same missing `/usr/bin/python3`, `/usr/bin/id` and
`pkg-config openssl` prerequisites recorded at import. Fetch finished 1,595 tests
plus 20 doctests with zero assertion failures and 63 invalid cases, including
the missing native peer setup. Runtime finished 290 tests with one failure at
`apps/http_runtime/test/http/http1/pool_test.exs:70`: contextual checkout returned
`:handoff_expired` instead of `:handoff_unconfirmed`. That distinction remains
undiagnosed; neither the test nor production code was changed or suppressed.

The run was stopped after these confirmed blockers, during WebSocket, at
`2026-11-07 01:00:56` (Asia/Shanghai). WebSocket, EventSource and WebTransport
therefore have no completed result from this run. A WebSocket process-liveness
failure logged after SIGTERM is an interruption artifact. The process returned
zero during shutdown; this does not make the incomplete regression a pass.
Only the owned test process group was stopped, and its processes were checked
afterward. Remote platform verification remains necessary.

## Remaining limitations

For the unified 1.0 RC, the approved minimum for `abyss` and `abyss_raw` is
Elixir `~> 1.18` with Erlang/OTP 27 or later; Hell retains `>= 1.18.0` but,
since it runs on `ex_ssl`, requires Erlang/OTP 28 or later.
The first remote minimum-version consumer reached actual UDP traffic after the
rebar3 repair, but OTP 24 rejected the default socket options. The imported raw
lock also selects Rustler 0.38.0, which already requires Elixir `~> 1.15`.
The former 1.13 declaration is therefore retired explicitly. CI checks the
Abyss consumer and native package at Elixir 1.18 / OTP 27. The independent UDP
macOS job uses macOS 26 because GitHub retired macOS 14 on 2026-11-02.

Current-engine QUIC gates pass. The `event_poll_failed` teardown log with
`:closed`/unknown references was traced to a race inside `Abyss.QUIC`: a queued
poll tick reached the closed connection before the worker handled the engine's
already-queued `{:quic_closed, ...}`, so the worker stopped abnormally and the
handler could miss `{:closed, reason}`. The worker now delivers that queued
close (or `{:closed, :closed}` when the connection is gone) and exits normally;
`Abyss.QUICServiceTest` covers the race. A `read_failed` log with
`:invalid_operation` seen in the same runs comes from the gate's handler, not
Abyss, and remains an unconfirmed lifecycle compatibility concern. Actual data,
idle negotiation, PING, listener recreation, Retry and isolation assertions
passed; no upstream blocker has been established from these logs alone.

## Full-regression diagnostics

The first root unit run completed all eleven suites with one assertion failure:
`SSL.Lifecycle.PairTest` exceeded its 250ms elapsed assertion (364ms) while other
verification processes were active. In the full integration run, Hell's 50ms
process-label observation and 2s stalled-upgrade deadline assertions failed;
SSL's native blocked-output snapshot also changed between observations. These
are not suppressed. A bounded serial diagnostic of the two Hell files and SSL
pair file passed 21 cases; the native-write case passed independently in both
the original target snapshot and migrated checkout. This provides timing/load
evidence, not proof that every intermittent failure is resolved. A final root-scoped Hell CI closure also passed all 166 tests with one test
case at a time. No test body, timeout, assertion or runtime implementation was
changed to obtain those passes.

The full regression completed with nine SSL test failures caused by unavailable
`/usr/bin/id` and `/usr/bin/python3`; native test-peer setup also lacks
`pkg-config openssl`, leaving 190 invalid cases across SSL/Fetch/WebSocket/SSE.
Equivalent prerequisites failed in the original snapshot. That baseline full run
was stopped after repeated missing-prerequisite errors rather than waiting
through repeated missing-h2 peer timeouts (the incomplete baseline is not a passing full gate). A temporary pinned peer venv supplied
h2/wsproto/aioquic for the migrated full run, allowing all eleven suites to finish.
The three existing QUIC skipped cases remain visible. The full gate therefore
remains FAIL/environment-blocked, rather than a claim of complete CI acceptance.

The repository's existing `_build` also contained 0.18.0 application metadata
before migration. Verification used an isolated `MIX_BUILD_PATH` to avoid stale
metadata; it did not add dependency overrides or change versions to fit a cache.
The root Dialyzer baseline passed; the migrated test build introduces seven
warnings in byte-identical Abyss test support (unmatched returns and mock
transport callback shapes), beyond the same two intentional core ignores.
Root Credo retained 59 priority findings (15 warnings, 4 refactoring, 40
readability); the standalone Abyss strict baseline had 83 findings under its
original configuration. These distinct configurations are not asserted to have
identical finding counts, and no ignore was added to conceal them.

Remote CI, the OS/OTP/minimum-Elixir matrices, privileged namespace wire tests,
and the existing full Caddy/production-release CI gates were NOT RUN locally.
No workflow was dispatched because this task authorizes no push/publication.
The new CI definitions keep those gates visible for the eventual submitted tree.

The root unit split initially exposed a migration-caused coverage failure:
all assertions passed on a subsequent run, but inherited automatic coverage
measured only 26.73% against the original 40% full-suite threshold. This was
repaired by making coverage an explicit complete-suite command and retaining
the threshold in the required full-suite CI job. A later default unit run passed
Abyss's split suite and all other applications except two unchanged Runtime
HTTP/3 100ms/opening-deadline assertions while candidate builds were active.
A bounded serial diagnostic of the Runtime file then passed all 12 cases.
The full integration run had passed the same Runtime suite (290 tests). These
last unit failures are retained; the migration does not claim a clean complete
regression or repair unrelated scheduler-sensitive tests.
