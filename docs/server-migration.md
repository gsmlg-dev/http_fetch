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
That proof still covers the original nine packages; Hell intentionally requires
OTP `:ssl`.

## Versions, packaging and CI

The root `release.yml`, `versions.exs`, Hex publishing, GitHub assets and consumer
contracts retain the original nine-package coordinated group. Server versions
are not rewritten by a core release. `stage.py` defaults to those nine packages;
`--package` accepts all twelve packages, while `--group abyss` and `--group hell`
select the independent groups. A requested archive version must equal its source
manifest. Portable manifests remove umbrella-only paths before Hex packaging.

`scripts/release/server_packages.py` provides `validate`, `prepare`, `build`,
`audit`, `docs`, `preflight`, `publish` and `publish-docs` for `abyss`, `hell`, or
read-only/build `all` selection. `prepare` changes only the selected group's
manifests and is not run by this migration. Abyss and abyss_raw stay synchronized.
Future server publication requires a clean checkout at `abyss-vVERSION` or
`hell-vVERSION`, exact rebuilt archive bytes, registry immutability checks and
explicit credentials. Documentation publication separately requires verified
published package bytes. These tools do not commit, tag or push. Existing
published versions must not be overwritten; this migration preserves their source
versions for review and candidate validation only.

Examples:

```sh
elixir scripts/release/versions.exs validate 1.0.0-rc.3
python3 scripts/release/server_packages.py validate all
python3 scripts/release/server_packages.py build all --stage /tmp/server-stage --archives /tmp/server-archives
python3 scripts/release/stage.py build 1.0.0-rc.3 /tmp/server-stage /tmp/server-archives --package ex_ssl
python3 scripts/release/stage.py build 1.0.0-rc.3 /tmp/server-stage /tmp/server-archives --package elixir_quic
python3 scripts/release/server_consumer_gate.py /tmp/server-archives --mode all
```

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

## Remaining limitations

`abyss` and `abyss_raw` retain Elixir `~> 1.13`; Hell retains `>= 1.18.0`.
Only Elixir 1.18.5 / OTP 28 was available locally. The raw source lock already
selects Rustler 0.38.0, whose manifest requires Elixir `~> 1.15`. Thus the locked
native build does not establish raw's advertised 1.13 minimum. No minimum was
silently raised; this pre-existing constraint requires a separate version-policy
choice or actual compatible Rustler validation.

Current-engine QUIC gates pass, but worker teardown can log
`event_poll_failed` with `:closed`/unknown references or `read_failed` with
`:invalid_operation`. The original published-engine idle run passed without
that log. These errors are disclosed as an unconfirmed lifecycle compatibility
concern, not silently treated as proven pre-existing or suppressed. No local
workaround was added. Actual data, idle negotiation, PING, listener recreation,
Retry and isolation assertions passed; no upstream blocker has been established
from these logs alone.

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
