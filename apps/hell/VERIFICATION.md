# Hell identity migration verification

> Historical standalone repository record. Current build, candidate validation
> and release instructions live in the http_fetch root documentation.

This document records historical local migration checkpoints from 2026-10-14.
Statements about disabled publishing, unrun remote checks and archived package
contents apply to those checkpoints, not subsequent delivery or publication.
For later remote evidence, consult [GitHub Actions](https://github.com/gsmlg-dev/hell/actions)
and [Hell releases](https://github.com/gsmlg-dev/hell/releases).

Verified locally on 2026-10-14 in `codex/rename-hell`. The starting checkout was
clean at upstream commit `e3eb2a7a05f98d79436abcefd8c954da2f8b05c0`.
At this verification checkpoint, HEAD and existing history/tags were unchanged;
all migration changes were uncommitted for review. The user subsequently
authorized a local commit and merge into `main`. Local `origin` points to
`https://github.com/gsmlg-dev/hell.git`; the original remote is retained as
`upstream` at `https://github.com/mtrudel/thousand_island.git`.
No remote writes, PRs, tags, releases, publication, credentials or repository
security-setting changes were performed.

The toolchain used before and after was Elixir **1.19.5**, Mix **1.19.5**,
Erlang/OTP **28.3**, on Darwin ARM64. Other installed Elixir versions were
`1.18.4-otp-28` and `1.20.4-otp-28`; no other OTP version was installed.
The upstream and initial rename requirement was `~> 1.13`. At the user's request,
Hell now requires `>= 1.18.0` and uses version `0.1.0`. All dependencies and `mix.lock`
are unchanged, including telemetry 1.4.2, Machete 0.3.12, ExDoc 0.40.4,
Dialyxir 1.4.7 and Credo 1.7.19.

## Changes and consumer migration

The project, namespace, OTP application and intended Hex package are now
Hell, `Hell`, `:hell` and `hell`. Source and test paths are
`lib/hell.ex`, `lib/hell/**` and `test/hell/**`; examples, package metadata,
repository links, badges and current documentation use the fork identity.
The upstream baseline version was **1.5.0**. The first planned Hell release is
now **0.1.0**; it remains unpublished. Historical upstream releases retain their
original identity.

Consumers must migrate dependency/application declarations and all
`ThousandIsland.*` references to `Hell.*`, rebuild affected dependencies and
restart their nodes. Telemetry prefixes and process-label prefixes become
`:hell`; custom handler readiness messages become `:hell_ready`.
Module-derived child IDs and Logger attachment IDs follow the new namespace.
Generic role IDs, telemetry suffixes, measurements, metadata structure, event
timing and error/shutdown reasons are preserved. There are no application
environment reads/writes or custom Logger metadata keys in the library.
There are no compatibility aliases or shims. See [MIGRATION.md](MIGRATION.md).

The three old workflows were removed and replaced with `ci.yml`, `test.yml`,
build-only manual `release.yml` and manual artifact `e2e.yml`. All request
only `contents: read`, use concurrency cancellation, pin action commits and
contain no publishing command. The initial rename preserved the effective eight
upstream Linux toolchain pairs and added matching macOS 26 ARM64 coverage.
The requested Elixir minimum then removed the two Elixir 1.17 pairs per OS;
six pairs remain per OS, covering Elixir 1.18/1.19 and OTP 26/27/28.
Pinned setup-beam support, OTP ARM64 build availability and runner architecture
were inspected; the macOS job asserts `RUNNER_ARCH=ARM64`.
See [RELEASE.md](RELEASE.md) for the exact matrix and source evidence.

## Initial identity-migration validation (version 1.5.0)

The baseline commands below ran before code changes. Generated baseline build,
documentation and package artifacts were preserved outside the checkout;
final compilation used a fresh build without stale upstream modules.

These results describe the identity-only checkpoint, before the version and
Elixir-requirement update. The follow-up checks below validate the current metadata.

| Check | Baseline | Identity-only checkpoint |
| --- | --- | --- |
| `mix deps.get` | exit 0 | exit 0, lock unchanged |
| `mix format --check-formatted` | exit 0 | exit 0 |
| `mix compile --warnings-as-errors` | exit 0 | exit 0 |
| `MIX_ENV=test mix compile --warnings-as-errors` | exit 0 | exit 0 |
| Full ExUnit suite, seed 35361 | 127 tests, 0 failures; `mix test` selected this seed | 127 tests, 0 failures; `mix test --seed 35361` |
| `mix credo --strict` | exit 0, no issues | exit 0, no issues |
| `mix dialyzer` | exit 0, 0 errors | exit 0, 0 errors |
| `mix deps.unlock --check-unused` | exit 0 | exit 0 |
| `mix docs` | exit 0, four warnings about two removed historical APIs | exit 0, no warnings |
| `mix hex.build` | exit 0 | exit 0 |
| Actual CI Credo/Dialyzer commands with `MIX_ENV=test` | exit 0 in frozen upstream snapshot | exit 0 |
| Actionlint 1.7.12, all four workflows | not applicable | exit 0 |
| YAML parsing and permission/concurrency assertions | not applicable | passed |
| `bash -n scripts/artifact_smoke.sh` | not applicable | exit 0 |
| Final tarball consumer smoke | not applicable | 3 tests, 0 failures; exit 0 |
| Release preparation identity/version check | not applicable | exit 0 |
| `git diff --check` | clean checkout | exit 0 |

Both baseline and final Dialyzer reported one unnecessary pre-existing ignore
entry. The ignore configuration was preserved byte-for-byte.

The initial final suite run at seed **281706** returned **127 tests, 1 failure**:
the existing handler test at line 788 expected at least 400 rendered characters
from a 1ms sender during a 500ms timeout window. A frozen, byte-identical upstream
source snapshot using the same toolchain/dependencies and seed returned:

| Run | Result |
| --- | --- |
| Upstream seed 281706, first repeat | 127 tests, 0 failures |
| Upstream seed 281706, second repeat | 127 tests, 0 failures |
| Upstream seed 281706, third repeat | 127 tests, 2 failures |
| Final seed 35361 | 127 tests, 0 failures |
| Final seed 281706, repeat | 127 tests, 1 failure |

Upstream's third repeat reproduced the same byte-count failure and also its
existing timer-reset test at line 931. These are evidenced inherited timing
flakes, not silently relabeled rename regressions. Assertions, timers, runtime
code and test concurrency were not changed. No upstream fix or workaround was
made; default-seed CI can still encounter these inherited flakes.

The final archive smoke compiles an isolated production consumer of the actual
tarball, using the checkout's unchanged telemetry source. Its three tests
verify application/version identity, TCP echo, certificate-verified TLS through
OTP `:ssl`, shutdown callbacks, socket closure and server termination.
Checksum corruption and mismatched package name, OTP app or version were each
rejected before destination files were written. Release checks reject an
upstream repository, mismatched version, pull-request ref and absent Hell tag.

Remote CI, the complete remote platform/toolchain matrix, actual GitHub-release
artifact download, successful real-tag preparation and publication were
**not run**. No Hell release/tag was created for testing.

## Rename comparison and package inspection

An AST comparison covered all **36** original Elixir source/test/example files
after normalizing only namespace, application identity and associated path/name
substitutions. Documentation attributes and compiler source-location metadata
were excluded from executable comparison. There were **zero executable AST
differences**. Mix `application/0`, dependency declarations, compile paths and
Dialyzer configuration were also AST-equivalent after identity normalization.
At the identity-only checkpoint, the generated `.app` resource was byte-identical
to upstream after only `ThousandIsland -> Hell` and `thousand_island -> hell`
normalization. The current resource additionally changes the version to `0.1.0`.

The reviewed normalized textual diff has eight files with differences:

- `lib/hell.ex`: identifies Bandit as an upstream integration requiring migration.
- `lib/hell/handler.ex`: retains Thousand Island 1.5.0 as timeout-history provenance.
- Both transport modules: correct split-line project-name prose.
- Four test files: formatter line wrapping after shortening names; assertions unchanged.

Mix project/doc metadata differences are intentional: fork namespace/name/app,
source and package links, explicit Hex package name, removal of the upstream
maintainer designation and logo use, and inclusion of migration/release guides.
The subsequent user-approved metadata changes are version `1.5.0 -> 0.1.0` and
Elixir requirement `~> 1.13 -> >= 1.18.0`.
The library's startup applications, dependencies, defaults, transport/socket
operations, ownership, supervision, callbacks, timeout handling, errors, shutdown
and cleanup code are otherwise unchanged.

The identity-only checkpoint's `hell-1.5.0.tar` was **47,616 bytes**, with SHA-256
`e2661e3bf89071fcdaf1163e32a27675af0ada8f3bbc546b532a078bc0776f68`.
Hex metadata declares package `hell`, OTP app `hell`, version `1.5.0`,
MIT licensing, Elixir `~> 1.13` and the fork repository links.
All 24 packaged regular files matched that checkpoint byte-for-byte:
18 library files, `mix.exs`, README, LICENSE, CHANGELOG, MIGRATION and RELEASE.
No old source paths, tests, dependencies, build products or workflows are packaged.

Remaining upstream references are intentional:

- README attribution, the original Mat Trudel copyright and historical claims.
- The entire historical changelog body, byte-identical after an explanatory header.
- Historical timeout documentation and original third-party Bandit links/regression URL.
- Consumer migration instructions describing old identities.
- Original artwork assets, byte-identical, retained without current README/ExDoc use.
- Release-toolchain provenance and explicit prohibition on publishing upstream's package.

## Version 0.1.0 and Elixir minimum follow-up

The user selected `0.1.0` and Elixir `>= 1.18.0`. Current README, migration,
release, security and changelog statements agree with `mix.exs`; historical
upstream version references remain intact. CI intentionally drops Elixir 1.17
while retaining the six Elixir 1.18/1.19 × OTP 26/27/28 pairs on each OS.
The existing process-label feature detection still tests Elixir 1.17/OTP 27;
that upstream capability threshold is unchanged, and OTP 26 retains its no-op.

On Elixir 1.19.5/OTP 28.3, formatting, warnings-as-errors compilation in dev and
test, the unused-lock check, strict Credo and Dialyzer in dev and test, docs,
Hex build, release preparation for `0.1.0` from `main`, Actionlint and whitespace
checks all returned exit 0. The full suite at seed **35361** returned
**127 tests, 0 failures**. The rebuilt artifact smoke returned **3 tests,
0 failures**. Expected rejection checks returned exit 1 for the obsolete
`1.5.0` release version and a `v0.1.0` tag not pointing at HEAD.

On Elixir **1.18.4/OTP 28.3**, warnings-as-errors compilation passed and the
same package's isolated artifact smoke passed (**3 tests, 0 failures**).
The full suite at seed **35361** returned **127 tests, 1 failure** at
`test/hell/handler_test.exs:788`, the same byte-count timeout assertion previously
reproduced upstream on Elixir 1.19.5. This failed run remains recorded; no
assertions or runtime behavior were changed. A matching upstream 1.18 run could
not start because Mise had no `erl` shim version outside the checkout.
Further testing stopped at the user's request, so that comparison is not run.

The first two minimum-toolchain compile attempts could not find Hex. Mise
overrode the outer `MIX_ARCHIVES` value; setting it after `mise exec` reused the
existing Hex **2.5.1** archive and compilation passed. No Hex installation,
toolchain configuration or dependency upgrade was performed.

The new `hell-0.1.0.tar` is **47,616 bytes**, with SHA-256
`9ed5c573b90fedc868f8dcea9c2f33bfb9b32f773ef1ef9a945406056d1ccc73`.
Checksum-verified inspection confirms Hex name/app `hell`, version `0.1.0`,
Elixir `>= 1.18.0`, MIT licensing and the fork links. All 24 regular package
files match the current checkout byte-for-byte; the previous `1.5.0` archive
above is historical evidence.

The 36-file executable AST comparison passed again with zero differences.
The dev `.app` resource is byte-identical after namespace/app/version
normalization. The test resource additionally reorders `TelemetryHelpers` after
the newly named `Hell` modules in its generated modules list; all module members
and every other property match after those substitutions. An initial strict
byte comparison detected this ordering difference; parsed-term comparison
confirmed its exact extent. Runtime source, tests and dependencies were not
edited for this follow-up.

## Release prerequisites

Publishing remains disabled. Version `0.1.0` has been selected. Before any first
Hell release, maintainers must recheck and secure the `hell` Hex name; establish
confirmed private reporting contacts; authorize/configure protected release
credentials; review a trusted fork commit; and validate repository, package/app
name, canonical version, real release tag and artifact metadata together.
The read-only Hex API lookup returned **HTTP 404** on 2026-10-14 at 13:15 UTC;
this indicates apparent availability at that time, without reserving the name.
Never publish `thousand_island` or treat inherited tags as Hell releases.

The current manual release workflow prepares candidate documentation/tarballs
only. Remote artifact e2e needs a future Hell GitHub release containing the exact
`hell-VERSION.tar` asset. Credentials and repository settings have not been
created or configured.

Raw logs, result JSON, the frozen baseline snapshot, comparison harness and
normalized textual diff remain locally at:

`/var/folders/sc/__3sj3tx5h9d4wxx953s0fgh0000gn/T/hell-migration-e3eb2a7-g38zmckw`
