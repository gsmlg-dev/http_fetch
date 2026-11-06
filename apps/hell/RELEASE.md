# Hell CI and release preparation

> Historical standalone repository record. Current build, candidate validation
> and release instructions live in the http_fetch root documentation.

Hell targets `gsmlg-dev/hell`, OTP application `:hell` and Hex package `hell`.
It is derived from Thousand Island at upstream version `1.5.0`. Hell `0.1.0`
was published locally by the fork maintainer and its Hex package and HexDocs
are available. `mix.exs` declares version `0.1.3`; publication uses the gated
manual workflow. Fork release tags use the Hell identity beginning
with `v0.1.1`; upstream commit history and historical release records remain
preserved, without treating upstream releases as Hell releases.

## Validation and supported toolchains

`ci.yml` checks compilation with warnings as errors, unused locked dependencies,
formatting, strict Credo, Dialyzer and documentation. `test.yml` runs the full
existing ExUnit suite separately. Machete is the suite's assertion dependency,
not a separate static-check command. Dependency/build caches use the
`hell-mix-v2` identity and PLT caches use `hell-plt-v2`; keys include resolved
Elixir/OTP versions, runner OS/architecture and both `mix.exs` and `mix.lock`.
The new cache schema avoids incompatible earlier PLTs without deleting caches or
falling back to broader keys. Workflows request only `contents: read` and cancel
redundant runs. Automatic retry and privileged cache-deletion workflows were removed.

The declared Elixir requirement is now `>= 1.18.0`; dependencies are unchanged.
The upstream delegated CI at
[`mtrudel/elixir-ci-actions@18c287f`](https://github.com/mtrudel/elixir-ci-actions/tree/18c287f5666c0873f6c8c585551b9416694a731c/.github/workflows)
effectively tested eight Linux combinations: Elixir `1.17.x` with OTP 26/27,
and `1.18.x` and `1.19.0` with OTP 26/27/28. Hell drops the two `1.17.x`
combinations to match the new minimum and tests these six pairs on each OS:

| Elixir | OTP |
| --- | --- |
| `1.18.x` | `26.x`, `27.x`, `28.x` |
| `1.19.0` | `26.x`, `27.x`, `28.x` |

These run on `ubuntu-24.04` and `macos-26` (ARM64).
Upstream's exclusions for `1.19.x` did not match its `1.19.0` matrix entry, so
removing those ineffective exclusions preserves the actual coverage. No claim
is made that every declared supported version is exercised by this matrix.

Runner/toolchain compatibility was inspected on 2026-10-14:

- Pinned [`setup-beam v1.24.1`](https://github.com/erlef/setup-beam/tree/54075bcc5e249e4758d363f27d099f55d843f124)
  documents macOS 26 on ARM64 with OTP 25–29. Its source resolves ARM64 builds
  through `aarch64-apple-darwin.csv` and uses `OTP-<version>-macos-arm64.tar.gz`;
  current OTP 26.2.5.21, 27.3.4.18 and 28.5.0.7 ARM64 release assets were checked.
- The official [runner-images inventory](https://github.com/actions/runner-images/blob/main/README.md)
  identifies `macos-26` as ARM64 on the newest stable macOS 26 image. The test
  job verifies `RUNNER_ARCH=ARM64` and prints the resolved Elixir/OTP versions.
- The Hex Elixir build listing includes OTP 26/27/28 builds for current
  `1.18.x` and exact `1.19.0`. This establishes toolchain availability;
  successful ARM64 CI still requires validation on the final commit.

The initial `macos-26` ARM64 matrix failed timing-sensitive handler tests at
lines 619, 657, 788 and 931, while all six Linux jobs passed. Tests at 788 and
931 were also reproduced as failures against the upstream baseline locally;
619 and 657 were newly observed and were not reproduced against upstream.
During that investigation, their test bodies and relevant runtime code were
unchanged apart from the identity migration.

The Intel runner attempt also failed: suites took 43–66 seconds, compared with
13.7–17.3 seconds on the initial ARM64 run and roughly 13 seconds on Linux.
Intel failures included 100ms socket read/connect checks and log capture in
addition to the previously observed timer assertions. At that stage, these newly
observed failures had not been reproduced against upstream. Limiting ExUnit
concurrency on Intel reduced the two inspected OTP 26 suites to 29.5 and 33
seconds, but 788/931 still failed; neither suite showed the newly observed socket
failures.

The matrix returns to ARM64 for its observed lower suite duration, retaining
`mix test --max-cases 1` on macOS to reduce contention between async test modules.
Linux retains `mix test`. All six toolchain pairs, tests and assertions remain;
subsequent pre-repair runs still included handler timing failures at 619, 657,
788 and 931.

The synchronous receive fixture uses readiness/start synchronization, then waits
for a handler-entry acknowledgment sent immediately before `Hell.Socket.recv/2`.
Only then does it check closure with the original 100ms client receive timeout.
It verifies the actual receive-timeout result, handler termination and captured
logs afterward. Its original 50ms server timeout remains. The recurring-send
fixture uses an absolute elapsed-time schedule with catch-up instead of adding
scheduler delay after every send. It sends an `A` every 2ms because the existing
`Enum.join/1` assertion renders each received byte as `"65"`; the 500ms server
timeout, 1000ms client receive timeout and 400..600 character bounds remain.
A [diagnostic run](https://github.com/gsmlg-dev/hell/actions/runs/38614069991)
recorded 50ms and 80ms sleeps lasting 111.880ms and 132.398ms, beyond the 100ms
server deadline, and a timeout callback 1.334ms before log capture began.
The two ping loops now use absolute monotonic deadlines with a test-only
cooperative `:erlang.yield/0` wait helper instead of per-ping sleeps. Their
schedules remain six pings over 300ms and four pings over 320ms. Timer-reset log
capture starts before connection and all ping traffic; the original socket,
closure and log assertions remain. These deadlines cannot guarantee timely
execution during OS suspension.
These handler fixture changes do not alter production behavior or socket
timeouts; there are no test filters or failure retries. Historical failures remain
part of the investigation record; the fixture repair does not establish that
every observed failure is resolved. Before entry acknowledgment was added, local
repetition of the synchronous 100ms client-deadline test failed on run 24 after 23
passes. Entry acknowledgment corrects a demonstrated fixture timing boundary; it
does not establish the cause of every spontaneous failure. Before publication,
the full remote matrix must pass on the final release commit, including ARM64
with its concurrency limit; retain actual run results with the release evidence.

Hell `0.1.1` also intentionally corrects an inherited production shutdown race:
pool teardown could kill an acceptor before it emitted its stop telemetry event.
The same failure occurred on upstream baseline `e3eb2a7` in
[run 38260511240, attempt 1, job 114849483327](https://github.com/mtrudel/thousand_island/actions/runs/38260511240/job/114849483327)
on Linux with Elixir 1.19 / OTP 27; upstream attempt 2 passed.
`ShutdownListener` now snapshots and monitors live acceptor tasks before stopping
the listener as before, then waits for their exit before pool teardown. Acceptors
emit their existing stop event once during normal cleanup; no new emitter is
added. The existing 5000ms shutdown-listener child bound still limits this wait;
acceptor cleanup can add shutdown latency. Dependency versions, socket options,
connection ownership and configured connection shutdown timeouts are unchanged.
The deterministic suspended-acceptor regression failed
before the source correction: the acceptor was killed and stop returned before
cleanup. Patch validation and the final full-matrix gate remain required.

Actions are pinned to inspected stable release commits: checkout v7.0.1,
cache v6.1.0, upload-artifact v7.0.2 and setup-beam v1.24.1.

## Local package and artifact tests

Run the existing validation commands with the unchanged dependency lock:

```sh
mix deps.get
mix format --check-formatted
mix compile --warnings-as-errors
MIX_ENV=test mix compile --warnings-as-errors
mix deps.unlock --check-unused
mix credo --strict
mix dialyzer
mix test
mix docs
mix hex.build
bash scripts/artifact_smoke.sh hell-0.1.3.tar 0.1.3
```

The smoke script verifies the tarball's Hex package name, application and version,
then uses Hex's checksum-checked in-memory archive unpacker and writes only
regular files with safe relative paths. An isolated temporary Mix
consumer compiles the unpacked package with the already downloaded, locked
telemetry source from this checkout, without resolving different dependency
versions. It tests TCP echo, certificate-verified TLS echo through OTP `:ssl`,
and graceful shutdown callbacks, socket closure and server termination. It uses
only this repository's existing test certificate fixtures and removes its
temporary consumer on exit. These artifact tests supplement the existing suite.

`e2e.yml` is manual and downloads the exact `hell-VERSION.tar` asset from the
`vVERSION` GitHub release in `gsmlg-dev/hell`, then runs the same consumer tests.
A future Hell GitHub release must contain that asset before this remote workflow
can succeed. Historical upstream releases are not candidates for this workflow.

## Manual preparation and publication

`release.yml` is manual. Its `publish` boolean defaults to `false`; preparation
from `main` remains available without publishing or a release tag. Both modes
validate the repository, package/application identities and exact version, then
compile, check formatting, run the existing suite, build docs and the Hex package,
smoke-test the tarball and upload candidate artifacts. Neither mode changes
versions, creates commits/tags/GitHub releases or pushes Git refs.

For Hell `0.1.3`, dispatch this workflow **from `main`** in `gsmlg-dev/hell`
with `version=0.1.3`, `git_ref=v0.1.3` and `publish=true` after the
trusted tag is created. Selecting `publish=true` is the explicit publication
opt-in; `git_ref=main` cannot publish. The tag must point at the checked-out commit,
which must be an ancestor of `origin/main`. Repository, workflow event/ref,
source URL, app/package name, version/tag and built tarball metadata are validated
again immediately before publication. No pull-request or automatic tag/push
trigger can access this publishing path.

The final publishing step uses only the existing organization-provided
`HEX_API_KEY` secret available to this repository. That credential must authorize
public Hex package creation/publication and documentation upload. It is exposed
only to that gated step, never printed, and no keys, authentication profiles,
GitHub environments or repository security settings are configured by the
workflow. A maintainer may add protected release-environment controls separately;
they are not an additional prerequisite imposed by this release implementation.

Immediately before publication, the read-only lookup of
`https://hex.pm/api/packages/hell` must either return HTTP 404 for first-package
creation or return valid JSON naming `hell` with `meta.links.GitHub` exactly
`https://github.com/gsmlg-dev/hell`. The package already exists with earlier Hell
releases;
its earlier 404 on 2026-10-14 at 13:15 UTC was only a historical availability check.
The requested version must be unpublished: for this release,
`https://hex.pm/api/packages/hell/releases/0.1.3` must return HTTP 404.
Mismatched package metadata, occupied release versions, network errors or
unverified responses abort publication. The publishing credential must have
permission for the existing package; metadata validation is not credential
authorization. No alternate package name or overwrite is allowed. If a partial
publish requires documentation recovery, use a separately reviewed flow instead
of republishing or replacing the package.

After these gates pass, `mix hex.publish --yes` publishes **both the package and
its documentation** using the installed Hex CLI. It has no replacement or private
organization flag, and can never target `thousand_island`. Successful preparation
alone is not publication; verify the publish-step result and public Hex/HexDocs
availability before claiming delivery. Historical upstream release records
remain Thousand Island history, independent of the fork's current tag refs.

The actual Hell GitHub release should attach the verified `hell-VERSION.tar`
asset so `e2e.yml` can consume it. GitHub release/tag creation remains a separate
maintainer action; this workflow requests only `contents: read`.
