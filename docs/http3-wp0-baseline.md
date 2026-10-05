# WP0: preserve the WebSocket and EventSource baseline

## Baseline and failed CI evidence

Investigated `codex/http3-completion` at
`6e33bcba7dae9acee1924af744c766b8e1d6147d` on 2026-10-05. The worktree was
clean when investigation started. Other workers' audit/plan documents were
preserved during the repair.

Actual failed logs were retrieved with:

```sh
gh run view 37199061203 --job 111426819401 --log-failed
gh run view 37199061203 --job 111426819440 --log-failed
```

| Job | Historical result | Seed | Failure |
| --- | --- | --- | --- |
| [WebSocket 111426819401](https://github.com/gsmlg-dev/http_fetch/actions/runs/37199061203/job/111426819401) | 82 tests, 3 failures; exit 2 | 532057 | `UndefinedFunctionError: function HTTP.fetch/2 is undefined (module HTTP is not available)` |
| [EventSource 111426819440](https://github.com/gsmlg-dev/http_fetch/actions/runs/37199061203/job/111426819440) | 64 tests, 2 failures; exit 2 | 704363 | Same missing Fetch module |

Affected existing tests:

- WebSocket `connection_http2_test.exs:49`: zero send credit preserves an ordinary sibling.
- WebSocket `connection_http2_test.exs:135`: strict H2 capability refusal retains the owner for an ordinary request.
- WebSocket `lifecycle_bounds_test.exs:250`: sibling traffic cannot reset the WebSocket idle deadline.
- EventSource `http2_test.exs:93`: only this SSE stream's body activity refreshes its idle timer.
- EventSource `http2_test.exs:288`: GOAWAY preserves accepted SSE data and a Fetch sibling owner.

The CI jobs used Ubuntu 24.04.5, OTP 28.5.0.7, Elixir 1.18.5 built for OTP 27,
`MIX_ENV=test`, `HTTP_FETCH_CI_APP` set to the selected package, and
`max_cases: 8`. Local reproduction used NixOS/Linux 6.18.48, OTP 28
(ERTS 16.4.0.5), and Elixir 1.18.5 built for OTP 28. Exact CI OS/toolchain
patch parity was unavailable; the missing-module failure reproduced in both
fresh local application selections.

## Root cause and repair

The root `mix.exs` `ci_apps/0` selects the umbrella applications compiled and
loaded for each matrix job. WebSocket and EventSource selections included
their runtime dependencies but omitted `:http_fetch`. Their existing
mixed-client HTTP/2 tests invoke `HTTP.fetch/2`, `HTTP.Promise`, and
`HTTP.Response` to prove that ordinary Fetch siblings survive or do not
refresh another stream's deadline. A full umbrella invocation masks this
selection defect by loading Fetch.

The repair adds `:http_fetch` to those two CI selections and updates the
selection comment to reflect test requirements. Tests, production runtime
code, package dependency declarations, and the selected test paths are
unchanged. No upstream dependency defect was encountered.

## Fresh red/green verification

Each command sequence ran from the umbrella root, with a new build directory
and the indicated application selection:

```sh
MIX_ENV=test HTTP_FETCH_CI_APP=http_web_socket MIX_BUILD_PATH=/tmp/http3-wp0-ws-red-build mix deps.get
MIX_ENV=test HTTP_FETCH_CI_APP=http_web_socket MIX_BUILD_PATH=/tmp/http3-wp0-ws-red-build mix compile --warnings-as-errors
MIX_ENV=test HTTP_FETCH_CI_APP=http_web_socket MIX_BUILD_PATH=/tmp/http3-wp0-ws-red-build mix test apps/http_web_socket/test --seed 532057

MIX_ENV=test HTTP_FETCH_CI_APP=http_event_source MIX_BUILD_PATH=/tmp/http3-wp0-sse-red-build mix deps.get
MIX_ENV=test HTTP_FETCH_CI_APP=http_event_source MIX_BUILD_PATH=/tmp/http3-wp0-sse-red-build mix compile --warnings-as-errors
MIX_ENV=test HTTP_FETCH_CI_APP=http_event_source MIX_BUILD_PATH=/tmp/http3-wp0-sse-red-build mix test apps/http_event_source/test --seed 704363
```

Before repair: both dependency/compile steps passed. WebSocket reproduced
82 tests/3 failures, and EventSource reproduced 64 tests/2 failures, with the
same five missing `HTTP.fetch/2` errors (local default `max_cases: 16`).

```sh
MIX_ENV=test HTTP_FETCH_CI_APP=http_web_socket MIX_BUILD_PATH=/tmp/http3-wp0-ws-green-build mix deps.get
MIX_ENV=test HTTP_FETCH_CI_APP=http_web_socket MIX_BUILD_PATH=/tmp/http3-wp0-ws-green-build mix compile --warnings-as-errors
MIX_ENV=test HTTP_FETCH_CI_APP=http_web_socket MIX_BUILD_PATH=/tmp/http3-wp0-ws-green-build mix test apps/http_web_socket/test --seed 532057 --max-cases 8

MIX_ENV=test HTTP_FETCH_CI_APP=http_event_source MIX_BUILD_PATH=/tmp/http3-wp0-sse-green-build mix deps.get
MIX_ENV=test HTTP_FETCH_CI_APP=http_event_source MIX_BUILD_PATH=/tmp/http3-wp0-sse-green-build mix compile --warnings-as-errors
MIX_ENV=test HTTP_FETCH_CI_APP=http_event_source MIX_BUILD_PATH=/tmp/http3-wp0-sse-green-build mix test apps/http_event_source/test --seed 704363 --max-cases 8

mix format --check-formatted mix.exs
git diff --check
```

After repair: all commands passed (exit 0). WebSocket: **82 tests, 0 failures**.
EventSource: **64 tests, 0 failures**. Neither suite reported skips. Existing
negative-certificate WebSocket tests emitted expected TLS alerts. One Sol
repair/validation round was used; no Astra repair was needed. All owned test
processes completed. Remote CI after repair, release, and external package
consumers were **NOT RUN** by this worker.

An additional attempted scoped lint command,
`MIX_ENV=test HTTP_FETCH_CI_APP=http_web_socket MIX_BUILD_PATH=/tmp/http3-wp0-ws-green-build mix credo --strict --files-included mix.exs`,
checked 405 files because Credo's inclusion option adds to the configured
file set. It **FAILED** with exit 14: 82 software-design suggestions,
23 readability issues, and 6 refactoring opportunities in existing source
files outside the changed root manifest. No finding named the changed
`mix.exs`, and no unrelated lint edits were made. This optional strict
invocation does not establish the normal CI Credo result.

## Local identity/provenance check

All nine current manifests declare version `0.16.1`; internal sibling
dependencies declare exact `== 0.16.1` constraints with `in_umbrella: true`
and their matching `hex:` identities. The local graph was checked against
[`migration-provenance.md`](migration-provenance.md):

| OTP app / package | Internal runtime dependencies | License |
| --- | --- | --- |
| `ex_ssl` (`SSL`) | none | Apache-2.0 |
| `elixir_quic` (`Quic`) | `ex_ssl` | MIT |
| `http_core` | `ex_ssl`, `elixir_quic` | MIT |
| `http_runtime` | `http_core` | MIT |
| `elixir_quic_http3` (`QuicHttp3`) | `http_core`, `elixir_quic` | MIT |
| `http_fetch` (`HTTP`) | `http_core`, `http_runtime` | MIT |
| `http_event_source` (`HTTP.EventSource`) | `http_core`, `http_runtime` | MIT |
| `http_web_socket` (`HTTP.WebSocket`) | `http_core`, `http_runtime` | MIT |
| `http_web_transport` | `http_core` | MIT |

The imported-source revision recorded there is
`gsmlg-dev/ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6`, with historical
standalone TLS provenance
`gsmlg-dev/ex_ssl@fb47051355c9d0a29caee046fa060a745ad0ce5b`. WP0 inspected
the current manifests/namespaces and the existing provenance record; it did
not repeat the full imported-blob comparison or verify published artifacts.
Local identity checks do not establish an available nine-package Hex release.

## Follow-up: release validation blockers

The first WP0 release attempt, [run 37269991020](https://github.com/gsmlg-dev/http_fetch/actions/runs/37269991020),
failed at Dialyzer before publication. The actual failed-step log reported six
warnings, five skipped, and one emitted opaque `member?` warning. Reading
`repos/gsmlg-dev/http_fetch/check-runs/111634756218/annotations` identified the
exact callsite: `lib/ssl/protocol/server_hello.ex:427`.

`SSL.Protocol.ServerHello` compiled its fixed 16 GREASE identifiers as a
`MapSet` module attribute, then passed that literal to `MapSet.member?/2`.
Scoped local Dialyzer reproduced the same opaque-argument warning, exit 2.
The repair keeps the same generated identifiers as a list and checks
membership with `in`; it changes no TLS selection/rejection rules and adds
no Dialyzer ignore. The existing ServerHello parser suite covers fragmented
inputs and negative GREASE selections for ciphers, groups, and extensions.

The release unittest fixture also assumed repository version `0.16.1`.
Against a complete temporary graph prepared at `0.16.2`, its unchanged suite
reproduced **11 tests, 2 failures**: archive metadata identity mismatch and
the missing-edge test failing to remove the version-specific dependency
line. Version tests now prepare their private complete graph at a fixed test
version before mutations, remove the edge regardless of requirement version,
and assert exactly one removal. Archive tests read the root source version
and use it consistently for archive filenames, metadata, rebuilds, audit,
and documentation. All existing rejection assertions remain intact.

Follow-up source baseline: `bc63a24a1c93447efedf402e14fdbc71b680641d`.
Validation used Elixir 1.18.5/OTP 28 and these scoped commands:

```sh
python3 -m unittest discover -s scripts/release -p 'test_*.py' -v
MIX_ENV=test HTTP_FETCH_CI_APP=ex_ssl MIX_BUILD_PATH=/tmp/http3-wp0-exssl-repair-build mix compile --warnings-as-errors
MIX_ENV=test HTTP_FETCH_CI_APP=ex_ssl MIX_BUILD_PATH=/tmp/http3-wp0-exssl-repair-build mix test apps/ex_ssl/test/ssl/protocol/server_hello_test.exs --seed 743209
mix format --check-formatted apps/ex_ssl/lib/ssl/protocol/server_hello.ex
git diff --check
```

Results: release unittest **11/11 PASS** at current source version and
**11/11 PASS** against the temporary `0.16.2` graph; fresh compile **PASS**;
ServerHello **1 property, 16 tests, 0 failures**; formatting/diff **PASS**.
The temporary-graph run copied root manifests/lock and all nine app sources,
ran `versions.exs prepare 0.16.2` there, then loaded the same unittest module
with its source root and `stage.ROOT` pointed to that graph. Local green logs
are `/tmp/http3-wp0-release-fixture-current-green.log` and
`/tmp/http3-wp0-release-fixture-prepared-green.log`.

Direct `:dialyzer.run/1` analyzed only the freshly compiled
`/tmp/http3-wp0-exssl-repair-build/lib/ex_ssl/ebin/Elixir.SSL.Protocol.ServerHello.beam`,
using the existing main-workspace PLT at
`apps/http_fetch/priv/plts/dialyzer.plt`, `check_plt: false`, and the release
warning flags `[:unmatched_returns, :error_handling, :underspecs, :unknown]`.
Result: **zero warnings, exit 0**. An initial invocation used an incorrect
extra `test/` path component and failed to locate the BEAM; the corrected
invocation above completed successfully. This scoped analysis does not claim
that a fresh full umbrella Dialyzer or repaired remote release passed.

These follow-up edits constitute the second cumulative WP0 Sol repair round;
both rounds passed their scoped validation. No Astra repair was used. All
owned commands completed, and concurrent HTTP/3 work was preserved.
