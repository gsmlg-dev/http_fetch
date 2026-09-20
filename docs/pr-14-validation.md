# PR #14 validation

Base reviewed and fetched: `f5c0fe60393bc8f0570b3f92e04fe45a0aa88ceb`
(`codex/replace-ssl-with-ex-ssl`). The remote PR had no later commits when work
started. Existing uncommitted fixes were preserved and completed.

Environment: Elixir 1.18.5, Erlang/OTP 28 (ERTS 16.4.0.5), Linux; Go 1.26.6
for the vendored E2E server (the workflow requires Go 1.22+).

## Application build failure

The failure is the child Mix dependency graph and code path, not a stale cache.
The child projects share the umbrella's `../../deps`, `../../_build`, and lock,
but an `in_umbrella` dependency is not recursively traversed in the same way
when running Mix from a child. `http_core` declares `ex_ssl`, while the four
client applications declare `http_core`; their child `mix deps` output lacks
`ex_ssl`. `http_core.app` still lists `ex_ssl` as a runtime application.

In an isolated detached worktree at the reviewed HEAD, `http_core` child tests
pass but all four client child tests fail with:

```text
** (Mix) Could not start application ex_ssl:
could not find application file: ex_ssl.app
```

Even after the root test-environment compile generates
`_build/test/lib/ex_ssl/ebin/ex_ssl.app`, child execution still fails. Thus
precompiling alone or clearing a cache does not fix the missing code path.
The original Test run 35490860631 and E2E run 35490860636 both show the same
failure, with undefined `SSL` module warnings during child compilation.

Test and E2E workflows now explicitly prepare `MIX_ENV=test` at the root and
run `mix test apps/<app>/test` or `mix test apps/<app>/e2e` from the root.
The root `test.e2e` alias also stays at the root. No client duplicates the
`ex_ssl` dependency, disables runtime startup, or suppresses compiler warnings.

## Dependency and transport contract

`http_core` now requires `ex_ssl ~> 0.3.0`; the existing lock remains 0.3.0 and
no unrelated dependency was upgraded. The external smoke uses freshly built
package contents in a separate temporary consumer, without the umbrella lock,
deps or build output. Only unpublished internal package resolution uses local
paths; the consumer does not declare `ex_ssl` itself.

OTP `:ssl` stays the default. `:ex_ssl` is explicitly selected or inherited
from `:http_core` configuration and remains captured across redirects and
EventSource reconnects. No backend fallback was added. The supported paths
are HTTP/1.1, HTTP/2, secure WebSocket and HTTPS EventSource. HTTP/3 and
WebTransport retain QUIC TLS and reject an explicit TCP TLS backend.

The ex_ssl 0.3.0 integration still requires verified TLS 1.3. TLS 1.2,
`verify_none`, client certificates and unsupported socket options are rejected;
custom profile ALPN must match the requested ALPN list.

## HTTP/2 response/close ordering

The parser emits response events and queues receive-window updates for nonempty
DATA, including END_STREAM DATA. SocketClient previously flushed those writes
before delivering the events. After a normal TLS shutdown, the write returned
`:closed` and the client discarded the already-complete response.

The change preserves that order. A failed write is non-fatal only when all four
conditions hold: HTTP/2 reports completion, this batch contains `:done`, all
queued frames are WINDOW_UPDATE / SETTINGS ACK / PING ACK, and the write error
is exactly `:closed`. Pending request DATA makes the failure fatal, including
when a coalesced WINDOW_UPDATE releases the final upload bytes. Reset and
protocol errors are returned by the parser before this exception is considered.
No `:einval`, `:econnreset`, certificate, cancellation or timeout errors are
ignored. Cleanup and stream delivery use the existing event handlers.

The new real TLS 1.3/ex_ssl tests establish the following order:

1. The local server waits on a message gate after receiving the request.
2. The test waits until the socket owner is waiting in `owner_loop/1`, then
   suspends it; the separate TLS process keeps running.
3. The server sends complete response frames and successfully closes TLS.
4. The test observes both data and `ssl_closed` queued for the suspended owner
   and monitors the TLS process exiting before resuming the owner.
5. The exact body is delivered, and the owner exits normally. For the streaming
   case, a concurrent reader handles normal backpressure, the final DATA is
   gated separately after earlier frames, and the stream also exits normally.

The buffered case coalesces SETTINGS/HEADERS/DATA. The 5,000,001-byte streaming
case separates response headers and DATA; its server does not wait for the
final WINDOW_UPDATE before closing. Waiting predicates use bounded polling of
actual process/message state; elapsed sleeps do not establish the ordering.

With these tests copied into the detached original-HEAD worktree, leaving both
production modules unchanged, the buffered test fails with `{:error, :closed}`
and the streaming test raises `stream read failed: :closed`. The final combined
line-selected baseline run executes both
regressions (17 discovered, 2 failures, 15 excluded by line selection). Both pass
with the fix. The final HTTP/2 file contains 17 tests, including
required upload-write failures with and without END_STREAM, truncation, and
both existing TLS backends. Two additional parser tests preserve errors when
RST_STREAM or an invalid WINDOW_UPDATE follows END_STREAM in the same batch.
The full 17-test HTTP/2 file was also repeated with seeds 1 through 5: all 85
executions passed, with no excluded tests. Earlier HTTP/1.1, EventSource and
WebSocket close-order regression tests remain unchanged and pass in the full
suite.

## Final local validation

All commands below were actually executed from the root unless indicated.
Unit and E2E suites have zero failures and zero skipped tests. Per-app rows
repeat the corresponding root-suite coverage; they are not additional unique
tests. Line-selected red/green runs intentionally exclude other tests.

| Command | Result |
| --- | --- |
| `mix deps.get`; `MIX_ENV=test mix deps.get` | Passed; lock unchanged |
| `mix format --check-formatted` | Passed, including the new smoke script |
| `mix compile --warnings-as-errors` | Passed |
| `MIX_ENV=test mix compile --warnings-as-errors` | Passed |
| `mix test` | 401 tests + 20 doctests; 0 failures, 0 skipped |
| `MIX_ENV=test mix test apps/http_core/test` | 161 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_fetch/test` | 157 tests + 20 doctests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_socket/test` | 33 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_event_source/test` | 26 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_transport/test` | 24 tests; 0 failures |
| `mix credo` | No issues |
| `mix dialyzer --format github` | Passed; 4 existing intentional ignores, 0 new warnings |
| `MIX_ENV=prod mix hex.build --unpack -o <temporary package directory>` in each app | All five packages built, also exercised by smoke |
| `bash scripts/external_consumer_smoke.sh` | Passed; five current packages, eight verified TLS client exchanges |
| `bash -n scripts/external_consumer_smoke.sh` | Passed |
| `go build -o ../test_server/server .` in `apps/http_fetch/priv/test_server` | Passed |
| `MIX_ENV=test mix test apps/http_fetch/e2e` | 50 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_socket/e2e` | 3 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_event_source/e2e` | 2 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_transport/e2e` | 3 tests; 0 failures |
| `MIX_ENV=test mix test.e2e` with the Go server running | All 58 E2E tests; 0 failures |

`http_core` has no E2E directory; the existing workflow conditional reports that
fact rather than skipping an existing suite. The root-scoped commands above
are the commands used by the modified Test and E2E workflows. CI retains the
development compile and also checks test-environment compilation.

Cold-start validation used detached worktrees under `.trees/` with independent
`deps` and `_build`, without deleting the user's existing build output. The
original root `mix deps.get` followed by child `mix test` reproduced undefined
SSL-module warnings and missing `ex_ssl.app`; cold root test preparation and
root-scoped execution succeeded. The external consumer likewise starts with
an empty temporary dependency/build tree and no repository lockfile on every
invocation. Three consecutive complete consumer smoke runs passed after its
server synchronization was finalized, followed by the final full-validation run.

The smoke checks actual `hex_metadata.config` requirements, including
`optional: false`, and executes HTTP/1.1, HTTP/2 with ALPN, WSS upgrade/message,
and HTTPS EventSource open/message with both the omitted/default backend and
explicit ex_ssl. WebTransport explicitly rejects a TCP TLS backend and retains
QUIC options under shared ex_ssl configuration. The existing real QUIC E2E
suite also passed; the consumer smoke itself does not create a QUIC session.

## Remaining limitation and diagnostic failures

The first external smoke server closed its HTTP/2 TLS connection immediately
without coordinating with the client. Repetition exposed an OTP `:einval` error.
A separate diagnostic loaded `HTTP.SocketClient` from the original f5c0fe6
worktree (the code path was printed and checked): 100 immediate-close OTP TLS
1.3 requests yielded 69 successes, 26 `:closed`, and 5 `:einval` errors. Thus
this risk predates this fix. This diagnostic is not a substitute for the
synchronized ex_ssl regression tests.

The general consumer smoke now waits for a SETTINGS ACK before server closure;
it tests installed-package operation. The dedicated close-order regression
still closes before the final client acknowledgement/window update. The
production fix deliberately does not treat `:einval` as a normal close; the
pre-existing OTP immediate-close limitation remains outside this narrow fix.
No dependency source was modified, and no ex_ssl upstream defect was needed
to explain either integration fix.

Local evidence logs are under `/tmp/http_fetch-pr14-validation/`, with original
workflow logs `/tmp/http_fetch-pr14-old-{test,e2e}.log`, cold reproduction logs
`/tmp/http_fetch-pr14-original-workflow-{deps,child}.log`, and the OTP baseline
diagnostic `/tmp/http_fetch-pr14-baseline-h2-immediate-close.log`. These local
logs are not shipped in the packages.

The final red/green commands were:

```bash
# In the detached original-HEAD worktree, after copying only the final test file
MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs:214 apps/http_fetch/test/http/socket_client_http2_test.exs:350 --trace
# Expected: 2 failures, 15 excluded (the two close-order regressions)

# In the fixed working tree; also repeated with --seed 1 through --seed 5
MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs
# 17 tests, 0 failures, 0 excluded
```
