# PR #14 validation

## Early final responses (baseline a1312cc)

The current round started at `a1312cc40c8d6aad2cb60e750bfba84f9b3ac1cf`,
which was also the remote PR HEAD; the working tree was clean. The previous
cross-record drain remains in place. This round corrects its overly broad
assumption that an unfinished request upload invalidates a completed response.
The earlier records below are historical; their blanket pending-upload and
NO_ERROR-reset failure rules are superseded by this section.

### Protocol basis and root cause

[RFC 9113 §8.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1) defines
response completion independently of request transmission. A server may finish
its response before receiving the entire request, then use RST_STREAM(NO_ERROR)
to stop the upload without invalidating that response. Completion requires
END_STREAM and completion of any associated HEADERS/CONTINUATION field block.
A final status, Content-Length, or body-forbidden response alone is insufficient.

Three decisions had been conflated:

1. `outbound_control_only?/1` classified the queued frames **and** required an
   empty `pending_body`. This prevented normal-close draining and discarded
   complete early responses even when only an ACK needed writing.
2. Parsing WINDOW_UPDATE could queue more request DATA before the final response
   was recognized, and response completion did not remove that obsolete upload.
3. Every target-stream RST_STREAM was returned as an error, including NO_ERROR
   after a complete response. Body-forbidden responses were also incorrectly
   considered complete without END_STREAM.

The implementation separates frame classification, stopped request transmission
and response completion. Valid completion stops the remaining upload and removes
queued request DATA while preserving control frames. A normal ex_ssl close
reported by an optional control write stops transmission without marking the
response complete; the original active-once/deadline loop drains and validates
what remains. Subsequent buffered WINDOW_UPDATE cannot restart that upload.
Actual request DATA write failures before this transition remain failures.
NO_ERROR reset is harmless only after verified response completion; CANCEL,
protocol/TLS errors, truncation, cancellation and deadline retain their errors.

### Initial baseline evidence

A fresh detached worktree at `.trees/r3-baseline` was prepared with independent
`deps` and `_build` using `MIX_ENV=test mix deps.get` and
`MIX_ENV=test mix compile --warnings-as-errors`. Only the regression test file
was copied in; production code remained at a1312cc.

```bash
MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs --only early_response --seed 0
# Initial baseline: 25 discovered, 1 executed, 1 failure, 24 excluded.
```

The client POSTs 65,535 + 5 bytes. The server reads only the initial window,
then waits for the test to suspend the HTTP owner before sending a valid 413
response with exact body `payload-too-large` and END_STREAM. The test confirms
normal TLS closure and the queued response before resuming the owner.
`HTTP.Promise.await` actually returns `{:error, :closed}`, so the expected 413
response assertion fails. Log: `/tmp/http_fetch-pr14-r3/a1312cc-first-red.log`.

### Corrected expectations and additional baseline evidence

The old test named `fails when SETTINGS acknowledgement cannot flush a pending
HTTP/2 request body` is corrected to expect a 413 and exact response body after
the same deterministic peer-close barrier. The completed branch of the existing
WINDOW_UPDATE/upload test is likewise corrected to preserve the response and
discard unsent DATA. Its incomplete branch retains the actual DATA-write failure
expectation; NO_ERROR-reset rejection is separate, so a parser reset cannot hide
loss of required-write coverage.

The queue-classification test now permits an ACK-only queue even when
`pending_body` is nonempty. Separate tests verify explicit upload stopping,
retention of non-upload frames, continued ordinary upload flow control, and no
false response completion. The old bodyless HEADERS/CONTINUATION fixture is made
protocol-valid by carrying END_STREAM on HEADERS and waiting for END_HEADERS on
CONTINUATION; the first fragment alone neither completes the response nor stops
the pending upload.

The final core test file was copied into the unchanged a1312cc worktree and run
with these selections:

```bash
MIX_ENV=test mix test apps/http_core/test/http/http2_test.exs:235 apps/http_core/test/http/http2_test.exs:288 apps/http_core/test/http/http2_test.exs:372 --seed 0
# 25 discovered, 3 executed, 3 failures, 22 excluded.
```

These are actual behavior failures, not missing-new-API errors: premature `:done`
for 204 without END_STREAM; request DATA still queued after a complete response;
and `{:stream_reset, :no_error}` after a complete response. Log:
`/tmp/http_fetch-pr14-r3/a1312cc-core-final-red.log`. The fixed full core HTTP/2
file passes all 25 tests. Same-batch and subsequent-call NO_ERROR resets are
covered, including repeated reset with no duplicate events, and reset before a
complete response remains an error.

### Final integration regression evidence

The final integration file was copied unchanged into the a1312cc worktree:

```bash
MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs --only early_response --seed 0
# Baseline: 31 discovered, 9 executed, 6 failures, 22 excluded.
```

Five failures returned `{:error, :closed}` instead of the complete response:
413 with body, bodyless 413, cross-record 413, a completed response followed by
a buffered NO_ERROR reset, and WINDOW_UPDATE plus a completed response. The
sixth returned `{:error, {:stream_reset, :no_error}}` for a complete response
and reset parsed in the same batch. The three passing controls were OTP's early
response, incomplete-response NO_ERROR reset, and the actual required DATA-write
failure. Log: `/tmp/http_fetch-pr14-r3/a1312cc-final-integration-red.log`.

All early-response fixtures use a 65,540-byte POST, with the peer reading the
initial 65,535-byte window. The simple 413 and bodyless variants provide no
additional upload credit. The cross-record variant adds WINDOW_UPDATE in its
buffered second batch to verify that draining cannot restart a stopped upload.
Message gates prove that the first plaintext batch is the paused owner's sole
TLS message before releasing the second write. A bounded probe then verifies
normal peer closure, inactive delivery, and the exact remaining plaintext buffer
size. Only these flags and sizes are observed; no TLS keys or state dumps are
printed. The owner resumes while the TLS receive buffer still exists.

The separate-record NO_ERROR integration test permits the owner to finish after
the complete first batch and release the buffered reset during cleanup. Protocol
unit tests additionally parse the reset in a subsequent call and prove that it
produces no duplicate events. Same-batch integration exercises actual reset
parsing. NO_ERROR before completion, CANCEL, truncation, fragmented frames,
required writes, streaming backpressure, cancellation and deadline keep their
negative coverage. Owner and TLS process monitors verify release in the gated
close tests. Existing cross-record/frame-fragment and streaming tests are kept.

The complete final integration file passed seeds 1, 2, 3, 4 and 5: **31 tests,
0 failures per run**, no skips or exclusions. The core HTTP/2 file passed seeds
101, 202, 303, 404 and 505: **25 tests, 0 failures per run**. These repetitions
check stability; the record/buffer barriers establish the timing itself.

### Current local acceptance results

Executed on Elixir **1.18.5**, Erlang/OTP **28** (ERTS 16.4.0.5), Go **1.26.6**.
All commands below ran from the umbrella root, except the explicitly noted Go
build and isolated baseline reproduction. Logs and exit codes are in
`/tmp/http_fetch-pr14-r3/final-*.log` and `final-results.json`.

| Actual command | Final result |
| --- | --- |
| `mix deps.get`; `MIX_ENV=test mix deps.get` | Both passed; lockfile unchanged |
| `mix format --check-formatted` | Passed |
| `mix compile --warnings-as-errors` | Passed |
| `MIX_ENV=test mix compile --warnings-as-errors` | Passed |
| `mix test` | **422 tests + 20 doctests, 0 failures, 0 skipped** |
| `MIX_ENV=test mix test apps/http_core/test` | 168 tests, 0 failures |
| `MIX_ENV=test mix test apps/http_fetch/test` | 171 tests + 20 doctests, 0 failures |
| `MIX_ENV=test mix test apps/http_web_socket/test` | 33 tests, 0 failures |
| `MIX_ENV=test mix test apps/http_event_source/test` | 26 tests, 0 failures |
| `MIX_ENV=test mix test apps/http_web_transport/test` | 24 tests, 0 failures |
| `mix test apps/http_fetch/test/http/socket_client_http2_test.exs --seed N` for N=1..5 | 31 tests/run, 0 failures |
| `mix test apps/http_core/test/http/http2_test.exs --seed N` for N=101,202,303,404,505 | 25 tests/run, 0 failures |
| `mix credo` | Passed, no issues |
| `mix dialyzer --format github` | Passed; 4 existing ignored diagnostics, 0 new diagnostics |
| `bash scripts/external_consumer_smoke.sh` | Passed: five packages built from current source, metadata checked, isolated dependency resolution/compilation/startup and eight local TLS exchanges |
| `MIX_ENV=test mix test apps/http_fetch/e2e` | 50 tests, 0 failures |
| `MIX_ENV=test mix test apps/http_web_socket/e2e` | 3 tests, 0 failures |
| `MIX_ENV=test mix test apps/http_event_source/e2e` | 2 tests, 0 failures |
| `MIX_ENV=test mix test apps/http_web_transport/e2e` | 3 tests, 0 failures |
| `MIX_ENV=test mix test.e2e` | Same 58 E2E tests, 0 failures |

The Go fixture was rebuilt with `go build -o ../test_server/server .` from
`apps/http_fetch/priv/test_server`, started before E2E, and stopped afterward.
`E2E_BASE_URL` pointed at its reported local port. `http_core` has no E2E suite;
its root-scoped unit suite covers that workflow matrix entry. All final selected
app and E2E runs had zero skipped/excluded tests. Baseline line/tag exclusions
above are deliberate selection, not skipped failing tests.

Cold compilation was exercised in the independent a1312cc worktree; the final
source was also cold-compiled by the external consumer with its own `deps`,
`_build`, and newly resolved lockfile. The consumer obtains ex_ssl transitively
from the built http_core package, with no manually added ex_ssl dependency.
WebTransport retains its existing QUIC boundary check; it is not a TCP TLS test.

No requested local checks remain unexecuted. These results are local, not proof
of remote CI on a future commit; new remote results belong to their exact SHA.
Known limits remain: tests probe private ex_ssl 0.3.0 buffer flags only for
synchronization; production uses public transport calls. OTP's previously
recorded immediate-close `:einval` is still an error, not a new exception. The
OTP early-response test keeps the peer open for control acknowledgements; the
ex_ssl regressions prove close-before-control-write behavior. No backend
fallback, POST retry, certificate-policy relaxation, new timeout, dependency
patch, or dependency upgrade was introduced.

## Historical: cross-record drain at a1312cc

Reviewed baseline and remote PR HEAD: `010b0b850745b43faab73093849d3fb6a1dc6650`.
The branch had no later commits when this follow-up started. The earlier fixes
below remain intact. Validation uses Elixir 1.18.5 / OTP 28, as required by CI.

### Reproduction and cause

The new test runs through `HTTP.fetch` with a trusted local TLS 1.3 server and
locked ex_ssl 0.3.0. It suspends the HTTP owner only after it reaches its receive
loop. The server sends SETTINGS/HEADERS and waits at a second message gate.
The test verifies that exactly this plaintext is the owner's sole TLS data
message, consuming `active: :once`, before releasing the second server write.
The server then sends DATA/END_STREAM and closes TLS without waiting for an ACK.
A bounded test-only probe checks only `closed`, `active`, and plaintext buffer
size in the TLS process: closed is true, active is false, and the second batch
is still buffered. The owner still has only the first data message. TLS process
exit and `ssl_closed` are deliberately **not** prerequisites for resuming it.

The test was copied into `.trees/r2-baseline`, a detached checkout at exactly
`010b0b8` with independently downloaded dependencies and compiled test output.
Production files there were unchanged. This actual command failed:

```bash
MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs:264 --seed 0
# 18 tests discovered, 1 failure, 17 excluded by line selection
# HTTP.Promise.await returned {:error, :closed}, not the expected response.
```

With the fix, the same initial test and command passed: 18 discovered, 0 failures,
17 excluded. A separate control-classification regression, copied unchanged into
the same baseline and selected with `apps/http_core/test/http/http2_test.exs:15`,
also failed there (19 discovered, 1 failure, 18 excluded): an unsent `pending_body`
was previously classified as optional controls. The fixed full parser file passed
all 19 tests. Evidence: `/tmp/http_fetch-pr14-r2/010b0b8-cross-record-red.log`
and `cross-record-first-green.log`. Later coverage is listed separately below.

The first batch creates a SETTINGS ACK but no `:done`. After peer close_notify,
`SSL.send` returns `:closed`; `send_request/4 -> close_on_error/3` then explicitly
closed the TLS socket before the caller could classify the error. That destroyed
the still-unconsumed second record. The previous complete-batch exception could
not help: the HTTP parser had not yet seen END_STREAM.

Read-only inspection of the locked dependency confirms its contract:
`active: :once` consumes one delivery; peer close_notify rejects new writes but
retains plaintext until subsequent `setopts(active: :once)` or `recv` drains it.
A raw TCP close without close_notify is `:econnreset`; fatal TLS alerts remain
TLS errors. Explicit `SSL.close` terminates the buffered receive side. The
public API has no connection-state query, and production uses no private TLS
state. Test probes never print TLS keys or complete internal state. No dependency
source or lockfile was changed; this is an http_fetch integration bug.

### Fix and safety boundaries

Send results now reach the caller without implicit socket destruction. Initial
request/upload failures still return to the owner's cleanup; failed required
protocol writes still use `fail -> finish -> cleanup`. Cancellation, deadlines,
worker-start failure and send timeout retain their termination paths.

Before removing outbound frames, the client checks the actual queue for only
WINDOW_UPDATE, SETTINGS ACK or PING ACK, **and** checks that `pending_body` is
empty. Thus both already-queued request DATA and uploads waiting for more window
credit prevent the exception. Only ex_ssl's established, exclusively owned
socket can use `:closed` to continue an incomplete response: this owner has not
locally closed it, and that backend distinguishes abnormal closure. Other
transports retain the previous completed-response/current-`:done` restriction.

An optional-control `:closed` clears that attempted queue once and runs the
existing event handlers and active-once rearm. It does not report success.
Each further attempt requires newly received data; there is no retry loop or
new timer. Stream chunk acknowledgements retain backpressure and the original
absolute request deadline remains in force. EOF without END_STREAM fails through
`HTTP2.close/1`; resets and protocol errors still fail in the parser. No `:einval`,
`:econnreset`, TLS error, required write error, cancellation or timeout is ignored.

### Final regression coverage and baseline comparison

Eight new integration tests use the `:cross_record` tag. They cover:

- Small buffered response with SETTINGS/HEADERS in the first delivery and
  DATA/END_STREAM still inside ex_ssl after peer close.
- A HEADERS frame header split across deliveries while SETTINGS ACK is pending.
- The same receive-buffer sequence without END_STREAM: still `:closed`.
- DATA/END_STREAM followed by RST_STREAM in the later buffered batch: still
  `{:stream_reset, :cancel}`, never a successful response.
- A complete response with only optional frames queued but an upload still
  waiting for window credit: still fails. Its fixture now proves closure before
  resuming the owner; an initial version exposed a fixture race in seed 202 and
  was corrected rather than weakening the expected error.
- A 5,000,001-byte stream whose final three DATA frames have not been consumed
  when the owner pauses. PING plus part of a DATA payload is the first delivery;
  the rest and two further DATA frames remain in TLS buffers before resume.
  Exact body equality and normal stream/TLS/owner exits are checked.
- Cancellation while the drained final chunk is held by a reader acknowledgement
  barrier and the owner is demonstrably waiting in `HTTP.Stream.chunk/3`.
- The original deadline under the same backpressure. A timer gate consumes half
  a 2-second request budget before entering drain; owner termination must occur
  by the original monotonic deadline plus 400ms, not a restarted deadline.

Server gates and state probes have timeouts. Failure cleanup resumes/aborts the
owner and releases test stream/reader processes. Successful and error scenarios
monitor the owner and TLS process; streaming cases also monitor the stream.
The existing complete-batch regressions and required-upload DATA failures with
and without END_STREAM remain in the file, alongside both TLS backends.

After completing the tests, the final test file was copied back into the same
`010b0b8` checkout, still without any production changes:

```bash
MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs --only cross_record --seed 1
# Baseline: 25 discovered, 8 executed, 7 failures, 17 excluded.
# The truncated-response rejection passes; the other seven regressions fail.
```

The full log is `010b0b8-final-cross-record-red.log`. The fixed tree passes all
8 selected tests with seeds 1–5 (40 executions). The **entire** HTTP/2 file was
also run with seeds 1–5, with no filtering: 25 tests per run, 125 executions,
0 failures, 0 skipped or excluded. Each full result is in `http2-seed-N.log`.

### Follow-up local validation results

All commands below ran from the umbrella root unless stated. These results are
from the follow-up working tree, not the previous commit's CI. Unit and E2E
suites report 0 failures and 0 skipped tests. Scoped suites repeat root coverage.

| Command | Actual result |
| --- | --- |
| `mix deps.get`; `MIX_ENV=test mix deps.get` | Passed; `mix.lock` unchanged |
| `mix format --check-formatted` | Passed |
| `mix compile --warnings-as-errors` | Passed |
| `MIX_ENV=test mix compile --warnings-as-errors` | Passed |
| `mix test` | 410 tests + 20 doctests; 0 failures |
| `MIX_ENV=test mix test apps/http_core/test` | 162 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_fetch/test` | 165 tests + 20 doctests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_socket/test` | 33 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_event_source/test` | 26 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_transport/test` | 24 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs --seed N`, N=1..5 | Each: 25 tests, 0 failures |
| `mix credo` | No issues |
| `mix dialyzer --format github` | Passed; 4 existing intentional ignores, no new warnings |
| `bash scripts/external_consumer_smoke.sh` | Passed; five newly built packages, isolated dependency/build tree, eight trusted TLS exchanges and QUIC boundary checks |
| `go build -o ../test_server/server .` in `apps/http_fetch/priv/test_server` | Passed |
| `MIX_ENV=test mix test apps/http_fetch/e2e` | 50 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_socket/e2e` | 3 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_event_source/e2e` | 2 tests; 0 failures |
| `MIX_ENV=test mix test apps/http_web_transport/e2e` | 3 tests; 0 failures |
| `MIX_ENV=test mix test.e2e` | 58 tests; 0 failures |

For E2E, the built Go server was started, its reported port set in
`E2E_BASE_URL=http://127.0.0.1:<port>`, and the server terminated afterward.
`http_core` has no E2E directory. The package smoke builds all five packages
with `mix hex.build` before starting a consumer that shares neither repository
`deps`/`_build` nor its lockfile and declares no extra ex_ssl dependency.
The detached baseline also started with independent empty build/dependency
folders; no user build files were deleted.

No requested local check remains unexecuted. Evidence and the command/exit-code
manifest are under `/tmp/http_fetch-pr14-r2/` (`final-results.json`, `final-*.log`).
Remote checks for `010b0b8` are historical and are not follow-up validation.

### Preserved limitations

The pre-existing OTP immediate-close `:einval` limitation described below is
unchanged; no new error whitelist or TLS fallback was introduced. Existing
stream deadline expiry can report either `:request_timeout` (owner timer) or
`:timeout` (the chunk acknowledgement wait reaches the same absolute deadline).
The deadline regression accepts exactly these existing timeout errors, never
`:closed` or success, and does not normalize production error semantics.
The bounded test-only buffer probe intentionally targets the locked ex_ssl
0.3.0 state layout; production code uses only its public transport operations.

## Earlier round (historical evidence at 010b0b8)

Base reviewed and fetched: `f5c0fe60393bc8f0570b3f92e04fe45a0aa88ceb`
(`codex/replace-ssl-with-ex-ssl`). The remote PR had no later commits when work
started. Existing uncommitted fixes were preserved and completed.

Environment: Elixir 1.18.5, Erlang/OTP 28 (ERTS 16.4.0.5), Linux; Go 1.26.6
for the vendored E2E server (the workflow requires Go 1.22+).

### Application build failure

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

### Dependency and transport contract

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

### HTTP/2 response/close ordering

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

### Final local validation

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

### Remaining limitation and diagnostic failures

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
