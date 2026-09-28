# Published ex_ssl consumer validation

Validation date: 2026-09-23. Implementation baseline: `http_fetch` commit `b4ad2f5` (0.13.0 release metadata),
following reviewed commit `6a6c93e`. Work is isolated on
`codex/ex-ssl-consumer-validation`. This document records local consumer evidence;
it does not assert a remote CI run, release, or independent security review.

## Runtime and fixture provenance

The latest released dependency was checked through the Hex package API, rather
than inferred from a changelog. Only `ex_ssl` changed in `mix.lock`, from 0.4.0
to **0.5.0**. The production requirement advances to `~> 0.5.0`; it is not widened
to accept arbitrary minor versions. No dependency sources were patched.

| Identity | Value |
| --- | --- |
| Runtime | `hexpm/ex_ssl 0.5.0`, resolved through `Hex.SCM` |
| Hex inner checksum | `4db0eaa5b0d5f3dee2b8a7f5f24d107fc437fc39d12cd3d41a38bbe84760d66b` |
| Hex outer checksum | `5ab2815947d3c76191b50837ad4c14a4e1c23da300623ae63b1c2b722417820c` |
| Fixture repository | `https://github.com/gsmlg-dev/ex_ssl.git` |
| Release fixture commit | `bcb946d40327c68f238df5fd66d945d90f251af4` (peeled `v0.5.0`) |
| Loaded runtime | isolated consumer `_build/test/lib/ex_ssl/ebin/Elixir.SSL.Connection.beam` |
| Local consumer runtime | Elixir 1.18.5 / Erlang OTP 28.5.0.5 |
| Independent peer | Python 3.13.15 / OpenSSL 3.6.3; OTP `:ssl` for policy and closure regressions |

The small `scripts/ex_ssl_fixture_manifest.env` records the immutable fixture
commit and expected Hex version/checksums. Published mode clones that commit or
validates an explicitly supplied `EX_SSL_FIXTURE_DIR`, including the actual Git
blob contents of `signature_fixtures.ex` and `client_auth_fixtures.ex`. Only these
support files are loaded; no ex_ssl runtime source is loaded from the fixture
checkout. The runtime verifier checks the lock tuple, resolved SCM/version,
dependency destination/build, and loaded module location. A same-version path
or Git override cannot pass the published provenance check.

## Three distinct entry points

Run from the umbrella root. Prerequisites are the normal Mix toolchain, Git,
Python 3 linked to OpenSSL with TLS 1.3 and ALPN, the `openssl` executable, and
GNU `timeout`. The gate uses local loopback peers; no external TLS service is
needed. Dependency and fixture acquisition require Hex/GitHub access.

```bash
# A: fresh transitive resolution, no copied umbrella lockfile, no direct ex_ssl dep
bash scripts/external_consumer_smoke.sh

# B: full feature tests of all five fresh packages against locked released Hex
EX_SSL_RESULTS_DIR=/tmp/http-fetch-published \
  bash scripts/ex_ssl_published_feature_gate.sh

# Equivalent compatibility entry point; EX_SSL_SOURCE_DIR is unnecessary here
EX_SSL_DEP_MODE=published EX_SSL_RESULTS_DIR=/tmp/http-fetch-published \
  bash scripts/ex_ssl_source_smoke.sh

# C: explicit isolated source candidate; results cannot satisfy B
EX_SSL_DEP_MODE=source EX_SSL_SOURCE_DIR=/absolute/path/to/ex_ssl \
  EX_SSL_RESULTS_DIR=/tmp/http-fetch-source bash scripts/ex_ssl_source_smoke.sh
```

Mode B uses an explicit test dependency and a copy of the checked-in umbrella
lock; it is **not** cold transitive-only resolution. Mode A retains that separate
packaging proof. Mode C labels source revision, dirty status, loaded module and
version separately; it never changes the production dependency declaration.

The feature gate validates required groups and executes every discovered
`scripts/ex_ssl_*_test.exs` file, including future groups. Each group must execute
at least one test, with zero failures, skips or exclusions. A historical count
of 47 is not hardcoded as an acceptance rule. `EX_SSL_TEST_SEED` defaults to 36;
use a distinct `EX_SSL_RESULTS_DIR` for each seed/mode to retain each report.
`EX_SSL_GATE_TIMEOUT_SECONDS` defaults to 1800. Temporary packages, fixtures,
consumer dependencies/build and certificate TMPDIR are isolated and removed on
success, failure and handled interruption. Only a sanitized summary is exported
before cleanup, without private keys, tickets or TLS secrets.

## Protocol and scenario evidence

Positive resumption requires two distinct TCP/TLS connections to the retained
independent server context: peer `session_reused=false`, then `true`. Response
or frame/event receipt is a barrier after the peer's NewSessionTicket output,
not a timing estimate or a cache inspection. Rejection tests additionally inspect
the second ClientHello for an offered PSK and require `session_reused=false`.
The peer uses a fresh ticket key with identical certificate and TLS policy for
that deliberate rejection; each client performs one application exchange per
connection, without fallback or replay.

| Consumer/scenario | Independent observation and assertions |
| --- | --- |
| HTTP/1.1 resumed/default-disabled/rejected | Two handshakes and complete exact response bodies; default test omits `session_tickets`; rejected second ticket is actually offered |
| HTTP/2 resumed/default-disabled/rejected | Explicit `http_version: :http2`, negotiated h2, 6,291,456-byte Content-Length, bounded 16 KiB DATA, WINDOW_UPDATE on both windows, END_STREAM, public response stream consumed exactly and terminated |
| HTTP/2 early response with pending upload | Original full-handshake regressions retained; two additional resumed variants independently report resumption through OTP `:ssl`, stop unsent upload DATA, and preserve complete 413 responses after authenticated close |
| HTTP/2 cross-record closure | Original truncation/reset/Content-Length/control-write/backpressure/cancellation/deadline regressions retained; resumed early response also spans gated TLS records |
| WSS resumed/default-disabled/rejected | Two separate clients; greeting coalesced with passive Upgrade response, subsequent active-once echo, one application frame, clean close, client process termination and no duplicate delivery |
| EventSource resumed/default-disabled/rejected | Existing automatic reconnect, event id 41, second request Last-Event-ID 41, next event delivered once; backend inherited from application configuration at creation, then global setting changed and restored afterward |
| All four consumer paths: policy | mTLS/TLS 1.2/mixed offers with auto tickets and verify-none produce explicit pre-I/O option errors; warmed tickets cannot bypass changed CA, hostname or incompatible ALPN; no unauthenticated application bytes |
| Resumed setup cancellation/deadline | Peer observes offered ticket then holds handshake; fetch abort/deadline and WSS/SSE connect deadline close the socket before application I/O |
| WSS/SSE owner death during resumed setup | Event owner exits after ticket offer; client terminates within the bounded assertion while server still holds handshake, peer observes EOF, no frame/event request is sent |
| Existing algorithms/mTLS/TLS 1.2 | All original feature scenarios preserved: signature policies, identities, redirects, safe TCP options, independent TLS 1.2 and mixed offers, WSS and SSE lifecycles |

Policy tests intentionally distinguish library policy from consumer propagation:
error rules remain in ex_ssl; these tests reach them through public fetch/WSS/SSE
APIs and verify no socket/application I/O. Policy cache warmups use public fetch
with the same TLS settings and endpoint before exercising the selected family.
They neither inspect a private ticket cache nor replace the library's TLS suite.

## Reproduced defects and changes

The deterministic setup tests initially reported **6 tests, 2 failures** (seed 474284):
WSS and EventSource remained alive after their event owner exited during a
held second handshake. The other cancellation/deadline cases passed. A small
linked `HTTP.OwnerMonitor` now enforces owner lifetime independently of a blocked
connect/Upgrade call. A DOWN message handled only by the blocked connection
would not solve this. The client exits with `:shutdown`; transport ownership
cleanup closes the underlying socket. Separate tests verify that the monitor
also exits on normal connection completion and leaves the event owner alive.
The six setup tests then passed. No ex_ssl engine defect was found or patched.

The existing private HTTP/2 buffer probe's 0.4.0 version guard intentionally
failed 12 baseline tests after the dependency update. Its `closed`, exact
buffer `size` and passive `active=false` assumptions were checked against the
published 0.5.0 implementation before updating the guard. The original 34-test
suite then passed; adding the two resumed variants brings it to 36. The
intermediate `MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs
--only early_response --seed 36` ran 11 tests successfully with 25 deliberately
excluded by that development filter. The final full 36-test runs have no exclusions.

Test development also caught and corrected an immediate-error monitor race
(`:noproc` when a WSS client had already exited before monitoring) and an
independent-peer fixture mistake that accidentally enlarged the old TLS 1.2
response into streaming mode. Existing TLS 1.2 fixtures retain their original
262,144-byte body; only the new resumption streaming mode sends 6 MiB.

## Executed local validation

```bash
mix deps.update ex_ssl
mix deps.get
mix compile --warnings-as-errors
MIX_ENV=test mix compile --warnings-as-errors
MIX_ENV=test mix test --seed 36
mix format --check-formatted
mix credo
mix dialyzer

# After starting the existing Go peer and setting E2E_BASE_URL from its PORT line:
MIX_ENV=test mix test.e2e --seed 36 apps/http_fetch/e2e \
  apps/http_event_source/e2e apps/http_web_transport/e2e apps/http_web_socket/e2e

bash scripts/external_consumer_smoke.sh
for seed in 36 7 91; do
  EX_SSL_TEST_SEED="$seed" EX_SSL_RESULTS_DIR="/tmp/http-fetch-final-published-$seed" \
    bash scripts/ex_ssl_published_feature_gate.sh
done
for seed in 7 91; do
  MIX_ENV=test mix test apps/http_fetch/test/http/socket_client_http2_test.exs --seed "$seed"
done
```

The Go peer was built in `apps/http_fetch/priv/test_server` using `go build -o
server .`, started with a bounded readiness wait on its `PORT` output, and
terminated/reaped in a `finally` block after E2E completion.

| Check | Local result |
| --- | --- |
| Full five-app suite, seed 36 | 448 tests + 20 doctests, zero failures; core 187, fetch 178 + 20 doctests, WSS 33, WebTransport 24, SSE 26 |
| Existing E2E, seed 36 | 58 tests, zero failures; fetch 50, WSS 3, WebTransport 3, SSE 2 |
| Development/test strict compilation | Passed |
| Formatting / Credo | Passed; Credo 118 files, no issues |
| Configured Dialyzer | Passed; four configured ignores, zero unnecessary ignores |
| Cold five-package consumer | Passed with fresh transitive Hex ex_ssl 0.5.0 |
| HTTP/2 lifecycle suite, seeds 7 and 91 | 36 tests per seed, zero failures |
| Full published feature gate, seeds 36 / 7 / 91 | 68 tests per seed, zero failures/skips/exclusions; verified Hex provenance in every run |
| Source-mode runner, seed 36 | 68 tests, zero failures/skips/exclusions; clean source commit `bcb946d40327c68f238df5fd66d945d90f251af4`, separately labeled |

The 68 feature tests comprise algorithms 12, redirects 5, mTLS streams 2, mTLS
11, options 9, resumption 8, consumer policy 8, resumed setup lifecycle 6, and
TLS 1.2 interoperability 7. The original 47 scenarios are retained and expanded;
the gate enforces group execution rather than a forever-fixed count.

Published reports: `/tmp/http-fetch-final-published-{36,7,91}/ex_ssl_feature_gate-published.txt`.
Source report: `/tmp/http-fetch-final-source-36/ex_ssl_feature_gate-source.txt`.
The source-mode command used was:

```bash
EX_SSL_DEP_MODE=source EX_SSL_SOURCE_DIR=/home/gao/Workspace/gsmlg-dev/ex_ssl \
  EX_SSL_TEST_SEED=36 EX_SSL_RESULTS_DIR=/tmp/http-fetch-final-source-36 \
  bash scripts/ex_ssl_source_smoke.sh
```

This source checkout equals the released fixture revision; it validates the
source-candidate runner interface, **not** a new unreleased dependency fix.
No source result is counted as published Hex evidence.

The gate was also exercised with disposable copies and command stubs, without
changing installed dependencies or shared test files:

| Injected gate fault | Observed failure |
| --- | --- |
| Missing required TLS 1.2 test file | Exit 2, explicit missing-group error |
| Group reporting zero tests | Exit 1, failing sanitized report |
| Group reporting an excluded test | Exit 1 |
| PATH lacking Python 3 | Exit 2 before fixture network access |
| Wrong fixture SHA | Exit 2 |
| Modified support blob under the correct checkout HEAD | Exit 2 |
| One-second gate timeout during blocked package build | Exit 143, exported report status 143, no temporary workspace remaining |

Shell syntax, Python parsing and whitespace checks passed. Positional Mix test
arguments are rejected so an extra healthy test file cannot mask a zero-test
required group. Use `EX_SSL_TEST_SEED` rather than test filters for this full gate.

## Changed files

- `apps/http_core/mix.exs`, `mix.lock`, and `scripts/external_consumer_smoke.exs`:
  released 0.5.0 requirement/lock and matching cold packaging assertions.
- `apps/http_core/lib/http/owner_monitor.ex`, its core test, and the WSS/SSE
  connection initializers: owner-lifetime cleanup during blocked setup.
- `apps/http_fetch/test/http/socket_client_http2_test.exs`: revalidated buffer
  probe and independently observed resumed early-response variants.
- `.github/workflows/ci.yml`, `.github/workflows/ex_ssl_compat.yml`: stable
  required published check, compatibility matrix, pinned actions and reports.
- `scripts/ex_ssl_source_smoke.sh`, published wrapper, fixture manifest,
  consumer Mix template, provenance verifier and report helper: three distinct
  modes, isolated builds, immutable fixtures, failure checks and cleanup.
- `scripts/ex_ssl_resumption_test.exs`, policy/lifecycle tests and independent
  Python peer: protocol resumption, negative cases and cleanup evidence.
- Existing algorithms/mTLS/options/TLS 1.2 scripts: fixture-only directory
  imports; their scenarios remain required. `.gitignore` excludes local reports.
- `README.md`, this report, `docs/ex-ssl-consumer-contract.md` and
  `docs/pr-14-validation.md`: current commands, evidence and historical boundaries.

## CI handoff and limits

Require **Published ex_ssl feature gate (Elixir 1.18 / OTP 28)** from `CI`.
It runs for pull requests and main pushes, provisions independent peers, prepares
the umbrella, runs the full locked published gate, and preserves the root HTTP/2
lifecycle regressions. It has a 45-minute job limit in addition to the local gate
limit. Its external actions are pinned to immutable commits and it has only
`contents: read`, with no publishing secrets or `pull_request_target` execution.
Only sanitized `.txt` reports are uploaded, including on failure.

The separate `ex_ssl compatibility` workflow provides bounded scheduled/manual
consumer coverage for Elixir 1.19/OTP 28 and 1.20/OTP 29. Those environments were
**not executed locally or remotely in this task**. No remote workflow was
dispatched, branch protection changed, PR merged, version bumped, tag created
or package released. The existing 0.13.0 release metadata is unchanged.

OTP `:ssl` remains the default; ex_ssl remains opt-in through per-call options
or the captured `:http_core` setting. Its default is still verified TLS 1.3
with resumption disabled. Backend pinning, same-origin mTLS restrictions, no
backend fallback, no uncertain-byte replay and QUIC's separate TLS remain intact.

HTTP selection and TLS selection are independent. Response streaming does not
imply HTTP/2 streaming uploads. There is no new connection pooling, automatic
WebSocket reconnection, TLS 1.2/mTLS resumption, persistent tickets or 0-RTT.
TLS 1.2 results cover the bounded tested OpenSSL ECDHE-RSA AES-GCM cases; other
servers, operating systems and unexecuted runtime pairs are not established.
Independent human security review is incomplete. Green CI is not a claim of
broad production readiness or improved performance. No upstream fix is required
by the reproduced consumer owner-lifetime defect.
