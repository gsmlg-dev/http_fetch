# HTTP/2 stream clients validation

Work is in progress. No new EventSource/WebSocket HTTP/2 acceptance or release
is claimed by this baseline record. Historical Fetch evidence is preserved in
`http2-production-validation.md` and its archives.

## P0 baseline

Source: `b5d17bfe3a6be9fbb20a3f3c185dc36773b9f367`, v0.15.1;
checkout and fetched `origin/main` matched (0/0 divergence).
Elixir 1.18.5, OTP 28 / ERTS 16.4.0.5. Locked published dependencies include
ex_ssl 0.7.2 and elixir_quic 0.3.0. Commands run at the umbrella root:

```sh
MIX_BUILD_PATH=/tmp/http-stream-clients-baseline-build MIX_ENV=test mix deps.get --check-locked
MIX_BUILD_PATH=/tmp/http-stream-clients-baseline-build MIX_ENV=test mix compile --warnings-as-errors
MIX_BUILD_PATH=/tmp/http-stream-clients-baseline-build MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test apps/http_event_source/test apps/http_web_socket/test --seed 342781 --max-cases 8
```

All three commands passed. Raw baseline output is temporarily collected at
`/tmp/http-stream-clients-evidence/p0/baseline-tests.log`; it will be included in
the accessible final evidence archive. A first default-build attempt failed on
stale cached 0.11.0 app metadata; a relative build-path attempt failed because
child dependency paths resolve relative to different project roots. Neither is
counted as a source test failure or silently treated as a passed gate.

## P1 extraction and bodyless stream contract

Seven independently constructed packages passed original Hex metadata audits.
Four isolated consumers declared only their selected top-level client(s): Fetch,
SSE, WS, or all three. Temporary extracted shared dependency paths were rewritten
after auditing original metadata; no developer umbrella code path, hidden Fetch,
or direct ex_ssl dependency supplied startup. Standalone SSE/WS had no HTTP or
HTTP.Telemetry module visible. All three shared supervision children and their
PIDs survived individual client application shutdown. This proves distribution
and supervision, not new SSE/WS H2 traffic.

```sh
ERL_FLAGS='+S 2:2' bash scripts/http_runtime_consumer_gate.sh
MIX_BUILD_PATH=/tmp/http-stream-clients-p1-build MIX_ENV=test mix compile --warnings-as-errors
MIX_BUILD_PATH=/tmp/http-stream-clients-p1-build MIX_ENV=test mix test apps/http_core/test apps/http_fetch/test apps/http_runtime/test apps/http_event_source/test apps/http_web_socket/test
MIX_BUILD_PATH=/tmp/http-stream-clients-p1-build MIX_ENV=test mix credo --all
MIX_BUILD_PATH=/tmp/http-stream-clients-p1-build mix format --check-formatted
```

All commands passed. The final scoped suite passed 655 tests and 20 doctests
(seed 903949), with three existing gated core skips. Runtime has 22 passing tests including the compatible
telemetry contracts; h2c generation-qualified DATA, independently encoded credit
and PING barriers; out-of-order, duplicate and unknown delivery references;
same-connection sibling cancellation; owner/subscriber death; stalled TLS dialing
cancellation; accepted GOAWAY followed by DATA; HEADERS/empty DATA/final DATA EOF
without an extra reset; ACK-delayed EOF release; expired/cancelled queued opens;
exclusive stalled-owner shutdown; and HTTP/1/bodyful pre-admission rejection.
The original F1/F2 suites and all existing scoped core/Fetch/SSE/WS tests passed.
The only changed historical test seam is the pool's supervising application.

P1 remote Test run `36753921036` passed. CI run `36753920980` failed on four
new Dialyzer warnings: three deliberately discarded pool cancellation results
and the pool registration API's inaccurate `:ok`-only return specification.
A follow-up repair explicitly matches discarded results and documents the
existing registration errors without changing pool algorithms or adding ignores.
It also preserves explicit infinite opening timeouts at the stream/dialer
boundary, using the pool's existing nil-deadline contract. Two new cancellation
regressions first reproduced the arithmetic failure; finite and infinite stalled
TLS dialing now settle on close/subscriber death.

An isolated P1-plus-repair source export passed strict compilation, formatting,
47 runtime/F1/F2 tests, and Dialyzer (four existing skips, zero new warnings).
Logs are `p1/repair-{compile,regressions,dialyzer}.log`; P2 work was excluded from
this repair snapshot. Remote CI for the follow-up remains pending until pushed.

Logs are collected under `/tmp/http-stream-clients-evidence/p1/`, including failed
intermediate attempts and successful final reruns. Independent source review
found and closed cancellation, EOF and GOAWAY issues before this phase's commit;
no accepted Fetch algorithm or regression assertion was disabled. Final-source
acceptance and all new client/independent traffic workloads still require P2–P5.

## P2 EventSource and byte-stream lifecycle

P2 passed 700 scoped tests and 20 doctests, seed 342781, with the three existing
gated core skips. Strict compile, formatting, Credo and Dialyzer passed (four
intentional Dialyzer skips, no new warnings). The scopes were core, runtime, Fetch,
EventSource and WebSocket; Fetch F1/F2 assertions and algorithms were preserved.
New raw-wire/lifecycle tests cover headers/MIME/204, UTF8/BOM/CRLF, empty cursor,
above-window events, total bytes/parts, ACK pause/order/idempotence, EOF/reset,
redirect credentials/downgrades/limits, cancellation/owner death, stale timers,
and accepted events before parser-fatal shutdown.

The 18 independent cases all passed: hyper-h2 and Node, each over h2c, OTP `:ssl`
TLS and explicit `:ex_ssl` TLS, each in SSE, faults and mixed modes. Every case
required both public workload and independent wire-audit PASS markers and zero
runtime task errors/timeouts. SSE mode delivered exactly 10,000 ordered events
with forced cursor resumption, above-window event assembly and bounded ACK pause.
Faults verified exact abrupt reset and accepted GOAWAY/replacement semantics.
Mixed mode independently observed three SSE streams plus 100 Fetch requests on
one connection, then surviving siblings after cancellation. Two supplementary
1,001-attempt churn cases proved exactly 1,000 reconnects per peer, ordered IDs
and cursors, one connection, and zero final streams/reservations/workers.

```sh
MIX_BUILD_PATH=/tmp/http-stream-clients-p2-build MIX_ENV=test mix compile --warnings-as-errors
MIX_BUILD_PATH=/tmp/http-stream-clients-p2-build MIX_ENV=test mix test apps/http_runtime/test apps/http_event_source/test apps/http_fetch/test apps/http_core/test apps/http_web_socket/test --seed 342781 --max-cases 8
MIX_BUILD_PATH=/tmp/http-stream-clients-p2-build MIX_ENV=test mix format --check-formatted
MIX_BUILD_PATH=/tmp/http-stream-clients-p2-build MIX_ENV=test mix credo --all
MIX_BUILD_PATH=/tmp/http-stream-clients-p2-build MIX_ENV=test mix dialyzer --format short
# Repeat each mode for both peers and all routes; TLS adds --tls --backend ssl|ex_ssl.
python scripts/http2_stream_clients_gate.py --peer hyper-h2 --mode sse
python scripts/http2_stream_clients_gate.py --peer node --mode faults
python scripts/http2_stream_clients_gate.py --peer hyper-h2 --mode mixed
python scripts/http2_stream_clients_gate.py --peer hyper-h2 --mode churn --count 1001
python scripts/http2_stream_clients_gate.py --peer node --mode churn --count 1001
```

Use a Python environment installed from `scripts/requirements-http2-stream-clients.txt`;
peer versions were h2 4.2.0/hpack 4.1.0/hyperframe 6.1.0, Node 24.19.0/nghttp2
1.69.0. The exact matrix commands and each log checksum are in the archive.
Its 240 executable/config/fixture files were invariant across workloads at
SHA256 `f9272c1a897d783dc09acc096192b0e93e3be3390e137578b20a986d999c0990`;
638 prepared BEAMs were invariant at
`78a786c094c102897ba6a1541ebf18c2c51fd1026ae93015a06d8e159b7f3593`.
HEAD was `c4ddad58` plus the included, individually hashed P2 source. Documentation
and evidence were added afterward; P5 will freeze the final executable candidate.

Finite per-process acceptance limits: owner/session/stream memory 8 MiB each;
referenced binaries 2/4/4 MiB; active mailbox 256 each (quiescent owner 16);
four owners/eight workers. Default parser/event is 1 MiB/16,384 parts, line 64 KiB;
ACK delivery 2 MiB/64 messages. Raw input reserves its profile receive window
in addition to a 1 MiB safe-admission allowance, with 128 retained chunks.
Legacy overload and excessive retained chunk counts terminate explicitly.
Samples at opening, every 500 events, pause barriers and quiescence observed:

| Process | Maximum memory bytes | Maximum referenced binary bytes | Maximum mailbox |
| --- | ---: | ---: | ---: |
| Owner | 198,472 | 383,136 | 64 |
| SSE | 1,812,928 | 782,174 | 31 |
| Stream worker | 110,664 | 511,733 | 6 |

These are sampled maxima, not continuous peaks. Assertions enforced the frozen
limits. DATA credit returns on bounded raw/parser admission; delivery ACKs are
separate. Valid queued events survive transport and parser terminal errors.
Opening/reconnect/idle/worker events have attempt tokens; finite idle pauses during
local ACK backpressure. New shared stream telemetry uses bounded labels/numeric
counters; existing Fetch and EventSource event prefixes remain compatible.

Source-derived red evidence identified infinite-opening arithmetic, blocking EOF
settlement behind a stalled owner, same-batch DATA/reset loss, parser-fatal loss of
accepted deliveries, and TLS frame-count pressure. The byte-stream path now packs
safe raw input and coalesces adjacent pending DATA under pressure without raising
event/parser limits. Fetch does not opt into this new byte-stream delivery policy.
Fixture failures and their repairs remain distinct from these production defects.

Accessible evidence:
[`p2-f9272c1a897d.tar.gz`](http2-stream-clients-evidence/p2-f9272c1a897d.tar.gz),
SHA256 `382434321fd4e8a4f64e199cb4a6d902ebb88ef446ff0adf99e5435b8d915dc0`.
The archive contains source files, exact commands, seeds, peer/wire logs, budgets,
completion markers, selected red reproductions and `MANIFEST.sha256`.

P1 follow-up remote Test `36758709094` and CI `36758708788` passed at `c4ddad58`.
P2 CI run `36763526295` at `708ca13f` passed quality/package jobs but failed the
published ex_ssl lifecycle gate: the new HTTP/1 opening timer reported
`:opening_timeout` instead of the established `:timeout`. The repair retains
`:timeout` for HTTP/1, including a held TLS handshake, and `:opening_timeout` for
HTTP/2. Three deterministic regressions cover both protocols and worker cleanup;
the scoped EventSource suite passed 63 tests, seed 785226, plus strict root
compilation, owned-file formatting and scoped Credo.

The full published ex_ssl consumer rerun then exposed an older policy fixture's
assumption that incompatible SSE ALPN always creates a client process. P2 now
rejects contradictory ALPN at construction, as required. The SSE-only gate
adaptation warms an authenticated ticket, asserts exactly
`{:error, :incompatible_alpn}`, and uses a message barrier followed by independent
listener checks to prove zero connection attempts. Trust/hostname failures and
all Fetch/WebSocket handshake assertions remain unchanged.

```sh
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-pool-build mix test apps/http_event_source/test
EX_SSL_RESULTS_DIR=/tmp/http-stream-clients-p2-ci-published-results-final EX_SSL_GATE_TIMEOUT_SECONDS=900 scripts/ex_ssl_published_feature_gate.sh
```

The full published consumer gate passed all nine groups (76 tests, seed 36), using
Hex ex_ssl 0.7.2 and its pinned fixture/checksum provenance. Repair logs are
`/tmp/http-stream-clients-p2-ci-{lifecycle-red,sse-final,published-gate,published-gate-final}.log`;
the sanitized report is
`/tmp/http-stream-clients-p2-ci-published-results-final/ex_ssl_feature_gate-published.txt`.
The existing P2 archive predates these repairs; P5 must freeze and revalidate the
final source. Remote CI for the repairs remains pending. Release and production
rollout have not occurred; full Fetch 42-gate and mixed 1,800-second acceptance
remain P5.

## P3 Extended CONNECT and duplex runtime

The pure core models peer `ENABLE_CONNECT_PROTOCOL`, including invalid values and
1-to-0 reversal within one SETTINGS frame. Only peer permission allows Extended
CONNECT. New immutable stream purpose keeps accepted tunnels duplex while the
original ordinary Fetch F1/F2 paths retain their cleanup/admission algorithms.
Successful 2xx tunnels ignore ordinary Content-Length/body-forbidden semantics;
rejected responses remain ordinary and deny outbound tunnel DATA.

Generation-qualified runtime writes allow one bounded pending write, report
transport progress, and share the existing owner scheduler with Fetch uploads.
The opening task remains cancellable while waiting for SETTINGS, admission, or
zero DATA credit. Ordered remote EOF does not release a tunnel until local end
and receive settlement. Raw tests prove empty write completion, zero-credit
half-close, rejection, byte/count admission, and sibling completion plus HTTP/2
PING and cancellation while a tunnel is parked.

Parent verification (absolute isolated build, root Mix project):

```sh
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build mix test apps/http_core/test apps/http_runtime/test apps/http_fetch/test apps/http_event_source/test apps/http_web_socket/test --seed 342781 --max-cases 8
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build mix test apps/http_runtime/test/http/runtime/tunnel_stream_test.exs apps/http_runtime/test/http/runtime/tunnel_capability_test.exs
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build mix compile --warnings-as-errors
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build mix credo
MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build mix format --check-formatted
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build mix dialyzer
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build /tmp/http2-stream-clients-venv/bin/python scripts/http2_stream_clients_gate.py --peer hyper-h2 --mode mixed
MIX_ENV=test MIX_BUILD_PATH=/tmp/http-stream-clients-p3-parent-build /tmp/http2-stream-clients-venv/bin/python scripts/http2_stream_clients_gate.py --peer node --tls --backend ex_ssl --mode mixed
```

All final commands passed on the archived P3 source. The combined run passed
**738 tests plus 20 doctests**, seed 342781, zero failures, three existing gated
core skips: core 274, runtime 59, Fetch 309, WS 33, SSE 63. The targeted tunnel
suite passed 11 tests. The raw capability oracle checks exact CONNECT fields,
absence of prohibited Upgrade/key fields, SETTINGS waiting/cancellation, local
advertisement versus peer permission, later enablement on a reused owner, and
stale-generation isolation. Fifteen pool capability tests include atomic
capability/capacity observation: enabling CONNECT together with zero stream
capacity keeps the waiter queued until a later capacity update.

Both independent mixed routes completed public/wire PASS markers. Each uses
three SSE sessions and 100 Fetch requests with a single-connection oracle and
cancellation/sibling checks; generic runner `count: 10000` metadata is not claimed
as a 10,000-message mixed workload. Dialyzer has zero new warnings and four
intentional existing skips; the profile type was narrowed to its validated policy
without adding an ignore. Source-derived writer-limit and terminal-byte defects
were reproduced before repair. New SETTINGS 8 violations emit connection
PROTOCOL_ERROR GOAWAY; opt-in byte streams preserve DATA preceding that terminal
error. Ordinary Fetch response delivery and F1/F2 behavior remain unchanged.

An independent audit passed its earlier 737-test snapshot and all quality/mixed
checks. Its source-drift records distinguish that snapshot from the subsequent
terminal-byte repair and the final 738-test checks. The archive also retains a
partial-integration run made before the new atomic pool cast was compiled; it is
not counted as a candidate failure or PASS.

P3 provenance: 299 source/config/test/fixture files, source manifest SHA256
`35b9337f671f3e35b6687fdf2d3e6a22c76b12c5cb713b4eef6eb91bd977bf73`;
638 BEAM modules, manifest SHA256
`56ed3cd69a7535f7c9c07eba1f2be610323e0256a7b56e1760b4027e29696476`.
Accessible source, commands, red/green logs, audit results and the P2 published
consumer repair report:
[`p3-35b9337f671f.tar.gz`](http2-stream-clients-evidence/p3-35b9337f671f.tar.gz),
archive SHA256 `c6fba63ca09220b9d1068240ea2e063d38aaaa046068259926719e48e5b873ce`.
This is P3 evidence; WS adapter and final frozen-release acceptance remain P4/P5.

## Remaining acceptance status

| Family | Status | Evidence required |
| --- | --- | --- |
| A0 | P1/P2 PASS | Extraction/F1/F2 and standalone startup; WS traffic pending |
| A1–A3 | P2 PASS | SSE wire/lifecycle/bounds, six peer/backend routes |
| B1 | P3 core/runtime subset PASS | Capability/header/tunnel policy; public WS handshake pending |
| B2–B3 | NOT RUN | Public WS duplex, frame/delivery/flow/close bounds |
| C1–C3 | SSE/Fetch subset PASS | WS mixed connection/sibling/isolation pending |
| D1–D2 | SSE/runtime subset PASS | WS backend traffic and final package closure pending |
| D3 | NOT RUN | Frozen full/static/interop/churn/30-minute soak, 42 Fetch gates |

Finite acceptance budgets and sampled maxima will be recorded before workloads;
an explicit completion marker and >=1,800,000 ms are required for soak PASS.
Local acceptance, remote CI, package publication and production rollout are
separate outcomes. P1/P2 remote status and P2 local repairs are recorded above;
P3–P5 remote CI and publication are NOT RUN.
