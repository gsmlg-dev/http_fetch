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

## P4 — public WebSocket adapter and independent traffic

The final app source uses the shared tunnel Stream API and preserves HTTP/1 as
the default. Strict h2/h2c requires peer SETTINGS 8 permission. WSS `:auto` allows
one separate HTTP/1 attempt only for ALPN/capability unavailability before
establishment, within the same opening deadline. Authentication, TLS identity,
malformed response and established-session failures do not downgrade or replay.
Actual negotiated version and fallback are exposed separately from subprotocol.

ACK delivery, parser/raw retention, application/control send queues and fragment
counts are finite. Controls follow a partially transmitted frame; closing drops
queued application frames and prioritizes Close. Clean H2 closure requires a real
masked WebSocket Close exchange and both stream directions ending. END_STREAM
without peer Close remains 1006 locally; 1006 is never transmitted. Idle uses this
stream's activity and pauses for deliberate ACK pressure. Runtime and owner death
settle reservations. New bounded runtime telemetry retains legacy client events.

Independent audit commands used `ERL_FLAGS='+S 4:4' MIX_ENV=test` and an absolute
isolated build. `mix deps.get --check-locked`, strict compile, full seeded tests
(`342781`), format, Credo and Dialyzer all passed: **834 tests + 20 doctests**,
three existing gated core skips, and four existing intentional Dialyzer skips.
Per-app tests: core 274, HTTP3 30, runtime 59, Fetch 309, WS 75, WebTransport 24,
SSE 63. Preserved Fetch F1/F2 assertions passed.

The pinned hyper-h2 4.2.0/wsproto 1.2.0 peer verified CONNECT headers, masking,
duplex data, Close and END_STREAM independently. Executed phase routes:

| Workload | h2c | TLS `:ssl` | TLS `:ex_ssl` |
| --- | --- | --- | --- |
| 10,000 text/binary round trips + 131,072-byte binary | PASS, 421,813 ms | PASS, 423,593 ms | PASS, 429,503 ms |
| Two SSE + three WS + Fetch, ACK pressure and sibling progress | PASS | PASS | PASS |
| Capability, handshake/frame errors, reset/GOAWAY, both zero windows and shrink/resume | PASS | PASS | PASS |
| 1,000 actual open/echo/clean-close cycles | PASS, 85,321 ms | NOT RUN | NOT RUN |

Every gate has separate public-workload and wire PASS markers. Each echo sends
10,001 messages including its extra large binary. Generic mixed/fault `count`
metadata is not a 10,000-operation workload. Earlier launches preceded final
masking/telemetry/fixture changes; P5 must rerun the frozen candidate. The final
audit repeated h2c mixed/faults and SSE hyper-h2 mixed/faults. The last WS fault
rerun used explicit post-Open barriers for malformed/oversized/fragment-limit
input, retaining all negative assertions. Initial failed fixture observations are
preserved rather than counted as PASS.

`scripts/http_runtime_package_traffic_gate.py` passed seven original package
metadata audits and four isolated consumers declaring only their selected
top-level client(s). The peer observed four actual h2c connections; the combined
consumer shared one connection across all three clients. Live WS traffic and SSE
state survived Fetch application stop/restart with unchanged runtime PIDs. No
direct hidden Fetch or ex_ssl dependency was added.

Frozen WS gate budgets: four owners, eight stream workers, eight owner-monitor
workers, 8 MiB process heap, 4 MiB referenced binaries, mailbox 256, receive/send
queues 1 MiB, 64 delivery events, 16 application/control frames, raw bytes 1 MiB.
Defined smaller ACK-pressure limits were also asserted. A blocked-send sample
exposed 16,365,544-byte heap allocation from per-byte masking lists; the regression
and binary-word repair passed without raising budgets or forcing GC. Samples
include owner/session/stream/monitor processes and distinguish sampled maxima
from continuous peaks. Gate cleanup requires zero logical/protocol streams,
reservations, admissions, workers and monitor processes.

P4 evidence: final 310-file source manifest SHA256
`cecefd585d5ecb49fc28a5f457355c3421a4471ec81c791eb92c3d468d129199`;
646 unchanged BEAM files, manifest SHA256
`501374fadb0eadb178b0fee28bf79a617d2e607a0ed4c68906cfa532a56cdab5`.
The archive documents earlier five-path runner/fixture drift with no app drift,
contains source, red/green/audit logs, seeds, wire records and checksums:
[`p4-cecefd585d5e.tar.gz`](http2-stream-clients-evidence/p4-cecefd585d5e.tar.gz),
SHA256 `a356bffa2592adc84c3a07b3add60e98c7d635407c71ce988074eac08aa199f0`.
Short soak checks are marked `acceptance:false`; they do not prove 30-minute
acceptance. The second full mixed Node peer and final frozen workloads remain P5.

Remote P2 repair CI/Test passed (`36767141810`, `36767141833`). P3 CI passed
(`36770202018`); its Test run (`36770201727`) failed an existing active-once
peer-close race. P4 adds an explicit peer-close ordering barrier without changing
the transport assertions. P4/P5 remote outcomes and publication remain pending.

## P5 entrypoint and candidate preparation

Version metadata and all shared dependency requirements are frozen at 0.16.0.
The executable runner preserves the original 42 Fetch gates and adds 36 new
gates: 20 SSE routes/churn, 12 WS echo/fault/mixed routes, WS churn, isolated
package traffic, documentation generation and the genuine mixed soak. Both
independent H2 servers now observe all three client types on one connection.
The new Node fixture passed h2c and both TLS routes during preparation; its
ordinary GET responses wait for the explicit request end before responding,
preventing a fixture-generated premature NO_ERROR reset. No client reset assertion
was weakened. Original phase SSE churn had 1,000 opens (999 reconnects); final
churn uses 1,001 opens per independent peer to prove 1,000 actual reconnects.

From the root clone, prepare the pinned peers and export the executable candidate:

```sh
MIX_ENV=test mix deps.get --check-locked
python3 -m venv /tmp/http2-peers
/tmp/http2-peers/bin/pip install -r scripts/requirements-http2-stream-clients.txt
candidate_tree=$(git rev-parse 'HEAD^{tree}')
candidate_source=$(mktemp -d /tmp/http2-candidate.XXXXXXXX)
git archive "$candidate_tree" | tar -x -C "$candidate_source"
ERL_FLAGS='+S 4:4' /tmp/http2-peers/bin/python \
  "$candidate_source/scripts/http2_stream_clients_acceptance.py" \
  --source "$candidate_source" --repository "$PWD" --tree "$candidate_tree" \
  --evidence /tmp/http2-final-acceptance
```

Use the pinned Node 24.19.0/nghttp2 1.69.0 environment. The evidence directory must
not already exist. Source blobs and added executable files are checked before and
after gates; builds/logs are outside the source export. ExDoc runs in a separate
development build. Both 30-minute workloads run alongside finite gates. A failed
or interrupted command cannot produce an acceptance PASS. The manual
`HTTP2 Stream Clients Acceptance` workflow runs this same entrypoint and uploads
logs, results, commands and source manifests.

P4 remote Test passed (`36778732987`). CI (`36778733087`) failed the older WSS
published ex_ssl ALPN-policy fixture, which expected a socket after an incompatible
constructor input. A surgical fixture repair now asserts the exact
`:incompatible_alpn` constructor error and independently zero connections after
ticket warming. Trust, hostname, Fetch and ticket-identity assertions remain
unchanged. The full published ex_ssl gate passed nine groups/68 tests using
published ex_ssl 0.7.2 with both pinned checksums; final-source acceptance reruns it.

The exported final executable candidate, all full acceptance outcomes, archive
checksum, final remote CI and release verification will be recorded after execution.
No short preparation check is claimed as final acceptance or publication.

The first P5 executable candidate was commit `9d2f6fb`, tree
`d541635d31beeb6867b78c57b6418db53ed59698`. Its frozen full regression run passed
834 tests plus 20 doctests, and remote CI/Test passed (`36780516073`,
`36780515935`). Full acceptance failed: the Node SSE oversized-event fixture sent
terminal input before the gate queried the current negotiated-version accessor
after Open. The three Node SSE routes failed that assertion. The run was then
interrupted; unfinished workloads, including both soaks, are NOT RUN. This
candidate is not accepted for release. The failure and interruption logs are
retained with final evidence; the repaired fixture requires a new frozen run.
The repair adds explicit post-Open controls for oversized input and the legacy
semantics EOF case. It retains protocol checks, exact input bytes and terminal
assertions. All six peer/backend SSE routes and both fixture self-checks passed
before refreezing; no application runtime source changed.

## P5 frozen candidate — accepted executable results

Executable candidate: commit `d99b9de655b3367c91eea0d59af14cc4b0afa7a7`,
Git tree `01dd03d447f709b27dea32f74d95050edadfbc18`. The complete tree was exported
outside the checkout. Each gate verifies tracked blobs and rejects added
executable files. Both isolated test builds contain 646 BEAM files, unchanged
after all finite gates. Subsequent evidence/documentation commits must preserve
the executable source of this candidate.

Finite results: 834 tests plus 20 doctests, zero failures, three existing gated
core skips; strict compile, format, full Credo, HPACK, preserved F1/F2/runtime
regressions, three seeded Fetch repeats, documentation generation and Dialyzer
passed. Dialyzer retains four existing intentional skips and no unnecessary skips.
The published ex_ssl consumer/provenance suite passed. Seeds and complete commands
are retained in the final ledger and logs.

Both independent peers passed all SSE routes/modes on h2c and TLS with OTP `:ssl`
and explicit `:ex_ssl`: six 10,000-event runs with forced reconnect, plus 1,001
opens/1,000 actual reconnects per peer. The EOF/Open counts are asserted by the
frozen gate contract and corroborated by ordered wire cursors/ranges. Final SSE
quiescence combines the gate's settle assertions and its owner-only resource
sample; the log does not print a separate EOF counter or quiescent flag.

WebSocket echo passed 10,000 round trips plus a 131,072-byte binary on h2c
(421,635 ms), TLS `:ssl` (425,705 ms) and TLS `:ex_ssl` (430,171 ms). All three
routes passed hyper-h2/wsproto mixed/fault gates and the independent Node mixed
gate. Churn passed 1,000 actual open/echo/clean-close cycles (93,343 ms).
All six original Fetch reuse runs passed 10,000 requests at peer limits 1/2/100.

Seven local packages and four isolated top-level consumers passed metadata,
dependency/startup and real H2 traffic checks. The combined consumer shared one
connection and preserved live SSE/WS across Fetch stop/restart. Remote candidate
CI passed (`36781638609`, 14 jobs), as did Test (`36781638418`, seven app jobs).
Both genuine soaks passed, with separate completed-workload and wire markers:

| Workload | Actual active duration | Completed traffic | Final cleanup |
| --- | --- | --- | --- |
| Mixed TLS `:ex_ssl`, hyper-h2/wsproto | 1,800,103 ms | 3,285 WS messages, 3,288 SSE messages, 1,643 Fetch requests | Zero logical/protocol streams, reservations, admissions, workers, monitors and sessions |
| Fetch TLS `:ex_ssl`, Node/nghttp2 | 1,800,161 ms | 61,712 requests | Zero active/protocol streams and reservations |

The mixed run completed separate slow-consumer, actual cancellation and GOAWAY
draining intervals; wire accounting includes the canceled session. It retained
two SSE and two WS sessions while Fetch progressed and explicitly replaced
sessions after draining. Its 1,650 resource samples had maxima of 198,136-byte
process heap, 538,549-byte referenced binaries and mailbox 12. Eligible idle
connection owners may remain after all logical clients settle.

Across all new-client gates, SSE sampled owner/session/stream heap maxima were
199,744 / 1,805,528 / 110,424 bytes; referenced binaries were 363,984 / 1,169,575 /
487,229 bytes; mailbox maxima were 64 / 39 / 5. Owner monitors peaked at 2,816-byte
heap and zero referenced binaries/mailbox. All WS gates together sampled maxima
of 199,000-byte heap, 1,015,587-byte referenced binaries and mailbox 12. The finite
budgets printed before workloads passed for every recorded sample. These are
sampled maxima, not continuous peaks or bounds on unrelated owner messages.

The final auditor passed all 42 Fetch ledger entries and 36 new gate results,
plus preparation/wrapper records. It checked workload sizes, both elapsed-time
markers, protocol/peer evidence, budgets, final settling and log/source hashes.
All 357 source-manifest entries match; manifest SHA256
`74a2ba91db427b70965d1a4a1ddfbe68de5effe94b88a5bb96896c14077777fd`.
Both 646-file BEAM manifests remained unchanged through all soaks: clients
`f1be7ea630295a7626525e5691efce3350356e4f178636ae852a3507ebcf4c81`,
Fetch `ccf43bf9477f6624f8440b1d2c5b68606d8de090f9a904d622ce6ca013705031`.

Accessible exact source, raw logs, commands, result ledgers, peer/toolchain
versions, independent audit, failed-candidate/repair evidence and checksums:
[`p5-01dd03d447f7.tar.gz`](http2-stream-clients-evidence/p5-01dd03d447f7.tar.gz),
archive SHA256 `e10829e0ba1cf47c50f5e204b931eb89d437a4a1020f69e1e91f5ff705ab46e3`.
Release verification is recorded separately below after publication.

## Historical candidate acceptance status

| Family | Status | Evidence required |
| --- | --- | --- |
| A0 | P5 PASS | Extraction/F1/F2 and standalone startup/traffic |
| A1–A3 | P5 PASS | SSE wire/lifecycle/bounds, six peer/backend routes and two actual reconnect churn runs |
| B1 | P5 PASS | Core and public capability/header/handshake/fallback |
| B2–B3 | P5 PASS | Public WS duplex, frame/delivery/flow/close bounds, three echo routes and actual cycles |
| C1–C3 | P5 PASS | Two independent shared mixed peers, sibling/isolation/capacity tests, full mixed soak |
| D1–D2 | P5 PASS | Three transport routes and isolated seven-package traffic closure |
| D3 | P5 PASS | Frozen full/static/interop/churn, both genuine 30-minute soaks and 42 preserved Fetch gates |

Implementation and local acceptance are complete. Candidate remote CI/Test passed.
The manual slower acceptance workflow is available but was not dispatched; the
complete local archive supplies final executable evidence. Publication checks are
pending at this evidence commit. Production rollout has not been performed.

The evidence-only commit `3abfbe1` passed CI (`36785324372`) but its separate Test
run (`36785324392`, seed `965078`) found a task-baseline fixture race in
`HTTP.HTTP2FailedOpenCleanupTest`: an unrelated pre-existing task was present
before the failed POST and had exited at the final exact-set comparison. The
current child set was empty; this observation does not show a leaked failed-POST
task. Release attempt `36785324660` passed its own full unit suite and Credo but
was canceled during validation before package publication. The fixture requires
an explicit task-settlement barrier, followed by a new frozen acceptance run.
The preceding archive remains the accepted `d99b9de` evidence; it is not evidence
for the forthcoming fixture change or a completed release.
The test-only repair waits for the monitored initial task set, explicitly
monitors the failed Promise task to normal termination, and settles the final
task set before the unchanged equality assertion. Pool, owner, bridge and sibling
assertions remain intact. The scoped fixture and complete Fetch suite passed
seeds `965078` and `342781` (309 tests plus 20 doctests each); format and Credo
passed. No runtime/application source changed. The repaired source is frozen for
a complete new acceptance run before another release attempt.

Repair candidate `cac815f`, tree `f3e70158648bb7ea2570de44706c1f5eef012e16`,
passed remote CI (`36786347089`, all 14 jobs) and Test (`36786347028`, all seven
apps; Fetch seed `788851`). Its fresh local full tests and three Fetch repeats
also passed, but Fetch42's packaged ex_ssl prerequisite failed before traffic:
Hex 2.4.0 returned `{:error, :eaccess}` while concurrent consumers persisted the
shared registry `cache.ets`. The run was interrupted and unfinished workloads,
including both soaks, are NOT RUN. This tooling failure is retained; it does not
establish final acceptance. Per-gate isolated Hex homes avoid sharing this mutable
cache without changing any workload, protocol assertion or application source.
The isolation repair passed fresh-home dependency setup and strict compilation,
then both packaged TLS gates concurrently (82 package tests each and explicit
public traffic PASS). The workload inventory and source/interruption guards are
unchanged. A complete new frozen run follows this runner-only change.

Cache-isolated candidate `e82f398`, tree
`d675aa795801cb592ff65684fafcf180cf1c5896`, passed remote CI (`36787203401`)
and Test (`36787203414`), plus both concurrently packaged TLS prerequisites.
Its external-consumer gate then timed out waiting for HTTP/1 WebSocket Open;
the helper discarded non-Open events, so the initial log did not identify the
backend or terminal reason. The peer sends its upgrade and message before
immediate TLS close. The incomplete run was interrupted and both soaks remain
NOT RUN. The failure requires explicit diagnostics and opening/handoff
investigation before selecting a fixture or runtime repair. The cache issue did
not recur, and no failure is counted as accepted traffic.

The H1 diagnosis reproduced two adapter defects with real TLS and deterministic
process barriers: a valid 101 response plus frame was discarded when ex_ssl
terminated after passive recv but before ownership transfer; separately,
transferred DATA/EOF could be processed before the opening worker result.
Installed published ex_ssl 0.7.2 preserves plaintext on normal authenticated peer
EOF; its recv can return final bytes and then terminate. This does not establish
an upstream data-loss bug. The adapter preserves validated handshake bytes on
terminal transfer, prepends those bytes to later staged input and defers parsing
and terminal delivery until the opening result. Staging retains existing finite
raw-byte/count bounds; opening deadline, local close and owner death remain
effective. EOF without a WebSocket Close stays abnormal (local code 1006).
The external-consumer helper now reports exact backend/event failures instead of
discarding its own socket's errors. The peer still closes immediately after
sending the upgrade and message. A new whole-source acceptance run is required
for this runtime change before release.

Independent review also found the closed-transfer branch must retain its closed
transport handle while parsing buffered control frames. A deterministic valid
Close fixture reproduced a nil-transport crash in the first repair draft. The
final branch retains the handle and uses the existing HTTP/1 closed-send policy,
preserving complete peer-Close classification and abnormal EOF classification.
This is separate from H2 END_STREAM, which still cannot manufacture a clean WS
close. The original fixture sends immediate TLS EOF unchanged.

Before freeze, root-scoped WebSocket tests passed 82 tests, zero failures, seed
342781. Parent independently reran the same suite on the final source and the
fresh-home seven-package external consumer (OTP ssl and published ex_ssl H1 TLS
traffic); both exited zero. Strict test compilation, root format and full Credo
passed. Test cleanup now waits for exact session/worker DOWN outcomes inside the
barrier before idempotent emergency cleanup, avoiding a resume-vs-exit race.
Deterministic original red (four tests/two failures), buffered-Close draft red
(eight tests/one failure) and final green evidence are retained separately from
the required upcoming 78-gate run. No production runtime outside the WebSocket
H1 seam changed; Fetch F1/F2 assertions and all workload thresholds remain intact.

The final requirement audit found the H2 SSE idle contract needed an explicit
regression beyond the existing H1 activity and H2 ACK-pause cases. The added
raw-wire test proves a comment heartbeat replaces the stream's idle token;
connection PING/ACK and a completed Fetch sibling on the same connection leave
that token unchanged. Injecting the current deadline token produces the exact
idle error/reset while the shared owner survives. No sleep or elapsed-time claim
is used. The H2 file passed 11 tests, independently rerun by the parent; the full
SSE suite passed 64 tests, seed 342781. Runtime source did not change. README now
documents accepted H2 uploads, all seven package artifacts, and the existing
TLS-auto scope/reuse profile restriction. A new whole-source candidate includes
this test and these corrections; da7adbb's incomplete run remains preparatory
evidence, with unfinished soaks NOT RUN.

Candidate 4ef1358, tree 83c954e405afefe57e3d982e408df653504f0803, failed
Node's cleartext SSE mixed gate: `/control/held` returned three entries after
local cancellation where the gate required two. The capture records the control
request before the peer's cancellation callback. This requires a deterministic
peer-observed cancellation barrier; local close is not a remote acknowledgement.
The exact two live siblings, their next ordered events, 100 Fetch requests and
same-connection assertions remain required. This run was stopped cleanly, with
unfinished soaks NOT RUN; it is not accepted. No failure is silently retried.

A raw independent H2 oracle reproduced this ordering deterministically:
control HEADERS then cancellation RST returned three, while RST then control
returned two. The runtime's local close initiates asynchronous owner cleanup;
it does not promise a peer acknowledgement. The repaired fixture adds a bounded
control request for the captured stream ID and requires the peer to observe its
exact CANCEL RST before advancing the existing held-sibling trigger. This
strengthens the wire oracle rather than changing runtime cancellation semantics.

The barrier repair passed all six mixed peer/backend routes, each with public
workload and independent wire PASS. Raw control-before-RST and RST-before-control
oracles both now return exactly two live siblings. Withholding the target RST
fails boundedly on both peers at approximately 10.01 seconds; no successful
barrier is emitted. Parent independently reran the Node cleartext mixed gate
with exact cancellation and zero final workers/monitors. Syntax, script format
and diff checks passed. No runtime source changed. Final acceptance still
requires a new exported candidate and all 78 complete outcomes.

Candidate 1485fd6, tree 6e834f833383292aa6c4f86895dd7906aa301d01, passed
remote CI/Test and the repaired mixed gates, but its scoped preserved Fetch
runtime suite failed: the complete-413 binary-upload fixture timed out waiting
for POST headers after warming its connection (37 tests, one failure). The
full unit suite also passed in this run. This is not accepted or explained by
a blanket retry. The failed run was stopped cleanly; both unfinished soaks are
NOT RUN. F1/F2 assertions and existing deadlines remain intact while the cause
is investigated.

The failure is deterministically reproduced by withholding warm coordinator
release after its 200 response: the pool still has one reservation at the
peer's one-stream limit, and the immediate POST opens a second TCP/H2 socket.
The original single-socket script then times out waiting for that POST. Async
ExUnit tests do not overlap the synchronous global-pool replacement fixtures.
The surgical F1 test repair captures and monitors the exact warm coordinator
before allowing its response, waits for normal termination after reservation
release, and verifies owner quiescence before the tested POST. This establishes
the intended reusable-slot precondition; it leaves early response, blocked
upload, reset, bridge/coordinator cleanup, sibling traffic and stream-ID
assertions unchanged. Runtime algorithms and original deadlines are preserved.

The deterministic original same-socket/stream-3 regression exits nonzero before
the warm barrier and passes afterward with the complete 413/CANCEL and cleanup
contract. Final verification passed nine F1 tests, the exact runtime gate
(core five tests plus Fetch 37 tests), and 309 Fetch tests plus 20 doctests,
seed 342781/max-cases 8. Parent independently reran the exact runtime gate and
confirmed zero failures. Strict compilation, format, Credo and diff checks
passed. Only the F1 fixture changed, with no production-source change. The
newly introduced warm-response wait is bounded by the existing five-second
deadline. A new whole-source acceptance run follows this precondition repair.

Candidate 6ca77f8, tree 1d3bdec76c69039019b3cdcd2e61a26d866d787d, passed
remote CI run 36817563489, but remote Test run 36817563483 failed at the
temporary-owner fixture's default 100 ms startup wait (seed 138478). No owner
initialization error was reported. The local acceptance run was interrupted
cleanly, exit 130; both unfinished soaks remain NOT RUN. Its partial gates do
not establish final acceptance.

The fixture has no 100 ms startup contract. A deterministic private-supervisor
suspension and exact start_child trace reproduces the empty-mailbox failure;
an explicit resume followed by startup and initialization completion passes
the original wire, caller-death, owner-alive and exact child assertions. The
natural original file passed at the remote seed; exact remote scheduler timing
is not claimed reproduced. The repair identifies the startup sender, monitors
that caller before waiting, bounds startup at five seconds, and observes owner
ready status before testing caller death. No runtime source or other receive
deadline changed.

The final source passed 11 scoped tests and 309 Fetch tests plus 20 doctests,
seed 138478/max-cases 8. Parent independently reran the 11 scoped tests.
Strict compilation, formatting, Credo and diff check passed. Deterministic
red/green and remote failure logs are preserved with the preparation evidence.
A new whole-source candidate must pass all 78 gates and remote CI/Test before
release.
