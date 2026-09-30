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

## Remaining acceptance status

| Family | Status | Evidence required |
| --- | --- | --- |
| A0 | P1–P4 PASS | Extraction/F1/F2 and standalone startup/traffic |
| A1–A3 | P2 PASS | SSE wire/lifecycle/bounds, six peer/backend routes |
| B1 | P3/P4 PASS | Core and public capability/header/handshake/fallback |
| B2–B3 | P4 PASS | Public WS duplex, frame/delivery/flow/close bounds |
| C1–C3 | P2–P4 PASS | Shared mixed connection, sibling and existing isolation/capacity tests |
| D1–D2 | P4 PASS | Three WS routes and isolated seven-package traffic closure |
| D3 | NOT RUN | Frozen full/static/interop/churn/30-minute soak, 42 Fetch gates |

Finite acceptance budgets and sampled maxima will be recorded before workloads;
an explicit completion marker and >=1,800,000 ms are required for soak PASS.
Local acceptance, remote CI, package publication and production rollout are
separate outcomes. P1/P2 remote status and P2 local repairs are recorded above;
P3 remote status is recorded above; P4/P5 remote CI and publication remain pending.
