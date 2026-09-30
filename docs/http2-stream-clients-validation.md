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

## Remaining acceptance status

| Family | Status | Evidence required |
| --- | --- | --- |
| A0 | P1 PASS | Extraction/F1/F2 and standalone startup; adapters pending |
| A1–A3 | NOT RUN | SSE wire/lifecycle/bounds and independent peers |
| B1–B3 | NOT RUN | RFC8441 capability, WS duplex, flow/bounds |
| C1–C3 | NOT RUN | Mixed connection/sibling/isolation proof |
| D1–D2 | NOT RUN | New client backend matrix and package closure |
| D3 | NOT RUN | Frozen full/static/interop/churn/30-minute soak, 42 Fetch gates |

Finite acceptance budgets and sampled maxima will be recorded before workloads;
an explicit completion marker and >=1,800,000 ms are required for soak PASS.
Local acceptance, remote CI, package publication and production rollout are
separate outcomes. P1 remote status is recorded above; P2–P5 remote CI and
publication are NOT RUN.
