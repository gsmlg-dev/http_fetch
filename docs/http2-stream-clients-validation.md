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

## Acceptance status

| Family | Status | Evidence required |
| --- | --- | --- |
| A0 | NOT RUN | New runtime extraction, F1/F2, standalone clients |
| A1–A3 | NOT RUN | SSE wire/lifecycle/bounds and independent peers |
| B1–B3 | NOT RUN | RFC8441 capability, WS duplex, flow/bounds |
| C1–C3 | NOT RUN | Mixed connection/sibling/isolation proof |
| D1–D2 | NOT RUN | New client backend matrix and package closure |
| D3 | NOT RUN | Frozen full/static/interop/churn/30-minute soak, 42 Fetch gates |

Finite acceptance budgets and sampled maxima will be recorded before workloads;
an explicit completion marker and >=1,800,000 ms are required for soak PASS.
Local acceptance, remote CI, package publication and production rollout are
separate outcomes. Remote CI for this implementation and publication are NOT RUN.
