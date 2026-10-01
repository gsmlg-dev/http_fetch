# HTTP/2 completion review — 2026-09-30

Repository: `gsmlg-dev/http_fetch`  
Reviewed main: `e24c4a139703afd14c11a3bc03cd73f71eb84074`  
Previous review baseline: `a2c508a48812556d43c85ba89654df3200e1551c`  
Decision: **Substantial implementation completed; production acceptance NOT COMPLETE.**

## Evidence boundary

This follow-up inspected pinned source, the repository validation report, GitHub Actions job status, and the actual logs of the failing http_fetch test job and both consumer jobs. No local Elixir/OTP test, independent peer reproduction, benchmark, or soak was executed by this reviewer: `elixir`, `mix`, and `erl` are unavailable in this review runtime.

Keep three evidence classes separate: (1) source-derived control-flow findings, (2) failures observed in GitHub Actions logs, and (3) earlier workload results reported by the repository author. Earlier reported passes are not independently reproduced passes on the current candidate.

## Implemented improvements confirmed in source

| Previous concern | Current implementation evidence |
| --- | --- |
| Ordinary requests bypassed the new runtime | `SocketClient.maybe_http2_owner` sends negotiated HTTP/2 to the new owner without requiring an explicit profile. Overall default remains HTTP/1. |
| Retained protocol stream state | `ConnectionOwner.release_stream` now invokes `Connection.remove_stream`, which removes protocol streams, committed IDs, pending headers, and priority entries. This fixes ordinary completed-stream retention, but does not by itself close unfinished request halves on the wire. |
| Upload progress and directional windows | Binary bodies now use the bridge; owner uses `send_data_prefix`; bridge replenishes credit and tracks outstanding source reads. Owner initializes the configured receive window rather than granting itself send credit. |
| Download backpressure | Stream consumption acknowledgements, bounded delivery queues, connection-level safe admission credit, and a monitored delivery worker are wired into the runtime. |
| Frame handling | Boundary validation precedes dispatch, padding is parsed, and PING/reset/no-push handling is present. |
| Response semantics | Core response phases and body-length validation are integrated; informational responses, trailers, redirects, and returned-stream errors have dedicated paths. |
| Ownership and pooling | Connection owners are independently supervised; callers, subscribers, and connectors are monitored; pool capacity and deadlines are tracked. Queue progress after owner loss still needs closure below. |
| HPACK | Pending minimum/final table updates are emitted; acknowledged decoder limits and decoded field/byte budgets exist. |
| Profile ordering | Request construction uses `order?: false`, leaving ordering to the owner rather than reversing/sorting twice. |

These are source-level implementation confirmations, not a statement that every adversarial or interoperable case passes.

## Remaining findings

### F1 — Early final responses can leave the request half open (P1; source-derived)

Relevant files/functions:

- `apps/http_fetch/lib/http/socket_client.ex`: `handle_http2_final_headers`, `maybe_cancel_http2_bridge`, `finish_http2`.
- `apps/http_fetch/lib/http/http2/body_bridge.ex`: `handle_call(:early_response, ...)`, `stop_stream`.
- `apps/http_fetch/lib/http/http2/connection_owner.ex`: `release_stream`, `drain_pending_body`.

Final headers stop the body bridge using `stop_stream(state, :early_response, false)`. This stops the producer without notifying the owner or emitting upload EOF. The owner may still have `pending_body`; its window-update/settings drain paths do not know the upload has been abandoned. A successful response then releases the local stream maps, without necessarily sending END_STREAM or RST_STREAM for a request whose upload never completed.

The peer can therefore retain an unfinished request stream while the local pool has reclaimed its slot. This is especially relevant with peer MAX_CONCURRENT_STREAMS=1. RFC 9113 permits an early complete response; the peer is not required to send the optional NO_ERROR reset. Completing the response direction alone does not close both stream directions.

Required regression: an independent peer advertises stream send credit zero and concurrency one, receives POST HEADERS without END_STREAM, sends a complete 413 or 200 response without RST_STREAM, and keeps the connection open. Verify valid response delivery, no abandoned upload resumption, a correct on-wire terminal transition for the request half, and successful subsequent reuse without peer concurrency disagreement. A second variant sends final headers before the response body finishes and then grants upload credit; pending upload bytes must not resume after the chosen abort policy takes effect.

Do not fix this by discarding a valid early response or resetting the stream before its response has been safely handled. Preserve the complete-response/NO_ERROR reset rule. This scenario was not executed locally during this review.

### F2 — Existing queued requests can remain stranded after connection capacity becomes available (P1; source-derived)

Relevant files/functions:

- `apps/http_fetch/lib/http/http2/pool.ex`: `do_dispatch`, owner DOWN, draining, and capacity paths.
- `apps/http_fetch/lib/http/socket_client.ex`: `reserve_or_claim_http2_owner`, `await_http2_reservation`.
- `apps/http_fetch/lib/http_fetch.ex`: the production pool starts without an owner factory.

The caller claims connection creation once. On `:wait` it waits for a reservation. With no available owner, `do_dispatch` merely returns the current state; it does not promote a waiting caller into a connector or start one. Owner DOWN only redispatches the affected key, and draining does not arrange replacement admission. Freeing a global connection slot for origin A also does not make an already-waiting origin B retry connection admission.

Required regressions: queue an unsent request, then close/drain all eligible owners without submitting a new request; separately fill the global connection limit using key A, queue key B, and release A. The existing waiter must progress when policy and capacity permit, preserving the original deadline and cancellation semantics. Assert finite per-key/global connecting counts and no duplicate cold connectors.

This concerns requests not yet sent to a peer; fixing admission liveness does not require automatic replay of ambiguous POSTs or consumed producers. This scenario was not executed locally during this review.

### F3 — A new HTTP/2 lifecycle test fails in current CI (acceptance blocker; observed log)

Test workflow: `36644446649`; job: `109664034826`; candidate: the reviewed main SHA.

Observed run: Elixir 1.18.5, OTP 28, seed `342781`, max_cases `8`.

```text
20 doctests, 284 tests, 1 failure

test deadline fails an already returned response stream
apps/http_fetch/test/http/http2_production_lifecycle_test.exs:76
KeyError: key :status not found in: {:error, :request_timeout}
assert response.status == 200
```

The test uses an end-to-end timeout of 200 ms in an asynchronous test module. Its intended post-response assertion is not reached: fetch has already timed out before yielding a response. The observation does not, on its own, establish a production deadline bug. Diagnose fixture scheduling versus runtime behavior, use a deterministic response-delivery/expiry arrangement, and retain a genuine deadline assertion. Do not weaken the test to accept a pre-header timeout as success.

This is distinct from the unchanged OwnerMonitor timing failures described by the local validation report; current `Test http_core` passed while this HTTP/2 test failed.

### F4 — Both existing consumer gates fail before protocol testing (acceptance/integration blocker; observed logs and source)

CI workflow: `36644446650`.

- External consumer smoke: job `109664034677`, failed.
- Published ex_ssl feature gate: job `109664034639`, failed; the subsequent HTTP/2 TLS lifecycle step was skipped.

Both logs report:

```text
missing dependency elixir_quic_http3 (../elixir_quic_http3)
the dependency is not available
(Mix) Can't continue due to errors on dependencies
```

`scripts/external_consumer_smoke.sh` and `scripts/ex_ssl_source_smoke.sh` still unpack only five applications. `http_fetch` and WebTransport require the sixth, `elixir_quic_http3`. The new HTTP/2 interop script's separate six-package consumer does not fix these older CI entry points.

Update all consumer manifests/fixtures and verify the exported dependency contract. `apps/http_fetch/mix.exs` currently declares the new umbrella dependency without an explicit version requirement; inspect package metadata and intended release version constraints rather than treating successful `mix hex.build` alone as consumer readiness. The observed failure is a package/fixture preparation failure, not proof of an ex_ssl TLS implementation defect.

### F5 — Final-candidate acceptance remains incomplete (reported and CI evidence)

`docs/http2-production-validation.md` explicitly says the production contract is not met. It identifies source candidate `93b36e0bc3f990ac361a53c9091a52367428a702` and labels the matrix/reuse/package passes at `2b462399a7611807eebd63331677044b0ba286c6` as intermediate evidence. The earlier soak was stopped; the full final-source soak and final matrix/reuse/package acceptance are NOT RUN.

Current CI also has Format Check and Credo failures. The local report attributes its corresponding failures to unchanged HTTP/3 files; keep this distinct from the new HTTP/2 test failure. Resolve those gates with narrowly scoped changes or an explicitly approved, documented release policy; do not silently convert failures to passes.

## Closure sequence

1. Add and execute F1/F2 regressions, fix owner request-half termination and admission liveness, and retain all existing flow-control/profile/response protections.
2. Repair F3's deterministic lifecycle test and F4's complete consumer dependency setup; diagnose the reported OwnerMonitor flakiness separately. Resolve repository quality gates without HTTP/3 feature expansion or blanket exclusions.
3. Select one immutable candidate, run the full existing acceptance matrix and complete 30-minute soak on it, and archive actual logs/resource samples as CI artifacts. Carry earlier results only as historical evidence. Update validation status with exact candidate/tree provenance and the outstanding-finding mapping.

No source was modified, no PR was created, and no CI rerun, merge, package publication, or deployment was triggered by this review.

## Source provenance

All code links below use the pinned review SHA.

- Main: https://github.com/gsmlg-dev/http_fetch/commit/e24c4a139703afd14c11a3bc03cd73f71eb84074
- Validation: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/docs/http2-production-validation.md
- Socket client: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/apps/http_fetch/lib/http/socket_client.ex
- Owner: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/apps/http_fetch/lib/http/http2/connection_owner.ex
- Bridge: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/apps/http_fetch/lib/http/http2/body_bridge.ex
- Pool: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/apps/http_fetch/lib/http/http2/pool.ex
- Core: https://github.com/gsmlg-dev/http_fetch/tree/e24c4a139703afd14c11a3bc03cd73f71eb84074/apps/http_core/lib/http/http2
- Lifecycle test: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/apps/http_fetch/test/http/http2_production_lifecycle_test.exs
- External consumer script: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/scripts/external_consumer_smoke.sh
- TLS consumer script: https://github.com/gsmlg-dev/http_fetch/blob/e24c4a139703afd14c11a3bc03cd73f71eb84074/scripts/ex_ssl_source_smoke.sh
- Test failure: https://github.com/gsmlg-dev/http_fetch/actions/runs/36644446649/job/109664034826
- External consumer failure: https://github.com/gsmlg-dev/http_fetch/actions/runs/36644446650/job/109664034677
- TLS consumer preparation failure: https://github.com/gsmlg-dev/http_fetch/actions/runs/36644446650/job/109664034639
- Stream state and early responses: https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1 and https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1
