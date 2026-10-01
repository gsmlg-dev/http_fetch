# HTTP/2 completion re-review — v0.15.0 / ec53f215

Review date: 2026-09-30  
Repository: `gsmlg-dev/http_fetch`  
Reviewed remote main: `ec53f21584b435d37768890b13c71a18a4584554`  
Previous review baseline: `e24c4a139703afd14c11a3bc03cd73f71eb84074`  
Decision: **Previous CI/release blockers are resolved; general production HTTP/2 acceptance remains blocked by F1, F2, and incomplete final acceptance.**

## Evidence boundary

This review compared live GitHub commit metadata, diffs, file blob identities, selected pinned source, the repository validation report, current workflow/job outcomes, and the successful `Test http_fetch` job log. Remote main was rechecked and remained at the reviewed SHA. The open-PR query returned no open pull requests.

No Elixir, Mix, or Erlang executable is available in this review container. No local repository test, independent network reproducer, benchmark, or soak was run. F1/F2 are source-derived defects carried forward after verifying that the relevant implementation is unchanged, not newly executed reproductions. GitHub CI outcomes are independently observed remote executions, not local executions by this reviewer.

## What changed since the previous review

The comparison contains three commits:

| Commit | Change |
|---|---|
| `c67aa4c2fb0a4041dfee96819e6d22ff3b764b19` | Complete six-package consumer preparation; versioned HTTP/3 dependency metadata; release ordering/rewrite updates; HTTP/3 format/Credo fixes; deterministic returned-response deadline test; validation report update. |
| `e3cad137aef03a5a3ee4749df541a6076382975f` | Add `http2_reuse: false` to the TLS ticket-resumption fixture so the fixture opens a new connection. |
| `ec53f21584b435d37768890b13c71a18a4584554` | Coordinated version/dependency bump to 0.15.0. |

Sources: [comparison](https://github.com/gsmlg-dev/http_fetch/compare/e24c4a139703afd14c11a3bc03cd73f71eb84074...ec53f21584b435d37768890b13c71a18a4584554), [release-preparation fix](https://github.com/gsmlg-dev/http_fetch/commit/c67aa4c2fb0a4041dfee96819e6d22ff3b764b19), [resumption fixture](https://github.com/gsmlg-dev/http_fetch/commit/e3cad137aef03a5a3ee4749df541a6076382975f), [version commit](https://github.com/gsmlg-dev/http_fetch/commit/ec53f21584b435d37768890b13c71a18a4584554).

## Completion matrix

| Previous item | Current assessment |
|---|---|
| F1: unfinished request direction after an early final response | **NOT FIXED.** Relevant runtime code is unchanged. |
| F2: existing queued requests cannot initiate a replacement connection after capacity changes | **NOT FIXED.** Relevant pool and admission code is unchanged. |
| F3: returned-response deadline test timing | **Prior observed CI failure resolved.** The test injects the deadline event after obtaining the response, and the current http_fetch test job passes. This checks event handling; it is not by itself a real-clock timing test. |
| F4: external consumers omit elixir_quic_http3 | **Resolved in code and CI.** Both previously failed consumer gates now succeed. |
| Root format/Credo failures | **Resolved in current CI.** Do not carry forward the historical red status. |
| F5: complete final independent HTTP/2 acceptance and soak | **NOT COMPLETE.** The current report explicitly says the final matrix and 30-minute soak remain NOT RUN. |

## Current CI evidence

The successful CI/Test runs are attached to the pre-version-bump source commit `e3cad137aef03a5a3ee4749df541a6076382975f`. Current main is its version-bump child. A separate workflow-run query for `ec53f215...` returned no runs; this provenance distinction is not itself being treated as a new runtime defect.

- [CI run 36668263712](https://github.com/gsmlg-dev/http_fetch/actions/runs/36668263712): success. All 12 returned jobs succeeded, including Compile, Format Check, Credo, Dialyzer, External consumer smoke, and Published ex_ssl feature gate. The latter's subsequent HTTP/2 TLS lifecycle regression step also succeeded, rather than being skipped as before.
- [Test run 36668263716](https://github.com/gsmlg-dev/http_fetch/actions/runs/36668263716): success. All five app jobs succeeded.
- [Test http_fetch job 109737526992](https://github.com/gsmlg-dev/http_fetch/actions/runs/36668263716/job/109737526992): the actual log records `mix test apps/http_fetch/test`, seed `284067`, max_cases 8, and `20 doctests, 284 tests, 0 failures`.
- [Release run 36668491244](https://github.com/gsmlg-dev/http_fetch/actions/runs/36668491244): reported success. Release success is not evidence that F1/F2 or the long-running HTTP/2 acceptance gate were completed.

The repository report additionally describes a local full-suite pass with 661 tests, 20 doctests and three gated QUIC skips during release preparation. This is author-reported evidence; the reviewer did not rerun that local command.

## Source identity: the runtime fixes have not landed

The following Git blob SHA values are identical at the previous and current reviewed commits:

| File under `apps/http_fetch/lib/http/` | Identical blob SHA |
|---|---|
| `socket_client.ex` | `22deca5215d361cce1010023fdcee63d16441c86` |
| `http2/connection_owner.ex` | `e9c0862e2b00fa0c2cbb1b1a7f95c417ac6eefdd` |
| `http2/body_bridge.ex` | `44618d66e3e481f662dbe8f52d11ff7d8e3cf285` |
| `http2/pool.ex` | `8f670dbc95be1fff4739b3a556eb68e746d07525` |

The intervening diffs modify tests/release preparation and metadata, not the runtime control flow that produced F1/F2. The comparison, not merely the document's NOT MET label, is the basis for retaining these findings.

## F1 / P1 — Early final response does not reliably close the unfinished request half

Relevant current sources: [SocketClient](https://github.com/gsmlg-dev/http_fetch/blob/ec53f21584b435d37768890b13c71a18a4584554/apps/http_fetch/lib/http/socket_client.ex), [BodyBridge](https://github.com/gsmlg-dev/http_fetch/blob/ec53f21584b435d37768890b13c71a18a4584554/apps/http_fetch/lib/http/http2/body_bridge.ex), [ConnectionOwner](https://github.com/gsmlg-dev/http_fetch/blob/ec53f21584b435d37768890b13c71a18a4584554/apps/http_fetch/lib/http/http2/connection_owner.ex).

`handle_http2_final_headers` stops the body bridge. `BodyBridge.early_response` uses `stop_stream(..., false)`, suppressing owner notification and producing no upload EOF. Successful response cleanup calls `release_stream`, which removes runtime/protocol state without first guaranteeing closure of an unfinished request direction on the wire. Stopping the bridge also does not atomically remove an owner-held pending upload chunk; a later credit update can reach the pending-data scheduler.

Consequences are conditional on early final responses while the request half is still open: peer-side half-closed streams can outlive locally released capacity, and abandoned upload bytes can still be scheduled. A normal GET or a request whose upload already ended is not this reproducer.

A legal peer can return a complete response before the full request and omit the optional NO_ERROR reset. Response END_STREAM alone is not bidirectional stream closure. See [RFC 9113 §5.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1) and [§8.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1).

Required regression: advertise initial stream window zero and maximum concurrency one; receive POST HEADERS without END_STREAM; return final 413 with END_STREAM, no RST, and keep the socket open. Verify a correct request-side closing action before admission of the next stream, unchanged valid response delivery, no residual upload, and successful sequential reuse. Also test final headers followed by delayed response DATA and an intervening WINDOW_UPDATE. Do not reset the stream prematurely and discard a valid response still in progress, or invent a Content-Length-inconsistent normal EOF.

## F2 / P1 — Existing waiters can remain stuck after connection capacity changes

Relevant sources: [Pool](https://github.com/gsmlg-dev/http_fetch/blob/ec53f21584b435d37768890b13c71a18a4584554/apps/http_fetch/lib/http/http2/pool.ex), SocketClient above, and [application supervision](https://github.com/gsmlg-dev/http_fetch/blob/ec53f21584b435d37768890b13c71a18a4584554/apps/http_fetch/lib/http_fetch.ex).

Production uses the pool without an owner_factory. The coordinator claims connection creation once before awaiting a reservation. `do_dispatch` simply returns state when there is no eligible existing owner. It does not promote an existing waiter to create a connection. Owner DOWN redispatches only the affected key against existing owners; freeing global connection capacity does not wake another origin's waiter to connect.

Required regressions: (1) queued never-sent work remains when all eligible owners drain/close; (2) origin A fills the global connection budget, origin B queues, and A closes/expires. Submit no extra request to trigger work. The already-queued work must acquire newly available creation capacity and finish, with original deadlines, cancellation, single-connector ownership and all limits preserved. This is admission liveness, not automatic replay of a sent POST.

## F5 — Final acceptance and report provenance remain incomplete

The current [validation report](https://github.com/gsmlg-dev/http_fetch/blob/ec53f21584b435d37768890b13c71a18a4584554/docs/http2-production-validation.md) begins with **Production contract: NOT MET** and explicitly states that the complete final independent HTTP/2 matrix and 30-minute soak have not run. Historical sections still name older candidates and old failures. Preserve history, but introduce one unambiguous current-candidate summary instead of mixing historical and current labels.

After F1/F2 are fixed, execute their regressions and the existing final acceptance plan on one frozen source candidate. Retain the prior independent-peer, TLS-backend, large-transfer, reuse, concurrent/paused-consumer, HPACK/profile and package-consumer gates. Record real commands, seeds, bounds, results and accessible logs. Unrun gates stay NOT RUN/BLOCKED.

## Recommended next change

Implement F1, implement F2, then complete final acceptance. Keep the now-green release and CI fixes. Do not reimplement all earlier hardening, remove fingerprint profiles, disable reuse globally to hide the issues, add unsafe retries, or expand HTTP/3/TLS scope. The companion prompt is limited to these remaining items.
