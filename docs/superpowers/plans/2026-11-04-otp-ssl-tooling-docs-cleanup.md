# OTP SSL Tooling and Documentation Cleanup Implementation Plan

> **For agentic workers:** Use `executing-plans` to implement this plan task by task in the current checkout. Keep dependent builds and benchmark runs sequential. Branches, worktrees, commits, pushes, workflow dispatches and publication require their own authorization.

**Goal:** Make current documentation and verification tools agree with the ExSSL-only production contract, while preserving independent reference coverage and valid performance comparisons.

**Architecture:** Current-source workloads use ExSSL. Comparative OTP workloads run only against an immutable pre-removal source export in a separate BEAM, with separate dependencies/builds and explicit provenance. Current guidance follows the shipped APIs; historical records retain their original evidence and receive clear status notices where needed.

**Tech Stack:** Elixir/Mix umbrella, Python `unittest`, Bash, independent Python/OpenSSL peers, existing GitHub Actions and isolated release gates.

## Verified starting point — 2026-11-04

- Checkout: clean `main` at `3eee470` before this plan was added; nine manifests use `1.0.0-rc.0`.
- `apps/http_core/lib/http/tls_backend.ex` defaults to `:ex_ssl`, accepts only `:ex_ssl`/`"ex_ssl"`, and rejects legacy selectors. Production removal is already implemented.
- `docs/tls-migration-validation.md` records completed P6/P7 acceptance and RC publication. Those are repository-recorded results, not new remote verification in this planning task. Performance and Credo/Dialyzer remain deferred.
- `scripts/tls_migration_benchmark.exs:47` still runs `[:ssl, :ex_ssl]`; its expected counts, order and completion caveats describe the old P0 baseline.
- `scripts/tls_migration_performance.py:30` requires `otp-before/candidate/otp-after`, but launches every arm from the current source. Its validator also requires identical source and BEAM identities across those arms. The Elixir runner maps every non-ExSSL backend to OTP.
- `python3 scripts/tls_migration_performance_test.py` passes **26 tests**. These pure synthetic-report/orchestration controls do not execute the retired backend and therefore miss the stale runtime routing.
- The current source/candidate feature gates already pin ExSSL; the historical published gate deliberately pins the old OTP default. Several `:ssl` listeners and generated test-consumer dependencies support independent reference peers.
- `apps/ex_ssl/scripts/resumption_benchmark.exs` unconditionally starts OTP and measures both implementations. It also documents a child-project invocation rather than the umbrella-root invocation.
- CI currently discovers `test_*.py` under `scripts/ci` and `scripts/release`; it does not discover `scripts/tls_migration_performance_test.py`. Root `scripts/tls_migration_*` changes are absent from CI's path filter.

## Scope and invariants

Allowed implementation writes are the script/test, workflow and documentation files listed below. Runtime library sources, package versions, lockfiles, dependency requirements, release auditors and directed proof machinery are outside this cleanup.

Keep these distinctions explicit:

| Reference | Treatment |
| --- | --- |
| Current TLS client default or successful `tls_backend: :ssl` example | Correct to the current ExSSL contract |
| Independent OTP TLS peer or explicit differential reference | Retain with its test/reference purpose documented |
| Legacy-selector rejection test | Retain; prove rejection before network activity |
| `ssl:` option container, `{:ssl, socket, data}` compatibility message, public `SSL` facade | Retain; none selects the retired backend |
| Historical changelog, raw measurement or accepted validation record | Preserve original values and outcomes; add a historical notice where current guidance is ambiguous |

Do not replace OTP reference servers with the system under test, remove comparative thresholds, reinterpret unsupported results as cleanup success, or claim that successful smoke measurements complete the deferred performance gate.

## Task 1 — Repair performance workload routing and evidence identity

**Modify:**

- `scripts/tls_migration_performance.py`
- `scripts/tls_migration_performance.exs`
- `scripts/tls_migration_performance_test.py`

- [x] Add failing orchestration controls to the existing Python suite before changing routing. Capture each launched process's command, working directory, environment and input configuration. Require candidate smoke to launch only ExSSL from the current root; require comparative OTP arms to launch only from a pinned reference export. Unknown backend values must fail before starting a peer or BEAM.
- [x] Keep the existing commands `fingerprint`, `run` and `validate`. Add `run --otp-reference-sha COMMIT` for full comparative runs. `run --smoke` needs no OTP reference and runs only the candidate; adding `--otp-reference-sha COMMIT` to smoke exercises bounded three-arm brackets. Both smoke forms return exit 2 and `INCOMPLETE` only after their functional evidence passes validation; malformed reports, failed exchanges or missing evidence return exit 1 and `FAIL`. A full comparative run without a reference must reject before builds/peers, with an actionable message.
- [x] Replace the existing `matrix()[0]` smoke selection with this explicit bounded matrix:

  ```python
  def smoke_matrix():
      cells = []
      for protocol, tls in itertools.product(("http/1.1", "h2"), ("TLSv1.2", "TLSv1.3")):
          for workload in WORKLOADS:
              cells.append(dict(kind="measurement", trial=1, protocol=protocol,
                                tls=tls, concurrency=1, workload=workload))
          cells.append(dict(kind="soak", trial=1, protocol=protocol,
                            tls=tls, concurrency=1, workload="reuse"))
      return cells
  ```

  `WORKLOADS` remains the existing five operations: cold, reuse, upload, download and cancel. This produces 20 measurement cells and four short-soak cells. Use three warmup exchanges and ten measured exchanges per measurement cell; short soaks run for five seconds and must complete at least one measured reuse cycle. Candidate-only smoke executes 24 arms; reference smoke executes the same 24 cells with all three phases, for 72 arms. Neither changes the full promotion matrix.
- [x] Use the following immutable reference candidate, confirmed by `git show` to retain the OTP adapter and selectors:

  ```text
  1ef7a51721138d533ea30b3237da1fd96e8a8712
  ```

  This is the parent of production-removal commit `55d719467f691d857df18323e162afcae338ecd3`. Export it with `git archive` into a task-owned temporary directory; do not switch the checkout or create a branch/worktree. Verify the resolved commit, archive digest, source manifest and required public workload APIs before measuring. If that baseline cannot execute the existing workload, report the concrete blocker without patching historical production code.
- [x] Compile current and reference sources separately with `MIX_ENV=prod` and distinct owned build/dependency paths. Resolve with `mix deps.get --check-locked` in each root and verify its lockfile remains unchanged. The current driver supplies the workload configuration; OTP arms execute the archived reference's own `scripts/tls_migration_performance.exs`. Finish one process before launching the next.
- [x] Make the current Elixir runner reject all backend values except `"ex_ssl"`; remove its `else: :ssl` mapping. Preserve TLS verification, payload checks, completion/retirement waits, cancellation barriers and cleanup deadlines.
- [x] Introduce schema `http-fetch-tls-p4-v2`. Bind each arm to its own source manifest, build receipt, selected transport and BEAM digests. Compare host, Elixir/OTP/ERTS, architecture, schedulers, effective options and peer identity across arms; compiled-library hashes are validated against each arm's own build rather than required to match different source revisions.

  The routing contract is:

  ```python
  PHASES = ("otp-before", "candidate", "otp-after")
  BACKEND_BY_PHASE = {"otp-before": "ssl", "candidate": "ex_ssl", "otp-after": "ssl"}
  # candidate -> current root + current source/build identity
  # otp-before/otp-after -> verified export + reference source/build identity
  ```

- [x] Keep one independent peer and identical verified policy/payload per bracket. Authenticate fixture hashes across roots; reject a mismatch. Record candidate loaded/started application state before and after workloads. A normal production-mode VM check is separate from the existing release gate that proves OTP modules are unavailable.
- [x] Separate functional evidence validation from promotion sample/duration requirements and comparative performance budgets. Add `validate_smoke_report` and invoke it before a smoke result is emitted. It must require the exact smoke cell/phase set; correct source/build/transport identity; verified peer TLS/cipher/ALPN; exact request and connection counts with no missing/duplicate/replayed exchange; checked payloads; proven blocked-output cancellation; confirmed request completion and resource retirement within the existing functional deadlines; and no peer/runner errors. Validate raw artifact hashes and paths as for full reports. Short soaks require timestamped public resource observations, actual elapsed duration and completed cycles. Smoke must not enforce or claim the deferred latency/goodput/memory-regression or 30-minute acceptance budgets, and must never write the full promotion `validated.json` artifact.
- [x] Preserve the complete matrix, 1,000-sample minimum, three trials, 30-minute soaks, 20% reference-drift rejection and existing latency/goodput/resource budgets for comparative validation. Preserve all failed trials and raw artifact hashes. Reject v1/P0 reports explicitly instead of silently upgrading historical evidence.
- [x] Extend regression controls for reversed/missing phases, wrong-source OTP arms, candidate execution in the reference root, reference execution in the current root, environment/fixture drift, modified raw artifacts, smoke promoted to acceptance, and failures that leave a child running. Replace the existing mocked smoke success fixture containing only `phase` with complete bounded functional evidence. Add negatives proving that a phase-only report, omitted H2/TLS-version/workload cell, incorrect payload, peer error, missing cancellation gate, unconfirmed cleanup or incomplete short soak yields `FAIL`/exit 1 rather than diagnostic exit 2. Existing full-report payload, replay, cancellation and unconfirmed-cleanup negatives remain required.

**Verification:**

```bash
python3 scripts/tls_migration_performance_test.py
```

Expected: all pure tests pass; they remain clearly labelled as orchestration/report validation rather than real performance acceptance.

## Task 2 — Make bounded benchmarks use the current implementation

**Modify:**

- `scripts/tls_migration_benchmark.exs`
- `scripts/tls_migration_benchmark_peer.py`
- `apps/ex_ssl/scripts/resumption_benchmark.exs`

**Create:** `scripts/ci/test_tls_benchmark_routing.py`, covering the peer's request-path boundary with in-memory inputs and no sockets or timed workloads.

- [x] Change the current H1 benchmark to a single `:ex_ssl` arm. Adjust order metadata, exact peer request counts, per-path exchange checks and upload-byte totals to that one arm. Give current output a new schema, `http-fetch-tls-benchmark-v2`; leave both committed `docs/tls-migration-p0-*.json` files byte-for-byte unchanged.
- [x] Extract the peer's inline path validation into `parse_path(path)` and accept only current ExSSL benchmark routes. Verify that `/ex_ssl/cold/small` returns `("ex_ssl", "cold", "small")`, while `/ssl/cold/small`, traversal components, unknown operations and extra path components raise `ValueError`. Preserve independent handshake, certificate/ALPN, payload and exact connection/exchange checks.
- [x] Replace the obsolete assertion that ExSSL completion is unsupported with current, measured completion outcomes. Keep VM/memory observations distinct from public cleanup receipts and keep the small-sample statistical caveat.
- [x] Make the raw TLS resumption benchmark default to `[:ex_ssl]`; allow `[:ex_ssl, :otp]` only through an explicit `--otp-reference` differential-test flag. Start OTP only for that flag, reject other arguments before fixture/peer creation, and retain full/resumed handshake and payload verification.
- [x] Document umbrella-root production-mode commands. The resumption script already loads its three fixture helpers explicitly, so it need not use `MIX_ENV=test` merely to obtain support modules:

  ```bash
  MIX_ENV=prod mix run scripts/tls_migration_benchmark.exs
  MIX_ENV=prod mix run apps/ex_ssl/scripts/resumption_benchmark.exs
  MIX_ENV=prod mix run apps/ex_ssl/scripts/resumption_benchmark.exs --otp-reference
  ```

  The final command is an explicit differential reference, not a current HTTP backend selection or proof of an OTP-free release.

**Verification:** focused routing/parser tests, one real default H1 run, one real default resumption run, and one real resumption run with `--otp-reference`, using the three commands above. The default resumption run must report both `ex_ssl/full` and `ex_ssl/resumed`; the reference run must report all four groups: `ex_ssl/full`, `ex_ssl/resumed`, `otp/full` and `otp/resumed`. Each group must execute its existing independent TLS1.3/cipher/ALPN, full-versus-resumed handshake and 1 MiB payload assertions. Require exit 0 for all three commands, exact peer counters and confirmed public cleanup where the API supplies it. Retain stdout/stderr, group measurements and actual exit codes.

## Task 3 — Correct current documentation and mark historical material

**Modify current guides:**

- `docs/managed-transports.md`
- `docs/http2-beta-support.md`
- `docs/ex-quic-consumer-contract.md`
- `docs/quic_http3_design.md`
- `docs/migration-provenance.md`
- `docs/ex-ssl-consumer-contract.md`
- `docs/tls-migration-plan.md`
- `docs/tls-migration-design.md`
- `README.md`

**Add status notices to historical designs/plans as needed:**

- `docs/http_web_socket_design.md`
- `docs/http_event_source_design.md`
- `docs/plans/http_web_socket_implementation_plan.md`
- `docs/HTTP2_IMPLEMENTATION_PLAN.md`
- `docs/HTTP2_IMPLEMENTATION_REPORT.md`
- `docs/http2-stream-clients-plan.md`
- `docs/http-fetch-ex-ssl-migration-plan.md`

- [x] Replace current claims that OTP is the default or that managed HTTPS rejects ExSSL. Derive managed policy, credential and retirement descriptions from `HTTP.ManagedTransport`, `HTTP.ManagedTransport.Policy`, existing contract tests and the current README. Keep direct-route limitations and conservative cleanup semantics accurate.
- [x] Remove current dependency/architecture instructions pointing to the deleted `HTTP.Transport.SSL`; direct readers to `HTTP.Transport.ExSSL` and public `SSL` as appropriate. Preserve `ssl:` options and documented unsupported-feature boundaries.
- [x] Update the TLS consumer contract's stale statement that P6/P7 remain open. Link the existing November 2 RC acceptance section, keeping formal `1.0.0` and deferred performance/quality work distinct.
- [x] Describe the repaired benchmark and performance commands, new schemas, pinned-reference isolation, diagnostic exit status and unchanged comparison budgets in the existing performance section. Add a short README link to that section.
- [x] For historical plans/reports, add a dated notice immediately below the title, after YAML front matter where present:

  ```markdown
  > Historical design or validation record. Backend defaults, transport names
  > and dependency examples below describe its stated baseline. For current TLS
  > behavior and migration acceptance, see the README and TLS migration ledger.
  ```

  Use working relative Markdown links in each document. Retain original versioned results and baselines. Treat root `CODEX_*` task prompts as historical inputs and leave their contents unchanged.
- [x] Review remaining references in `README.md`, `CLAUDE.md`, root/nested `AGENTS.md` and ExSSL compatibility docs. Existing statements that OTP is used by test/reference peers are accurate; avoid editing them merely to eliminate search matches.

**Verification:** `mix docs --warnings-as-errors`, local links/anchors in edited Markdown, and manual review that current examples use ExSSL while historical evidence remains identifiable. No new test suite is needed for prose replacements.

## Task 4 — Keep test/reference scripts explicit and wire regression checks into CI

**Modify:**

- `.github/workflows/ci.yml`
- `scripts/ci/changed_apps.py`
- `scripts/ci/test_changed_apps.py`

**Review without automatic rewrites:**

- `scripts/ex_ssl_source_smoke.sh`
- `scripts/ex_ssl_algorithms_test.exs`
- `scripts/ex_ssl_mtls_redirects_test.exs`
- `scripts/ex_ssl_feature_consumer_mix.exs`
- `scripts/release/consumer_gate.py`
- `scripts/external_consumer_smoke.exs`
- `scripts/ci/test_ex_ssl_compat.py`
- `scripts/release/test_published_consumer.py`

- [x] Keep current source/candidate consumers explicitly ExSSL. Preserve the pinned historical published consumer's OTP-default checks and independent OTP servers. Any newly found current workload selecting OTP must be corrected or turned into an explicit legacy-selector rejection case with a no-I/O assertion.
- [x] Keep `:ssl` in generated **test** consumers when their in-VM peer requires it. Their smoke results remain separate from `no_otp_consumer_gate.py`; do not describe them as production-removal proof.
- [x] Add `scripts/tls_migration_*` to CI push/PR paths and shared-tool selection. Test that a performance-runner change selects the existing affected H2 consumers and candidate TLS gate, while unrelated Markdown still does not select app jobs.
- [x] Add a small Python-only step, outside the manual-only `full_gate` step, that runs on selected CI executions:

  ```bash
  python3 scripts/tls_migration_performance_test.py
  python3 -m unittest discover -s scripts/ci -p 'test_tls_benchmark_routing.py' -v
  ```

  Keep long load/soak workloads outside automatic push/PR runs. Do not add a second static source auditor or change existing release-audit requirements.

**Verification:**

```bash
python3 -m unittest discover -s scripts/ci -p 'test_*.py' -v
python3 -m unittest discover -s scripts/release -p 'test_*.py' -v
```

## Task 5 — Integrated verification and completion evidence

- [ ] Run Python routing/report tests, then formatting for changed Elixir scripts, Bash syntax checks only if a shell file changes, and documentation generation. Run Mix operations sequentially from the umbrella root:

  ```bash
  mix format --check-formatted scripts/tls_migration_benchmark.exs scripts/tls_migration_performance.exs apps/ex_ssl/scripts/resumption_benchmark.exs
  MIX_ENV=test mix compile --warnings-as-errors
  MIX_ENV=test mix test apps/http_core/test/http/tls_backend_test.exs apps/http_runtime/test/http/managed_transport_ex_ssl_policy_test.exs
  mix docs --warnings-as-errors
  git diff --check
  ```

- [x] Run all three real bounded benchmark commands from Task 2, including the successful resumption `--otp-reference` branch. Verify the required groups and their handshake/payload assertions, and separately verify invalid raw-resumption CLI arguments fail before fixture/peer startup.
- [ ] Run `tls_migration_performance.py run --smoke` with the exact digest returned by `fingerprint`, writing evidence to a new task-owned output directory. Require all 24 cells and their functional checks to pass before expecting diagnostic `INCOMPLETE`/exit 2; confirm that only candidate arms run. Exercise `run --smoke --otp-reference-sha 1ef7a51721138d533ea30b3237da1fd96e8a8712` in a different output directory and require the same validated cell coverage across all 72 arms. Retain functional-validation results, peer/payload/cancellation/cleanup evidence and artifact identities. An `INCOMPLETE` label alone is insufficient. Do not run the full comparative load matrix merely to validate script routing.
- [ ] For the implementation's shared CI/tooling changes, perform the repository-required manual full regression once authorized delivery reaches GitHub. Use the existing delivered branch or tag in `TLS_CLEANUP_DELIVERY_REF`; do not create a ref for this step. Explicitly preserve the current static-analysis deferral:

  ```bash
  : "${TLS_CLEANUP_DELIVERY_REF:?set to the authorized delivered branch or tag}"
  gh workflow run ci.yml --ref "$TLS_CLEANUP_DELIVERY_REF" -f defer_static_analysis=true
  gh workflow run test.yml --ref "$TLS_CLEANUP_DELIVERY_REF"
  gh workflow run integration.yml --ref "$TLS_CLEANUP_DELIVERY_REF"
  gh workflow run e2e.yml --ref "$TLS_CLEANUP_DELIVERY_REF"
  ```

  Verify every run's resolved commit matches the delivered source, CI records Credo/Dialyzer as `DEFERRED`, and all required non-deferred jobs complete successfully. Dispatch acknowledgment alone is not a regression result. Keep the existing candidate isolated release/no-OTP gate intact. Local script tests or a production-mode source VM do not substitute for it.
- [x] Review every remaining relevant `:ssl`, `HTTP.Transport.SSL` and `--backend ssl` match as a current action, independent reference, rejection case, compatibility name or historical statement. Inspect the final integrated diff and verify lockfiles, package versions and runtime library sources are unchanged.
- [x] Report documentation/tooling completion separately from performance acceptance. Retain command lines, source/reference identities, environment, artifact hashes, peer counts, failures, skips and actual exits. Full comparisons and long soaks remain **NOT RUN** until the deferred performance work is explicitly resumed; keep Credo/Dialyzer's existing deferral rather than claiming a pass.

## Acceptance criteria

1. All default current-source performance and smoke entry points use ExSSL and can execute without starting OTP SSL for the client workload.
2. OTP comparison arms run only in the pinned independent reference runtime. Their differing source/build identities are authenticated rather than conflated with the candidate.
3. Candidate-only and reference smoke validate all 24 bounded cells, including H1/H2, TLS1.2/TLS1.3, all five workloads and short soaks. Missing or failed functional evidence returns `FAIL`/exit 1; only functionally validated smoke returns `INCOMPLETE`/exit 2. Existing comparative performance thresholds remain enforced for full validation; synthetic tests and short smoke runs cannot claim performance acceptance.
4. Current published guides describe the actual ExSSL-only runtime and removed adapter accurately. Historical results, raw P0 evidence, compatibility options and independent peers remain valid and clearly scoped.
5. The resumption benchmark's default and successful `--otp-reference` branches execute all required groups and assertions. CI exercises the repaired routing/report controls; manual CI explicitly uses `defer_static_analysis=true`, records those checks as deferred, and retains completed non-deferred regression results for the delivered commit.
6. Keep implementation and local verification separate from Git delivery and full performance acceptance. No branches, worktrees, commits, pushes, workflow dispatches or releases are authorized by this plan.


## Execution results — 2026-11-04

Tasks 1–4 are implemented and passed independent specification and code-quality
reviews. Their checkboxes track implementation; Task 5 and the table below record
actual verification outcomes. Integrated verification is **incomplete** because the actual performance
smoke exposed a runtime admission failure outside this cleanup's write scope.
Strict documentation generation also retains independently reproduced baseline
warnings. Open Task 5 items above are not passes.

| Check | Result | Evidence / limitation |
| --- | --- | --- |
| Performance routing/report controls | PASS | 41 Python tests, including all original controls, exact 24/72 synthetic arms, malformed evidence, preserved budgets and owned-child failure cleanup |
| CI controls | PASS | 45 Python tests; TLS tooling paths select shared consumers and automatic bounded regression checks |
| Release-tooling regression controls | PASS | 253 Python tests; source/candidate versus historical published-provider distinctions retained |
| Locked production dependency preparation and compilation | PASS | `MIX_ENV=prod`, separate owned build/dependency paths; `--check-locked` and `--warnings-as-errors` |
| Pinned reference export/build preflight | PASS | Verified commit `1ef7a51721138d533ea30b3237da1fd96e8a8712`, Git archive manifest/digest, matching fixtures, separate locked production build and own OTP transport BEAM receipt; no reference workload traffic |
| Locked test preparation and strict compilation | PASS | Umbrella-root isolated test build; the two planned focused files ran 8 tests, zero failures |
| H1 benchmark | PASS | ExSSL-only v2 output; 135 requests, 36 accepted/closed connections, zero active connections/errors, exact routes/bytes and public request completion |
| Default raw resumption | PASS | `ex_ssl/full` and `ex_ssl/resumed`, six exact handshake/exchange samples each (one warmup); independent TLS1.3/cipher/ALPN and 1 MiB assertions |
| Explicit raw OTP reference | PASS | All four ExSSL/OTP full/resumed groups and the same handshake/payload assertions; OTP path restored only for the flag |
| Invalid raw arguments | PASS | `--unknown` returned exit 1 with usage before fixture/peer setup |
| Fresh production-source VMs | PASS | Additional direct Elixir runs of both default benchmarks kept OTP SSL unloaded and unstarted; this remains separate from release-unavailability proof |
| Elixir formatting / final diff | PASS | All three changed scripts pass `mix format --check-formatted`; `git diff --check` passes |
| Edited Markdown links | PASS | 105 local/source-mapped paths and anchors checked; required historical notices preserve relative links and YAML |
| Strict ExDoc | BLOCKED | `mix docs --warnings-as-errors` returned 1: 272 warnings. Unchanged `HEAD` archive returned 1 with 274 warnings; final warning comparison has no introduced warnings. Existing excluded Markdown targets and hidden runtime module/type references remain outside allowed manifest/runtime edits. |
| Candidate 24-cell smoke | FAIL / BLOCKED | Actual run returned `FAIL`/exit 1 after the first cold cell passed. The next H1/TLS1.2 reuse warmup hit `{:transport_scope_capacity, :requests}` after the preceding public completion returned `:ok`. No functional acceptance artifact or promotion artifact was written. |
| Pinned-reference 72-arm smoke | NOT RUN / BLOCKED | The same admission logic exists in the pinned source. No historical code patch, capacity increase, readiness poll, sleep or request retry was used to bypass it. |
| Remote manual CI/Test/Integration/E2E | NOT RUN | No authorized Git delivery or workflow dispatch; local dirty source was not misrepresented as remote `main` verification |
| Full promotion load / 30-minute soaks | NOT RUN | Remain deferred; no performance acceptance claim |
| Credo / Dialyzer | DEFERRED | Existing deferral retained |
| Protected source/evidence | PASS | All 257 runtime library, manifest, lockfile and historical P0 JSON hashes match the starting checkout; `HEAD` remains `3eee470fb0485602bc52fd5df5ee086ebf560f1b` |

### Runtime blocker

`TODO(upstream): gsmlg-dev/http_fetch#151` —
[Managed request admission can reject a free slot after confirmed completion](https://github.com/gsmlg-dev/http_fetch/issues/151).
Filed and read back as a `Bug` with `internal request` label under the repository's
upstream issue policy. The runtime code was not changed.

The live failure is recorded independently from source diagnosis. In
`HTTP.ManagedTransport.claim/1`, Scope can release a completed ingress row between
the initial free-slot CAS and the fallback reclaim lookup/CAS. The fallback can
then return false even though the slot is free. The exact scheduler interleaving
was not traced. The existing admission regression suspends Scope during reclaim
and excludes this interleaving. The runner already awaits public completion;
adding waits or retries would mask the required runtime behavior.

Resume affected smoke acceptance only after a separately authorized runtime fix
is available and verified, and the immutable reference baseline can execute the
required workload without driver patches to historical production code. Issue
closure alone does not establish either result.

### Retained local evidence

All task command receipts, logs, source guards, benchmark reports, documentation
baseline comparison and failed smoke artifacts are under:
`/tmp/http-fetch-tls-cleanup-0m1o95g3`.

- `commands.jsonl` records actual commands, environments, exits and elapsed time.
- `h1-benchmark-report.json`, `resumption-default-final.log` and
  `resumption-reference-repair.log` retain the successful bounded workloads.
- `h1-fresh-vm.log` and `resumption-fresh-vm.log` record false/false OTP application
  state before and after both default source workloads.
- `candidate-fingerprint.json` binds the actual failed smoke to source manifest
  `1ba51f323b0878ebb8c0f99a2cf3e1c58439397b40e41812abd486af9354ac90`.
- `reference-preflight/preflight.json` retains the authenticated archive/source/build
  identity; static preflight passed while runtime smoke remains blocked.
- `candidate-smoke-1/report.json` retains the failure and SHA256 diagnostic index,
  per-arm configurations/output/logs, peer state, owned build receipts and wrapper.
- `docs-warning-final-comparison.json` records 272 final versus 274 baseline warning
  lines and no introduced warnings; the baseline used an owned `git archive` of
  unchanged `HEAD`, not a checkout switch or worktree.
- `markdown-links.json`, `guard-check.json` and final formatting/diff logs retain
  the remaining local checks.

No branch, worktree, commit, push, workflow dispatch, tag, publication or release
was performed. Test/reference OTP peers, `ssl:` options, compatibility messages,
legacy-selector rejection cases and original P0 measurements remain intact.

## Follow-up — 2026-11-05

The user separately authorized fixing issue #151 in the current checkout. This
extends the earlier docs/tooling write scope to
`apps/http_runtime/lib/http/managed_transport.ex` and its admission regression
tests. The November 4 failure records above remain historical results.

Admission now makes one final atomic free-row claim when the initial claim and
completed-row reclamation fail. Scope can release the old row between either
earlier operation without causing a false capacity rejection. Work remains
bounded; request retry/replay, admission waits and capacity increases were not
introduced. Existing completion proofs, live-tracker checks and token guards
remain intact.

Two deterministic tests compile the actual source under a test module name and
gate only its ETS boundaries. They use real request completion and Scope `DOWN`
processing to release the row after the initial claim miss or after the reclaim
lookup. Both fail against the original runtime and pass with the fix. Independent
specification and code-quality reviews passed.

| Check | Result | Evidence / limitation |
| --- | --- | --- |
| Deterministic regression before fix | EXPECTED FAIL | 18 admission tests, exactly the two new race schedules failed with request-capacity exhaustion |
| Runtime admission, Scope and policy regression | PASS | 59 tests, zero failures, including integration cases |
| Fetch managed/completion consumers | PASS | 106 tests, zero failures, including real TLS1.2/TLS1.3, H1/H2, capacity and cleanup cases |
| Python tooling regression | PASS | 41 performance, 45 CI and 253 release-tooling tests; 339 total |
| Strict compilation / scoped Credo / formatting | PASS | Owned test and production builds; scoped Credo checked both runtime/test files; all five changed Elixir files formatted |
| Candidate smoke | FUNCTIONAL PASS | All 24 cells/24 arms validated; expected diagnostic exit 2. 244 measured exchanges and 96 warmups; 112 accepted/closed connections, zero final active connections and peer errors, confirmed public completion and retirement |
| Fixed historical OTP reference smoke | FAIL / BLOCKED | Exit 1 in cell 0 `otp-before` warmup: `{:transport_scope_capacity, :requests}`. Immutable commit `1ef7a51721138d533ea30b3237da1fd96e8a8712` retains the old runtime logic. No complete reference arm or 72-arm acceptance; archive source unchanged |
| Strict ExDoc | BLOCKED | Exit 1 with the same 272 warning messages as the earlier cleanup; baseline has 274. No new warnings in this follow-up |
| Current guide corrections | PASS | HTTPS-over-HTTPS table now names ExSSL; 72 reference arms are required coverage, with the historical #151 limitation explicit |
| Source/evidence guard | PASS | Of 257 protected starting files, only the separately authorized runtime module changed; manifests, lockfile and historical P0 evidence unchanged |
| Missing report scripts / concurrency measurements | SKIPPED | User instructed skipping these if their uncommitted scripts could not be found; no throughput-regression claim |
| Full performance / remote workflows / Dialyzer | NOT RUN / DEFERRED | No full promotion or long-soak acceptance, Git delivery or workflow dispatch |

Candidate source-manifest SHA256:
`40068a7fa6618cb0ea5f37a27f9cd3639a3a80e90a9d2925afe90ea42201cc90`.
Evidence is retained under `/tmp/http-fetch-tls-cleanup-0m1o95g3/followup-151`
(command receipts, candidate/reference reports, peer/log/config artifacts, guard
and documentation-warning comparisons). Runtime RED/GREEN, compilation and
scoped Credo logs use the sibling `issue151-*.log` paths.

Current runtime repair and candidate smoke are complete locally. Historical OTP
comparison remains blocked by its unchanged source; the deferred full performance
gate has not passed. No commit, push, issue closure or other external write was
performed.

## Release authorization — 2026-11-05

After the local repair, the user authorized committing, pushing and releasing,
and selected `1.0.0-rc.1`. The earlier no-delivery statements record the preceding
verification phase. Release preparation also requires renewing the finite
directed source binding for the changed managed-admission module; the original
175 dispatch findings and all gate requirements remain intact. Workflow results
and published-package verification belong in the
[TLS migration ledger](../../tls-migration-validation.md).
