# Abyss 0.8.1 post-release hardening

R1–R4 PASS. Abyss **0.8.1** is committed, pushed and published through the existing release workflow. Independent GitHub/Hex archive checks and a fresh published-only consumer PASS.

Release tag/source: `71ecf7883c0aaf666406d24634ff5c022382029d`; validated executable/test candidate: `cd7f26822e366d65e3f168246020cd41ee7b7f3f`. The acceptance commit advances only nonpackaged evidence and reports. [Source parity](https://github.com/gsmlg-dev/abyss/blob/89f6879edd163ff023d8bcb44b9686175dca0109/docs/udp-runtime/evidence/post-release/release-source-parity.json) proves identical executable, tests, workflows, locks and every packaged source/document byte. A final evidence-only handoff may advance main; the tag remains immutable and its byte parity is checked separately.

[GitHub release](https://github.com/gsmlg-dev/abyss/releases/tag/0.8.1) · [Hex package](https://hex.pm/packages/abyss/0.8.1) · [Release workflow](https://github.com/gsmlg-dev/abyss/actions/runs/38568588638) · [Independent publication proof](https://github.com/gsmlg-dev/abyss/blob/89f6879edd163ff023d8bcb44b9686175dca0109/docs/udp-runtime/evidence/post-release/published-verification.json)

The input is Agent Note `27a599ba-c246-4263-92e9-77b80ef5605c`, revision 2, read in full and retained verbatim in [agent-note](https://github.com/gsmlg-dev/abyss/blob/89f6879edd163ff023d8bcb44b9686175dca0109/docs/udp-runtime/evidence/post-release/agent-note.md). Baseline is actual checkout `cd65c84073c66de460ab883206414cf8ce0154bf`, preserving its documentation reorganization. Worktree `.trees/post-release-hardening`, branch `codex/post-release-hardening`; primary's three untracked user input Markdown files and all lockfiles remain preserved. Historical [0.8.0 acceptance](https://github.com/gsmlg-dev/abyss/blob/89f6879edd163ff023d8bcb44b9686175dca0109/docs/archive/udp-runtime/acceptance.md) is unchanged and is not evidence for this patch.

| Finding | Result | Discriminating evidence |
|---|---|---|
| R1 watchdog identity | PASS | Final old-source RED: 4 tests, 2 intended stale init/callback kills. Fixed interacting suites: 46/0 on OTP27 and OTP28. `r1-source-identity.json`, `r1-*` logs. |
| R2 endpoint lifetime | PASS | Isolated R1 source RED: 4 tests, 2 intended state/timer failures. Fixed interacting suites: 50/0 each. `r2-source-identity.json`, `r2-*` logs. |
| R3 local native send accounting | PASS, including final macOS OTP28 | Exact final portable fixture RED on isolated R2 source: 15 tests, 5 intended failures. Fixed OTP27/28: 15/0; earlier interacting suites: 84/0 each. `r3-source-identity.json`, `r3-portable-repair-source-identity.json`, corresponding raw logs. |
| R4 public drop accounting | PASS | Portable RED: 14/14 intended failures; native RED: 2/2; separate stopped-window extension RED: 1 intended failure. Fixed interacting suites: 144/0 each; native final: 2/0 each. `r4-source-identity.json`, `r4-native-source-identity.json`, `r4-*` logs. |

Every watchdog arm now carries its own identity, phase and monotonic deadline and validates worker, invocation and generation. Actual previous-phase timer messages are held at observed barriers and delivered after the new arm is installed. Current limits and helper-DOWN/worker-settlement credit barriers remain enforced. The timer audit found no demonstrated analogous defect requiring another change. Small helpers remove the two introduced nesting findings without changing limits.

Endpoint state is lazy and persists through ordinary idleness and pause/resume for its current generation, with no completed input or send credit retained merely to keep state. `idle_timeout` continues to govern finite keyed eviction; pending timers do not pin inactive keys. Stop, generation replacement and existing callback/application failure policies still retire state and managed timers. This is in-memory lifetime, not durable recovery.

Native instrumentation records the actual `sendmsg` result once under the registered logical server. Payload bytes exclude address controls; empty sends count once with zero bytes. Definite socket errors count once; validation/admission rejection, caller wait timeout and repeated receipt reads do not create send results. The Writer and custom-transport/optional QUIC contracts remain unchanged. Real IPv4/IPv6 traffic, strict replies, both transmitting same-handler endpoints, sampling 0/1 and late completion are covered.

Public `dropped` is `drop_counts.ingress + drop_counts.runtime`, counting each known network input at its definitive ingress or runtime rejection. `internal_events_rejected` separates timer and send-outcome admission rejection, with fixed telemetry counter names. Network drop bytes use observed payload length; truncated native input never invents its original length. Callback failure, send failure, teardown discard and unknown kernel queue loss are separate. Runtime snapshots are absolute bounded maps, sent before rejection telemetry and guarded by original runtime PID/generation. They preserve counts while a stopped generation remains inspectable after normal or forced drain, without duplicate increments or a synchronous control cycle. Public counts reset with generation; telemetry retains logical-server lifetime. Legacy statistics keep their previous contract.

## Combined validation

Executable/workflow candidate `997e6800def6beb14c430f94de65ac4e1a233716` was pushed first; final portable fixture repair is `cd7f26822e366d65e3f168246020cd41ee7b7f3f`. The latter changes only two test/support files and their evidence. Local OTP27 uses the project devenv shell (Elixir 1.18.4, OTP27); OTP28 uses system Elixir 1.18.5. Exact ERTS identity, commands, environment, exit codes and captured hashes are in `final-*-results.json` and raw logs under [evidence](https://github.com/gsmlg-dev/abyss/tree/89f6879edd163ff023d8bcb44b9686175dca0109/docs/udp-runtime/evidence/post-release).

Starting commands, run from this worktree with `CI=true`, `ERL_FLAGS='+S 8:8'` and isolated `MIX_BUILD_PATH` per runtime:

```sh
mix format --check-formatted
mix compile --warnings-as-errors
MIX_ENV=test mix compile --warnings-as-errors
mix test --include integration --no-cover
mix dialyzer
mix docs --warnings-as-errors
mix credo --strict --format json
git diff --check
```

| Gate | Result/evidence |
|---|---|
| Baseline integration | PASS, 648 tests + 3 doctests / 0, `baseline-otp27-tests.log` |
| OTP28 combined integration/static/docs | PASS, 688 tests + 3 doctests / 0; format, both strict compiles, Dialyzer and documentation exit 0. `final-otp28-*` |
| OTP27 combined integration | Initial FAIL, 688/1: unchanged async dispatcher EXIT assertion after 100ms. Same-seed 886179 targeted test PASS, full retry 688 + 3 doctests / 0. `final-otp27-integration.log`, `final-otp27-writer-diagnostic.log`, `final-otp27-integration-retry.log` |
| Strict Credo | Absolute FAIL, exit30, 83 baseline findings; delta PASS, zero introduced. `baseline-credo.json`, `final-otp28-credo-comparison.json`; final OTP27 also83/zero introduced |
| Optional QUIC compatibility | PASS, both unchanged scripts exit0; published engine/TLS0.21.6 provenance, network/control/lifecycle, fresh external UDP/QUIC release consumers and actual1MiB collector. `final-quic-source-identity.json`, `final-quic-*` logs; all lockfiles/source hashes preserved |
| Resource gate | PASS:3policies ×5epochs; process116→116; input8items/7160bytes, egress4entries/2048bytes within quotas. `final-runtime-stress-otp27.log` |
| Performance comparison | MEASURED:6serial samples per source/mode in both paired orders. Median throughput vs actualbaseline:legacy−5.09%, per_datagram−3.26%, endpoint−4.32%, keyed−8.14%. `final-performance-comparison.json` and48raw sample logs |
| Final remote regression matrix | PASS3/3 atcd7f268:Linux27/28 andmacOS28. [run38567015353](https://github.com/gsmlg-dev/abyss/actions/runs/38567015353), `final-regressions-results.json` andall3joblogs |
| Final remote wire/package matrix | PASS19/19 atcd7f268. [run38567021087](https://github.com/gsmlg-dev/abyss/actions/runs/38567021087), `final-network-results.json` andall19joblogs. Initial matrix38565997724 also19/19 |
| Publication | PASS: release38568588638 bothjobs; tag0.8.1 at71ecf78; non-draftGitHubrelease, Hexchecksums/dependencies, all46packagedfiles matchtag/GitHubarchive/installeddependency; freshHex-only18endpoints/54actualexchanges, noRust/QUIC. `published-verification.json`, `published-verifier.log` |

The initial macOS fixture assumed a 65,536-byte IPv6 send must fail with `:emsgsize`; Darwin actually completed it locally. The final fixture suspends only its owning listener and closes its real registered socket, then requires public send/await to return `:closed`, exactly one six-byte error event, and unchanged isolated success counts. No failure assertion, family/backend/sample coverage or production deadline was weakened. Its exact-final-byte RED remains discriminating.

The Writer test and production dispatcher are byte-identical to the baseline. Shutdown can wait100ms per child plus fallback cleanup, so the existing async test's100ms assertion has a timing limitation; competing compilation was present but causation is unproven. No unrelated repair was made. OTP27's first Dialyzer attempt also found the configured shared `priv/plts/dialyzer.plt` overwritten by OTP28 (OldPLT); the task-generated28 cache was preserved and27 cache rebuilt and passed without source configuration changes. All initial failed logs remain retained.

The initial19-job wire matrix verifies independent peers in fixture-owned namespaces across3backends ×3policies ×2runtimes, plus optional DHCP/ARP. It includes a fresh packaged core consumer with no Rust/QUIC and the optional native package; optional DHCP is not part of this publication. Final logs are collected with `collect_workflow.py`, checking each run's exact `headSha` and retaining every job's raw log/hash. Socket scoped IPv6 keeps its documented capability subset.

## Delivery

R1 `babc1d1`, R2 `d9c01b1`, R3 `c1aff38`, watchdog lint `960c40a`, R4 `7574a4a`, version preparation `997e680`, portable fixture repair `cd7f268`. Version0.8.1 was confirmed available after live GitHub/Hex checks. Final OTP28 integration after the fixture repair also passes688tests+3doctests/0 (`final-otp28-integration-final-results.json`). Executable candidatecd7f268 has passed final required local andremote gates; Main source71ecf7883c0aaf666406d24634ff5c022382029d also passesTest38568153767 (688tests+3doctests/0,7defaultintegration exclusions), Compile/Format/Dialyzer inCI38568153779, regression38568153900(3/3), andwire38568153777(19/19). CI is absoluteFAIL only for83baselineCredo findings, zero introduced. Release38568588638 succeeded at71ecf78, with688tests+3doctests/0 and7defaultintegration exclusions in itsOTP27testjob. Tag/package independentverification passed; finalfullintegration separately includesintegration without thoseexclusions. Follow [progress](progress.md) for the exact resumable next action.

Performance measurements retain both initial and reverse sample orders. First-order legacy throughput fell9.96%, reverse-order0.91%; the combined median remains5.09% below baseline. Other policies' combined declines are3.26–8.14%, with increased sampled tail latency. These are reported limitations, not a claim of unchanged production performance. The maintenance prompt requires measurement against current source and supplies no new performance threshold. No unrelated optimization or threshold change was made. Resource results certify only sampled host-managed bounds and observed completion; kernel drops and whole-VM/native reclamation remain unmeasured.

## Publication evidence and final handoff

The workflow ref and checkout SHA both resolve to71ecf7883c0aaf666406d24634ff5c022382029d; its version rewrites are no-ops. Bothrelease jobs succeed. GitHub release is non-draft/non-prerelease. The verifier checks outerHex checksum, innerarchive checksum, exact dependency requirements, all46packaged file bytes against tag, GitHub source archive and fresh installed dependency. The fresh registry/dependency/build consumer has no Rust executables, DHCP native artifacts or QUIC/TLS dependencies and completes54realUDP exchanges through18endpoints: legacy/all3policies, inet/socket, IPv4/IPv6, empty/binary/text and native strict replies. Optional DHCP remains unpublished.

Reproduce publication verification from the repository'sOTP27devenv shell:

```sh
python3 docs/udp-runtime/evidence/post-release/published_verifier.py \
  --version 0.8.1 --expected-sha 71ecf7883c0aaf666406d24634ff5c022382029d
```

Raw source-linked logs and exitcodes for allmain/release jobs remain in `main-*-results.json`, `release-workflow-results.json` and correspondingjoblogs. Final scope contains no unrelated code/lock changes; the three original untracked user Markdown inputs remain preserved. There is no remaining implementation or publication blocker. Existing strict-lint failure, the original Writer timing failure and measured throughput cost are explicitly retained limitations.

The final publication receipt handoff0f3a2cd202e4e0738f54576c811278ea0c475814 is pushed to bothmain and`codex/post-release-hardening`, with the immutabletag still71ecf78. [Completion audit](https://github.com/gsmlg-dev/abyss/blob/89f6879edd163ff023d8bcb44b9686175dca0109/docs/udp-runtime/evidence/post-release/completion-audit.json) proves distributed/package/source/test/workflow/lock parity and source-linked job evidence; the following audit-record commit contains only nonpackaged evidence. Re-run `python3 docs/udp-runtime/evidence/post-release/completion_audit.py` to check currentrefs without mutations. There is no uncommitted implementation or remaining publication work.
