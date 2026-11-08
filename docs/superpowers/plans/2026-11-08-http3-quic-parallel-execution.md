# HTTP/3 and QUIC Parallel Execution Plan

> **For agentic workers:** Use the applicable `writing-plans` and
> `scoped-prd-execution` skills for your bounded lane. The user explicitly
> approved this design and parallel tasks; do not reopen the same approval.

**Goal:** Implement the approved client and QUIC capabilities through independent
tasks with exclusive write ownership and evidence-backed integration.

**Architecture:** Keep protocol engines, pure TLS, shared H3 runtime and public
clients in their existing apps. Run four lanes concurrently; serialize dependent
integration within the owner of each shared module. This coordinator owns final
cross-lane review and integrated verification.

**Tech Stack:** Existing Elixir/Mix umbrella, OTP crypto/public_key, ExUnit,
QUIC v1, RFC 9220/9297, WebTransport draft-17 and reliable-reset draft-11.

Approved spec:
`docs/superpowers/specs/2026-11-08-http3-client-and-quic-completion-design.md`.
The approved M2/R1/R2 design is
`docs/superpowers/specs/2026-11-07-quic-migration-and-early-data-design.md`.

Created project tasks, all on the saved http_fetch project at nuc9i5:

| Lane | Title | Chat ID |
| --- | --- | --- |
| A | QUIC 客户端主动迁移与传输能力 | `01a1baa1-4900-7c82-9fd3-e2918a782588` |
| B | QUIC TLS 会话恢复与 0-RTT 核心 | `01a1baa1-4c2c-70a3-a90c-e5c587f9b7e8` |
| C | HTTP/3 扩展 CONNECT 与 WebSocket 客户端 | `01a1baa1-4fe3-7e91-9f0e-321135e0544e` |
| D | WebTransport draft-17 客户端与独立互通 | `01a1baa1-5349-7122-ac8d-d4ff7d2ed7ae` |

The initial bounded four-task snapshot confirmed all four active and inspecting
their respective implementations. Task creation is not implementation acceptance.

## Common execution rules

All tasks use the current checkout/branch at
`/home/gao/Workspace/gsmlg-dev/http_fetch`. Other tasks are editing this checkout:
preserve their changes, re-read dependencies, and never revert another owner's
work. No branches, worktrees, commits, pushes, releases, lockfile edits, root
formatting, shared dependency fetching, or external-repository edits.

Do not edit this coordinator plan or the approved specs from a child task. Each
task writes its own detailed implementation plan before changing behavior and
its own scoped evidence/contract document. Root AGENTS.md applies; ExSSL also
requires its nested instructions. Existing user-owned untracked files remain
untouched. Missing in-scope engine capability is implemented by its assigned
owner, not locally emulated in a consumer.

Use a unique task-owned `MIX_BUILD_PATH` under `/tmp`, always ending in the actual
environment directory (for example `/tmp/http-fetch-h3-quic-A-<unique>/test`).
Compile and run scoped tests from the umbrella root. Keep dependency sources and
mix.lock unchanged; if preparation requires writes there, report that prerequisite
to the coordinator. Format explicit owned paths only. Use finite peer deadlines,
allocated ports and owned resources; cap build VM schedulers to avoid exhausting
the host. No concurrent writes to root `_build` or shared test fixtures.

Capability flags stay false until the complete advertised profile passes its
required independent-traffic acceptance. Report implemented, locally checked,
independent-peer checked, BLOCKED and NOT RUN separately. Local tests do not prove
published artifacts or browser/production acceptance.

## Task A: QUIC transport and client migration

Exclusive write ownership:

- `apps/elixir_quic/**`, including its scoped architecture and consumer docs.
- `scripts/migration/**` and new `scripts/quic_client_features/**`.
- `docs/superpowers/plans/2026-11-08-quic-client-features.md`.
- `docs/quic/client-features-validation.md`.

- [ ] Write the M2 implementation plan against the current path/IO/cleanup code.
- [ ] Implement exclusive-client `Quic.migrate/2` and same-ref status semantics.
- [ ] Prove port/IP migration with exact stream/FIN and DATAGRAM continuity,
  rejected/busy/bind-failed/lost-validation cases and receipt-based socket cleanup.
- [ ] Implement negotiated reliable reset draft-11, with prefix/final-size,
  flow-control, loss/reordering, recovery, and resource-bound regressions.
- [ ] Publish the transport API and negotiation results in the owned validation
  document for Task D to consume; capability advertisement requires real acceptance.
- [ ] After Task B's provider contract is ready, integrate endpoint-local QUIC
  resumption authority/cache and R1, followed by separately gated R2.
- [ ] Verify and report affected pure/runtime cases plus independent peer traffic.

Do not write ExSSL or HTTP/3/WebTransport code. Task B owns TLS action structs and
the public continuation contract. Task C/D consume transport APIs without writing
this app. M2 and reliable reset can progress while Task B implements TLS.

## Task B: QUIC TLS resumption and early-data provider

Exclusive write ownership:

- `apps/ex_ssl/**`, following its nested architecture instructions.
- New `scripts/quic_tls_features/**`.
- `docs/superpowers/plans/2026-11-08-quic-tls-resumption.md`.
- `docs/quic/tls-continuation-contract.md` and `docs/quic/tls-resumption-validation.md`.

- [ ] Read the required ExSSL architecture documents; write the R1 provider plan.
- [ ] Define the public continuation/action/session contract in the owned contract
  document before Task A starts its dependent engine integration.
- [ ] Implement pure `SSL.QUIC.continue/3`, binder/PSK-DHE/HRR/ticket actions and
  once-only continuation semantics; keep runtime/storage/IO out of the TLS core.
- [ ] Verify malformed, duplicate/stale, authentication and transcript cases;
  retain current TCP TLS policy and run applicable TCP/QUIC regressions.
- [ ] Add separately tested R2 early-secret/acceptance/rejection actions, keeping
  early data default-off and readiness contingent on verified Finished.
- [ ] Supply deterministic vectors and independent TLS/QUIC evidence where the
  actual runtime is available; label full engine traffic acceptance pending Task A.

Do not write `apps/elixir_quic`, Abyss, root manifests, package versions or CI.
Provider availability alone does not make transport resumption/0-RTT supported.

## Task C: HTTP/3 extended CONNECT and WebSocket client

Exclusive write ownership:

- `apps/http_core/lib/http/h3/**` and focused tests under
  `apps/http_core/test/http/h3/**` (inspect the existing test layout first).
- `apps/elixir_quic_http3/**` and `apps/http_runtime/**`.
- `apps/http_web_socket/**`.
- New `scripts/http3_connect/**` and `scripts/http3_websocket/**`.
- `docs/superpowers/plans/2026-11-08-http3-connect-websocket.md`.
- `docs/http3-extensions-contract.md` and `docs/http3-websocket-validation.md`.

- [ ] Plan explicit extended CONNECT, SETTINGS readiness and bounded tunnel state.
- [ ] Implement caller-owned H3 session and shared-runtime tunnel interfaces,
  preserving ordinary Fetch/EventSource behavior and unknown-operation semantics.
- [ ] Publish the actual adapter/ownership/event/credit API in the owned contract
  document; Task D implements against this API, not a guessed parallel runtime.
- [ ] Add versioned draft-17 SETTINGS without changing historical codec behavior;
  implement bounded capsule/HTTP-DATAGRAM and WT stream-routing primitives needed
  by Task D within these owned H3 layers.
- [ ] Add explicit `http_version: :http3` WebSocket selection, RFC 9220 handshake
  and existing frame/Close/credit integration without automatic fallback.
- [ ] Verify an independent server, exact text/binary/fragmented data, ping/pong,
  Close plus FIN order, settings refusal, cancellation, limits and sibling isolation.
- [ ] Rerun affected H1/H2 WebSocket and Fetch/EventSource H3 regressions.

Do not change QUIC/TLS engines, WebTransport files, root lockfile, root tooling or
shared existing protocol harnesses. Task D owns the WebTransport network adapter,
session lifecycle and profile-specific acceptance. Task C owns all shared H3
parsers/runtime code, including dependency-driven changes requested by Task D.

## Task D: WebTransport draft-17 client and independent acceptance

Exclusive write ownership:

- `apps/http_web_transport/**` (including its scoped exact internal dependency).
- New `scripts/webtransport/**`.
- `docs/superpowers/plans/2026-11-08-webtransport-client.md`.
- `docs/webtransport-peer-profile.md` and `docs/webtransport-validation.md`.

- [ ] Find and pin an independently implemented draft-17/reliable-reset server,
  recording immutable source/tool identity and actual negotiated capabilities.
- [ ] Plan the single-session profile, bounded public queues/waiters/streams,
  owner monitoring, deadline/unknown-operation and terminal-event behavior.
- [ ] Implement independently testable capsule/profile/session/API regressions
  in owned files while the shared H3 and QUIC prerequisites are being implemented.
  Keep protocol parsing owned by Task C; do not duplicate it as a workaround.
- [ ] Once Task C's actual contract is available, connect the default QUIC backend
  to its owner/tunnel/WT interfaces and add the exact `http_runtime` dependency.
- [ ] Require Task A's real negotiated reliable-reset and QUIC capabilities before
  draft-17 session admission. Never substitute ordinary RESET_STREAM.
- [ ] Exercise both-direction bidi/uni streams, FIN/reset, empty/duplicate/boundary
  datagrams, reordered association, refusal, close/drain, owner death and cleanup.
- [ ] Report browser compatibility separately. If no matching independent peer is
  available, stop only the affected acceptance gate and keep capability false;
  continue safe independent work without substituting old aioquic acceptance.

Do not edit shared H3/core/runtime, QUIC, TLS, root manifests or CI. Dependency
requests for Tasks A/C go in the owned profile/validation documents with concrete
required behavior. Do not change gaoxy or the independent peer to mirror us.

## Coordinator: integration and shared policy

The parent chat owns this plan, approved-spec status, root docs/manifests/tooling,
package-inventory/CI changes and final integrated verification. These files have
no child writer. Update inventories only after actual dependency changes are
known. Publication remains publication-only; ordinary validation stays in its
dedicated workflows.

- [x] Record user approval and concurrent task/file ownership.
- [x] Start all four local-project tasks using the saved http_fetch project.
- [x] Confirm initial task progress with compact bounded snapshots.
- [x] Review real provider/H3/transport contracts and remaining dependent steps.
- [x] Integrate finished changes and run relevant combined checks without
  concurrent shared build/test state.
- [x] Report each milestone's result, real blockers and unrun evidence honestly.

Coordinator checkpoint: `docs/http3-quic-integration-validation.md`. All four
task turns are completed/idle. Fresh combined regression passes 1,077 tests;
strict compilation and three independent WebSocket/H3 gates pass with unchanged
source hashes. The programme remains incomplete: QUIC negative acceptance and
live WebTransport integration/matching independent-peer acceptance remain open.

No child task should claim the whole programme complete. Completion of setup or
one lane does not complete the remaining dependent implementation or acceptance.

## Subsequent delivery authorization

On 2026-11-08 the user separately requested integrating the completed source into
main, then creating a patch version on GitHub. The checkout was already on main;
the coordinator may commit the scoped changes there while preserving the user's
untracked file. Version naming and GitHub-only versus unified GitHub/Hex scope
are being clarified before any publication. This later authorization supersedes
the earlier no-commit restriction for the coordinator, without granting child
tasks new Git authority or changing the recorded incomplete acceptance.
