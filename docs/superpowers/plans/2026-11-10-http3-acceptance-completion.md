# HTTP/3 Acceptance Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the open HTTP/3 acceptance items so every client's HTTP/3 path is backed by independent-peer evidence in CI, and flip the engine `resumption` / `migration.local` capability flags once their negative matrices pass.

**Architecture:** No new client features — Fetch, EventSource, WebSocket and WebTransport already speak HTTP/3 (streaming uploads included). Work is (1) wiring existing local independent gates into CI, (2) a new HTTP-level migration gate against quic-go/http3 (which answers path probes, unlike aioquic), (3) the engine negative acceptance matrices against quic-go, then (4) capability flags and docs.

**Tech Stack:** Elixir umbrella (`elixir_quic`, `elixir_quic_http3`, `http_runtime`, clients), Python 3.12 + uv + aioquic 1.2.0, Go 1.26 + quic-go (pinned v0.62.0 in `scripts/quic_client_features/`), GitHub Actions.

**Spec:** `docs/superpowers/plans/2026-11-09-http3-remaining-work.md` (roadmap + contracts), `docs/quic/client-features-validation.md` (acceptance table), `docs/http3-extensions-contract.md`.

## Global Constraints

- Work on `main`; no branches or worktrees.
- Independent peers are unmodified upstream releases, pinned by exact version/commit. A patched peer is not independent evidence.
- `Quic.capabilities().http3` stays `false` by design (raw QUIC owns no HTTP/3; `QuicHttp3.capabilities()` reports HTTP/3).
- A capability flag flips only after its full positive + negative matrix passes against an independent peer; otherwise it stays false and the doc says why.
- Gates are fail-closed, bounded in time, own and terminate every peer process, and record exact peer versions.
- Do not weaken existing tests or gates.

## Baseline (2026-11-10, local, HEAD 2ee2ce6)

| Gate | Result |
| --- | --- |
| `scripts/http3/alt_svc_gate.py` (Python ssl origin + aioquic 1.2.0) | PASS: learned h3, 21 H3 requests; blackhole and closed-port fallback in ~2 s |
| `scripts/http3/qpack_dynamic_gate.py` | PASS: 124 requests |
| `scripts/http3/resumption_gate.py` | PASS: full, resumed, 0-RTT GET/HEAD, 425 retry/passthrough, rejected 0-RTT re-send |
| CI | only `scripts/http3/public_gate.py` runs (`.github/workflows/http3-public.yml`) |

Upstream peer audit (2026-11-10): no released server implements WebTransport draft-17 (`SETTINGS_WT_ENABLED` 0x20b8933b); webtransport-go v0.13.0 is draft-16. Reliable reset `0x1d`/frame `0x24`: quic-go ≥0.62, picoquic, neqo (opt-in). quic-go/http3 v0.65.0 always advertises extended CONNECT and answers PATH_CHALLENGE on the arrival path.

## Rulings

- WebTransport independent acceptance stays BLOCKED (no draft-17 peer); `Profile.supported?/0` stays false. Adding a draft-16 interop profile is a product decision for the user, not part of this plan.
- Reliable-reset negative matrix uses quic-go (unmodified) for the peer-observable cases; malformed/decreasing-size frames that an honest peer never sends are covered by codec/engine tests and recorded as such, not claimed as independent evidence.

## Review Focus

1. A gate that passes when the peer never started (must fail closed on missing peer receipts).
2. Migration gate that "passes" without a real path change (must assert the peer observed the new client address and exact bytes after migration).
3. Flipping a flag while any matrix row is NOT RUN.
4. CI jobs that silently skip (path filters) — gates must run on changes to their owning apps/scripts.
5. Peer version drift — every gate prints and asserts the pinned version.

---

### Task 1: Run the existing independent HTTP/3 gates in CI

**Files:**
- Modify: `.github/workflows/http3-public.yml` (add steps or a job)
- Modify: `docs/superpowers/plans/2026-11-09-http3-remaining-work.md` (WP1 status → independent gate PASS with CI reference)

- [ ] Add CI steps running, with the same setup as the existing job: `scripts/http3/alt_svc_gate.py`, `scripts/http3/qpack_dynamic_gate.py`, `scripts/http3/resumption_gate.py`, `scripts/http3_websocket/gate.py` (read its header for the pinned peer venv), and the quic-go client-features gate under `scripts/quic_client_features/` (`wire_gates.py`; needs Go via `actions/setup-go` pinned to the repo's go.mod). Make the workflow's path filters include `scripts/http3/**`, `scripts/http3_websocket/**`, `scripts/quic_client_features/**` and the owning apps.
- [ ] Run each gate locally first; record results. Any failing gate is a real bug: diagnose and fix at the root (separate commit), do not skip.
- [ ] Commit.

### Task 2: HTTP-level migration gate against quic-go/http3

**Files:**
- Create: `scripts/http3_migration/peer.go`, `go.mod`, `go.sum` (quic-go/http3 pinned, unmodified; RFC 9220 extended CONNECT handler echoing WebSocket frames; reports each request's observed remote address per frame)
- Create: `scripts/http3_migration/gate.py` + `gate.exs` (launcher + Elixir driver), following `scripts/http3_websocket/gate.py` conventions
- Modify: `docs/http3-extensions-contract.md`, `docs/superpowers/plans/2026-11-09-http3-remaining-work.md` (WP5b status)
- Modify: `.github/workflows/http3-public.yml` (run it)

- [ ] Gate: WebSocket/H3 with `http3_reuse: false`; exchange message both ways; `HTTP.WebSocket.migrate/2` to a new local port; exchange both ways again; peer must report a different client address for post-migration frames, exact bytes, one connection, clean close. Fail closed on missing receipts. (Source-IP migration only where a 127.0.0.2 alias exists — CI Linux.)
- [ ] Negative: migrate on a pooled/shared connection returns the documented error without disturbing the session.
- [ ] Commit.

### Task 3: Engine negative acceptance — client migration (M2)

**Files:** `scripts/quic_client_features/` (extend `peer.go`, `migration.exs`, `wire_gates.py`), `apps/elixir_quic/test/**` for owner-death cases, `docs/quic/client-features-validation.md`.

- [ ] Independent negatives vs quic-go: peer `disable_active_migration`, no spare CID, migrate before confirmation, bind failure, deadline expiry with fallback to old path, duplicate ref, concurrent migrate (busy). Each asserts the connection keeps working on the old path.
- [ ] Forced owner death at every two-socket transition (candidate bound, probe sent, validated, old retiring) — all sockets/Ports closed, no leaked births (in-repo tests; quic-go peer for the wire side).
- [ ] Mark M2 negative row PASS only when all pass. Commit.

### Task 4: Engine negative acceptance — reliable reset, R1, R2

**Files:** same harness dirs (`scripts/quic_client_features/`, `scripts/quic_tls_features/`), engine tests, `docs/quic/client-features-validation.md`.

- [ ] Reliable reset vs quic-go: loss/reorder of RESET_STREAM_AT and prefix data (use the harness's loss injection), STOP_SENDING repeat, prefix > admitted, non-negotiated peer falls back to RESET_STREAM.
- [ ] R1: HRR resumption against Go `crypto/tls` via quic-go (forces HRR by key-share mismatch), trust/profile partition mismatch → full handshake, endpoint restart → no stale ticket, concurrent reuse single-use.
- [ ] R2: 0-RTT rejected by peer → re-send after handshake, invalid binder → full handshake, Retry + 0-RTT, quota exhaustion, late receipt.
- [ ] Record each row; commit.

### Task 5: Capability flags and docs

**Files:** `apps/elixir_quic/lib/quic.ex` (`capabilities/0`), its tests, `docs/quic/client-features-validation.md`, `docs/http3-fetch-contract.md`, `docs/http3-extensions-contract.md`, `CLAUDE.md`, CHANGELOGs.

- [ ] Flip `resumption: true` only if R1+R2 matrices are all PASS; `migration.local: [:port, :address]` (exact shape per `docs/quic/client-features-validation.md`) only if M2 is all PASS. Update tests asserting the flags.
- [ ] Update docs/CLAUDE.md HTTP/3 status lines. Commit.
