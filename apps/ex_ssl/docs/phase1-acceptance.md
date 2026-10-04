# Phase 1 acceptance and downstream handoff

Date: 2026-09-28. Scope and sequencing:
[phase1-implement-plan.md](phase1-implement-plan.md). Public API and option/limit
definitions: [QUIC_TLS_INTERFACE.md](QUIC_TLS_INTERFACE.md). This report records
the initial validation and subsequent authorized release preparation; earlier entries in [QUIC_TLS_IMPLEMENTATION.md](QUIC_TLS_IMPLEMENTATION.md)
remain historical evidence, including their failed full TCP integration runs.

## Source identity and environment

- Repository: `https://github.com/gsmlg-dev/ex_ssl`, branch `main`.
- Initial HEAD: `bcb946d40327c68f238df5fd66d945d90f251af4` (QUIC absent).
- Reviewed base after verified fast-forward:
  `02eb981f59d4e182d4473e264a9f8b093ec6bf3d`, version field `0.7.1`.
- Pre-existing dirty entry: untracked `01-ex_ssl-plan.md`, preserved unchanged;
  SHA-256 `ce92e3b6caa09fb22a96b8f733a42461f690a304eda10bf05025e8c286296d68`.
- Runtime: NixOS 26.05, Linux x86_64; Elixir 1.18.5 compiled for OTP 28;
  OTP 28.5.0.5 / ERTS 16.4.0.5; OTP crypto and OpenSSL CLI 3.6.3;
  Python 3.13.15 with OpenSSL 3.6.3; pinned aioquic 1.2.0 reference.
- Implementation commit: `f1327e0bb7fb2093b8dc2b07e72b26233a739963`.
  ex_quic can pin this immutable source commit. The reviewed base SHA does not
  include the fix. The initial delivery was uncommitted; the user subsequently
  authorized commit, push and the next release on 2026-09-28.
- Release target: `0.7.2` (patch: invalid-input validation, no new API or feature).
  The existing Release workflow validates and publishes Hex, then creates a
  version-only commit/tag and GitHub release. Release preparation is not proof
  of publication; verify the workflow result and `v0.7.2` tag before consuming
  the released version.

The sole changed runtime source file is `lib/ssl/quic/config.ex`, SHA-256
`452dcbd478b2bae35817ece952facbeb0c74ed27dc701d9fe2e8ceed25d4fddb`.
All other tracked files under `lib/` match the reviewed base. A release version
change in `mix.exs` is separate from this runtime correction. The checksum
identifies the tested source file, not a published package.

## Actual changes

- `lib/ssl/quic/config.ex`: validate IPv4/IPv6 component ranges and parse textual
  IP reference identities at `new/2`. Previously malformed IPs could emit a
  ClientHello and fail later; they now return the existing redacted configuration
  error without state/actions. No shared TLS core or TCP behavior changed.
- `test/ssl/quic_phase1_contract_test.exs`: public real-handshake order and
  authentication milestones, both-role abort, diagnostic redaction and bounded
  fragmented/coalesced post-handshake ticket handling.
- `test/ssl/quic_config_contract_test.exs`: public configuration, trust and IP
  identity negatives, independent SNI, opaque ALPN and fresh explicit profiles.
- `scripts/phase1_consumer_smoke.sh`: unpublished package plus normal standalone
  consumer build/startup in a fresh VM, including public QUIC API use and an
  assertion that OTP `:ssl` is not started.
- Authority/documentation: updated `QUIC_TLS_INTERFACE.md`, linked this run from
  `QUIC_TLS_IMPLEMENTATION.md`, and added the phase-one plan and this report.

## Validation record

PASS means executed successfully in the environment above. NOT RUN is not a
passing result. Commands use the repository root unless stated otherwise.

| Command/check | Status | Observed result |
| --- | --- | --- |
| `git status --short`, `git rev-parse HEAD`, `elixir --version`; `git ls-remote origin refs/heads/main`, `git fetch origin main`, `git rev-list --left-right --count HEAD...origin/main`, `git merge --ff-only origin/main` | PASS | Initial checkout recorded; 0/9 ahead/behind; fast-forward to the requested base; user plan checksum unchanged |
| `mix test test/ssl/quic_test.exs test/ssl/fingerprint_test.exs --seed 101` before changes | PASS | 1 property + 36 tests, 0 failures |
| New config regression before repair: `mix test test/ssl/quic_config_contract_test.exs` | FAIL (expected red, fixed) | Initial 3-test version rejected the expected contract: out-of-range IPv4 tuple returned success. Final 7-test textual-IP red run had 1 failure: `not-an-ip` returned success |
| Same configuration module after final repair | PASS | 7 tests, 0 failures, including real textual/tuple IPv4/IPv6 handshakes |
| `mix format --check-formatted` | PASS | Exit 0 on final source/tests |
| `mix compile --warnings-as-errors` | PASS | Exit 0 on final source |
| `env MIX_ENV=test mix compile --warnings-as-errors` | PASS | Exit 0 on final source/tests |
| Public contract command below | PASS | 50 checks: 1 property + 49 tests; 0 failures, excluded or skipped |
| Shared-core command below | PASS | 140 checks: 7 properties + 133 tests; 0 failures, excluded or skipped |
| `./scripts/ci_preflight.sh` | PASS | Required crypto/independent-peer capabilities present; exact runtime recorded above |
| TCP interop command below | PASS | 18 tests; 0 failures, excluded or skipped; includes OTP, OpenSSL, STARTTLS and HRR |
| `python3 -m venv _build/phase1/quic-reference-venv` and `_build/phase1/quic-reference-venv/bin/pip install -r e2e/quic_tls/requirements.txt` | PASS | Pinned test-only reference installed |
| `QUIC_TLS_PYTHON="$PWD/_build/phase1/quic-reference-venv/bin/python" mix run e2e/quic_tls/run.exs` | PASS | 13/13 scenarios, repeated on final source; both roles, three suites, RSA/ECDSA, optional client identity, complementary secret digests, ALPN, parameters and completion |
| `bash scripts/phase1_consumer_smoke.sh` | PASS | Repeated on final source; package/consumer compile and fresh-VM normal startup; no OTP `:ssl` application started |
| `bash -n scripts/phase1_consumer_smoke.sh`; `git diff --check` | PASS | Exit 0 |
| Static `rg -n ':ssl\.' lib` | PASS | No runtime calls found (expected search exit 1); fresh-VM smoke separately verifies startup |

Exact scoped commands:

```sh
CI_REPORT_DIR="$PWD/_build/phase1/public-contract" ./scripts/ci_run_suite.sh --seed 101 \
  test/ssl/quic_test.exs test/ssl/quic_phase1_contract_test.exs \
  test/ssl/quic_config_contract_test.exs test/ssl/fingerprint_test.exs

CI_REPORT_DIR="$PWD/_build/phase1/core-contract" ./scripts/ci_run_suite.sh --seed 101 \
  test/ssl/protocol/server_hello_test.exs \
  test/ssl/protocol/handshake_machine_test.exs \
  test/ssl/protocol/server_flight_verifier_test.exs \
  test/ssl/protocol/server_flight_test.exs \
  test/ssl/protocol/resumption_hrr_test.exs \
  test/ssl/protocol/resumption_verifier_test.exs \
  test/ssl/protocol/client_authentication_test.exs \
  test/ssl/pkix/pkix_test.exs test/ssl/client_hello/materializer_test.exs

CI_REPORT_DIR="$PWD/_build/phase1/tcp-interop" ./scripts/ci_run_suite.sh \
  --include integration --seed 103 \
  test/ssl/connection_interop_test.exs test/ssl/p384_interop_test.exs
```

The shared-core and TCP checks ran before the configuration-only correction;
their source files were not modified. The final public-contract, independent
aioquic and packaged-consumer runs include the correction. Public suites include
13 new tests (6 lifecycle/action tests and 7 configuration tests). No existing
test was weakened or deleted.

Local disposable logs under `_build/phase1/`: `preflight.log`, `aioquic.log`,
`consumer.log`, and each suite's `mix-test.log` / `mix-test-summary.txt` in
`public-contract/`, `core-contract/`, `tcp-interop/`. These ignored build artifacts
are not published evidence; commands and observed counts are retained here.

## G-S decision

**PASS for the identified working-tree candidate on Elixir 1.18.5 / OTP 28.5.0.5.**
This is a scoped TLS-contract gate, not a claim that all repository suites or
runtime combinations pass. There is no remaining in-scope implementation blocker.
Immutable downstream Git pinning is available at implementation commit
`f1327e0bb7fb2093b8dc2b07e72b26233a739963`. Publication status is separate from
this local gate; see the release preparation entry above.

| Requirement | Status | Evidence |
| --- | --- | --- |
| Five public call signatures and ordered actions | PASS | Packaged export checks; real-handshake exact action sequence; no changes to `lib/ssl/quic.ex` |
| Both roles, complementary directional secrets and authentication boundaries | PASS | Existing duplex tests + new milestone assertions + independent 13-scenario reference; server's `peer_authenticated` remains false without a client certificate request |
| CA/DNS/IP/ALPN failures; SNI is not identity | PASS | Wrong CA and wrong DNS/IP real flights; matching SNI cannot rescue wrong IP; unrelated SNI with matching IPv4/IPv6 succeeds; no-common/unoffered ALPN rejects |
| Invalid configuration and resource boundaries | PASS | Unknown/duplicate options and nested limits, verify_none, identity/key mismatch, invalid IPs, ALPN lengths, certificate/extension/signature/message/cumulative limits |
| Fragmentation, levels, failure/abort terminal behavior | PASS | Bytewise and coalesced feeds; exact closed results after failure/abort; no repeated action/completion |
| Tickets and forbidden post-handshake input | PASS | Fragmented/coalesced valid tickets ignored without actions or retention; cumulative bounds enforced; KeyUpdate/PHA reject with existing explicit error domains |
| No downgrade, protocol-specific default or sensitive diagnostics | PASS | Required trust/reference; opaque non-UTF-8 ALPN negotiated unchanged; fresh decoded key shares/random with stable fingerprints; Inspect/info checks and normal-handshake empty log capture |
| Actually consumable source identified | PASS (committed source) | Implementation SHA + runtime file checksum + successful unpublished package/consumer test |

## Supported boundary and remaining work

Both record-free TLS 1.3 certificate-handshake roles, local-direction traffic
secrets, generic opaque ALPN, explicit client trust/DNS/IP authentication,
transport-parameter authentication, HRR, bounded ignored client-side tickets,
fresh ClientHello profiles and derived fingerprints remain supported. Server TLS
completion does not authenticate a client certificate identity. Parameters are
opaque TLS-authenticated bytes; their QUIC semantics belong to ex_quic.

QUIC packets/CRYPTO offsets/reliability/stream flow control/lifecycle networking,
HTTP/3/QPACK, DNS/DoQ, 0-RTT/resumption and server mTLS remain outside this change.
No `:quic_h3` shim or application-protocol hardcoding was added. Abyss and other
application servers consume this contract through ex_quic.

At initial local acceptance, NOT RUN: full repository test/integration suites,
other Elixir/OTP matrix tuples, remote CI dispatch and live Caddy fingerprint e2e.
Subsequent release/CI runs are separate evidence from these local results. The latter is CI-only per
`e2e/README.md`. Historical full-suite TCP failures are not fixed or relabeled
PASS by this scoped run. Independent HRR remains NOT RUN: pinned aioquic 1.2.0
cannot perform HRR; local protocol tests are not an independent HRR oracle.
No full QUIC network interoperability or production-security certification is
claimed. The implementation commit is now available for downstream Git pinning;
release publication must be verified separately.
