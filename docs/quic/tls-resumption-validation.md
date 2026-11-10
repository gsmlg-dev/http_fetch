# QUIC TLS resumption provider evidence — Task B

Scope: `apps/ex_ssl`, new `scripts/quic_tls_features`, the Task B plan and TLS
contract/evidence documents. No transport engine, Abyss, HTTP consumer, root
manifest, lock, version, branch, worktree, commit or release is changed by this
lane. Other lanes concurrently modify the checkout; the following evidence is
scoped to the ExSSL provider and its existing TCP policy.

## Implemented provider

- Public `SSL.QUIC.continue/3`, bounded/redacted `Session` and `Request`, one
  outstanding continuation, recoverable stale/mismatched/duplicate IDs, pending
  input backpressure and terminal secret cleanup. One owner must thread the
  current immutable state; endpoint atomic consumption is outside this API.
- Exact identity-zero PSK binder verification, SHA256/SHA384 and legal additional
  identities; fresh PSK-DHE; committed CH1 before resumed HRR, rewritten CH2 binder
  and no second lookup/commit. Selected binder and Finished failures are fatal.
- Client revalidation under current trust/name/certificate algorithm policy,
  context/SNI/ALPN/expiry checks and fresh authenticated fallback for ineligible
  sessions. Existing TCP resumption and early-data policy remains in effect.
- One server store request after verified client Finished, NST only after store
  acknowledgment, optional store failure and bounded private client receipts.
  QUIC early-data NST maximum is `0xffffffff` and is checked even when caching is
  disabled. Receipt count is bounded to four and then releases the retained RMS.
- Separately enabled R2 client early write/server early read secrets. Server
  secret/acceptance requires positive atomic commit with runtime policy/quota
  admission; HRR, incompatible cipher/age and quota decline reject early data.
  Completion still requires verified Finished. No EndOfEarlyData, application
  delivery, automatic replay, packet keys or QUIC transport state is implemented
  in this lane.

The exact actual option/action/reply shapes and runtime obligations are in
[tls-continuation-contract.md](tls-continuation-contract.md).

## Verification environment and commands

Commands run from the umbrella root, with installed dependency sources and no
`deps.get`. Common environment:

```sh
ERL_FLAGS='+S 2:2' MIX_ENV=test HTTP_FETCH_CI_APP=ex_ssl \
MIX_BUILD_PATH=/tmp/http-fetch-quic-tls-B-20261108/test
```

Local runtime: Elixir 1.18.5 / OTP 28. ExUnit uses at most four cases. Build
output is task-owned under `/tmp`; root `_build` is not written by these commands.

| Gate | Result / evidence |
| --- | --- |
| `mix compile --warnings-as-errors` | PASS |
| `mix test apps/ex_ssl/test` | PASS: 703 tests + 20 properties executed; 2912 integration/E2E cases excluded (raw footer: 20 properties, 3615 tests, zero failures) |
| Existing TCP OpenSSL resumption/manual-ticket/HRR plus QUIC config integration | PASS, 29 tests, zero failures |
| Existing independent record-free certificate/reference gate | PASS, 13 scenarios, both roles, three suites, EC/RSA identity and client identity |
| New independent full+resumed provider gate | PASS, 12 full+resumed pairs (24 handshakes), both roles, three suites, early off/on |
| Deterministic binder/early-secret vectors | PASS, eight stdlib Python HKDF/HMAC vectors: SHA256/SHA384 × one/two identities × initial/HRR-prefix |
| Owned explicit formatting and diff checks | PASS: explicit changed Elixir paths and scoped `git diff --check`; vector reproduction is byte-identical |

Integration command:

```sh
mix test apps/ex_ssl/test/ssl/resumption_interop_test.exs \
  apps/ex_ssl/test/ssl/manual_ticket_integration_test.exs \
  apps/ex_ssl/test/ssl/protocol/resumption_hrr_test.exs \
  apps/ex_ssl/test/ssl/quic_config_contract_test.exs --include integration
```

Independent peers use `/tmp/http-fetch-quic-tls-B-peer/bin/python`, installed from
`apps/ex_ssl/e2e/quic_tls/requirements.txt` (aioquic 1.2.0). Both scripts have
bounded request deadlines and close their owned peer processes. They use public
`SSL.QUIC` calls and compare SHA256 digests of all directional handshake and
application secrets; resumed early-enabled pairs additionally match the early
secret and negotiated acceptance. Secrets/tickets are not printed.

```sh
QUIC_TLS_PYTHON=/tmp/http-fetch-quic-tls-B-peer/bin/python \
  mix run apps/ex_ssl/e2e/quic_tls/run.exs
QUIC_TLS_PYTHON=/tmp/http-fetch-quic-tls-B-peer/bin/python \
  mix run scripts/quic_tls_features/run.exs
python3 scripts/quic_tls_features/binder_vectors.py
```

Logs under `/tmp/http-fetch-quic-tls-B-`: `compile-final.log`, `unit-final.log`,
`integration.log`, `existing-peer.log`, `resumed-peer.log`. The vectors JSON is
checked in under `apps/ex_ssl/test/fixtures/quic_binder_vectors.json`; the Python
script reproduces it byte-for-byte. Vectors contain public synthetic secrets.

## NOT RUN / dependent acceptance

Full R1/R2 QUIC network acceptance depends on Task A's actual endpoint-local
cache/authority/runtime integration. This lane has not exercised real resumed
QUIC packets, early STREAM/DATAGRAM packets, server delivery barriers, atomic
concurrent claims, authority deadline/late-reply/restart/eviction/quota settlement,
address amplification or combined migration. Provider stub/loopback assertions
are not used to claim those gates. The independent TLS harness above uses a
control pipe and no QUIC packet protection or sockets.

Independent HRR resumption against aioquic is NOT RUN (pinned aioquic 1.2.0 has
no HRR support); rewritten transcript/binder behavior has deterministic and
provider-duplex tests. Superseded for the runtime: HRR resumption and HRR 0-RTT
rejection now PASS against Go `crypto/tls` in unmodified quic-go v0.62.0 (R1/R2
negative matrices, CI-confirmed on `1d5dbe7`).
Whole-repository integration/E2E, browser/provider/production acceptance,
Dialyzer, release/package artifacts and remote CI are NOT RUN in this lane.
Capability flags `SSL.QUIC.capabilities().resumption` and `.zero_rtt` were gated
on the full runtime acceptance. Update 2026-11-10: the R1/R2 runtime positive and
negative matrices (including HRR resumption, peer 0-RTT rejection, Retry + 0-RTT
and late 0-RTT receipt) pass against independent peers and are CI-confirmed on
`1d5dbe7`, so both flags are now true. Rows that require a dishonest peer
(invalid binder, server receive quotas, trust/profile partition mismatch) are
accepted with in-repo evidence by ruling; see
[client-features-validation.md](client-features-validation.md#capability-decision-2026-11-10).
The provider-scoped NOT RUN items above remain as stated for this lane.
