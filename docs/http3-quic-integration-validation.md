# HTTP/3 and QUIC cross-task integration checkpoint

Date: 2026-11-08. All four project task turns are completed/idle. Their completion
does not mean the full approved feature programme has passed acceptance.

## Reviewed task outcomes

| Lane | Implemented and reported checks | Remaining scope |
| --- | --- | --- |
| A: QUIC transport | Client local migration, draft-11 reliable reset, R1 and opt-in R2; 470 tests and seven independent positive wire gates reported PASS | Complete independent negative/adversarial acceptance, including transition owner death, HRR and concurrent ticket/quota/rejection cases |
| B: QUIC TLS | Pure continuation/binder/PSK-DHE/HRR/ticket and early actions; 703 unit cases, 20 properties, selected integration and 24 independent provider handshakes reported PASS | Complete transport acceptance belongs to A; independent HRR and wider analysis remain open |
| C: HTTP/3/WebSocket | Explicit extended CONNECT and WebSocket/H3; 530 scoped cases and three independent peer gates reported PASS | Live WebTransport owner integration absent; H3 public native-completion receipt remains explicitly unsupported |
| D: WebTransport | Bounded session/waiter/stream lifecycle, operation refs and draft-17 profile admission; 47 tests reported PASS | Default network backend remains unsupported; matching independent draft-17 peer and live owner integration required |

Provider/H3/transport contracts and validation documents were read in the
coordinating chat. Earlier lane notes that reliable-reset positive traffic was
pending are superseded by A's final source checkpoint: bilateral quic-go positive
traffic passed, while its complete independent negative matrix remains open.

The audited WebTransport peers have incompatible profiles. This is evidence
about the pinned implementations in `webtransport-peer-profile.md`, not a claim
that a compatible implementation does not exist anywhere. No legacy fallback,
ordinary-reset substitution or peer source patch was authorized or implemented.

## Fresh coordinator verification after all writers stopped

Evidence directory: `/tmp/http-fetch-h3-quic-integrated-EEvpod`.
The coordinator performed these checks directly; the table above is separately
identified as reviewed lane evidence.

Environment: Elixir 1.18.5 / OTP 28; `ERL_FLAGS='+S 4:4'`, `MIX_ENV=test`,
`MIX_BUILD_PATH=/tmp/http-fetch-h3-quic-integrated-EEvpod/test`. Existing dependency
sources were compiled into this new private build without `deps.get`, lockfile
edits or writes to root `_build`. Independent peer packages came from Task C's
private pinned aioquic/wsproto environment.

| Fresh combined check | Actual result |
| --- | --- |
| Root `mix compile --warnings-as-errors` | PASS, exit 0 |
| Combined targeted unit/integration closure | PASS: 1,077 tests, zero failures, exit 0 |
| Independent WebSocket/H3 positive gate | PASS, exit 0: exact messages, 256-KiB transfer/tiny window, fragmentation, Close/FIN, Ping/Pong, negative frames, ACK credit, TLS negatives, pooled sibling continuity |
| Independent missing-CONNECT-SETTINGS gate | PASS, exit 0: refusal without fallback |
| Independent withheld-SETTINGS gate | PASS, exit 0: no early CONNECT bytes, opening cancellation/deadline and owner-state cleanup |
| Source stability | PASS: the same app source/test, root mix.exs and mix.lock hash before/after both combined regression and independent gate runs |
| `git diff --check` | PASS |

The original checkpoint source hash is
`ff48b33f405ec2c39013c7f8c52dab3c3b920137bef893272b1a332b66caaeff`.
This hashes ordered relative paths and contents of app `.ex`/`.exs` files plus
root mix.exs/mix.lock. It identifies the source at the original checkpoint,
not a package artifact or permanent source freeze.

The 1,077-test closure was:

| Area | Tests / failures |
| --- | --- |
| Selected new/existing QUIC TLS provider/config/binder cases | 30 / 0 |
| QUIC engine, including integration | 470 / 0 |
| Shared H3 primitives | 28 / 0 |
| H3 engine | 142 / 0 |
| WebTransport application | 47 / 0 |
| H3 runtime | 65 / 0 |
| EventSource/H3 | 9 / 0 |
| WebSocket, including existing H1/H2 integration | 256 / 0 |
| Fetch/H3 and ordered request trailers | 30 / 0 |

Exact test paths/commands and exit codes are retained in `verify.py`,
`compile.log`, `tests.log`, and `summary.json` in the evidence directory.
The sequential peer commands are retained in `wire.py`, per-gate logs and
`wire-summary.json`. They ran:

```sh
python scripts/http3_websocket/gate.py
python scripts/http3_websocket/gate.py --settings-refusal
python scripts/http3_websocket/gate.py --hold-settings
```

## Pre-push TLS provider follow-up

Root `mix credo` subsequently identified five new findings in the QUIC TLS
provider and its test helper. The follow-up extracts the existing session
predicates into private helpers, simplifies equivalent `with` expressions and
groups two test-driver policy arguments. Validation rules, binder failure
handling and assertions remain unchanged.

Fresh evidence is retained separately under
`/tmp/http-fetch-h3-quic-integrated-EEvpod/followup`:

| Follow-up check | Actual result |
| --- | --- |
| Root `mix compile --warnings-as-errors` | PASS, exit 0 |
| Same combined targeted unit/integration closure | PASS: 1,077 tests, zero failures, exit 0 |
| Root `mix credo` | PASS: 894 files, no issues, exit 0 |
| Source stability during all three checks | PASS |
| Root `mix format --check-formatted` | PASS, exit 0 |

The follow-up source hash is
`a5d9eafec8627cad3ed7ee19d6ed914fd5cd6b7df140c68b286d63bb672e6dea`,
using the same hashing method. The original independent H3 gate results above
predate this behavior-preserving refactoring; those three standalone gates were
not rerun. This follow-up does not certify strict Credo, Dialyzer or docs.

## Open acceptance and delivery

Global capability fields still report local migration/resumption/early data and
WebSocket/H3/WebTransport as unsupported where the previous source contract did.
This checkpoint did not change those flags. Positive source/wire evidence is
recorded explicitly rather than inferred from a capability flag or task status.

WebTransport still needs both in-repository live H3/adapter integration and a
matching independent-profile gate. Missing live integration is unfinished work,
not an external dependency failure. Engine negative acceptance remains incomplete.
Strict Credo findings, raw Dialyzer warnings and documentation warnings reported
by the lanes remain uncertified; the follow-up only certifies ordinary root Credo.
The joint scope does not include a whole-repository quality/E2E run, browser,
production, remote CI, published artifacts or release verification.

Remote checks for the integrated `8c095fc` source were inspected before release.
Test, E2E, Public HTTP3 acceptance and Server packages passed. CI run
[`42490698385`](https://github.com/gsmlg-dev/http_fetch/actions/runs/42490698385)
reported the following failures:

| Check | Observed failure |
| --- | --- |
| QUIC Dialyzer | `streams.ex:92`: `new/1` opaque subtype differs from success typing |
| ExSSL Dialyzer | `quic.ex:181`: unreachable pattern |
| WebSocket Dialyzer | `web_socket.ex:178`: opaque completion pattern and map guard |
| WebTransport Dialyzer | `session.ex:1086`: unmatched return types |
| No-OTP production release proof | `complete production source census changed`; source audit stopped before runtime proof |

These checks have not been bypassed or certified clean. Integration and other CI
jobs were still running at that inspection. Detailed job logs and annotations are
retained under the evidence directory's `release-preflight` subdirectory.
Integration subsequently passed. After reviewing the failures, the user explicitly
accepted the current CI failures and authorized proceeding with RC10 publication.

The original coordinator checkpoint made no source changes or delivery actions.
The user subsequently authorized main integration and a GitHub patch release;
the follow-up above records the additional lint refactoring before push. Main
was pushed at `8c095fc`. The user confirmed `1.0.0-rc.10` through the existing
unified GitHub/Hex publication workflow. Publication results require separate
verification. The existing user-owned untracked plan remains preserved. The
overall implementation programme remains incomplete.
