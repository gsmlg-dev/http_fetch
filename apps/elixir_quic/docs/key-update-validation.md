# Native QUIC peer key-update validation

Validated in `codex/http3-completion` against baseline
`5f801df93472aebe7f304be008851843fae1dc99` (0.16.4), with the existing
NEW_TOKEN repair retained. Internal transport blockers:
[NEW_TOKEN #17](https://github.com/gsmlg-dev/http_fetch/issues/17) and
[RFC9001 key update #18](https://github.com/gsmlg-dev/http_fetch/issues/18).
Both are repaired in the imported native source in this umbrella.

## Root cause and resulting behavior

Caddy 2.8.4 completed authenticated `h3` readiness and then sent a key-phase1
packet at PN84, following successfully authenticated application PN83. The
original scheduler ignored the phase bit and discarded the application
traffic secret after deriving packet keys. It reported `:bad_tag` and the
connection closed. An independent diagnostic derived the next traffic secret
with RFC9001 `quic ku` and authenticated the exact failing packet. Diagnostic
output contained packet metadata and authentication booleans only.

Application secrets now remain in the internal protection context. An
authenticated peer phase change derives the next read and write protection
keys, preserves the original header-protection keys, and changes the outgoing
phase before an ACK is built. A failed authentication does not advance keys,
packet numbers, ACK state, stream data, TLS state, or the connection's idle
deadline. The scheduler still returns `:bad_tag`; the connection discards
that precise authentication failure without altering its state.

The receiver retains at most one previous read generation for reordering and
accepts it only below the earliest authenticated current-phase packet number
and before three PTO durations from the transition. A later authenticated
packet clears expired retained keys. A subsequent peer update requires an
actually successful local send of an ACK covering the current generation.
Authenticated updates before handshake confirmation or with invalid packet
number ordering produce transport KEY_UPDATE_ERROR (`0x0E`).

This repair responds to peer-initiated updates. It does not add a public
local-update API or automatic local key-usage-threshold policy.

## Deterministic regressions

`test/quic/key_update_test.exs` constructs wire packets with independently
implemented single-block RFC8446 HKDF-Expand-Label and OTP AEAD/header
protection primitives. It covers:

- Authenticated phase0-to-phase1 transition and independently decrypted ACK
  under the new write keys, retaining the original header-protection keys.
- Reordered previous-phase packets without rolling back current keys.
- Tampered next-phase packets with unchanged scheduler state, followed by
  acceptance of the valid packet.
- Authenticated update before handshake confirmation.
- Phase wrap to phase0, the successful ACK-send barrier, and bounded previous
  generation retention.
- Previous-key expiration at three PTOs.
- Invalid next-phase packet-number ordering.
- Native connection authentication discard with exact full-state equality,
  followed by acceptance of a valid datagram.

All eight regressions failed against the pre-repair behavior. After the
repair, the scoped native suite passes **235 tests, zero failures**, including
the existing 227 tests and retained NEW_TOKEN tests.

## Caddy wire gate

Peer: `caddy:2.8.4@sha256:226d1f059b75399fe19182893c7184591c07b97afc8dfcf44eeb80c9a77a530f`,
container `http3-caddy-probe`, host-network UDP/TCP48443 with echo upstream
TCP48080. `caddy version` reports `v2.8.4`.

Run from the umbrella root:

```sh
HTTP3_PEER_PORT=48443 HTTP_FETCH_CI_APP=elixir_quic_http3 MIX_ENV=test \
  mix run scripts/http3/session_gate.exs
```

**PASS:** authenticated `h3` readiness, POST of 61,725 bytes with explicit
content-length, status200, exact binary echoed DATA, and zero retained
terminal requests. A sanitized native runtime trace records accepted peer
`generation: 1, phase: 1, first_received: 84` during a second successful run.
The gate's historical output label names aioquic; the peer for these runs was
the pinned Caddy container above.

## Scoped local checks

```sh
HTTP_FETCH_CI_APP=elixir_quic MIX_ENV=test mix compile --warnings-as-errors
HTTP_FETCH_CI_APP=elixir_quic MIX_ENV=test mix test apps/elixir_quic/test
mix format --check-formatted apps/elixir_quic/lib/quic/handshake_scheduler.ex \
  apps/elixir_quic/lib/quic/connection.ex apps/elixir_quic/test/quic/key_update_test.exs
HTTP_FETCH_CI_APP=elixir_quic MIX_ENV=test mix credo \
  apps/elixir_quic/lib/quic/handshake_scheduler.ex \
  apps/elixir_quic/lib/quic/connection.ex apps/elixir_quic/test/quic/key_update_test.exs
```

Compile, tests, formatting, and configured scoped Credo: **PASS**.
Optional strict scoped Credo reports four unchanged baseline low-priority
style findings: two explicit-try preferences in `connection.ex` and alias
ordering in `connection.ex` and `handshake_scheduler.ex`. No new strict
findings remain. These baseline lines were preserved.

HTTP/3 runtime/Fetch acceptance, Dialyzer, remote CI, and publication are
separate gates and are not established by this transport validation.
