# Server peer migration acceptance (M1)

The accepted milestone preserves an established Quic/Abyss server connection
when its authenticated client changes source port, then IP address. The approved
design is `docs/superpowers/specs/2026-11-07-quic-migration-and-early-data-design.md`
at `91c18288b86b86634890de36fc0ac929eab8b6fd`. Client-initiated local migration,
resumption and 0-RTT remain separate milestones.

## Independent UDP gate

On 2026-11-07 both standalone Quic and the Abyss shared listener passed against
aioquic **1.2.0**, with an explicit eight-byte peer CID length and verified local
certificate. The gate owns three relay sockets: two ports on `127.0.0.1`, then
one on `127.0.0.2`. It retains the old sockets so an old-path challenge can reach
the client and its response can arrive through the newly selected path.

Each run proved:

- Exactly two ready connections and two streams: one migrating, one control.
  Each independent peer completed one handshake; server and peer stream IDs
  remained unchanged across all phases.
- Migrating stream: 6,220 exact bytes, SHA-256
  `bdd6f8708774f182655f2496d4727665b37004db61e4ecc843a0a51deff65800`.
  Control stream: 6,214 exact bytes, SHA-256
  `6dbd8932ed9869f201769969fe3d30efe9add5d03bcfcba1314203e369e32ec5`.
  Both ends observed the exact bytes and one FIN per stream.
- Three distinct DATAGRAM markers were sent per connection per phase. All three
  were observed in these runs; the gate requires at least one and does not
  introduce retransmission or a reliable-DATAGRAM contract.
- Port rebinding retained the incoming CID. The IP phase rotated it, and actual
  server short headers used a different outgoing CID from both old destinations.
  A probe sent to the retained old path kept that path's outgoing binding.
- Public observations selected the expected remote, with validated reachability
  and a 1200-byte MTU certificate for both migrated phases. At most two path
  records were live; the port phase settled to one before the IP phase began.
  Initial paths truthfully reported no migration MTU certificate.
- The peer and server exited successfully, the server emitted its shutdown
  receipt, and both owned process groups were joined/cleaned within finite bounds.

Prepare from the umbrella root, then run:

```sh
MIX_ENV=test mix deps.get --check-locked
MIX_ENV=test mix compile --warnings-as-errors
MIX_ENV=test python3 scripts/migration/gate.py --mode standalone --timeout 30
MIX_ENV=test python3 scripts/migration/gate.py --mode abyss --timeout 30
```

An explicit task-owned `MIX_BUILD_PATH` may be used for all preparation and gate
commands. `--project /absolute/consumer` selects an already-built isolated Hex
consumer; tools and certificates remain source fixtures, while executable app
modules come from that consumer's dependency closure. The existing server
candidate/published consumer gate requires both modes after checking Hex.SCM,
exact versions and module provenance.

JSONL receipts for the initial source runs are in
`/tmp/http-fetch-quic-m1-barBLX/{standalone,abyss}-final.log`; the verification
record there retains earlier failures and repairs. CI's Integration migration
matrix stores receipts as artifacts. Release requires the same source traffic
gates plus fresh candidate and published consumers. Publication is a later gate;
the source acceptance above does not itself establish a published package.

## Deterministic regressions

The QUIC source closure passed 408 unit/integration cases, including the public
server-only capability assertion. New pure and runtime regressions cover forged
sources, malformed unauthenticated known-path headers, preconfirmation/third-path
rejection, every probing frame shape, reordered packet/CID selection, short vs
padded challenges, wrong/duplicate/stale responses, and response arrival on another
path. They also cover independent reserved amplification credit, old-path late
ACK/receipts, larger-new-PTO deadlines, congestion-blocked probing, validation
loss/fallback, unavailable-CID selection, reliable pending-send recovery without
DATAGRAM replay, CID registration/publication ordering, and bounded CID churn.

The full eleven-app source suite also passed with seed `28092026`, including
integration and slow cases: 7,762 tests, 23 doctests and 20 property checks, with
zero failures. Strict test/default compilation, formatting, Credo and Dialyzer
passed. Documentation generated successfully; unrelated existing link and
hidden-module warnings remain recorded. E2E and distributed publication are
separate workflow gates.

The initial pre-feature traffic baseline completed both initial exchanges, then
timed out after the source-port change. Subsequent failures exposed TLS option
leakage, a stale routing test hook, probe padding accounting and a duplicate
post-FIN harness notification. Their logs remain in the verification directory;
none counts as a passing acceptance run.

This evidence covers controlled localhost address changes. Arbitrary middleboxes,
long-running production churn, multipath, server address migration and an explicit
client migration operation are not established by these gates.
