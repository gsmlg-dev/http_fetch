# M3-E independent peer evidence

On 2026-09-24 both ordinary certificate-handshake directions passed against
**aioquic 1.2.0**, using Python 3.12.12 and Elixir 1.20.1 / OTP 29. The ALPN is
`ex-quic-test`. Certificate verification stays enabled with the disposable
`example.test` CA/leaf fixtures from the pinned ex_ssl dependency.

The current requested M3-E matrix passes in both roles, including Retry, packet
impairment and authentication negatives. See [acceptance mapping](m3-acceptance.md)
for scope and remaining wider milestones. Increment records below preserve the
validation order and earlier partial status; none is a general security claim.

| Scenario | Result |
| --- | --- |
| ex_quic client → aioquic server | passed; TLS_AES_256_GCM_SHA384 (0x1302), server certificate authenticated, QUIC confirmed |
| aioquic client → ex_quic server | passed; TLS_AES_128_GCM_SHA256 (0x1301), peer Finished and QUIC confirmation; no client-certificate identity claimed |
| ex_quic client → aioquic Retry server | passed; integrity tag, token echo, preserved ClientHello, increasing packet numbers and authenticated Retry CID |
| aioquic client → ex_quic Retry server | passed; authenticated expiring address-bound token, both handshakes and QUIC confirmation |
| Independent Initial/Handshake loss, reorder, duplicates, corruption | passed in both roles for the deterministic single-fault cases below |
| Independent wrong CA, hostname and ALPN | passed in both roles; exact failures recorded below |
| Independent ChaCha negotiation | not run; packet AEAD and RFC 8439 block/header-mask unit tests pass |

## Subsequent key-retirement regression

The [key-retirement increment](m3-key-retirement.md) reran all 20 cells above and
added both-role authenticated HANDSHAKE_DONE packet loss: 22/22 passed. Positive
runs now require independent QUIC confirmation in addition to HandshakeCompleted.
Its captures/results live in the separate `key-retirement/` fixture directory,
so the historical evidence below remains intact.

## Reproduction

From the repository root, with `uv` and the Mix dependencies available:

```sh
mix run scripts/interop/run.exs client _build/interop/client-final
mix run scripts/interop/run.exs server _build/interop/server-final
```

Both commands exited 0. The runner invokes:

```text
uv run --python 3.12 --with aioquic==1.2.0 python scripts/interop/peer.py ...
```

The exact resolved Python and aioquic versions are emitted into each result.
The aioquic version is fixed; transitive Python packages are not yet locked.
The runner requires both the independent peer's HandshakeCompleted event and
the local endpoint's established/confirmed state. It does not equate a UDP
send, TLS secret export or an open socket with handshake success.

Each run emits `result.json` and `udp.jsonl`. Successful baseline copies are
in `test/fixtures/interop/aioquic-1.2.0/`. Capture records contain exact raw UDP
payloads, peer socket addresses, monotonic timestamps and direction at the
Python transport boundary. They are **not kernel/pcap captures**. No traffic
secret or private key is logged. These are explicit test artifacts, not runtime
telemetry defaults. The captured source is the working tree introducing this
harness, based on parent `f35c8883ce7c96a1507543624769700a6d1484c7`.

## Defects exposed by the independent baseline

- Packet encryption/decryption ignored the installed AEAD and always called
  AES-128-GCM. The algorithm is now passed explicitly; Initial retains AES-128.
- NEW_CONNECTION_ID was an unknown frame, causing rejection of a packet also
  carrying HANDSHAKE_DONE. CID decoding, bounded peer CID state, consistency
  checks and retirement handling now preserve that confirmation path.
- Packet-number reconstruction preserved low epoch bits instead of high bits,
  producing wrong numbers across gaps/windows. Fixed expectations cover both.
- ChaCha header protection used the wrong OTP argument shape and IV order.
  The corrected primitive matches RFC 8439 section 2.3.2's fixed block prefix.

Remaining protocol lifecycle and resource edge cases from `m3-runtime.md` are
not waived by these two passing scenarios. At that baseline increment, the remaining independent network matrix was open;
subsequent records below supply its results.

Local gates on the final baseline increment: `mix format --check-formatted`,
`mix compile --warnings-as-errors`, `mix test` (97 tests, seed 531985), and
`git diff --check` all exited 0. Capture integrity digests are recorded in
`test/fixtures/interop/aioquic-1.2.0/SHA256SUMS`.

## Client Retry increment

```sh
INTEROP_SCENARIO=retry mix run scripts/interop/run.exs client _build/interop/client-retry-fixed
```

This command exited 0 on 2026-09-24 with aioquic 1.2.0 / Python 3.12.12 and
Elixir 1.20.1 / OTP 29. The result requires an observed Retry event in addition
to both peers completing their handshake. Captures/results are archived as
`client-retry-*` beside the ordinary baseline artifacts. Source parent:
`7b3986f27e832780cec8abe303fe20a72a06e78f`, with this Retry increment applied.

The independent test exposed an incorrect v1 Retry nonce. RFC 9001 Appendix
A.4 now supplies an independent fixed integrity vector rather than only a
locally generated round trip. Retry processing preserves original DCID and TLS
state, discards obsolete Initial recovery work without resetting packet-number
allocation, installs fresh Initial packet protection from the Retry SCID, and
echoes the token in the new Initial. Authenticated transport parameters must
match the Retry SCID; a Retry CID is forbidden when no Retry occurred.

The remaining independent impairment and negative-case matrix remains open.
Server-side Retry evidence follows below.

Retry increment local gates: format, warnings-as-errors compilation, all 100
ExUnit tests (seed 619226), and diff checks exited 0. Server Retry, independent
impairment and independent certificate/ALPN negatives were not run here.

## Server Retry increment

```sh
INTEROP_SCENARIO=retry mix run scripts/interop/run.exs server _build/interop/server-retry
```

Exited 0 on 2026-09-24 with aioquic 1.2.0 / Python 3.12.12 and
Elixir 1.20.1 / OTP 29. The aioquic client observed Retry and completed the
verified certificate handshake with ALPN `ex-quic-test`; the local server
reached established/confirmed with valid parameters and a validated address.
One Retry was sent and one token was admitted. Capture/results are archived
as `server-retry-*`, with SHA256SUMS. Source parent: `36bec72771de676213794ce278be4672bce691b8`,
with this server Retry increment applied.

Server endpoints opt in using `retry: true`. Tokens use an endpoint-generation
32-byte random HMAC key, bind the client IP/port, original DCID and Retry SCID,
and expire after `retry_ttl` monotonic microseconds (default 5,000,000; maximum
60,000,000). A restart invalidates them. Tokens are not single-use: retransmitted
Initials route to the existing connection; after connection removal a still-valid
token can admit another bounded connection from the same address. They prove
address reachability, not client identity.

`retry_limit` bounds issuance attempts per endpoint-wide one-second fixed window
(default 100, maximum 10,000); it is not a per-client fairness guarantee.
There is no per-peer token cache. A Retry response is smaller than the required
1200-byte incoming Initial. Nonempty invalid tokens are dropped without a new
Retry, and no connection is allocated before token validation. Original DCID
transport parameters remain separate from the Retry DCID used for Initial keys.

Unit tests mutate every token byte and cover expiry, future time, key replacement,
IPv4/IPv6, address/port/CID mismatch and bounded malformed inputs. UDP tests
cover pre-validation allocation, rate limiting, cross-address replay rejection,
duplicate routing and a real certificate handshake. At that increment, independent impairment and certificate/ALPN negative
scenarios remained pending; subsequent records below supply their results.

Server Retry local gates: `mix format --check-formatted`,
`mix compile --warnings-as-errors`, `mix test` (104 tests, seed 184043),
and `git diff --check` passed. The independent server Retry command exited 0.

## Deterministic independent impairment increment

All ten combinations of `client|server` and
`drop_initial|drop_handshake|reorder|duplicate|corrupt` passed (exit 0) on
2026-09-24 with the same aioquic/Python/Elixir/OTP versions above. Source parent:
`5a4856faf16e7086a58a64958f0e0f5004952f62`, with the harness changes applied.
Reproduce each cell with:

```sh
INTEROP_SCENARIO=<scenario> mix run scripts/interop/run.exs <role> _build/interop/<role>-<scenario>
```

Each case requires both completed/confirmed handshakes and an actual matching
`impairment` event. The fault is applied once at aioquic's UDP transport boundary:

- `drop_initial`: discard the first client Initial datagram.
- `drop_handshake`: discard the first server datagram containing Handshake.
  aioquic can coalesce Initial and Handshake, so this also drops that Initial.
- `reorder`: hold the first server Handshake-containing datagram, deliver the next
  datagram in the same direction, then release the held one. The maximum hold is
  one second. Timer-only release emits `reorder_timeout` and does not satisfy the
  acceptance gate. In the ex_quic-client case the later datagram is a retransmission.
- `duplicate`: deliver the first server Handshake-containing datagram twice.
- `corrupt`: flip exactly one bit in the first Handshake packet's final tag byte;
  preserve any other coalesced packets and require recovery to completion.

Captures record original `send`/`receive` observations and post-impairment
`wire_send`/`protocol_receive` deliveries. They remain transport-boundary JSONL,
not kernel PCAP. Inbound discarded packets reached the OS but were not delivered
to the independent QUIC parser. Outbound discarded packets did not reach the socket.
Archived artifacts use `<role>-<scenario>-*`, with SHA256SUMS.

The first client reorder attempt used a 100ms hold and exited 1 because no second
packet arrived before release; handshake success alone did not pass the gate.
The final one-second schedule produced actual order reversal and exited 0:
`INTEROP_SCENARIO=reorder mix run scripts/interop/run.exs client _build/interop/client-reorder-second`.
This is a corrected impairment schedule, not a retry policy masking QUIC failure.

Harness qualification:
`uv run --python 3.12 --with aioquic==1.2.0 python scripts/interop/test_peer.py`
passed three tests using archived independent packet bytes. They verify actual
loss/duplication/one-bit corruption, reversed delivery order and failure to report
mere delay as successful reordering. These cases do not establish sustained-loss,
all packet-direction combinations, congestion-load or production robustness.
Certificate/ALPN negatives were still pending at that increment; the next
section records their results.

Impairment increment local gates: formatting, warnings-as-errors compilation,
104 ExUnit tests (seed 589848), and diff checks passed. All ten final network
cells and all three harness qualification tests exited 0.

## Independent authentication negatives

All six combinations of `client|server` and
`wrong_ca|wrong_hostname|wrong_alpn` exited 0 on 2026-09-24. These are **expected
rejections**, not successful handshakes. Verification remains enabled. Source
parent: `cd408b51fb76d9848f596ffc74aecd8db4fb51a8`, with the negative harness applied.
The runtime/peer versions match the matrix above. Reproduce with:

```sh
INTEROP_SCENARIO=<scenario> mix run scripts/interop/run.exs <role> _build/interop/<role>-<scenario>
```

The CA case trusts only the unrelated public `pkix/wrong_root.pem` fixture from
the pinned dependency; hostname uses `wrong.example.test`; ALPN uses `incompatible`.

| ex_quic role | Case | Required observed error |
| --- | --- | --- |
| client | wrong CA | local TLS `unknown_ca`, `path_validation_failed` |
| client | wrong hostname | local TLS `certificate_unknown`, `hostname_mismatch` |
| client | wrong ALPN | aioquic termination 296 (TLS handshake_failure), `No common ALPN protocols` |
| server | wrong CA | aioquic termination 298 (TLS bad_certificate), `unable to get local issuer certificate` |
| server | wrong hostname | aioquic termination 298, hostname `doesn't match` |
| server | wrong ALPN | local TLS `no_application_protocol` |

The runner requires the matching structured local TLS error or independent
termination event, no independent HandshakeCompleted and no local established
connection. A timeout, generic close, missing process or arbitrary failure is not
an accepted negative result. Server cases do not claim client-certificate auth.

Initial runs exposed harness observation defects: it stopped at the local generic
peer-close notification before aioquic emitted its structured termination event,
and a route could disappear between enumeration and status lookup. The runner
now waits for the expected TLS evidence and tolerates only normal/noproc status
races. The initial ALPN expectation was corrected from TLS alert 120 to aioquic
1.2.0's actual alert 40; the specific `No common ALPN protocols` reason is required.
Four initial cells exited 1; their corrected `*-final` commands exited 0. Client
wrong-CA and wrong-hostname cells passed on their first execution. Archived final
results/captures use `<role>-<scenario>-*` and SHA256SUMS.

Negative increment local gates: formatting, warnings-as-errors compilation,
104 ExUnit tests (seed 860694), and diff checks passed. An ordinary client
handshake was rerun after the runner changes and passed. All six final negative
cells exited 0; the earlier harness failures are described above.

## Independent raw packet negatives

`mix run scripts/interop/raw_negative.exs` passed on 2026-09-24. A separate
UDP socket sent reserved-bit, fixed-bit, and truncated Initial datagrams to an
ex_quic server endpoint. The endpoint reported zero routes, zero Retry sends,
and no UDP responses for all three inputs. This does not cover authenticated
transport-parameter or Finished mutations, which require decrypting and
re-protecting a captured handshake packet.

The runtime now validates authenticated transport parameters during TLS action
processing and terminates the connection with a structured error before it can
become established. A separate aioquic mutation probe observed the local
`invalid_max_udp_payload_size` error and zero retained routes, but also observed
a pre-rejection handshake packet; the no-reflection requirement remains open
pending a provider-level ordering solution.

## Reverse-role impairment revalidation

On 2026-09-24, the server-role runner was revalidated against aioquic 1.2.0
for `drop_initial`, `drop_handshake`, `reorder`, and `corrupt`. Each command
exited 0 and emitted the required impairment event, `handshake_complete`, and
`quic_confirmed`; no endpoint admission drops or runtime errors were reported.

```sh
INTEROP_SCENARIO=<scenario> mix run scripts/interop/run.exs server _build/interop/reverse-<run>-<scenario>
```

This rerun is evidence for the aioquic-client to ex_quic-server direction. It
does not add independent evidence for sustained-loss congestion pressure,
malformed authenticated packets, or an HRR-capable peer.
