# M4 profile and backpressure evidence

`Quic.Profile.compile/2` exposes two local policy variants: `:ordered` keeps
the supported cipher/group order and uses an 8-byte CID policy; `:compact`
reorders the supported cipher/group lists and uses a 16-byte CID policy. Both
use the QUIC record-free ClientHello policy, ALPN `ex-quic`, and raw transport
parameters supplied by the caller. Validation is delegated to the public
`SSL.ClientHello.Profile` capability contract.

`Quic.Profile.materialize/2` calls the public ex_ssl materializer. Random and
key-share values are therefore generated per materialization and are not
stored in a reusable profile.

Application sends are bounded by both stream flow control and scheduler queue
bytes (`max_queue_bytes`). `Quic.Streams` can be configured with
`delivery: :manual` and `max_ready_bytes`; peer data then remains in a
connection-owned ready queue until `consume/3` is called. Queue exhaustion
returns `:receive_queue_limit`; `Quic.Connection.send_stream/5` returns
`:admission_timeout` when the bounded admission call times out.

Profiles are now accepted by `Quic.Endpoint` through the public `profile:`
option. Connection-specific source CID transport parameters replace the profile
placeholder before `SSL.QUIC` materialization, while the profile's ordered
cipher/group policy and packet-size policy remain active.

Independent aioquic 1.2.0 runs passed for both profiles:

- `INTEROP_PROFILE=ordered mix run scripts/interop/run.exs client /tmp/ex_quic_profile_ordered_20260924`
- `INTEROP_PROFILE=compact mix run scripts/interop/run.exs client /tmp/ex_quic_profile_compact_20260924`

The captured Initial ClientHello observations were:

| Profile | JA3 | JA4 | Stream/handshake result |
| --- | --- | --- | --- |
| ordered | `1b123fa8bb66f306d88417cb151ed447` | `q13i0207ec_62ed6f6ca7ad_7ce92f1763d4` | aioquic handshake and QUIC confirmation passed |
| compact | `c6d419ac70651660d495a2e2b83241c2` | `q13i0207ec_62ed6f6ca7ad_7ce92f1763d4` | aioquic handshake and QUIC confirmation passed |

Independent stream transfer also passes with `mix run scripts/interop/stream_interop.exs`:
the aioquic peer sends two FIN-terminated bidirectional streams, and the ex_quic
server observes both complete payloads and FIN events. Endpoint transport
parameters advertise bounded initial data and stream credits from the configured
stream limits.

JA4 remains equal because its normalized fields do not encode the reordered
cipher/group policy; the JA3 and raw ClientHello observations distinguish the
profiles. The captures are transport-boundary JSONL records, not kernel PCAPs.
