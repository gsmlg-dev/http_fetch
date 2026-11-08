# WebTransport client peer profile

Profile: **draft-ietf-webtrans-http3-17**, reliable stream reset
**draft-ietf-quic-reliable-stream-reset-11**. First implementation uses one
session on an exclusive HTTP/3 connection, zero WT session flow-control limits,
and post-handshake 1-RTT application operations. No automatic replay or legacy
fallback is permitted.

The client and server must exchange the draft-17 SETTINGS codepoint
`SETTINGS_WT_ENABLED=0x20b8933b`, value 1 (section 7.1). The extended CONNECT
protocol is `webtransport-h3`. Server extended CONNECT, both H3 DATAGRAM settings,
both nonzero QUIC `max_datagram_frame_size` parameters, and both empty
`reset_stream_at` parameters are required. Sending a parameter alone is
insufficient: engine reset semantics must also pass independent acceptance.

`HTTP.WebTransport.Profile.validate/4` checks decoded evidence and exclusive
single-session policy, reusing Task C's `HTTP.H3.WebTransport.Draft17` setting
validation. It does not advertise runtime support. `Profile.supported?/0` remains
false. Protocol parsing, association, error-code mapping and capsules remain
in Task C's shared H3 layer.

## Independent implementation audit, 2026-11-08

These are immutable **source inspections**, with no negotiated wire result.
None of the inspected implementations qualifies as the selected acceptance peer.

| Implementation | Immutable revision | Observed incompatibility |
| --- | --- | --- |
| [webtransport-go](https://github.com/quic-go/webtransport-go/tree/5232f760bf1b10b1e85841725cd73bc22ecf61e7) | `5232f760bf1b10b1e85841725cd73bc22ecf61e7` | README says draft-16; `protocol.go` sets `settingsWebTransportEnabled=0x2c7cf000`, plus draft-06 compatibility. CONNECT token is `webtransport-h3`; H3 DATAGRAM and QUIC partial reset are enabled in server source, but the required draft-17 setting is absent. |
| [wtransport](https://github.com/BiagioFesta/wtransport/tree/b16674edca87e52969e32d9f969a34e2c4abd1c2) | `b16674edca87e52969e32d9f969a34e2c4abd1c2` | `wtransport-proto/src/settings.rs` uses `SETTINGS_ENABLE_WEBTRANSPORT=0x2b603742` and `SETTINGS_WEBTRANSPORT_MAX_SESSIONS=0xc671706a`. |
| [neqo](https://github.com/mozilla/neqo/tree/4b6d13566f56824bd4e1c161ec32f49bfceb3c7c) | `4b6d13566f56824bd4e1c161ec32f49bfceb3c7c` | `neqo-http3/src/features/extended_connect/mod.rs` formats the token as `webtransport` and explicitly allows ordinary RESET_STREAM when reliable reset is absent. That fallback is forbidden by this client profile. |

Reproduce the primary peer inspection from the umbrella root:

```sh
python3 scripts/webtransport/probe_peer.py
```

Expected exit **2**, result **BLOCKED**: the pinned source is incompatible. The
probe emits SHA-256 for inspected files and distinguishes source flags from wire
acceptance. `protocol.go` SHA-256 is
`668ccce98ac7faf65b98d89f41e4243edef1d96abc172ef716b39e2a38a0fd42`;
its manifest pins `github.com/quic-go/quic-go v0.62.0`. That dependency's immutable
source identity `793f74d8e03368c5aded128af6f48d21dbb47f73` contains QUIC DATAGRAM,
empty `reset_stream_at` parameter `0x1d` (also a legacy parameter), and
RESET_STREAM_AT frame `0x24`. Its comments still reference reliable-reset draft-09;
this source inspection does not prove full draft-11 semantics. No peer source was patched
and no server was launched. aioquic 1.2.0's older profile is not substituted.

This is a bounded audit of the revisions above, not a claim that no compatible
implementation exists anywhere. A matching immutable implementation and actual
wire capture/traffic must replace this BLOCKED result before capability changes.
Browser acceptance is a separate gate.

## Required cross-lane interfaces

Task C's `docs/http3-extensions-contract.md` currently supplies pure SETTINGS,
prefix, DATAGRAM and capsule primitives and explicit CONNECT state. At this
checkpoint it explicitly has **no live WT stream/datagram API**. Task D needs:

1. Exclusive owner creation and CONNECT admission, with the actual negotiated
   local/peer QUIC parameters and reset implementation evidence available before
   CONNECT; no unsupported-profile bytes may be sent.
2. Session-qualified bidi/uni open/write/FIN/reliable-reset/STOP_SENDING operations;
   reliable reset must preserve the entire WT prefix through its final Session ID
   byte, including under loss/reordering. Ordinary RESET_STREAM is insufficient.
3. Bounded accepted stream/DATAGRAM/capsule events with byte/item credit receipts,
   stale-generation rejection, and pending-association budget shared with the
   owner's 262144-byte application budget. The adapter must not drain QUIC itself
   or forward unlimited messages into Session.
4. Explicit deadline/admission/result refs, unknown-operation reconciliation,
   terminal once-only events, and connection/resource cleanup receipts. A local
   callback result must not masquerade as an engine completion receipt.
5. Draft-17 close/drain decoding, stream application-error mapping, FIN/reset
   distinction, DATAGRAM association overhead and correct max application payload.

Task A must publish real negotiated `reset_stream_at`, prefix-aware reset send,
receive delivery/order and terminal APIs in
`docs/quic/client-features-validation.md`. Its latest checkpoint now publishes
`Quic.client(reliable_reset: true, ...)`, `Quic.info(connection).reliable_reset`
with `%{draft: 11, local: boolean, peer: boolean, negotiated: boolean}`, and
`Quic.reset_stream_at(stream, code, reliable_size, opts)` with retained admission
refs. `reliable_size` includes the complete WT prefix. The app's pure profile
gate requires all four negotiated-engine fields as well as the decoded transport
parameters; parameter presence alone is insufficient. Task A explicitly says
independent reliable-reset acceptance remains pending. Production profile support
and the network gate stay blocked until that acceptance and Task C's live owner
contract are available.
