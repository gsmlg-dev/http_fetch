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

## Independent implementation re-audit, 2026-11-09

Source inspection only; no peer was built, patched or run. Pinned draft
identifiers re-read from the IETF texts: draft-17 `SETTINGS_WT_ENABLED=0x20b8933b`
(clients MUST send it during the draft period), token `webtransport-h3`;
reliable reset draft-11 `reset_stream_at=0x1d` (also draft-09; `0x17f7586d2cb571`
is draft-07), frame `RESET_STREAM_AT=0x24`.

| Implementation | Immutable revision | Finding |
| --- | --- | --- |
| quic-go/webtransport-go | HEAD `5232f760bf1b10b1e85841725cd73bc22ecf61e7`; v0.13.0 `58c37d9b959d910e27145dd39f11df7382f9def4` | `protocol.go`: `0x2c7cf000` (+`0x2b603742`). quic-go HEAD `2d95e479adb9d8bc707675b5ba5c2a53b77692b9` (v0.65.0): `0x1d` claiming draft-09 plus legacy `0x17f7586d2cb571`. INCOMPATIBLE (WT codepoint). |
| BiagioFesta/wtransport | HEAD `b16674edca87e52969e32d9f969a34e2c4abd1c2`; 0.7.2 `d022a6ad5f6260cb526e06d8ca42d09516ce6440` | `0x2b603742`; no reset_stream_at (quinn). INCOMPATIBLE. |
| mozilla/neqo | HEAD `4b6d13566f56824bd4e1c161ec32f49bfceb3c7c`; v0.34.0 `e302b43503f44e09f4257573dd320621516d1560` | `0x2b603742`, token `webtransport`, ordinary reset fallback. INCOMPATIBLE. |
| aiortc/aioquic | HEAD `4e68e48630ec47d3e1a6a8378299057805252217`; 1.7.2 `101861ad37530074f831f36e9eda122e7dd1ba8f` | `h3/connection.py`: `0x2B603742`; no reliable reset. INCOMPATIBLE. |
| cloudflare/quiche + tokio-quiche | `fa0e48072e945ff2da5bb9a21684f86a91f35877` (0.30.0) | No WebTransport. INCOMPATIBLE. |
| microsoft/msquic | `83a44975e381c13a6f721839326b0d1172ed9380` (v2.6.3) | No H3/WT; custom RELIABLE_RESET frame `0x21`. INCOMPATIBLE. |
| hyperium/h3 (h3-webtransport) | `43745ad87e95b0c035ac9c547aad467303213425` | `0x2B603742`; no reliable reset. INCOMPATIBLE. |
| denoland/deno (web-transport-proto 0.2.7) | `e7b39ebd55c85aaf6a29290c1f5a99e2e21e09dd` (v2.9.8) | `0x2b603742`/`0xc671706a`, token `webtransport`. INCOMPATIBLE. |
| google/quiche | `854314dcc99028933a436ebe29716e084ffa4525` | `0x2b603742`/`0xc671706a`, token `webtransport`, reset param draft-07. INCOMPATIBLE. |
| mvfst + proxygen | `0a1c344990b4cc427591c45b943921a0bf28911d`; `b923acf7b3640a93e3cffd53f8974564b432a217` | `0x2c7cf000`/`0x2b603742`, token `webtransport`, reset draft-07. INCOMPATIBLE. |
| private-octopus/picoquic | `77fa50201a2897a1aa90f9d0ff43e8d2fd39d182` | `0x2c7cf000`; reset `0x1d` claiming draft-11. INCOMPATIBLE (WT codepoint). |
| alibaba/xquic | `dffd32c42a511edae544b87169976516b7c4cbfa` | WT drafts 7/16 only; reset draft-09. INCOMPATIBLE. |
| benoitc/erlang-webtransport + erlang_quic | `b681c7862d56b6c423deefda35f1bbe69161179b`; quic `ceba82da8fc867b26396f7f7719ba7fa95defb72` | `0x20b8933b` and `webtransport-h3`, but reset param draft-07 and ordinary-reset fallback. INCOMPATIBLE. |
| shiguredo/webtransport-py | `df83e56790d63bbccd69fb66553b6bb4c94e5be1` | `0x20b8933b`, but deliberately does not require peer `reset_stream_at`; unmerged ngtcp2 branch. INCOMPATIBLE. |
| pywebtransport | `92557c2098dae69795a985c5762f088d5843bf33` (v0.22.0) | `0x20b8933b`; no reliable reset (quinn). INCOMPATIBLE. |
| webtransport4j | `3dcd82790be82dc86ff5704a17a86c34fa6867b4` (0.3.0) | `0x20b8933b`; ordinary shutdown instead of reliable reset. INCOMPATIBLE. |
| shiguredo/http3-rs `examples/wt_server` | `6a930781b53f29109cb74599f6d9032b1fdad7c5` | `0x20b8933b`, but example runs on s2n-quic without RESET_STREAM_AT. INCOMPATIBLE as shipped. |
| shiguredo/tobi-quic (`tobi_webtransport`) | `fc7762068d1a8c36deaaf49115c01e3d993202a6` (no tag/release/crate) | Closest: `0x20b8933b`, `webtransport-h3`, `0x33`, `reset_stream_at=0x1d` claiming draft-11, frame `0x24`, draft-17 CONNECT refused without peer reset support. Not a clean match: server `reset_stream_at` off by default, peer DATAGRAM parameter not checked, no server-side WT reliable-reset call, STOP_SENDING answered with ordinary RESET_STREAM, no example server, unreleased with private tests. |

Result: **BLOCKED**. No independent draft-17 + reliable-reset-11 server
qualifies, so no independent gate was built under `scripts/webtransport/` and
`Profile.supported?/0` stays false. The tobi-quic revision above is the best
candidate for a future gate: a harness binary that only *configures* it
(certificate paths, `reset_stream_at`, `max_datagram_frame_size`) would not patch
the peer, but its missing server reliable-reset call means the reset gate could
still only be exercised in the client-to-server direction.

## Required cross-lane interfaces

Status 2026-11-09: items 1–5 below are now implemented by the live owner
contract in `docs/http3-extensions-contract.md`, except that a cleanup-scoped
session cannot yet admit `RESET_STREAM_AT` (engine `Quic.Cleanup` gap, see
`docs/webtransport-validation.md`). The original requirements are retained.

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
