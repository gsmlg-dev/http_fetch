# Task A: QUIC client feature contract and validation

Current work-in-progress evidence, 2026-11-08. No release/published/browser acceptance.

## Public transport contract

`Quic.migrate(connection, local: {ip, port}, ref: ref, deadline: bound)` returns admission `{:ok, ref}`. Repeat the retained ref with the same local address to obtain its original admission result without another bind. `Quic.operation_status(connection, ref)` retains `status`, `result`, and final `outcome: {:ok, actual_local} | {:error, reason}`; pull events contain `{:migration, ref, outcome}`. Final path outcome does not itself prove obsolete IO retirement; the two-path budget stays occupied until retirement acknowledgement. Exclusive standalone client only, confirmed handshake, peer migration enabled, unused peer CID, concrete local IP and finite deadline. Server address stays unchanged.

New socket writer is pinned to its path ID. Endpoint authenticates ingress generation and local socket address. Both sockets remain owned until pending effects and recovery permit retirement; monitored IO termination follows native socket closure. Supplied Cleanup lease enrolls all IO/Port resources before traffic; endpoints without a lease use an endpoint-owned candidate scope.

`Quic.capabilities().migration.local` remains `[]` pending the complete independent acceptance. M1 server migration remains unchanged.

## M2 evidence

- PASS: 84 scoped path/migration/scheduler/IO/cleanup cases including integration.
- PASS: 16 scoped runtime cases including candidate binding, zero-receive-credit padded probe, CID/policy rejection and retained-ref deduplication.
- FAIL (fixed): first independent run exposed nested `put_in` root assignment in bound-result handler; direct runtime regression now covers it.
- BLOCKED: aioquic 1.2.0 independent port/IP acceptance. Real initial stream/DATAGRAM succeeds. Candidate probe reaches independent server at a new source port; candidate expires without PATH_RESPONSE. Installed unmodified `aioquic/quic/connection.py` `datagrams_to_send()` selects only `_network_paths[0]`; `_handle_path_challenge_frame()` queues response on `context.network_path`; new path promotion requires a non-probing packet. A pure padded probe therefore leaves its response unsent. Sending PING before validation would violate the approved commit order; the gate remains failing and capability stays false.
- PASS (independent alternative): unmodified `quic-go v0.62.0`, immutable source `793f74d8e03368c5aded128af6f48d21dbb47f73`, source-port then source-IP changes. One handshake, one stream ID 0; exact 9646 bytes and FIN, SHA256 `048ab165ed8ff0294042bb45986fb08dc8f14b0abf3817b60d5a7e9f46662ab4`. Each phase has exact stream and DATAGRAM echo, each settled path count is one. Cleanup joins eight resources: endpoint, connection, three IO processes, three native Ports; all down and no unresolved births/operations. Localhost source-IP change is controlled loopback evidence, not distributed-network acceptance.
- NOT RUN: complete negative independent migration matrix and owner-death at every two-socket transition. Matching-profile reset and R1/R2 positives are recorded below; complete negative acceptance remains open.

Commands use `ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-quic-A-20261108/test` from the umbrella root. Independent gate: `python3 scripts/quic_client_features/migration.py --python /tmp/http-fetch-quic-A-peer/bin/python` (`aioquic==1.2.0`). The gate has finite child/peer deadlines, records exact bytes/FIN/path addresses and requires a retained native cleanup receipt.

## Reliable reset prerequisite for Task D

Pinned draft: `draft-ietf-quic-reliable-stream-reset-11`. Transport parameter `reset_stream_at=0x1d` has empty value; frame `RESET_STREAM_AT=0x24` carries stream ID, application error, final size and reliable size. Receive support must be explicitly negotiated. Source API now exists: opt in to receive advertisement with `Quic.client(reliable_reset: true, ...)` / `Quic.listen(reliable_reset: true, ...)`. `Quic.info(connection)` exposes `reliable_reset: %{draft: 11, local: boolean, peer: boolean, negotiated: boolean}`. `Quic.reset_stream_at(stream, application_error_code, reliable_size, opts)` returns ordinary retained admission refs; send requires bilateral negotiation and never downgrades to RESET_STREAM. `reliable_size` is an absolute byte offset from stream start, including the complete WebTransport stream/session prefix. It must not exceed already admitted bytes and may only decrease on later resets with the same error code.

Reliable prefix on peer STOP_SENDING: `Quic.open_stream(connection, kind, reliable_prefix: bytes)` declares the first `bytes` of the send direction as a reliable prefix (`0`, the default, declares none; negative or non-integer values return `{:error, :invalid_reliable_prefix}`). When both endpoints negotiated reliable reset, a peer STOP_SENDING on that stream is answered with RESET_STREAM_AT carrying the STOP_SENDING code, final size = admitted send offset and reliable size = `min(prefix, admitted offset)`; a prefix not yet admitted cannot be completed after the reset, so only its admitted part is retained. Repeated STOP_SENDING is idempotent and never enlarges an earlier reliable size. Without negotiation, or with no admitted prefix bytes, the answer is the ordinary RESET_STREAM. `QuicHttp3.Session` passes the draft-17 WT prefix length for every WT stream it opens.

Manual reads deliver ordinary `{:data, stream_id, bytes}` before exactly one `{:reset, stream_id, code, final_size}`; reset is withheld until the smallest reliable prefix is contiguous. Stream-open/readable events retain their existing pull/ownership contract. Sparse reassembly uses existing byte/range/stream-record limits. Final size charges stream and connection credit once; reset consumption releases remaining discarded-tail credit. Sender recovery retains/retransmits only unacknowledged prefix bytes plus smallest reset information, with global packet numbers unchanged. Bilateral quic-go traffic now passes; independent draft-11 negative acceptance remains open. Task D must gate production profile claims on the complete profile acceptance, not parameter presence alone.

## R1/R2 dependency

Task B has published `docs/quic/tls-continuation-contract.md` and passing independent provider evidence. QUIC endpoint-local cache/authority, continuation and default-off early transport now exist in source. Independent positive traffic is recorded below; global capability claims remain false pending complete acceptance.

## Updated runtime evidence (2026-11-08)

The preceding progress notes are superseded by this section where a gate was pending.
All source remains unreleased, and the global capability claims stay unchanged:
`migration.local == []`, `resumption == false`, `http3 == false`. No early-data or
reliable-reset production capability is advertised. The complete adversarial and
independent acceptance matrices remain open; positive traffic is not that matrix.

| Area | Source/runtime checks | Independent positive traffic | Remaining acceptance |
| --- | --- | --- | --- |
| M2 client local migration | PASS: CID/policy/role/confirmation/address/busy/bind failure, dedup, padded probe, deadline fallback and retained old writer | PASS: quic-go v0.62.0 port then IP migration, exact stream/FIN/DATAGRAM and eight-resource cleanup | NOT RUN: full independent negative matrix and forced owner-death at every two-socket transition |
| Reliable reset draft-11 | PASS: exact TP/frame codec, negotiation, final-size/error checks, decreasing/reordered prefix, sparse receive, prefix loss/recovery and separate reset ACK | PASS: both directions against quic-go v0.62.0; negotiated support, prefix then reset, codes 42/43, retained ref and native cleanup | NOT RUN: independent loss/reorder and exhaustive malformed/decrease/final-size matrix against an explicitly draft-11-certified peer |
| R1 | PASS: bounded endpoint-local store, atomic single use, expiry/partition/eviction/redaction; serialized bounded continuation, timeout/stale/duplicate/late reply handling; actual full then resumed connections | PASS: unmodified aioquic 1.2.0, both client and server roles, exact 269-byte stream plus FIN, no early data, joined socket cleanup | NOT RUN: independent HRR resumption (aioquic has no HRR support), exhaustive trust/profile/restart/concurrent-network matrix; Task B records provider-level HRR/binder evidence separately |
| R2 | PASS: type-1 early protection in application PN space, opt-in operations, receive staging/quotas, withheld delivery, rejection/ref retention/stream epochs, Retry without TLS rejection, reliable loss crossing to 1-RTT, DATAGRAM loss isolation and immutable early limits | PASS: aioquic 1.2.0 in both roles with an explicit Finished barrier; exact 274-byte stream/FIN and 23-byte DATAGRAM; PASS: resumed early connection followed by quic-go port and IP migration | NOT RUN: complete independent rejection/invalid binder/Finished/HRR/Retry/concurrent reuse/quota/late-receipt matrix; no global support claim |

### R1 authority contract

Opt in with `resumption: [enabled: true, application_profile: "raw-r1-v1"]` on the
endpoint. Direct TLS `resumption` configuration is rejected: runtime owns the
endpoint-local authority. Defaults are 256 tickets and 1 MiB, configurable through
bounded `max_entries`/`max_bytes`; ticket lifetime is 1..600 seconds. There is no
persistence, process-global cache, arbitrary callback or distributed replay claim.

The private partition binds version, role, application/profile version, remote
server for clients, and static trust/name/credential/algorithm configuration. Client
tickets are consumed before connection start; provider revalidates current trust
and reference identity before offering. Server lookup grants a <=100 ms lease;
binder verification precedes atomic consumption. A continuation is bounded by both
100 ms and handshake deadline, matches generation/request ID, and buffers bounded
CRYPTO while pending. Timeout is a miss; stale replies do not revive work. Store
failure skips ticket issuance without failing an authenticated connection. Fatal
TLS continuation failures emit the corresponding QUIC TLS close before retirement.

`Quic.info(connection).resumption` exposes only `resumed` and early disposition.
Sessions/PSKs/tickets are not ordinary events. Default-off R1 evidence reports
`early_data: :disabled` on both flights. A ticket never validates a new path.

### R2 opt-in, ownership and limits

Endpoint policy additionally requires
`early_data: [enabled: true, application_profile: "early-raw-v1"]`; that profile is
bound into the ticket partition. Each pre-ready `open_stream`, `send_stream` or
`send_datagram` additionally needs `early_data: :replayable`. Unmarked operations
retain `:not_established`. No Fetch, WebSocket or WebTransport operation opts in
automatically. The runtime sends actual long-header type-1 packets using early
keys and the existing application PN space. No ACK or CRYPTO is sent at the early
level. Accepted reliable ranges retransmit under current keys with fresh packet
numbers; DATAGRAM never retransmits. Retry requeues reliable transport work without
turning it into TLS rejection.

Early-enabled endpoints advertise at most 64 KiB initial connection/stream credit
and eight bidi plus eight uni stream slots. Larger configured ordinary credit is
granted using 1-RTT MAX_* after authenticated readiness. Tickets remember the
original handshake parameters, never later MAX_* grants. Delayed early STREAMs
retain separate immutable wire-offset/stream-count accounting after readiness;
fresh credit cannot expand early allowance. Early packet numbers must precede
1-RTT numbers. Clients release their early write keys at readiness; server early
read keys retire within three PTO after first authenticated 1-RTT traffic.

Before keys, whole UDP datagrams are retained under 16-datagram/32-KiB per-connection
and 1-MiB endpoint staging reservations. Reliable payload reserves at most 64 KiB
and 16 stream slots; existing range/stream/reassembly bounds also apply. DATAGRAM
has a separate 64-KiB/64-item allowance, dropping whole excess messages and leaving
reliable credit intact. Endpoint reservations plus occupancy are bounded by 8 MiB;
full STREAM+DATAGRAM reservations admit at most 64 connections. Capacity or remembered
parameter mismatch rejects early data while retaining valid ordinary resumption.
Generation-owned release messages and connection DOWN settle reservations, including
authority timeout or a late positive result. No plaintext copy is made during
transfer to ordinary receive ownership.

Before verified Finished and authenticated parameters, `ready` stays false and
pulls/application events do not expose early bytes. On readiness, ready notification
precedes stream/readable events; retained data transfers once. Failed handshakes
lose that connection's retained plaintext and authority reservation.

Admitted early operations keep their original `result`; their `outcome` and
`{:early_data, ref, :accepted | :rejected}` event report disposition separately.
Rejection clears early queues/recovery/stream state without resetting packet numbers,
increments stream epochs, and invalidates stale handles even when the numeric stream
ID is reused. Repeating a retained operation ref returns its original admission
without resubmitting bytes. The live connection remains usable for explicit new
operations. There is no automatic application replay after rejection/reconnect.

### Independent fixture and receipts

The peer stacks are unmodified `aioquic==1.2.0` and `quic-go v0.62.0` (source commit
`793f74d8e03368c5aded128af6f48d21dbb47f73`). Go module checksums are verified through
`GOSUMDB=sum.golang.org`; no repository Go manifest, root lockfile or dependency was
changed. Python's fixture configures 64-KiB wire credit/eight streams and wraps its
UDP transport to retain selected flights; it does not replace packet protection,
TLS, stream, ACK or recovery logic.

For the client gate, aioquic withholds its server flight until it has observed both
early STREAM and DATAGRAM before Finished. For the server gate, Python retains the
client Handshake flight while the QUIC runtime records retained 274/23-byte payloads,
`ready == false`, absent application stream events and rejected reads. Only that
barrier releases Finished; both sides then verify exact bytes/FIN/message boundaries.

The combined quic-go gate records full then resumed/0-RTT handshakes, exact 274-byte
initial stream, then exact 21-byte streams and DATAGRAMs from a new port and from
`127.0.0.2`. Cleanup confirms nine enrolled/down resources: endpoint, two connections,
three IO actors and three native Ports, with zero unresolved births/operations.
Controlled loopback IP changes are not distributed-network acceptance.

Run from the umbrella root with task-owned build state:

```sh
export ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-quic-A-20261108/test
mix compile --warnings-as-errors
mix test apps/elixir_quic/test --include integration
python3 scripts/quic_client_features/wire_gates.py --gate migration
python3 scripts/quic_client_features/wire_gates.py --gate reset
python3 scripts/quic_client_features/wire_gates.py --gate resumption-client
python3 scripts/quic_client_features/wire_gates.py --gate resumption-server
python3 scripts/quic_client_features/wire_gates.py --gate early-client
python3 scripts/quic_client_features/wire_gates.py --gate early-server
python3 scripts/quic_client_features/wire_gates.py --gate early-migration
```

Peer executables default to task-owned paths and can be overridden with `--python`
and `--go-binary`. The orchestrator bounds startup, subprocesses and cleanup; polling
is only scheduling, never an acceptance criterion. A gate prints its final
`independent_gate/passed` record only after both peers' receipts are checked.

Local evidence logs are `/tmp/http-fetch-quic-A-{go-migration,reset-final,r1-client,r1-server,r2-client,r2-server,r2-migration}.log`.
They are local task artifacts, not published CI/release evidence.


## Final source verification and fixed wire failures

Final Task A checkpoint, 2026-11-08. These are current-checkout results using the
isolated build above, not published-package or programme-wide acceptance.

Two distinct migration retirement races were reproduced and fixed:

1. **FAIL -> PASS:** a valid late packet on the old local socket found its path
   identity after recovery/IO accounting had been released, causing
   `Recovery.pto_duration/2` to dereference a missing controller. Connection now
   discards ingress for the settled retiring path before decryption/accounting.
   A deterministic regression commits a real protected PATH_RESPONSE, retains
   the native retirement interval, then proves old ingress is ignored and the
   same packet still authenticates on the selected path.
2. **FAIL -> PASS:** after IO had been closed and marked retiring, an already
   queued UDP message attempted `GenUDP.consumed/3` against the dead actor.
   Endpoint now excludes retiring IO generations from routing and receive-credit
   return. The deterministic regression reproduces the exact `:noproc` exit
   before the fix. The combined independent early-data/migration gate passes
   after this change.

Readiness now confirms/schedules the server handshake before setting
`ready: true, parameters_valid: true` and notifying the consumer. A regression
asserts validated/confirmed ready metadata and that the ready event precedes
retained early stream-open/readable and DATAGRAM-readable events.

| Final check | Result |
| --- | --- |
| Root `mix compile --warnings-as-errors` with isolated build | PASS |
| `mix test apps/elixir_quic/test --include integration` | PASS: 470 tests, 0 failures |
| Explicit changed/new owned Elixir files, `mix format --check-formatted` | PASS |
| Normal `mix credo` with 91 explicit engine lib/test paths | PASS: no priority issues |
| Strict Credo on 24 changed/new engine files | FAIL: only two low-priority existing explicit-try suggestions, `Protection.header_protection_mask/3` and `Endpoint.safe_call/3`; their bodies are unchanged from HEAD |
| Direct Dialyzer, 48 current QUIC beams, configured warning classes, private PLT | FAIL: one existing `Streams.new/2` MapSet opaque-origin warning; no other QUIC warnings |
| Root `mix docs --output /tmp/http-fetch-quic-A-docs` | PASS generation, with unresolved link/hidden-type warnings, including the existing hidden handle types used by the new APIs |
| Python fixture syntax / `gofmt -l scripts/quic_client_features/peer.go` | PASS |
| Owned `git diff --check` | PASS |

The root Dialyzer PLT was copied to `/tmp/http-fetch-quic-A-dialyzer.plt`.
Stale project module paths were removed only from that private copy before
adding the current TLS dependency contract. Dependency PLT preparation reported
18 provider warnings; this is not a clean Task B analysis claim. QUIC analysis
used `:succ_typings`, `check_plt: false` and
`[:unmatched_returns, :error_handling, :underspecs]`. New early-level contract
omissions and unchecked retirement outcomes were fixed. The remaining
`Streams.new/2` exception is already documented in `.dialyzer_ignore.exs` at
line 90; adding reset fields moves its spec to line 92. The root ignore file is
outside Task A ownership and was not changed or bypassed. The raw warning remains
visible. The repository PLT checksum is unchanged.

Final independent gates are **PASS** for `migration`, `reset`,
`resumption-client`, `resumption-server`, `early-client`, `early-server`, and
`early-migration`. The harness checks exact enrolled/down resource counts, native
closure and zero unresolved births/operations for each retained client receipt;
server-role gates require IO and native-port DOWN evidence. Combined migration
also requires the independent peer's exact later stream bytes/hash and FIN from
both changed source addresses. The full negative matrices in the acceptance table
remain NOT RUN; capability flags remain unchanged.

Current logs are `/tmp/http-fetch-quic-A-verified-<gate>.log`,
`/tmp/http-fetch-quic-A-{strict-compile,engine-suite,format,credo-normal,credo-changed,docs,dialyzer}-final.log`.
Red/green lifecycle evidence is retained in
`/tmp/http-fetch-quic-A-{race-regression,ready-regression,fixed-regressions,credit-regression,credit-fixed}.log`.
The local direct analysis driver is `/tmp/http-fetch-quic-A-dialyzer.exs`;
`mix run --no-start /tmp/http-fetch-quic-A-dialyzer.exs` prepares and checks only
private PLT/build state under the environment above. No Git delivery was performed.

### Migration without a cleanup scope (2026-11-09)

A standalone client endpoint created without `cleanup:` previously failed every
`Quic.migrate/2` with `{:bind_failed, :invalid_producer}`: it bound the new
socket inside a private cleanup scope in which the endpoint was not an enrolled
producer. It now binds the migration socket exactly like its first socket (no
scope), and endpoints with a `cleanup:` scope are unchanged. Regression:
`apps/elixir_quic/test/quic/uncleaned_migration_integration_test.exs`.
