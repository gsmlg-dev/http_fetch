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
- PASS locally on macOS (2026-11-10), CI confirmation pending: independent negative migration matrix and forced owner death at every two-socket transition; see [M2 negative matrix](#m2-negative-matrix-2026-11-10). The source-IP positive phase stays CI-only (needs a `127.0.0.2` alias).

Commands use `ERL_FLAGS='+S 4:4' MIX_ENV=test MIX_BUILD_PATH=/tmp/http-fetch-quic-A-20261108/test` from the umbrella root. Independent gate: `python3 scripts/quic_client_features/migration.py --python /tmp/http-fetch-quic-A-peer/bin/python` (`aioquic==1.2.0`). The gate has finite child/peer deadlines, records exact bytes/FIN/path addresses and requires a retained native cleanup receipt.

## Reliable reset prerequisite for Task D

Pinned draft: `draft-ietf-quic-reliable-stream-reset-11`. Transport parameter `reset_stream_at=0x1d` has empty value; frame `RESET_STREAM_AT=0x24` carries stream ID, application error, final size and reliable size. Receive support must be explicitly negotiated. Source API now exists: opt in to receive advertisement with `Quic.client(reliable_reset: true, ...)` / `Quic.listen(reliable_reset: true, ...)`. `Quic.info(connection)` exposes `reliable_reset: %{draft: 11, local: boolean, peer: boolean, negotiated: boolean}`. `Quic.reset_stream_at(stream, application_error_code, reliable_size, opts)` returns ordinary retained admission refs; send requires bilateral negotiation and never downgrades to RESET_STREAM. `reliable_size` is an absolute byte offset from stream start, including the complete WebTransport stream/session prefix. It must not exceed already admitted bytes and may only decrease on later resets with the same error code.

Reliable prefix on peer STOP_SENDING: `Quic.open_stream(connection, kind, reliable_prefix: bytes)` declares the first `bytes` of the send direction as a reliable prefix (`0`, the default, declares none; negative or non-integer values return `{:error, :invalid_reliable_prefix}`). When both endpoints negotiated reliable reset, a peer STOP_SENDING on that stream is answered with RESET_STREAM_AT carrying the STOP_SENDING code, final size = admitted send offset and reliable size = `min(prefix, admitted offset)`; a prefix not yet admitted cannot be completed after the reset, so only its admitted part is retained. Repeated STOP_SENDING is idempotent and never enlarges an earlier reliable size. Without negotiation, or with no admitted prefix bytes, the answer is the ordinary RESET_STREAM. `QuicHttp3.Session` passes the draft-17 WT prefix length for every WT stream it opens.

Manual reads deliver ordinary `{:data, stream_id, bytes}` before exactly one `{:reset, stream_id, code, final_size}`; reset is withheld until the smallest reliable prefix is contiguous. Stream-open/readable events retain their existing pull/ownership contract. Sparse reassembly uses existing byte/range/stream-record limits. Final size charges stream and connection credit once; reset consumption releases remaining discarded-tail credit. Sender recovery retains/retransmits only unacknowledged prefix bytes plus smallest reset information, with global packet numbers unchanged. Bilateral quic-go traffic now passes; the independent draft-11 negative matrix passes locally (CI confirmation pending), with malformed-frame rows in-repo only; see [reliable reset negative matrix](#reliable-reset-negative-matrix-2026-11-10). Task D must gate production profile claims on the complete profile acceptance, not parameter presence alone.

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
| M2 client local migration | PASS: CID/policy/role/confirmation/address/busy/bind failure, dedup, padded probe, deadline fallback and retained old writer; PASS: forced owner death at all four two-socket transitions (in-repo server) | PASS: quic-go v0.62.0 port then IP migration, exact stream/FIN/DATAGRAM and eight-resource cleanup | PASS locally (port-based, macOS): independent negative matrix vs quic-go v0.62.0 (preconfirmation, bind in-use/unavailable, deadline fallback, concurrent busy, duplicate ref, owner death x4), zero-length-CID quic-go (no spare CID) and quinn 0.11.11 (peer `disable_active_migration`); pending CI confirmation of the new gates; source-IP phases CI-only |
| Reliable reset draft-11 | PASS: exact TP/frame codec, negotiation, final-size/error checks, decreasing/reordered prefix, sparse receive, prefix loss/recovery and separate reset ACK | PASS: both directions against quic-go v0.62.0; negotiated support, prefix then reset, codes 42/43, retained ref and native cleanup | PASS locally (macOS), CI confirmation pending: independent negative matrix vs quic-go v0.62.0 through a test-owned relay (loss and reorder of RESET_STREAM_AT and prefix in both directions, repeated STOP_SENDING, prefix beyond admitted, non-negotiated peer falls back to RESET_STREAM); see [reliable reset negative matrix](#reliable-reset-negative-matrix-2026-11-10). In-repo only: malformed/decreasing/final-size frames an honest peer never sends |
| R1 | PASS: bounded endpoint-local store, atomic single use, expiry/partition/eviction/redaction; serialized bounded continuation, timeout/stale/duplicate/late reply handling; actual full then resumed connections | PASS: unmodified aioquic 1.2.0, both client and server roles, exact 269-byte stream plus FIN, no early data, joined socket cleanup | PASS locally (macOS), CI confirmation pending: HRR resumption vs Go crypto/tls in quic-go v0.62.0, remote-server partition, endpoint restart, stale ticket after peer key rotation, concurrent single use; see [R1 negative matrix](#r1-negative-matrix-2026-11-10). In-repo only: trust/profile partition mismatch (endpoint-static, no wire path) |
| R2 | PASS: type-1 early protection in application PN space, opt-in operations, receive staging/quotas, withheld delivery, rejection/ref retention/stream epochs, Retry without TLS rejection, reliable loss crossing to 1-RTT, DATAGRAM loss isolation and immutable early limits | PASS: aioquic 1.2.0 in both roles with an explicit Finished barrier; exact 274-byte stream/FIN and 23-byte DATAGRAM; PASS: resumed early connection followed by quic-go port and IP migration | PASS locally (macOS), CI confirmation pending: peer rejection and re-send, HRR rejection, undecryptable ticket, Retry + 0-RTT, client quota exhaustion, concurrent reuse, late 0-RTT receipt (server role, quic-go client); Finished barrier by the existing aioquic gates; see [R2 negative matrix](#r2-negative-matrix-2026-11-10). In-repo only: invalid binder, server-side receive quotas; no global support claim |

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

## M2 negative matrix (2026-11-10)

Each case uses a fresh exclusive client endpoint with its own Cleanup scope
against an unmodified independent server. The orchestrator
(`scripts/quic_client_features/wire_gates.py`) requires: the pinned peer
version in the peer's `listening` record; one independent handshake per
retained client receipt; each receipt `confirmed`/`resolved`, `down == enrolled`,
zero unresolved births/operations and the exact native roles below; and, for
every exchanged phase, exactly one peer receipt with the same cumulative byte
count and SHA-256 whose observed client address equals the address the engine
reports (old path = the connection's initial address; new path = a different
port). Every rejected or failed migration is followed by an exact echo plus FIN
observed by the peer from the original address. Driver:
`scripts/quic_client_features/migration_negative.exs`.

| Row | Peer and the knob producing the condition | Result | Native roles (IO/Port) |
| --- | --- | --- | --- |
| Peer `disable_active_migration` | quinn 0.11.11 / quinn-proto 0.11.17 (`scripts/quic_client_features/quinn_peer`, Cargo.lock pinned), public `ServerConfig::migration(false)`, which sets the transport parameter. quic-go v0.62.0 and aioquic 1.2.0 have no knob that sends it. | PASS: admission and retained ref `{:error, :peer_disabled_migration}`, one path, exact old-path bytes/FIN. Control: the same case against migration-enabled quic-go fails (admitted) | 1/1 |
| No spare peer CID (peer uses zero-length CIDs) | quic-go v0.62.0 `--zero-cid`: public `Transport.ConnectionIDGenerator` with zero-length IDs, so quic-go issues no NEW_CONNECTION_ID | PASS: `{:error, :no_unused_connection_id}` after 200 ms, retained, one path, exact old-path bytes/FIN | 1/1 |
| Migrate before confirmation | quic-go v0.62.0, default config; tight migrate loop from `connect` | PASS: `:not_established` while handshaking, then `{:error, :handshake_not_confirmed}` before HANDSHAKE_DONE (bounded retry if confirmation wins; never needed in 11 local runs); no candidate socket | 1/1 |
| Bind failure, address in use | quic-go v0.62.0; local port held by another socket | PASS: admitted `{:ok, ref}`, retained, `:operation_ref_conflict` for another address, outcome `{:error, {:bind_failed, :eaddrinuse}}`, same ref after outcome returns the original admission without another bind; old path exact | 2/1 (failed IO actor, no Port) |
| Bind failure, unavailable address | quic-go v0.62.0; local `192.0.2.1` (TEST-NET-1, never local; port-agnostic, runs without an alias) | PASS: as above with `:eaddrnotavail` | 2/1 |
| Deadline expiry with fallback + concurrent migrate | quic-go v0.62.0 paused with SIGSTOP for the validation window (no peer change; simulates total loss of the candidate path) | PASS: two concurrent migrations, exactly one admitted and one `{:error, :migration_busy}` (retained as rejected); admitted outcome `{:error, :validation_timeout}`; after SIGCONT the old path carries exact bytes; a later migration on the released two-path budget then succeeds from a new port | 3/3 |
| Duplicate retained ref | quic-go v0.62.0 | PASS: repeat during binding and after completion return the original `{:ok, ref}`; status keeps result and final outcome; peer saw one new port only (ends on the new path; old-path continuity for retained refs is covered by the bind-failure rows) | 2/2 (exactly one candidate bind) |
| Owner death: candidate bound | quic-go v0.62.0 and in-repo server | PASS: connection held before handling its `{:quic_path_bound, ...}`; endpoint killed; all six resources DOWN, both Ports closed | 2/2 |
| Owner death: probe sent | quic-go paused (SIGSTOP) / in-repo server `:sys.suspend` | PASS: candidate `:validating` with an outstanding PATH_CHALLENGE; endpoint killed; all joined | 2/2 |
| Owner death: validated | quic-go v0.62.0 and in-repo server | PASS: endpoint held before handling `{:quic_select_local_path, ...}`; migration outcome `{:ok, _}`, phase settling/retiring; endpoint killed; all joined | 2/2 |
| Owner death: old retiring | quic-go v0.62.0 and in-repo server | PASS: endpoint held before handling `{:quic_retire_local_path, ...}` (old socket still owned); phase `:retiring`; endpoint killed; all joined | 2/2 |

Owner-death holds use a `:sys.install/2` debug hook that blocks inside the
target process before it handles the transition message, released right after
the kill. The in-repo ExUnit tests are
`apps/elixir_quic/test/quic/migration_owner_death_integration_test.exs`; the
wire-side runs are the `owner_death/*` cases of the `migration-negative` gate.

**FAIL -> PASS (engine bug found by this matrix):** a migration to an in-use or
unavailable local address killed the client endpoint and its linked caller.
`Quic.IO.GenUDP.open/1` used `GenServer.start_link/2`, so the init stop reason
(`:eaddrinuse`/`:eaddrnotavail`) was also delivered as an exit signal. The actor
is now linked only after it owns a socket. Regressions:
`apps/elixir_quic/test/quic/io_gen_udp_test.exs` and
`apps/elixir_quic/test/quic/migration_bind_failure_integration_test.exs`.

Gates (CI job `independent-quic-client` runs all three):

```sh
python3 scripts/quic_client_features/wire_gates.py --gate migration-negative
python3 scripts/quic_client_features/wire_gates.py --gate migration-no-cid
python3 scripts/quic_client_features/wire_gates.py --gate migration-disabled --quinn-binary <path>
```

Local results, 2026-11-10, macOS (no `127.0.0.2` alias): all three gates PASS;
`migration-negative` passed 11 consecutive runs. CI confirmation of the three
new gates and of the existing source-IP positive phase is pending. Capability
flags are unchanged by this section.

## Engine negative matrices: harness (2026-11-10)

The reliable-reset, R1 and R2 matrices below share one harness. The independent
peer is unmodified quic-go v0.62.0 (`scripts/quic_client_features/peer.go`,
built in a throwaway module exactly like CI; Go 1.26.3 `crypto/tls`). New modes
use only public configuration: `--mode matrix` (a command-per-stream server:
`echo`, `sink`, `stop`, `reset`, `rotate`) and `--mode client` (a 0-RTT client).
Every listening/client record carries the quic-go module version read from the
binary's build info, and the orchestrator asserts it equals
`github.com/quic-go/quic-go@v0.62.0`. Public knobs used:

| Knob | Public API |
| --- | --- |
| reliable reset on/off | `quic.Config.EnableStreamResetPartialDelivery` (`--no-reliable-reset`) |
| frame-level peer evidence | `quic.Config.Tracer = qlog.DefaultConnectionTracer` (`--qlog`, `QLOGDIR`); flushed by closing the transports on SIGTERM |
| ticket presentation/issue evidence, key rotation | `tls.Config.GetConfigForClient`, `WrapSession`/`UnwrapSession` delegating to `Config.EncryptTicket`/`DecryptTicket`, `SetSessionTicketKeys` |
| HelloRetryRequest | `tls.Config.CurvePreferences = [P-256]` (runtime key share is X25519); evidence `ConnectionState.HelloRetryRequest` |
| peer rejects 0-RTT | `UnwrapSession` clears `SessionState.EarlyData` (server policy); resumption itself still succeeds |
| Retry | `quic.Transport.VerifySourceAddress` always true |
| 0-RTT | `quic.Config.Allow0RTT` + `Transport.ListenEarly`; client `DialAddrEarly` + `tls.NewLRUClientSessionCache` |

Loss and reordering come from a test-owned UDP relay between the runtime and the
peer (`scripts/quic_client_features/relay.exs`). It never parses or changes
packet contents: it forwards, drops, or holds-and-reverses whole short-header
datagrams per direction on the driver's command, and for the late-receipt case
holds datagrams whose first packet is a 0-RTT long header (type bits are not
header-protected) until after the handshake. Some R2 cases pause the peer
process with SIGSTOP/SIGCONT (as in the M2 matrix) so that early admissions
deterministically precede its first flight. Neither changes the peer binary.

Malformed or dishonest frames that an unmodified peer never sends are covered by
in-repo tests and are listed below as **in-repo only**; they are not claimed as
independent evidence. Every client case owns its Cleanup scope; the gate checks
each retained receipt (`confirmed`/`resolved`, `down == enrolled`, zero
unresolved births/operations, exact roles) and one peer handshake per runtime
connection, matched by client address.

## Reliable reset negative matrix (2026-11-10)

Driver `scripts/quic_client_features/reset_negative.exs`; gates `reset-negative`
(quic-go `--qlog`) and `reset-not-negotiated` (`--qlog --no-reliable-reset`).
Peer-side evidence is quic-go's own application read (`StreamError` code and
bytes, reported back on the stream) and its qlog frames.

| Row | Condition and knob | Result |
| --- | --- | --- |
| RESET_STREAM_AT + prefix lost, runtime -> peer | 8000 bytes admitted, `reset_stream_at(42, 6000)` (plus the same ref again) while the relay drops every runtime->peer 1-RTT datagram for 250 ms | PASS: quic-go read >= 6000 exact bytes then `StreamError` 42 (remote); its first RESET_STREAM_AT receipt is after the drop window (a retransmission) and its received packet numbers have gaps; every received RESET_STREAM_AT is (42, final 8000, reliable 6000), no RESET_STREAM |
| Reordered, runtime -> peer | relay holds the same burst and releases it in reverse order | PASS: quic-go's qlog shows RESET_STREAM_AT received before prefix STREAM frames (offset < 6000); it still read the complete prefix, then 42 |
| RESET_STREAM_AT + prefix lost, peer -> runtime | quic-go writes 6000 bytes, `SetReliableBoundary`, 2000 more, `CancelWrite(43)`; relay drops every peer->runtime 1-RTT datagram for 250 ms | PASS: runtime delivers exact prefix bytes (>= 6000, pattern-checked), then exactly one `{:reset, _, 43, 8000}`, nothing after; quic-go logged `packet_lost` and sent RESET_STREAM_AT (43, 8000, 6000) at least twice |
| Reordered, peer -> runtime | relay reverses the burst | PASS: same delivery; qlog proves the RESET_STREAM_AT packet was sent after prefix packets and before the relay released them, so the runtime received it first |
| Repeated STOP_SENDING | stream `reliable_prefix: 1500`, 2000 bytes admitted; quic-go `CancelRead(77)` after 1000 bytes while the relay drops runtime->peer traffic for 1.2 s, so quic-go retransmits STOP_SENDING | PASS: quic-go sent STOP_SENDING(77) >= 2 times; every RESET_STREAM_AT it received is identical (77, final 2000, reliable 1500); no RESET_STREAM; repeats never enlarged the reliable size |
| Declared prefix > admitted | `reliable_prefix: 4096`, 100 bytes admitted, `CancelRead(78)` | PASS: answer RESET_STREAM_AT (78, final 100, reliable 100). Local `reset_stream_at` beyond admitted (6 > 5) returns `{:error, :invalid_reliable_size}`; the stream stays usable and a valid reset at 5 is read by quic-go as 5 bytes + code 1 |
| Non-negotiated peer | quic-go `--no-reliable-reset`; runtime advertises | PASS: `info.reliable_reset == %{draft: 11, local: true, peer: false, negotiated: false}`, `reset_stream_at` returns `{:error, :reliable_reset_not_negotiated}` (never downgraded), stream still delivers 18 bytes + FIN; STOP_SENDING(79) on a prefixed stream is answered with RESET_STREAM (79, final 100); quic-go's trace contains no RESET_STREAM_AT |
| Malformed frame, reliable size > final size, changed code/final size, decreasing/increasing reliable size on receive, RESET_STREAM_AT without advertised receive, final-size flow control | none: an honest peer never sends these | **in-repo only**: `apps/elixir_quic/test/quic/reliable_reset_test.exs`, `reliable_reset_scheduler_test.exs`, codec tests |

## R1 negative matrix (2026-11-10)

Driver `scripts/quic_client_features/resumption_negative.exs`; gates
`resumption-negative` (`--listeners 2`) and `resumption-hrr`
(`--curves p256 --allow-0rtt`). The gate compares the runtime's
`resumption.resumed` with quic-go's `DidResume`, ticket presentations seen by
`UnwrapSession`, and requires every exact echo to be read with FIN by quic-go.

| Row | Condition and knob | Result |
| --- | --- | --- |
| HRR resumption | `CurvePreferences = [P-256]` vs runtime X25519 key share | PASS: both handshakes took an HRR (peer `HelloRetryRequest == true`, `CurveP256`); the second resumed on both sides, so the rewritten binder over the HRR transcript verified at Go's server; exact echo |
| Partition by remote server | quic-go with two listeners sharing one `tls.Config` and ticket keys (listener B *could* decrypt A's ticket) | PASS: ticket from A present, connection to B presents no ticket and is a full handshake; A then resumes (presented once, decrypted) |
| Trust/profile partition mismatch | trust, reference identity, ALPN, profile and early policy are endpoint-static and part of the partition digest; a different value means a different endpoint and store, so no wire path can present a cross-partition ticket | **in-repo only**: `resumption_store_test.exs` (partitions isolate), `apps/ex_ssl/test/ssl/quic_resumption_test.exs` (changed context/reference identity never offers a cached PSK) |
| Endpoint restart | new endpoint with identical configuration | PASS: 0 tickets, quic-go sees no presentation, full handshake |
| Stale ticket (peer key rotation) | in-band `rotate` -> `SetSessionTicketKeys` with a fresh key | PASS: the runtime offers the old ticket, quic-go cannot decrypt it, full handshake on both sides; the fresh ticket then resumes |
| Concurrent reuse | one stored ticket, two connects back to back (peer paused during admission) | PASS: store 1 -> 0 at connect, exactly one connection resumed (runtime and peer agree), exactly one presentation |

## R2 negative matrix (2026-11-10)

Same driver; gates `early-negative` (`--allow-0rtt`), `early-rejected`
(`--allow-0rtt --reject-early`), `early-retry` (`--allow-0rtt --retry`),
`resumption-hrr` (`hrr_early`) and `early-late-server` (runtime as server,
quic-go `--mode client`, driver `scripts/quic_client_features/early_late_server.exs`).

| Row | Condition and knob | Result |
| --- | --- | --- |
| 0-RTT rejected by peer -> explicit re-send | `UnwrapSession` clears `EarlyData`: resumption accepted, early data rejected | PASS: `resumed: true`, `early_data: :rejected`; operation outcome `{:early_data, :rejected}` and the matching event; the retained ref returns its original admission; the old handle returns `{:error, :stale_stream_epoch}`; a new-epoch stream re-sends; quic-go's application never read the early bytes and read the re-send exactly once |
| HRR -> 0-RTT rejected | `CurvePreferences = [P-256]` | PASS: as above, with `resumed: true` and peer `HelloRetryRequest` |
| Invalid binder | an honest independent client never sends one and the runtime cannot be made to | **in-repo only**: `quic_resumption_test.exs` (selected binder mismatch fatal before atomic consumption; changed CH2 binder after HRR), Python binder vectors. Closest independent row: undecryptable ticket + 0-RTT -> PASS: full handshake, early rejected, exact re-send |
| Retry + 0-RTT | `VerifySourceAddress` always true | PASS: every connection's first Initial at quic-go carries the Retry token; early data still accepted; quic-go received the 0-RTT STREAM (offset 0, 317 bytes, FIN) after the Retry; exact echo |
| Quota exhaustion (client) | remembered quic-go limits 64 KiB credit / 8 bidi; peer paused during admission | PASS: 64 early DATAGRAMs admitted, the 65th `{:blocked, :early_datagram_limit}`; stream bytes beyond credit `{:blocked, %{type: :data_blocked, value: 64005}}`; the 9th early stream `{:blocked, %{type: :streams_blocked_bidi, value: 8}}`; early accepted; the refused tail is sent after readiness under ordinary backpressure; all 8 echoes exact; quic-go's 0-RTT packets carry STREAM frames only on the first 8 bidi streams, <= 64005 bytes on stream 0 and <= 65536 in total |
| Quota exhaustion (server receive staging/reservations) | an honest client stays within the advertised limits | **in-repo only**: `early_data_test.exs` (staging, reservations, DATAGRAM/STREAM independence, coalesced overflow) |
| Concurrent reuse | one ticket, two early-enabled connects back to back (peer paused) | PASS: exactly one connection admits early operations and is accepted; the other returns `{:error, :not_established}` before readiness and does a full handshake |
| Late receipt (runtime as server) | quic-go client (one full, two 0-RTT connections of 20 007 bytes); the relay withholds every standalone 0-RTT datagram (9-18 per connection) until after the client's first 1-RTT datagram, then releases it 0 ms or 1000 ms later | PASS: delay 0 arrives before the server's early-key retirement deadline (three PTO after first 1-RTT), delay 1000 after retirement; the runtime stays established, every echo is exact and single, quic-go's connections are alive at close, server IO and native Port DOWN |
| Finished barrier | existing `early-client`/`early-server` gates (aioquic flight barriers) | PASS (positive gates, unchanged) |
| Authority late/stale continuation reply | not observable on the wire | **in-repo only**: `tls_continuation_runtime_test.exs`, `tls_continuation_driver_test.exs` |

Gates (CI job `independent-quic-client` runs all eight):

```sh
python3 scripts/quic_client_features/wire_gates.py --gate reset-negative
python3 scripts/quic_client_features/wire_gates.py --gate reset-not-negotiated
python3 scripts/quic_client_features/wire_gates.py --gate resumption-negative
python3 scripts/quic_client_features/wire_gates.py --gate resumption-hrr
python3 scripts/quic_client_features/wire_gates.py --gate early-negative
python3 scripts/quic_client_features/wire_gates.py --gate early-rejected
python3 scripts/quic_client_features/wire_gates.py --gate early-retry
python3 scripts/quic_client_features/wire_gates.py --gate early-late-server
```

Controls: the `early-rejected` driver against a peer without `--reject-early`,
and the HRR driver against a peer without `--curves p256`, both fail
(`expected :rejected, got :accepted`), so those rows depend on the peer knob.
Capability flags are unchanged by these sections.
