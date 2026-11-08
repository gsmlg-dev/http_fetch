# HTTP/3 CONNECT / WebSocket validation

Task C, current checkout, 2026-11-08; WP3 completion receipt 2026-11-09.
Explicit WebSocket/H3 is supported (no fallback); implementation and
independent peer gates pass at the checkpoints below. WebTransport remains pure
primitives only: live owner integration and matching independent acceptance are
BLOCKED. Public capability flags remain false. No version, lockfile, branch,
worktree, commit, push or release change is included.

## Implemented source

- `QuicHttp3.Connect` and `Session.extended_connect/4` validate explicit CONNECT,
  defer allocation until peer SETTINGS, refuse missing support and reject
  ordinary-request `:protocol`. WT network admission fails explicitly.
- `QuicHttp3.Response` has a dedicated accepted-tunnel phase. Accepted 2xx keeps
  upload open; content-length/bodyless semantics do not constrain tunnel DATA.
  Tunnel trailers are rejected; informational/rejected response rules remain.
  Remote FIN preserves the local sending half for a Close reply.
- Sole `HTTP.HTTP3.ConnectionOwner` demux retains deadlines/unknown-operation
  reconciliation, monitored consumers and bounded queues. Tunnel DATA stays
  charged until ACK/removal within a 262144-byte aggregate extension budget.
  Unknown ACKs release no credit; STOP_SENDING isolates the affected tunnel.
- `HTTP.HTTP3.Stream` reuses the existing generation-qualified runtime envelope,
  with one outstanding bounded write, 16384-byte chunks, an original finite
  writer deadline even under a busy mailbox and explicit indeterminate public
  write refs. Timeout cancels native work and releases the lease without replay.
- Explicit `http_version: :http3` WebSocket uses QUIC trust/name verification and
  existing handshake, masking, frame parser, Close/Ping/Pong and application ACK
  machinery. H1/H2 defaults are preserved; H3 has no automatic fallback.
- Historical WT setting codepoint remains unchanged. Draft-17 settings,
  Capsule/Datagram/stream-prefix/error codecs and a bounded pure single-session
  router are tested. The router performs no IO and is not live WT support.

The exact APIs/events are in `http3-extensions-contract.md`.

## Evidence ledger

| Check | Result | Evidence / limits |
| --- | --- | --- |
| Final scoped combined source regression | PASS at checkpoint | 530 tests, 0 failures: core H3 28, H3 engine 142, runtime H3 65, WebSocket 256, Fetch H3 30, EventSource H3 9. Includes integration. `/tmp/http-fetch-task-c-test-final.log`, exit 0; previous run `/tmp/http-fetch-task-c-verified.log` also 530/0. |
| Strict root compile | PASS at checkpoint | `mix compile --warnings-as-errors`, `/tmp/http-fetch-task-c-compile-final.log`, exit 0. |
| Independent RFC 9220 positive gate | PASS | `/tmp/http-fetch-task-c-peer-final.log`: exact text/binary; 256KiB binary under a 16KiB peer receive window; fragmented messages; local Close; peer Close+FIN; Ping/Pong; HTTP refusal; subprotocol mismatch; oversized/malformed frames. |
| Independent delivery credit | PASS | Same positive gate: tiny ACK-mode delivery budget retains second message, random receipt cannot release it, correct opaque receipt releases it. |
| Independent TLS identity | PASS | Same positive gate: wrong reference identity and untrusted CA both fail before public Open. |
| Pooled sibling wire traffic | PASS | Independent peer connection identity is identical for ordinary Fetch before and after closing WebSocket/H3. This proves same-connection sibling continuity for that scenario. |
| Missing CONNECT setting | PASS | `/tmp/http-fetch-task-c-refusal-final.log`: peer omits CONNECT setting; explicit `:extended_connect_not_supported`, no fallback. |
| Peer SETTINGS withheld | PASS | `/tmp/http-fetch-task-c-held-final.log`: peer exits on any early client bidi bytes; owner is ready with SETTINGS absent; opening cancellation and deadline clear owner/session request and queue state. This is local owner-state cleanup, not a native cleanup receipt. |
| Scoped formatting / diff whitespace | PASS | Explicit owned Elixir paths formatted and checked; `git diff --check` passes. Python fixtures parse without generated repository output. |
| Scoped Credo | FAIL, existing findings remain | Each app scanned separately with `--strict`; engine/runtime/WebSocket logs `/tmp/http-fetch-task-c-credo-final-{engine,runtime,websocket}.log`; refreshed core `/tmp/http-fetch-task-c-credo-verified-core.log`. Existing nested alias/readability/test apply findings remain. New writer complexity, alias and line-length findings were fixed. No unrelated cleanup performed. |
| Public H3 completion receipt | PASS (WP3, 2026-11-09) | Supported with the stream-level/exclusive-native meaning in `http3-extensions-contract.md` ("WebSocket/H3 completion receipt"). Superseded the earlier explicit `{:unsupported_completion, :http3}`. Evidence in the WP3 section below. Shared-owner QUIC connection/endpoint reclamation remains outside this receipt. |
| WT independent profile / network adapter | BLOCKED | Task D's audited independent peers do not match draft-17/reliable-reset. Shared pure router is not wired into sole-owner live streams/datagrams. `webtransport-h3` admission returns `:webtransport_network_not_ready`. |
| Dialyzer / generated docs | NOT RUN | No shared PLT or generated documentation state was mutated. |
| Browser / production / published artifacts | NOT RUN | Separate gates; no publication authorized. |

## WP3 completion receipt checkpoint (2026-11-09)

Root `_build`, `MIX_ENV=test`, current shared checkout. Python peers via
`uv run --python 3.12` with `aioquic==1.2.0`, `wsproto==1.2.0` (and `h2==4.2.0`,
`hpack==4.1.0`, `hyperframe==6.1.0` for H1/H2 WebSocket fixtures);
`aioquic.h3.connection` SHA-256 unchanged from the ledger below.

| Check | Result | Evidence / limits |
| --- | --- | --- |
| Strict compile | PASS | `MIX_ENV=test mix compile --warnings-as-errors`. |
| Owner settlement units | PASS | `tunnel_owner_test.exs`: settle retires only the caller's tunnel, natively cancels before `:settled`, rejects queued opens, stays pending while a pending write/open references it. |
| Relay receipt units | PASS | `tunnel_completion_test.exs` (6): confirmed only after owner `:settled`; never-settling owner -> `:cleanup_unconfirmed`; owner death -> confirmed; relay killed before proof -> `:cleanup_unconfirmed`; tracker abort is graceful and still settles; untracked tunnels unchanged. |
| Exclusive native integration | PASS | `cleanup_integration_test.exs` (native QUIC peer, SETTINGS CONNECT=1, 200 CONNECT): for local close, peer RESET_STREAM and tracker abort the public receipt is `:ok` only with the relay-owned `Quic.Cleanup` scope `:confirmed` and the owner down. |
| Runtime/engine/Fetch/EventSource H3 regression | PASS | `mix test apps/http_runtime/test/http/http3 apps/elixir_quic_http3/test apps/http_fetch/test/http/http3_test.exs apps/http_event_source/test/http/event_source/http3_test.exs --include integration`: runtime 76/0, engine 171/0, EventSource 9/0, Fetch 20/0. |
| WebSocket suite | PASS for H3; pre-existing H1/H2 env failures | `mix test apps/http_web_socket/test --include integration` with the uv peer env: 257 tests. New H3 opening-deadline receipt test passes. `TransportControlsTest` pinned-address cases (2) fail identically with the WP3 files stashed (`:eaddrnotavail`, macOS loopback alias). `WebSocketTLSLifecycleTest` cancel/timeout/eof cases fail intermittently (1 in ~5-8 runs) on both baseline and WP3; other one-off H1/H2 fixture timeouts under full-suite load did not reproduce on file reruns. No H3 test failed. Without the uv env, 59 H1/H2 cases fail on missing Python `h2`. |
| Independent positive gate | PASS | `uv run ... python scripts/http3_websocket/gate.py`: every local Close, peer Close+FIN, peer RESET_STREAM (new `reset-stream` peer message), refusal/subprotocol mismatch and exclusive `http3_reuse: false` socket assert `ClientCompletion.await/2 == :ok`; sibling continuity still passes. |
| Independent SETTINGS refusal | PASS | `--settings-refusal`: refused opening receipt `:ok`. |
| Independent held SETTINGS | PASS | `--hold-settings`: cancellation and opening-deadline receipts `:ok`, owner state empty. |
| Scoped format / Credo | PASS for new code | `mix format --check-formatted` on changed files. `mix credo --strict` on changed files reports only 3 pre-existing nested-alias suggestions in `connection_owner.ex`. |

## Independent peer identity and ownership

Private venv `/tmp/http-fetch-task-c-peer-venv` pins `aioquic==1.2.0` and
`wsproto==1.2.0`. Source SHA-256:

- `aioquic.h3.connection`: `e7e89dc74f7b353771132a7fdfad10ff81208a7102cb58ff33b8e0e09088d7dd`.
- `wsproto.frame_protocol`: `079a7fc11ab9e20bd38a17a06c9dfd46438dadd86d8a9a180c4898abde417409`.

The fixture uses these independent protocol codecs. Its omission/withholding of
SETTINGS is a negative fixture; it is not modern WT acceptance. Assertions fail
closed by terminating the peer, and the launcher checks peer liveness after the
client. The launcher owns a dynamically allocated UDP port, bounds readiness and
client duration, and terminates/kills/reaps its peer in `finally`.

Existing H2 regression fixtures use private-venv `h2==4.2.0`, `hpack==4.1.0`,
`hyperframe==6.1.0` and `wsproto==1.2.0`. OpenSSL fixture discovery uses
`PKG_CONFIG_PATH=/run/current-system/sw/lib/pkgconfig`.

## Reproducible commands

Run from umbrella root with:

```sh
export ERL_FLAGS='+S 4:4'
export MIX_ENV=test
export MIX_BUILD_PATH=/tmp/http-fetch-task-c-20261108/test
export PATH=/tmp/http-fetch-task-c-peer-venv/bin:$PATH
export PKG_CONFIG_PATH=/run/current-system/sw/lib/pkgconfig
mix compile --warnings-as-errors
mix test --include integration \
  apps/http_core/test/http/h3 apps/elixir_quic_http3/test \
  apps/http_runtime/test/http/http3 apps/http_web_socket/test \
  apps/http_fetch/test/http/http3_test.exs \
  apps/http_fetch/test/http/http3_request_trailers_test.exs \
  apps/http_event_source/test/http/event_source/http3_test.exs
python scripts/http3_websocket/gate.py
python scripts/http3_websocket/gate.py --settings-refusal
python scripts/http3_websocket/gate.py --hold-settings
# or, without a private venv:
# uv run --python 3.12 --with aioquic==1.2.0 --with wsproto==1.2.0 \
#   python scripts/http3_websocket/gate.py [--settings-refusal|--hold-settings]
mix credo apps/http_core --strict
mix credo apps/elixir_quic_http3 --strict
mix credo apps/http_runtime --strict
mix credo apps/http_web_socket --strict
```

No deps.get or shared root `_build` writes were performed. Run Mix commands
sequentially against this task's build directory. Formatting was scoped to
explicit owned files; do not replace it with a shared root format mutation.

## Intermediate failures preserved

Earlier strict compile encountered Task A's then-unimplemented
`Connection.migrate/3`. Later strict compiles passed. Some independent peer
checkpoints failed with `{:http3_not_established, {:runtime_down,
{:shutdown, :connection_start_failed}}}` before SETTINGS. The final rerun
initially reproduced this in refusal and held-SETTINGS cases
(`/tmp/http-fetch-task-c-{refusal,held}-verified.log`). During read-only diagnosis,
QUIC sources changed again; the diagnostic refusal passed, followed by the
unmodified positive/refusal/held launchers passing. Those failures are not hidden
or attributed to a specific lane without causal evidence. Final cross-lane
integration remains the coordinator's responsibility.

Initial H1/H2 integration preparation lacked Python hyper-h2 and OpenSSL
pkg-config discovery; the private venv/path above resolved those environment
prerequisites, and the complete 256-test WebSocket suite subsequently passed.
A deadline regression's first startup assertion used 100ms and failed; its
startup bound is now 1000ms, while its meaningful 30ms unresolved-writer
deadline, same-ref indeterminate outcome, cancellation and lease assertions are
unchanged and pass. Credo invocations that reported "No files found" are not
counted as analysis evidence.

## Shared-source checkpoint qualification

The last combined command compiled strictly and passed all 530 tests, but a hash
of all application library/test `.ex`/`.exs` files changed during that run:

- Before: `673bbc1513c08d28938e8db1a560495995a224a8f8a7b85c48d7d2c6f4bd2dac`.
- After: `b7c9542ae25b8958692aa21deae0de8c68e9206309c51aa71fac09e5a4d628bc`.

The recorded file is `/tmp/http-fetch-task-c-final-source.txt`. Task C changed
only its documentation during this run; other lanes continued writing shared
sources. These are successful local checkpoints, not verification of a frozen
final cross-lane tree. The coordinator must run the combined acceptance after
all source writers finish. No repeated test loop was used to chase concurrent
source changes.
