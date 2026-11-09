# Hell Server TLS on ex_ssl Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the last production use of OTP `:ssl` in the umbrella by giving
`ex_ssl` a TCP TLS 1.3 server with mutual TLS (client-certificate auth) and running
`Hell.Transports.SSL` on it.

**Architecture:** The client side is already ex_ssl-only. The remaining
production `:ssl` calls are all in `apps/hell/lib/hell/transports/ssl.ex`, plus
the `:ssl` types in `apps/hell/lib/hell/transport.ex` and
`extra_applications: [:logger, :ssl]` in `apps/hell/mix.exs`. ex_ssl already has a
record-free TLS 1.3 server handshake (`SSL.Protocol.ServerHandshake`, driven
today only by `SSL.QUIC` with `role: :server`). This plan adds a TCP server
connection process that frames that handshake with the existing record layer,
and exposes OTP-shaped `SSL.listen/transport_accept/handshake`. It then rebuilds
`Hell.Transports.SSL` on those functions and keeps its module name and behaviour.

**Tech Stack:** Elixir 1.18+, `:gen_tcp`, `:crypto`, `:public_key`, ex_ssl
internals (`SSL.Protocol.{ServerHandshake, ServerFlight, Record, RecordFramer,
InnerPlaintext, HandshakeFramer}`, `SSL.ClientIdentity`, `SSL.Socket`).

**Spec:** No separate spec. The request is "replace `:ssl` with `:ex_ssl`". Repo
evidence: `CLAUDE.md` ("Hell's server TLS transport retains OTP `:ssl`") and
`docs/server-migration.md:72-74` ("Hell intentionally requires OTP `:ssl`").
This plan reverses that decision.

## Scope decisions (confirmed 2026-11-09: TLS 1.3 and mTLS are required)

1. **Production code only.** OTP `:ssl` stays as the independent *reference
   peer* in tests, for example `:ssl.connect` clients in Hell tests and
   `apps/ex_ssl/test/ssl/otp_reference_test.exs`. If ex_ssl tested against
   itself, the interop evidence would mean nothing. Like `apps/ex_ssl/mix.exs:25`,
   Hell lists `:ssl` in `extra_applications` only when `Mix.env() == :test`.
2. **Server is TLS 1.3 only.** `ServerHandshake` is TLS 1.3. A TLS 1.2 server is
   out of scope. With `versions:` other than `[:"tlsv1.3"]`, `listen` fails
   with `{:error, {:unsupported_option, :versions}}`.
3. **Server-side mTLS is in scope (Task 5).** The server options are `verify: :verify_peer`,
   `cacerts`/`cacertfile`, `fail_if_no_peer_cert` and `depth`, with OTP semantics.
   The server sends a TLS 1.3 CertificateRequest, validates the client's chain
   through the existing `SSL.PKIX`, and checks the client CertificateVerify with
   `SSL.Crypto.Signature.verify_client`. `peercert/1` returns the client leaf DER.
   The TCP server only: the QUIC server keeps `server_mtls: false` and its
   current behavior. No silent fallback to OTP `:ssl`.
4. **No server session tickets/resumption.** The server does not send
   NewSessionTicket. A client offering a PSK is answered with a full handshake.
5. `Hell.Transports.SSL` keeps its name and `Hell.Transport` behaviour. Its option
   type changes from `:ssl.tls_server_option()` to a documented subset.

## Global Constraints

- `apps/ex_ssl/lib` and `apps/hell/lib` contain no calls to OTP `:ssl` modules,
  and their compiled BEAMs import no `:ssl`/`:tls_*`/`:ssl_*` functions.
- No new Hex dependencies. Hell adds `{:ex_ssl, "<exact umbrella version>", in_umbrella: true}`,
  using the same exact-version form as the other umbrella siblings.
- Active-mode messages keep OTP shapes with `%SSL.Socket{}`: `{:ssl, socket, data}`,
  `{:ssl_closed, socket}`, `{:ssl_error, socket, reason}`. Hell's handler already matches
  these tags (`apps/hell/lib/hell/handler.ex:391,462,475,483`).
- TLS failures use the existing ex_ssl shape `{:tls_alert, {alert_atom, charlist}}`.
- No silent backend fallback anywhere. Unsupported options are errors, not ignored.
- Work on the current branch. Do not create branches or worktrees.
- Verification uses the umbrella root: `MIX_ENV=test mix compile --warnings-as-errors`,
  `mix test apps/<app>/test`, `mix format --check-formatted`, `mix credo --strict`, `mix dialyzer`.

## Review Focus

(The mTLS failure alerts are pinned in Task 5's own tests.)

1. **Client sends no ALPN to a server configured with `alpn_preferred_protocols`.**
   The handshake must succeed with no protocol, and `negotiated_protocol/1` returns
   `{:error, :protocol_not_negotiated}`. Today `ServerHandshake.accept_hello` runs
   `select(config.alpn, offer.alpn_protocols, :no_application_protocol)`, which
   would reject it. Pinned in Task 2.
2. **TLS 1.2-only client, or a client mid-handshake disconnect.** The server sends
   a fatal `protocol_version` alert or sees `:closed`. Handshake returns
   `{:error, _}`, the connection process exits, the carrier closes, and the Hell
   listener keeps accepting. Pinned in Tasks 2 and 6.
3. **Handshake timeout.** `SSL.handshake(sock, 100)` against a silent client returns
   `{:error, :timeout}` within the deadline and leaks no process. Pinned in Task 3.
4. **Ownership transfer.** After `controlling_process/2` from the acceptor to the
   handler, active data reaches the new owner only. Owner death closes the
   socket. Pinned in Task 3.
5. **TCP option passthrough and sendfile.** Carrier options such as `send_timeout`
   are readable through `getopts/2`. `sendfile/4` over 1 MiB chunks delivers
   exact bytes. Pinned in Task 6 (existing Hell tests
   `server_test.exs:540` and the sendfile tests).

---

### Task 1: Server option normalization (`SSL.ServerOptions`)

**Files:**
- Create: `apps/ex_ssl/lib/ssl/server_options.ex`
- Test: `apps/ex_ssl/test/ssl/server_options_test.exs`
- Modify (only if extraction is needed): `apps/ex_ssl/lib/ssl/quic/config.ex`.
  Reuse its server-side cipher, group and signature selection rather than
  duplicating it.

**Interfaces:**
- Produces: `SSL.ServerOptions.build(keyword()) :: {:ok, SSL.ServerOptions.t()} | {:error, {:unsupported_option, atom()} | {:invalid_option, atom()} | term()}`.
  `t()` is a map holding the keys `ServerHandshake.accept_hello/3` and `flight/4`
  read (`ciphers`, `groups`, `alpn`, `signature_algorithms`, `identity`, `limits`),
  plus `sni: nil | {:hosts, %{charlist() => keyword()}} | {:fun, (charlist() -> keyword() | :undefined)}`
  and `tcp: keyword()` (passthrough carrier options).
- Accepted keys: `certfile`, `keyfile`, `cert`, `key`, `certs_keys` (first entry only),
  `password`, `alpn_preferred_protocols`, `ciphers` (TLS 1.3 suite atoms or OTP maps
  resolving to 0x1301–0x1303), `versions` (`[:"tlsv1.3"]` only), `sni_hosts`, `sni_fun`,
  `verify` (`:verify_none` default | `:verify_peer`), `cacerts`, `cacertfile`,
  `fail_if_no_peer_cert` (default `false`), `depth`. Every `:gen_tcp` listen option goes to `tcp`.
- `t()` also carries `client_auth: nil | %{trust: <SSL.PKIX.normalize_trust/2 result>, require: boolean(), depth: pos_integer()}`.
  It is `nil` unless `verify: :verify_peer`.
- Rejected: `verify: :verify_peer` without `cacerts`/`cacertfile` returns `{:error, {:invalid_option, :cacerts}}`
  (an mTLS server with no trust anchors would be a silent hole). Each of the following returns
  `{:unsupported_option, key}`: `versions` with anything but `:"tlsv1.3"`,
  `session_tickets` other than `:disabled`, `reuse_sessions: true`, `verify_fun`, `partial_chain`.

- [ ] **Step 1: Write failing tests.** Cover: `build(certfile: cert, keyfile: key)` returns `{:ok, %{alpn: nil}}`;
  `alpn_preferred_protocols: ["h2", "http/1.1"]` gives `alpn: ["h2", "http/1.1"]`;
  `versions: [:"tlsv1.2"]` returns `{:error, {:unsupported_option, :versions}}`;
  `verify: :verify_peer, cacertfile: ca` gives `client_auth: %{require: false}`, and adding
  `fail_if_no_peer_cert: true` gives `require: true`;
  `verify: :verify_peer` alone returns `{:error, {:invalid_option, :cacerts}}`;
  `send_timeout: 1230` ends up in `tcp`; with no cert source and no `sni_*` it returns
  `{:error, :server_identity_required}`. Use the fixtures in `apps/hell/test/support/{cert,key}.pem`
  or copy them to `apps/ex_ssl/test/support/server/`.
- [ ] **Step 2:** `mix test apps/ex_ssl/test/ssl/server_options_test.exs`. Expect: FAIL (module undefined).
- [ ] **Step 3: Implement `SSL.ServerOptions.build/1`.** Load identity via `SSL.ClientIdentity.load/1`
  (the same loader the QUIC server uses).
- [ ] **Step 4:** Re-run the test. Expect: PASS.
- [ ] **Step 5:** Commit `feat(ex_ssl): normalize TLS server options`.

### Task 2: TCP TLS 1.3 server connection (`SSL.ServerConnection`)

**Files:**
- Create: `apps/ex_ssl/lib/ssl/server_connection.ex`. This is a `:gen_statem` with
  states `:hello → :client_finished → :connected → :closing`.
- Modify: `apps/ex_ssl/lib/ssl/protocol/server_handshake.ex`, to make it transport-neutral without changing QUIC behavior.
  When the offer has no ALPN, select `nil` instead of failing (Review Focus 1). With an
  ALPN offer and no overlap, keep the `no_application_protocol` alert (RFC 7301 §3.2).
  `config.alpn == nil` means ALPN is not configured, so ignore the client's offer.
  Omit EncryptedExtensions ext 16 when `state.alpn == nil`.
  Make the QUIC transport parameters (ext 57) conditional on a `config.transport_parameters`
  key: `accept_hello` requires ext 57 and `flight` emits it only when that key is non-nil.
  The QUIC server config keeps setting it, so `SSL.QUIC` stays unchanged.
- Modify: `apps/ex_ssl/lib/ssl/connection_supervisor.ex`, so it starts server connections too.
- Test: `apps/ex_ssl/test/ssl/server_connection_test.exs` (OTP `:ssl` client as reference peer).

**Interfaces:**
- Consumes: `SSL.ServerOptions.t()` (Task 1).
- Produces: `SSL.ServerConnection.start(carrier :: :gen_tcp.socket(), SSL.ServerOptions.t(), owner :: pid()) :: {:ok, SSL.Socket.t()}`
  and `SSL.ServerConnection.handshake(SSL.Socket.t(), timeout()) :: {:ok, SSL.Socket.t()} | {:error, term()}`.
  Once in `:connected`, the process must answer the **same call protocol** that
  `SSL.Connection` answers, for every message `SSL` sends via `call/2` (`send`, `recv`,
  `setopts`, `getopts`, `negotiated_protocol`, `connection_information`, `peercert`,
  `peername`, `sockname`, `close`, `controlling_process`, `shutdown`, `getstat`).
  That way `SSL.send/2`, `SSL.recv/3` and the rest work on server sockets unchanged.
  `peercert/1` returns `{:error, :no_peercert}`.
- Record protection: reuse `SSL.Protocol.Record`, `RecordFramer` and `InnerPlaintext` and
  the key-schedule secrets that `ServerHandshake.flight/4` and `finish/2` return.
  Do not add a second record implementation. HelloRetryRequest goes through `accept_hello`'s
  `{:retry, state, bytes}`. Ignore middlebox `change_cipher_spec` records the way the client does.

- [ ] **Step 1: Write failing tests** in `server_connection_test.exs`. Each starts a `:gen_tcp` listener and
  connects an OTP `:ssl` client (`versions: [:"tlsv1.3"], verify: :verify_peer, cacertfile: ca`):
  - `test "completes TLS 1.3 handshake and echoes data"`: the client sends `"ping"`, the server `SSL.recv(s, 0, 1000) == {:ok, "ping"}`, and the server echoes it back.
  - `test "negotiates ALPN h2"`: both sides report `"h2"`.
  - `test "client without ALPN connects with no protocol"`: `SSL.negotiated_protocol(s) == {:error, :protocol_not_negotiated}`.
  - `test "ALPN mismatch sends no_application_protocol"`: the client sees `{:error, {:tls_alert, {:no_application_protocol, _}}}`.
  - `test "TLS 1.2-only client gets protocol_version and server process exits"`: monitor the server pid and assert `:DOWN`.
  - `test "HelloRetryRequest when client key_share lacks a server group"`: the client offers `supported_groups: [:secp256r1, :x25519]` with the key share on the group the server ranks second.
  - `test "active once delivers {:ssl, socket, data} and {:ssl_closed, socket}"`.
- [ ] **Step 2:** `mix test apps/ex_ssl/test/ssl/server_connection_test.exs`. Expect: FAIL.
- [ ] **Step 3: Implement `SSL.ServerConnection`** and the ALPN change in `ServerHandshake`.
- [ ] **Step 4:** Re-run, then the whole ex_ssl suite `mix test apps/ex_ssl/test`, so the QUIC server
  regressions (`ServerHandshake` is shared) still pass. Then run `mix test apps/elixir_quic/test`.
  Expect: PASS.
- [ ] **Step 5:** Commit `feat(ex_ssl): add TCP TLS 1.3 server connection`.

### Task 3: Public server API on `SSL`

**Files:**
- Modify: `apps/ex_ssl/lib/ssl.ex`
- Modify: `apps/ex_ssl/README.md` and `docs/ex-ssl-consumer-contract.md` (add a server section listing the scope limits 2–4 above)
- Test: `apps/ex_ssl/test/ssl/server_api_test.exs`

**Interfaces:**
- Consumes: Task 1 and Task 2.
- Produces (OTP-shaped, so Hell's delegates map 1:1):
  - `SSL.listen(:inet.port_number(), keyword()) :: {:ok, SSL.ListenSocket.t()} | {:error, term()}`. This validates
    options via `ServerOptions.build/1` *before* opening the port, then calls `:gen_tcp.listen` with
    `tcp ++ [:binary, active: false]`.
  - `SSL.transport_accept(SSL.ListenSocket.t(), timeout() \\ :infinity) :: {:ok, SSL.Socket.t()} | {:error, term()}`
    accepts TCP and starts a `ServerConnection` without handshaking.
  - `SSL.handshake(SSL.Socket.t(), timeout()) :: {:ok, SSL.Socket.t()} | {:error, term()}`
  - `SSL.handshake(:gen_tcp.socket(), keyword(), timeout()) :: {:ok, SSL.Socket.t(), []} | {:error, term()}`
    handles server upgrade of an existing TCP socket (Hell `upgrade/3`). The return keeps OTP's 3-tuple.
  - `SSL.getstat(SSL.Socket.t(), [atom()] \\ all) :: {:ok, keyword()} | {:error, term()}` reads the carrier's `:inet.getstat`.
  - `SSL.shutdown/2` if it does not already exist.
  - `SSL.close/1`, `SSL.sockname/1` and `SSL.controlling_process/2` accept `SSL.ListenSocket.t()`.
  - `SSL.ListenSocket` is a new opaque struct `{carrier, ServerOptions.t()}` in `apps/ex_ssl/lib/ssl/listen_socket.ex`.

- [ ] **Step 1: Write failing tests:**
  - `listen(0, verify: :verify_peer, certfile: c, keyfile: k) == {:error, {:unsupported_option, :verify}}`, and no port stays open.
  - Full `listen → transport_accept → handshake` with an OTP client. `SSL.sockname(listen)` returns the bound port.
  - `test "handshake timeout"`: a raw `:gen_tcp` client that sends nothing. `SSL.handshake(s, 100)` returns `{:error, :timeout}` in <500 ms, and the connection pid is dead (Review Focus 3).
  - `test "controlling_process moves active delivery"`: transfer to a spawned pid with `active: :once`. Only the new pid gets `{:ssl, _, _}`. Killing it closes the socket, and the peer sees `{:ssl_closed, _}` (Review Focus 4).
  - `test "server upgrade of an existing gen_tcp socket"`: `SSL.handshake(tcp, [certfile: c, keyfile: k], 2000)` returns `{:ok, %SSL.Socket{}, []}`.
  - `test "getstat returns carrier counters"`: has `:recv_oct`.
- [ ] **Step 2:** `mix test apps/ex_ssl/test/ssl/server_api_test.exs`. Expect: FAIL.
- [ ] **Step 3: Implement the functions in `ssl.ex`** and `listen_socket.ex`.
- [ ] **Step 4:** Re-run, then `mix test apps/ex_ssl/test` and `mix dialyzer`. Expect: PASS, with no new warnings.
- [ ] **Step 5:** Commit `feat(ex_ssl): expose TLS server listen/accept/handshake API`.

### Task 4: SNI certificate selection

**Files:**
- Modify: `apps/ex_ssl/lib/ssl/server_connection.ex`. Before `accept_hello`, parse
  `server_name` from the ClientHello and resolve the identity.
- Test: `apps/ex_ssl/test/ssl/server_sni_test.exs`, using two certs. Generate them in the test with
  `:public_key.pkix_test_data/1`, which is the existing pattern in ex_ssl tests.

**Interfaces:**
- Consumes: `ServerOptions.t().sni` (Task 1).
- Resolution order: `sni_hosts[name]`, then `sni_fun.(name)` (`:undefined` → default identity),
  then the default identity. If there is none, send an `unrecognized_name` fatal alert.

- [ ] **Step 1: Write failing tests:**
  - `sni_hosts: [{~c"a.test", [cert: a, key: ka]}]`: a client with `server_name_indication: ~c"a.test"` verifies against CA A.
  - With an unknown name it falls back to the default cert.
  - `sni_fun` returning `:undefined` with no default identity: the client gets `{:tls_alert, {:unrecognized_name, _}}`.
- [ ] **Step 2:** Run. Expect: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Run. Expect: PASS.
- [ ] **Step 5:** Commit `feat(ex_ssl): select server identity by SNI`.

### Task 5: Server-side client-certificate authentication (mTLS)

**Files:**
- Modify: `apps/ex_ssl/lib/ssl/protocol/server_flight.ex`. Add
  `encode_certificate_request(context :: binary(), extensions :: [{non_neg_integer(), binary()}]) :: {:ok, binary()} | {:error, term()}`
  (handshake type 13). It must round-trip through the existing `decode/2` into `%CertificateRequest{}`.
- Modify: `apps/ex_ssl/lib/ssl/protocol/server_handshake.ex`. When `config.client_auth != nil`
  and the handshake is not PSK-resumed, `flight/4` inserts a CertificateRequest between
  EncryptedExtensions and the server Certificate (RFC 8446 §4.3.2). It has an empty context and carries
  `signature_algorithms` (13) and, when the trust list is small enough, `certificate_authorities` (47).
  Add `accept_client_certificate(State.t(), binary()) :: {:ok, State.t()} | {:error, term()}`
  and `accept_client_certificate_verify(State.t(), binary()) :: {:ok, State.t()} | {:error, term()}`.
  Each appends to the transcript, so `finish/2` verifies the client Finished over the full transcript.
- Modify: `apps/ex_ssl/lib/ssl/server_connection.ex`. Add states
  `:client_certificate → :client_certificate_verify → :client_finished`.
- Test: `apps/ex_ssl/test/ssl/server_mtls_test.exs`, with the OTP `:ssl` client as reference peer.
  Generate the CA, server and client certs with `:public_key.pkix_test_data/1`, and an untrusted second CA.

**Interfaces:**
- Consumes: `ServerOptions.t().client_auth` (Task 1); the existing `SSL.PKIX.peer/6` or `verify/4`
  with `mode` for client identities (no hostname check); `SSL.Crypto.Signature.verify_client/…`;
  `ServerFlight.decode/2` for Certificate and CertificateVerify.
- Produces: `SSL.peercert(server_socket) :: {:ok, der :: binary()} | {:error, :no_peercert}`,
  and `connection_information/1` gains a `:peer_authenticated` key, `:client` or `false`.
- Failure alerts (RFC 8446 §6.2), which the server sends and returns from `handshake/2`:
  - empty client Certificate with `require: true` → `certificate_required`
  - unknown CA → `unknown_ca`
  - expired → `certificate_expired`
  - bad CertificateVerify → `decrypt_error`
  - chain longer than `depth` → `unknown_ca`

- [ ] **Step 1: Write failing tests:**
  - `encode_certificate_request` round-trips through `ServerFlight.decode/2`.
  - With `verify_peer` and `fail_if_no_peer_cert: true`, a client presenting a valid cert connects. The server's
    `SSL.peercert(s)` equals the client leaf DER, and `connection_information(s)[:peer_authenticated] == :client`.
  - With the same server, a client with no cert: the server `handshake` returns `{:error, {:tls_alert, {:certificate_required, _}}}`.
  - With `fail_if_no_peer_cert: false`, a client with no cert connects, and `peercert` returns `{:error, :no_peercert}`.
  - A client cert signed by the untrusted CA gives `{:tls_alert, {:unknown_ca, _}}`.
  - An expired client cert (`pkix_test_data` with a past validity) gives `{:tls_alert, {:certificate_expired, _}}`.
  - Without `verify_peer`, no CertificateRequest is sent. Assert this by checking that OTP's
    `:ssl.connection_information(c, [:client_cert])` side has no request, or use a recording carrier.
  - A QUIC server regression: an `SSL.QUIC` server config never emits CertificateRequest
    (the existing QUIC suite passes unchanged).
- [ ] **Step 2:** `mix test apps/ex_ssl/test/ssl/server_mtls_test.exs`. Expect: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Run `mix test apps/ex_ssl/test` and `mix test apps/elixir_quic/test`. Expect: PASS.
- [ ] **Step 5:** Commit `feat(ex_ssl): authenticate TLS 1.3 server clients (mTLS)`.

### Task 6: Rebuild `Hell.Transports.SSL` on ex_ssl

**Files:**
- Modify: `apps/hell/lib/hell/transports/ssl.ex`. Replace every `:ssl.` call and `to: :ssl`
  delegate with `SSL`. Drop the hand-written certificate presence checks (`listen/2:58-70`),
  since `SSL.listen/2` now validates. The moduledoc lists the supported options (including mTLS)
  and the TLS 1.3-only limit.
- Modify: `apps/hell/lib/hell/transport.ex:20,24,27,60,71,109`. Replace `:ssl.*` types with
  `SSL.ListenSocket.t()`, `SSL.Socket.t()`, `{:tls_alert, {atom(), charlist()}}` and `keyword()`.
- Modify: `apps/hell/lib/hell.ex:187-191` (the option type union).
- Modify: `apps/hell/mix.exs`: `extra_applications: [:logger] ++ if(Mix.env() == :test, do: [:ssl], else: [])`;
  add `{:ex_ssl, <exact version>, in_umbrella: true}`.
- Modify: `mix.exs` (root) and `scripts/release/*` if they compute Hell's dependency closure or
  release groups (check `mix.exs:60-150` and `scripts/release/stage.py`).
- Test: the existing `apps/hell/test/hell/*.exs`. Update only the assertions that check
  OTP-specific error values.

**Interfaces:**
- Consumes: Task 3's `SSL.listen/2`, `transport_accept/1`, `handshake/2,3`, `getstat/1`, plus the existing
  `SSL.send/recv/setopts/getopts/controlling_process/close/shutdown/sockname/peername/peercert/negotiated_protocol/connection_information`.
- `accept/1` delegates to `SSL.transport_accept/1`. `upgrade/3` calls `SSL.handshake(tcp, opts, timeout)` and strips the 3-tuple.

- [ ] **Step 1: Add failing Hell tests.** In `apps/hell/test/hell/server_test.exs`, add
  `test "ssl mTLS exposes the client certificate to the handler"`. Hell runs with
  `transport_options: [certfile: c, keyfile: k, verify: :verify_peer, cacertfile: ca, fail_if_no_peer_cert: true]`.
  A handler replies with `Hell.Socket.peercert/1`, and an OTP client presenting a cert receives its own DER.
  Add `test "ssl rejects TLS 1.2 versions option"`: `start_supervised` returns an error containing
  `{:unsupported_option, :versions}`.
  Also add a BEAM import check: after compile,
  `:beam_lib.chunks(:code.which(Hell.Transports.SSL), [:imports])` contains no module in `[:ssl, :tls_socket, :ssl_gen_statem]`.
- [ ] **Step 2:** `mix test apps/hell/test`. Expect: the new tests FAIL. Record the current pass count as the baseline.
- [ ] **Step 3: Implement the transport, types and mix changes.**
- [ ] **Step 4: Fix the one known OTP-specific assertion.** `server_test.exs:693-724`
  ("unsupported ciphers") asserts `{:tls_alert, {:insufficient_security, _}}`. Keep the test's intent,
  "no shared cipher fails with a fatal alert delivered to `handle_error`". Make the client offer TLS 1.3 with
  only a suite the server excludes via `ciphers:`, and assert the alert ex_ssl maps
  `:no_shared_cipher` to (`:handshake_failure` per RFC 8446 §4.1.1). Do not weaken other assertions.
  If any other test fails, diagnose it before you change anything.
- [ ] **Step 5:** `MIX_ENV=test mix compile --warnings-as-errors && mix test apps/hell/test && mix test apps/abyss/test`.
  Expect: all PASS, with the pass count ≥ baseline + 2. Then run `mix dialyzer` and `mix credo --strict`.
- [ ] **Step 6:** Commit `feat(hell)!: run SSL transport on ex_ssl`.

### Task 7: No-OTP proof, docs and release notes

**Files:**
- Modify: `scripts/release/no_otp_release_audit.exs` (and its `test_no_otp_release_audit.*` tests).
  Add `hell` (and `abyss`, which already has no `:ssl` calls) to the audited BEAM set, so a
  `:ssl` import in either fails the audit.
- Modify: `CLAUDE.md` (Project Overview and Requirements). Remove "Hell's server TLS transport retains OTP `:ssl`".
  OTP `:ssl` becomes required only by test/reference peers.
- Modify: `docs/server-migration.md:72-74`, `docs/migration-provenance.md:217`, and `apps/hell/CHANGELOG.md`.
  The CHANGELOG entry is breaking: TLS 1.3-only server, the option subset (mTLS supported), and the changed alert values.
- Modify: `apps/ex_ssl/CHANGELOG.md` (server API added).

- [ ] **Step 1:** Add a failing audit test case: a fixture BEAM importing `:ssl.send/2` under the `hell` app is reported.
- [ ] **Step 2:** Run the audit's test (`elixir scripts/release/test_no_otp_release_audit.exs` / `python3 scripts/release/test_no_otp_release_audit.py`). Expect: FAIL.
- [ ] **Step 3:** Extend the audit's app list.
- [ ] **Step 4:** Run the audit tests and then the real audit over a `MIX_ENV=prod mix compile` build. Expect: PASS, with zero `:ssl` imports across all eleven portable packages.
  Run `bash scripts/external_consumer_smoke.sh`. Expect: PASS.
- [ ] **Step 5:** Update the docs and CHANGELOGs, then `mix format --check-formatted`.
- [ ] **Step 6:** Commit `docs: record ex_ssl-only server TLS and extend no-OTP audit to Hell`.

## Follow-ups (not in this plan)

- `verify_fun` / `partial_chain` server hooks, and post-handshake client auth.
- TLS 1.2 server.
- Server NewSessionTicket / PSK resumption and 0-RTT on TCP.
