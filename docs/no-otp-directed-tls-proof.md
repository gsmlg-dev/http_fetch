# Directed TLS callable-origin review

This review covers the 14 TLS occurrences in
[the production inventory](no-otp-release-dispatch-inventory.csv), proofs TLS-1
through TLS-6. It reviews actual constructors, option projections and retained
values from supported TLS, HTTP and QUIC entries. It does not extend the generic
analyzer or remove its findings. The selected-source inputs and exact original
occurrences are recorded in [the review binding](no-otp-directed-tls-proof.json).
Source equality binds the review to these inputs; a hash alone is not a safety
proof or an external-callback exemption.

## TLS-1: fresh key-share generator

The three library callers of `Materializer.materialize` are
`SSL.Connection.start_tls/3`, `SSL.QUIC.Config.materialize/1` and
`Quic.Profile.materialize/2`. All call arity 3, whose default fourth argument is
`[]`. Consequently `key_share_generator/1` takes its `:error` branch and returns
`&SSL.Crypto.KeyExchange.generate/1`. Group selection changes data passed to that
capture, not its callable identity. `generate/1` selects supported OTP crypto
primitives and does not invoke OTP SSL.

`SSL.Options.normalize/2` accepts only `:lifecycle`, `:profile` and
`:reference_identity` under `:ex_ssl`; neither it nor QUIC configuration projects
`:test_key_share_generator` into the fourth materializer argument. The standalone
codec's explicit four-argument deterministic test hook therefore has no incoming
path from supported connection operations. This is a concrete caller argument
proof, not an assumption that every exported function receives production data.

## TLS-2: encrypted-key password callback

`SSL.Options.normalize/2` projects the caller's identity keys into
`ClientIdentity.load/1`. Its legacy single identity and every `:certs_keys` map
reach `load_single/2`; each map retains its own `:password`. Only
`password_option({:ok, callback})` with `is_function(callback, 0)` constructs
`{:callback, callback}`. The corresponding `resolve_password/1` invocation is
the sole sink. No library caller supplies a password function. QUIC projects only
`:cert` and `:key`, so it cannot introduce this callback.

The user-supplied zero-argument function is the supported password callback
boundary. Its result must pass bounded iodata validation before decryption.
Neither its result nor an exception becomes another callable, module selector,
verifier or connection state. Subsequent prepared snapshots contain resolved
identity material; they do not defer or substitute the password callback.

## TLS-3: CRL cache operations

`Options.certificate_policy/1` constructs `:crl_cache` from the validated public
option or the literal `{:ssl_crl_cache, {:internal, []}}`. Its supported custom
cache shape is `{module, {reference, options}}`; the four generic invocations
(`lookup/2,3`, `select/2`, `fresh_crl/2`) originate in that option. There is no
library-supplied custom cache module. Cache results are bounded DER/data inputs,
not replacement cache modules or callbacks.

The compatibility atoms are handled before generic dispatch:

- `:ssl_crl_cache` lookup/select call `SSL.CRLCache.lookup_owned/3` and
  `select_owned/3`. Its optional HTTP lookup uses the owned ExSSL policy HTTP
  client. The atom never selects OTP's cache implementation.
- `:ssl_crl_hash_dir` lookup/select enumerate bounded hash-directory files through
  `SSL.PolicyIO.read_file/2`.
- Refresh for both built-in cache names returns the current CRL without a module
  call. The `update_crl` function passed to `public_key` is a library closure
  around this same `refresh/4` selection.

Thus built-in cache bodies remain audited library code; arbitrary custom cache
bodies retain the supported callback boundary and are not certified OTP-free.

## TLS-4: verification and hostname callbacks

`SSL.Options` validates `:verify_fun` with `VerifyFun.valid?/1` and accepts only
the supported arities. It accepts a hostname matcher only as the single
`:match_fun` option with arity 2. QUIC independently validates this same matcher
shape; its `verifier_options` contains the matcher and depth, with no verifier
injection. Resumption revalidation projects the normalized hostname options back
into `PKIX.peer/6` and supplies no new callback.

There are exactly two library callers of `VerifyFun.wrap/2`:

1. `PKIX.callback_paths/4` creates a hostname closure calling
   `verify_identity/3` with the retained reference identity and matcher options.
2. `PolicyIO.policy_callback/6` creates a hostname closure calling
   `:public_key.pkix_verify_hostname/3` with the same retained inputs.

`wrap/2` creates the fixed policy wrapper for `:undefined`, a supported three- or
four-argument user verifier, or the legacy one-argument verifier. Its
`policy_event/3` hostname call always receives one of the two library closures
above. Its `invoke/5` and `legacy/4` calls receive only the validated verifier
projection. Callback-returned state is passed back as verifier state, never used
as a function selector. Private failures and invalid results are sanitized.

`HTTP.Transport.ExSSL.tls_options/1` supplies one additional built-in matcher:
`:public_key.pkix_verify_hostname_match_fun(:https)`. Caller options may replace
it with the supported matcher. The built-in function is an OTP `public_key`
hostname-comparison primitive, not an SSL transport. Both built-in and caller
alternatives are retained in this review; the default is not mislabeled as user
code. No other library verifier, password or hostname callback producer appears
in the production-source census.

## TLS-5: partial-chain callback

The only producer of `policy.partial_chain` is
`Options.certificate_policy/1`, using the public `:partial_chain` option validated
as an arity-one function. `PolicyIO.prepare/4` captures that normalized policy;
`verify_policy/8 -> select_candidates/3 -> partial_selection/2` retains it.
Absent callbacks and self-signed peers take the explicit non-call branches.
The callback receives an ordered DER path. Its result is interpreted by
`PartialChain` as a trust-selection result; it cannot replace the callback,
certificate verifier or TLS state. No library producer supplies an alternative
partial-chain function. The callback body is the existing user-code boundary.

## TLS-6: certificate-policy verifier

All supported TCP connection and upgrade forms normalize through `SSL.Options`.
`prepare_upgrade/1` creates an opaque `PreparedUpgrade` from those normalized
options; the documented snapshot contract forbids constructing or modifying its
internal representation. `Connection.start_tls/3` calls `PolicyIO.prepare/4`:
no policy returns `nil`, while an enabled policy returns the literal six-argument
closure around `verify_policy/8` and the retained context/options.

That value is supplied explicitly to `HandshakeMachine.init/4`. The TLS1.3 path
retains it through `verifier_options/1`, `ServerFlightVerifier` and
`HandshakeCore` configuration. The TLS1.2 selection passes the machine's retained
options to `TLS12.new/5`. Each verification sink chooses exactly the retained
policy closure or `&SSL.PKIX.peer/6`. Neither peer certificate data nor user
verification callback results update that selector. The policy closure executes
the TLS-3, TLS-4 and TLS-5 routes reviewed above. Completion drops retained
callback options; it does not introduce another callable.

The QUIC `HandshakeCore.start_client/3` path receives
`SSL.QUIC.Config.verifier_options`, which has no `:certificate_policy` field;
its verifier is consequently `PKIX.peer/6`. Standalone handshake/codec test
constructors are not supported transport inputs. All actual library constructors
and both TLS-version branches remain included in the review.

## Evidence and remaining acceptance

The binding records hashes for every source file used by these derivations and
the exact 14 inventory occurrences. It is matched to the packaged sources in
CI artifact `13119243608` at `524edb2`. The independent no-OTP production releases
pass all 70 planned traffic cases; those samples support interoperability and
cleanup, and do not replace the origin derivations above.

The generic audit still retains these 14 findings within its total of 175.
No source-bound compiled discharge has been accepted by this document, and P6
remains blocked. The separate manual-ticket suite passes 9/9 on local
Elixir 1.18.5 / OTP 29; its two OTP 28 reference-client failures remain open.
Credo/Dialyzer and performance retain their user-approved deferrals.

## 2026-11-05 source review amendment: RC2 static checks

This amendment reviews production commit `5050bfcfd82c7a650d7d87113d30ca8360d91edf`
against RC1 (`b3a145956c59824ab7e38e3d708fc3a197c30e90`). `Socket.new/3` constructs
the same PID/reference/status handle; `Socket.fetch/1` returns that exact handle
after PID/reference checks and a bounded `:atomics.get/2` validation of the status.
The status retains its actual opaque `:atomics.atomics_ref()` type. Validation
does not authenticate the handle; the connection still checks its own reference.
Malformed private carriers return `badarg` before reaching TCP/native operations.

Every nested carrier branch still calls literal `SSL` functions. The writer's
new private helper retains the original bytes, finite absolute deadline or
infinite deadline, result message and receive order. Its guard expands to the
original binary-or-list predicate. Connection and setup constructors acquire no
new module or callback fields. TLS1.2 lifetime validation is the same conjunction
in a private helper; cache puts and error cleanup explicitly discard only results
that were already best effort. No callback producer or supported TLS selector
changes, and no original TLS occurrence changes its line or owning function.

The fresh isolated candidate compiled 350 BEAMs and retained exactly the original
175 raw dispatches. Its 35 TLS1.3 peer scenarios passed; collection mode correctly
retained a static FAIL until directed binding. The historical artifact, checks,
source commit, census and BEAM hashes remain historical evidence. The JSON
amendment records current selected inputs and a new 244-file source census;
strict candidate and published release gates must bind the current BEAMs.


## 2026-11-07 source review amendment: RC7 default version order

The sole production change in `SSL.Options.profile/2` sorts the already validated
numeric version list with the literal call `Enum.sort(versions, :desc)` only when
constructing a generated `:default` profile. Concrete WireProfiles keep their
ordered policy. This changes protocol preference data; it introduces no callback,
module selector, verifier or OTP SSL implementation. Identity, trust and callback
projections reviewed in TLS-1 through TLS-6 are unchanged, as are mandatory EMS
and downgrade-marker validation.

`SSL.Options` owns none of the 14 reviewed TLS dispatch occurrences. The three
added source lines therefore require no occurrence-coordinate rebindings; the
existing occurrence sources, owning functions and coordinates remain unchanged.
The JSON binding pins the new options source hash and records the current
246-file production census. Historical source commits, artifacts, BEAM hashes
and prior acceptance results remain historical evidence. Strict candidate and
published release gates must independently bind and inspect the current BEAMs;
this source review does not claim that compiled acceptance has already passed.


## 2026-11-07 source review amendment: RC8 legacy TLS 1.2 full handshakes

The reviewed production diff in `SSL.Protocol.TLS12` records the ServerHello EMS
extension as a boolean. Full-handshake key derivation selects only the literal
`TLS12KeySchedule.derive/5` or `derive_legacy/4` calls. The latter validates bounded
premaster/random inputs and derives the RFC 5246 master with the existing bounded
SHA-256/SHA-384 HMAC PRF, then constructs the same TLS 1.2 record states. Neither
path invokes OTP SSL or introduces a callback or module selector.

TLS-6 retains the same six-argument certificate-policy closure or
`SSL.PKIX.peer/6` selector and its existing trust, identity and verification
options. Its `verify_certificate/3` invocation moves from source line 390 to 396;
no other reviewed TLS invocation moves. Legacy full handshakes retain certificate,
ECDHE signature, Finished and AEAD verification. An accepted session echo still
requires EMS, and only an EMS full handshake emits reusable session material;
completion clears the legacy master and policy state as before.

The JSON binding records both changed source hashes, adds the key-schedule source
to the selected inputs, and rebinds only occurrence 74. Original source commits,
artifacts, checks and BEAM hashes remain historical evidence. This amendment is
source review only: it supplies no new compiled certification and adds no
automatic publication gate. Source tests and any future compiled audit remain
separate evidence from publishing packages and documentation.

## 2026-11-10 source review amendment: rc.11 TLS 1.3 server and QUIC resumption

This amendment reviews the production sources at `4ae97fc` against the last bound
census at `1a1f81d`. Seven selected TLS inputs change and the census gains the
server modules `SSL.ServerOptions`, `SSL.ServerConnection`, `SSL.ListenSocket`
and the QUIC `SSL.QUIC.Resumption`/`SSL.QUIC.Session` modules. The three server
modules are added to the selected inputs because they produce and invoke the new
server callback. The complete ten-package production census is now 267 files.

### TLS-7: server SNI identity callback

`SSL.listen/2` and the upgrade form `SSL.handshake/3` normalize options only
through `ServerOptions.build/1`. Its `sni/1` is the sole producer of
`{:fun, fun}`: the caller's `:sni_fun`, accepted only when it is an arity-one
function and `:sni_hosts` is absent. `ListenSocket` is opaque and constructed
only by `listen/2`; `transport_accept/2` passes its retained options to
`ServerConnection.start/3`, which stores them as the connection's `config`.
OTP-only server options, including `:verify_fun`, are rejected before any port
is opened.

The only caller of `lookup/2` is `ServerOptions.select_identity/2`, called once
from `ServerConnection` for the first ClientHello. It replaces only the selected
identity and signature schemes and retains `sni`. The callback receives the
ClientHello server name and returns `:undefined` or identity keyword options. Those
options are data: their keys are restricted to identity keys, and they are loaded
by `ClientIdentity.load/1`, whose password callback remains TLS-2. A raise,
throw, exit or invalid result becomes an `internal_error` alert. No library
producer supplies `sni_fun`; Hell forwards its caller's options to `SSL.listen/2`.
The user `sni_fun` body is the approved server callback boundary; it is not
certified free of OTP SSL.

Server mTLS verifies client certificates with the new `PKIX.client_peer/3`. It
runs the existing path validation against normalized trust anchors with a nil
verifier and no hostname matcher, then checks extended key usage. It introduces no
callback. The server handshake, server flight and connection bodies add no other
unresolved dispatch and import no OTP SSL module.

### Moved and unchanged client occurrences

`PKIX.hostname_match_fun/3` (ID 71) moves from line 767 to 817 because
`client_peer/3` is inserted above it; its closure is unchanged (TLS-4).
`HandshakeCore.verify_peer/3` (ID 73) moves from 768 to 789. It still selects
`config.certificate_policy || &PKIX.peer/6` and now only delegates the alert
mapping to `certificate_alert/1` (TLS-6). The new `allow_early_data` handshake
input is a boolean. `SSL.QUIC` adds resumption and 0-RTT requests answered by
`continue/3`. `SSL.QUIC.Config` accepts only the data-valued `:resumption`
policy. Neither adds a module or callback option. `SSL.Connection` now rejects
server-socket requests, and `HandshakeMachine` exposes two key-update helpers to
`ServerConnection` as literal calls.

The JSON records all seven old/new input digests, the three added inputs, the
current census digest, the two line rebindings and new ID 181. TLS now has 15
reviewed occurrences. The complete compiled inventory of a locally built isolated
candidate release has 206 sites in 382 BEAMs, matching the five reviews exactly,
with no direct OTP SSL import. CI strict candidate and published gates must
still bind these sources and BEAMs independently.

### Follow-up: capability reporting (2026-11-10)

`capabilities/0` values and `migrate/2` documentation changed after the
CI-confirmed M2, reliable-reset, R1 and R2 matrices (`b2239e7`, `b1276f9`,
`f70e874`) and the `QuicHttp3` extension flags. These are literal map values and
documentation only: no dynamic dispatch is added or moved, and no reviewed
occurrence is rebound. Producer hashes, the release census and every group's
rc.11 census digest are updated.

### Follow-up: transport close without close_notify (2026-11-11, #158)

`SSL.Connection` now delivers buffered authenticated plaintext before reporting
a transport close or error that arrives without close_notify (still
`:econnreset` for a plain close), and `SSL.ServerConnection` drains its buffer
before reporting a `tcp_error`. Only literal calls and state updates changed: no
dynamic dispatch is added or moved and no reviewed occurrence is rebound.
Producer hashes, the release census and every group's census digest are updated.

A second #158 follow-up lets the writer settle an in-flight duplex write after an
unclean close; it adds no dynamic dispatch and rebinds no occurrence.

### Follow-up: rc.13 review fixes (2026-11-11)

Server certificate selection and pre-auth bounds (`8e810b4`) change `ssl.ex`,
`pkix/pkix.ex`, `server_options.ex` and `server_connection.ex`. `ServerOptions`
now runs `sni_fun` in a monitored helper process bounded by the handshake
deadline, so the TLS-7 invocation (occurrence 181) moves from `lookup/2` into the
helper closure body `call_sni_fun/2` (line 194 to 262, expression `fun.(name)`
unchanged). Its only origin is still the caller `:sni_fun` that `sni/1`
validates and stores as `{:fun, fun}`; no library caller supplies one. The
rebinding records `previous_mfa` and `previous_line`. The PKIX sites (71, 73)
keep their lines. The wildcard rule, `certs_keys` handling and pre-auth bounds
add only literal calls and guards. Producer hashes, the release census and every
group's census digest are updated.

### Follow-up: rc.14 production changes (2026-11-11)

No TLS input changes after `v1.0.0-rc.13`. `HTTP.Transport.ExSSL` is unchanged.
It is now named literally where `HTTP.TLSBackend.transport/1` used to return it
(HTTP review). Only the census digest and the reviewed inventory digest are
updated.

### Follow-up: rc.14 ex_ssl server fixes (2026-11-12)

`ssl.ex` and `server_connection.ex` change in three commits:

- `707d2c2`: an exact recv after peer close keeps buffered plaintext.
- `e27a9c8`: `SSL.getopts/2` reads listen-socket carrier options through
  `:inet.getopts/2`.
- `d978d36`: server carrier writes become jobs for an `SSL.ConnectionWriter`
  started through the literal `ConnectionWriter.start/1`.

They add only literal calls, guards and local closures for `Enum.each/2`. The
compiled inventory reports no site in either module or in
`SSL.ConnectionWriter`. No TLS occurrence is added, removed or rebound.
Producer hashes and the digests are updated.

### Follow-up: rc.15 ex_ssl client recv and trust-store fixes (2026-11-12)

`connection.ex` and `ssl.ex` change in `1967e6e` (#164). After the peer closes,
a client exact-length recv that buffered plaintext cannot satisfy returns
`:timeout` and keeps the bytes. The closed branch calls the new private
`closed_recv_result/1`, a literal local call whose two guarded clauses return
literal error tuples. Code after line 1512 moves by 6 lines, but
`SSL.Connection` holds no reviewed occurrence, so nothing is rebound. The
`ssl.ex` change is `recv/3` documentation only.

`SSL.Application` (`cc5514f`, #165) is not a selected TLS input and is bound by
the census. Its `start/2` now calls the literal `:public_key.cacerts_get/0`
before the supervisor starts, inside a local rescue. No dynamic dispatch is
added.

A release-audit BEAM scan of the rc.14 and current sources reports identical
sites, none in `SSL.Connection` or `SSL.Application`. No TLS occurrence is
added, removed or rebound. Producer hashes and the census digest are updated;
the reviewed inventory digest is unchanged at 209 sites.

### Follow-up: rc.16 HTTP/2 unprocessed-retry option (2026-11-12)

No TLS input changes. Only the census digest and the reviewed inventory digest
are updated: twelve HTTP-4 SocketClient sites move by 5 lines, and the total
stays 209.

### Follow-up: rc.17 ex_ssl bounded active-once delivery (2026-11-12)

`055f9fb` (#169) adds the `active_chunk_size` option. `server_options.ex`
validates it in the private `active_chunk_size/1` (three literal guarded
clauses), stores it in the server config and keeps it out of the carrier
options. `options.ex` accepts it in `setopts/2` through a literal
`valid_option?/2` clause. `server_connection.ex` and `connection.ex` bound each
active-once message with literal `min/2`, `Map.get/3` and `Keyword.get/3`
calls; the remaining bytes stay buffered in order. The `ssl.ex` change is
`listen/2` documentation only.

TLS-7 occurrence 181 (`fun.(name)` in `call_sni_fun/2`) moves from line 262 to
266 with an unchanged expression and owning function, and is rebound. No
dynamic dispatch is added or removed. Producer hashes, the census digest and
the reviewed inventory digest are updated; the total stays 209.
