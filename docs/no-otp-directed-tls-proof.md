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
