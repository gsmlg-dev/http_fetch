# Directed QUIC callable-origin review

This review covers Q1–Q4: the 28 original `elixir_quic` occurrences in the
[production inventory](no-otp-release-dispatch-inventory.csv), plus the two
reviewed M1 path-clock occurrences numbered 176 and 177. It follows the
actual constructors and state transitions used by the public QUIC operations.
The [source binding](no-otp-directed-quic-proof.json) identifies the reviewed
inputs and original compiled occurrences. It does not remove generic findings
or certify a user-supplied implementation.

## Q1: cleanup retirement capability

`Quic.Cleanup.new/1` is the only production constructor of `Cleanup.Lease`.
It creates a fresh handle, secret and atomics receipt, then constructs the
two-argument retirement closure. The closure accepts only that exact handle
and secret and calls the local `fence/1`; other arguments return
`:invalid_lease`. The lease is opaque. Constructing or modifying its private
representation is outside the approved input boundary.

`Quic.client/1` passes the lease to tracked endpoint creation. Endpoint, IO and
connection admission retain the same lease or a `Permit` containing it; none
updates `retirement`. HTTP/3 Session, Transport.Quic, Pool, ConnectionOwner and
Stream retain a cleanup descriptor, pass its lease to `retire/2`, or call
`retire_descriptor/2`. The descriptor validator preserves the input lease and
checks its matching handle. It does not construct another retirement function.
There is no library implementation of an alternate cleanup lease.

The optional connector callback can return a descriptor, but a supported
descriptor still contains the opaque values returned by `Cleanup.new/1`.
Its validation does not grant arbitrary fabricated leases a callback exemption.
Expiry, abort, watchdog retirement and successful shutdown all reach the same
closure. Peer bytes and native operation results never replace it.

## Q2: endpoint and connection IO

`Quic.listen/1` and `client/1` start `Quic.Endpoint` with an explicit role.
`Endpoint.open_io/2` has exactly two successful constructors:

- No `:io` option creates a `Quic.IO.GenUDP` process and records that literal
  module with its writer PID.
- The supported server `{:external, local, send_fun}` form creates
  `Quic.IO.ExternalWriter` and records that literal module with its writer PID.
  Invalid external forms return an error; other forms cannot return an IO value.

Endpoint initialization copies those two fields into `io_module` and
`io_writer`. Admission constructs the connection options explicitly, including
`io: {data.io_module, data.io_writer}`. Both connection-start branches use those
options; the tracked branch adds only a cleanup birth permit. This is the only
production caller of `Connection.start/1`.

`Connection.init/1` stores the tuple as `adapter` and `writer`. No subsequent
state update writes `adapter`; timer, recovery, idle, closing, draining and send
failure paths retain it. All 21 current connection dispatches therefore select
`GenUDP` or `ExternalWriter`, including the monotonic-time queries used after
an IO failure. Endpoint retry output uses the retained `io_module`, accounting
for the twenty-second Q2 occurrence.

`GenUDP` uses `:gen_udp`, `:inet`, process messages and the owned cleanup API.
Its clock is `System.monotonic_time/1`. `ExternalWriter` uses the same clock
and the Q3 callback. Neither built-in implementation calls OTP SSL. Raw
connection initialization with arbitrary IO tuples is an internal entry, not
an additional supported module extension.

## Q3: external datagram writer

`Endpoint.open_io/2` checks the external send function has arity two.
`ExternalWriter.init/1` independently checks that shape and retains it as
`send_fun`. The only invocation passes remote-address data and bounded datagram
bytes. Its reply is normalized to completion time or an error; reply data is
never stored as a callback or module.

`Quic.AbyssDispatcher.init/2` is the only other library producer of the external
IO option. It takes the host's arity-two send capability from the dispatcher
context and forwards it unchanged, replacing any incoming `:io`. It creates no
library wrapper or alternative callable. Thus the external send function is
the existing user callback boundary; both library adapters remain included in
the review.

## Q4: TLS adapter

`TLSDriver.new/2` obtains `:adapter` from its options with the literal default
`SSL.QUIC`. This is the approved module extension root. `base/7` stores that
module separately from the adapter's TLS state. Every later `info/1`,
`abort/2`, `feed/4` and pending-input drain calls the retained module. Action
folding updates TLS facts, offsets, buffers and terminal status, but never the
adapter selector. Adapter returns are TLS state and actions, not a replacement
driver or selector.

The only library caller is `HandshakeScheduler.new/2`, through its
`tls_options/1` projection. Public endpoint TLS options may preserve the
approved extension; no library caller supplies a different adapter.
The built-in `SSL.QUIC` constructor normalizes through `SSL.QUIC.Config` and
uses ExSSL's handshake core. Its verification targets and callback projections
are covered by [TLS-4 and TLS-6](no-otp-directed-tls-proof.md). TLS records,
CRYPTO fragments and negotiated metadata do not supply a module selector.

## Evidence and remaining acceptance

The original selected sources matched the package sources in CI artifact `13119243608`
at `524edb2`. The full production-source census binds the caller searches and
the absence of library alternatives to this revision. Hashes detect drift;
the constructor, retention and built-in-body derivations above supply the
actual origin proof. The amendments below bind subsequent source revisions;
the historical artifact does not cover those amended bytes.

The original 28 compiled findings remain in the strict audit. This source
review is ready for the directed release gate to bind it to actual BEAMs;
it does not by itself accept P6. The other package proofs and the two OTP 28
manual-ticket reference failures
remain open. The 70 passing no-OTP traffic cases remain supporting evidence.

## 2026-11-05 source review amendment: RC2 static checks

Production commit `5050bfcfd82c7a650d7d87113d30ca8360d91edf` extracts only the
existing address-validation conjunction and closing encryption-level selection
from `Quic.Connection`. The address helper retains the server role and validated
TLS fact conditions, literal Endpoint/TLSDriver operations and their exact data.
The closing helper retains application, handshake, initial, then nil precedence.
Adapter construction, retained adapter fields, timer calls and error transitions
are unchanged, so Q2 still establishes every connection dispatch's callable origin.

Fresh BEAM abstract forms locate all 19 original connection occurrences. Thirteen
line numbers move; all owning MFAs, expressions and inventory IDs remain unchanged.
The JSON amendment records each old-to-new line and the new source binding while
preserving historical artifact/check/census/BEAM metadata. The complete fresh
inventory remains 175 sites in 350 BEAMs, with a one-to-one mapping to IDs 1–175.
Collection traffic passed all 35 TLS1.3 scenarios; its raw static failure remains
visible. Strict release gates must independently bind the current source/BEAMs.

## 2026-11-07 source review amendment: M1 peer migration

The working source based on `91c18288b86b86634890de36fc0ac929eab8b6fd`
adds authenticated server peer migration. The JSON source hashes and release
bundle bind the reviewed bytes, including the two new production modules
`Quic.Paths` and `Quic.LocalCIDs`; no immutable amended source commit or
published-release acceptance is asserted here. The complete original
nine-package production-source census is now 246 files. Other package proof
inputs and the reviewed configuration remain unchanged.

Q2's constructors are unchanged. `Endpoint.open_io/2` still produces only the
literal `GenUDP` or `ExternalWriter` tuple, and connection initialization still
retains it without later selector assignment. Both new dispatches query that
retained adapter's monotonic clock: the path validation timeout in
`handle_event/4` (inventory ID 176) and deadline calculation in `path_timer/1`
(ID 177). Path/CID bytes, arrival addresses, packet numbers, validation timers
and generation messages are data; none writes an adapter or callback field.

The existing send eligibility clock moves from `flush/1` to `eligible_send/1`;
the receive clock moves from `receive_packet/4` to `receive_authenticated/6`;
and `local_send/2` gains a path argument as `local_send/3`. Their retained
selector origins and effects remain covered by Q2. The amendment records exact
raw BEAM annotation lines and owning MFAs for every moved original occurrence.
All 175 original global inventory IDs are preserved; the exact reviewed set is
IDs 1–177, with 30 QUIC sites and no silently discharged raw finding.

The new path/local-CID modules and the changed peer-CID, IO accounting,
codec, scheduler and recovery bodies introduce no unresolved dispatch or OTP
SSL import. Recovery's congestion operations still resolve to the finite
literal `NewReno` implementation. Scheduler TLS option projection preserves the
existing Q4 constructor. Cleanup and the external writer retain Q1/Q3's
original capability and callback origins.

Independent inspection of the existing root test build finds 45 QUIC BEAMs,
30 raw dynamic-call findings, no direct OTP `:ssl` import and no missing
abstract code. This is a QUIC-only build observation, not a whole-release
acceptance result. Historical artifact, checks, census and BEAM hashes remain
available; current observations are separately recorded in the amendment.
Strict candidate and published-release gates must still independently bind
the complete production source census and actual release BEAMs to these exact
reviewed occurrences, retaining all raw static findings and other checks.

Final type-contract verification tightens IO constructor/path-ledger shapes and
Recovery constructor/default-controller/ACK-space/result shapes. Independent
comparison confirms that IO and Recovery runtime ASTs are unchanged; their
five standalone pure suites pass all 59 cases and isolated Dialyzer reports
zero warnings. The final capability-type adjustment is also behavior preserving.
Current source hashes include these type edits. The root-build observation
above predates the final type-only edits; final whole-release compilation and
strict candidate/published binding remain required.

## 2026-11-07 corrective amendment: current Connection call lines

Strict candidate artifact `13572580831` failed directed binding with
`unreviewed or missing compiled dispatch`. Its full report retains all 177 raw
sites across 352 production BEAMs and reports zero direct OTP SSL imports.
The preceding M1 review used a stale `Quic.Connection` BEAM snapshot: all 21
Connection call lines were one below the current source. Fresh root test and
quality BEAM abstract forms agree with CI Elixir 1.18.6 on every owning MFA and
call line. This was stale evidence, not compiler-dependent annotation behavior.
The earlier observations and failure remain recorded in the JSON history.

The active proof now binds all 21 current Connection lines, including ID 176
at `handle_event/4:768` and ID 177 at `path_timer/1:1420`. It preserves every
inventory ID, MFA and callable-origin argument; all 156 other occurrence
bindings remain unchanged. The current call statements were also checked
against the source bound at `a966c2360bc7f57eb0b5456c9087bf78a2b50210`.

The corrected complete proof matches the failed remote report's exact multiset
of `(module, line, kind)` identities: 177 matches, zero missing, extra or duplicate
sites. Comparison removes only the leading colon on inspected Erlang atom module
names; it preserves all lines and findings. The JSON amendment records the
report hash, normalized multiset hash, current local BEAM hashes and all 21
old-to-current bindings. Production source hashes and census are unchanged.
This reconciliation does not turn the failed artifact into an accepted release;
a fresh strict candidate run and published-release gates remain required.

## 2026-11-07 source review amendment: bounded PTO probes

The source based on `0a1f6c8958626142d1f44bcf2f9877350a379790` repairs a
congestion-credit stall: an expired PTO may reserve one path-pinned fresh probe
without increasing cwnd or prematurely releasing the original flight. The
scheduler isolates the selected original's reliable frames; queued application
work cannot spend the grant. DATAGRAM and path-validation frames are filtered
from replay. Original and probe writes/ACKs retain independent accounting.

The amended Connection, scheduler and Recovery sources retain Q2/Q4's callable
origins. No new adapter, callback or unresolved dynamic call is introduced.
The current source hashes bind all three changed bodies and the complete
246-file production-source census. Fifteen Connection annotation lines move;
all 177 inventory IDs, modules, owning MFAs, kinds and origin proofs remain.
Current root test and quality BEAMs agree on all 21 Connection MFA/call lines.
All 45 current QUIC BEAMs reconcile exactly to the same 30 reviewed raw sites,
with zero additional sites, OTP SSL imports or missing abstract code.

The complete root production-module diagnostic audit retains 186 raw sites
across 348 BEAMs: all 177 currently reviewed sites, plus nine generated
collector invocations in three unchanged `for ... into: MapSet.new()` bodies.
Those nine remain unresolved because the root build excludes the host Elixir
Collectable implementation from its release context; the audit deliberately
refuses to borrow code from outside that context. No local finding is hidden,
removed or granted an exemption. The JSON records the full audit hash and
all nine remaining identities. A bundled release must prove its own in-release
Collectable implementation and reconcile its complete raw multiset.

The earlier strict remote report's full 177-site multiset matches the prior
review exactly; applying only the 15 source/BEAM-derived line rebindings gives
the current reviewed multiset. Its history remains intact and does not certify
the PTO repair. Current source/build observations and independent controls are
supporting evidence; fresh strict candidate and published-release gates remain
required for complete release acceptance.

## 2026-11-10 source review amendment: rc.11 migration, resumption and reliable reset

This amendment reviews the production sources at `4ae97fc` against the census
bound at `1a1f81d`. Seventeen selected inputs change; `Quic.EarlyData` and
`Quic.ResumptionStore` are new. The store is added to the selected inputs
because it answers TLS provider requests. The complete production census is
267 files.

### Q2

`Endpoint.open_io/2` still has exactly the `GenUDP` and `ExternalWriter`
constructors, and `Connection.init/1` is still the only assignment of
`adapter`. Client local migration is admitted only for an exclusive,
non-external client endpoint after the handshake is confirmed. The endpoint
binds a new socket through `open_udp/2` and returns its `GenUDP` PID in a
generation- and reference-qualified `quic_path_bound` reply. Connection stores
that PID in `path_writers`. `local_send/4` selects the PID for the packet's path
as writer data and calls the retained `data.adapter`. ID 15 is the same send
call rewritten with the path writer; IDs 16 and 17 are its unchanged clock calls
under the new arity.

New sites 182–187 query the retained adapter clock. They cover early-key
retirement in `handle_event/4` and `early_keys_timer/1`, path-binding and
validation handling in `handle_event/4`, and migration admission in
`start_local_migration/6`. Path, CID, ticket and early-data values are data. None
writes an adapter or callback field.

### Q4

`TLSDriver.continue/3` (ID 188) calls the retained `state.adapter`. It accepts
only the single outstanding `SSL.QUIC.Request` ID. The reply comes from the
endpoint-local `Quic.ResumptionStore`, which uses literal module calls and no
persistence or IO. `abort/2` (ID 23) also clears the continuation. `new/2` still
defaults `:adapter` to `SSL.QUIC`, and no action fold updates the selector.

### Q1 and Q3

The cleanup observer admits two more operation kinds (`reset_stream_at`,
`migrate`). `AbyssDispatcher.terminate/2` tolerates an endpoint that exits
during stop. Lease and external-send constructors are unchanged.

### Moved occurrences and acceptance

All other Connection, Endpoint and TLSDriver occurrences keep their call
expressions and owning functions. Their lines move as recorded in the JSON.
QUIC now has 37 reviewed occurrences. The complete compiled inventory of a
locally built isolated candidate release has 206 sites, matching the five
reviews exactly. CI strict candidate and published gates remain required.
