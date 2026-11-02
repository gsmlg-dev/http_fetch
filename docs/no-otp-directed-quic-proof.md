# Directed QUIC callable-origin review

This review covers Q1–Q4, the 28 `elixir_quic` occurrences in the
[production inventory](no-otp-release-dispatch-inventory.csv). It follows the
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
failure paths retain it. All 19 connection dispatches therefore select
`GenUDP` or `ExternalWriter`, including the monotonic-time queries used after
an IO failure. Endpoint retry output uses the retained `io_module`, accounting
for the twentieth Q2 occurrence.

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

All selected sources match the package sources in CI artifact `13119243608`
at `524edb2`. The full production-source census binds the caller searches and
the absence of library alternatives to this revision. Hashes detect drift;
the constructor, retention and built-in-body derivations above supply the
actual origin proof.

The original 28 compiled findings remain in the strict audit. This source
review is ready for the directed release gate to bind it to actual BEAMs;
it does not by itself accept P6. HTTP/3's separate `:ops` contract decision,
the other package proofs and the two OTP 28 manual-ticket reference failures
remain open. The 70 passing no-OTP traffic cases remain supporting evidence.
