# Directed telemetry callable-origin review

This review covers TEL-1 and TEL-2, the seven original occurrences in the actual
`telemetry` 1.4.2 dependency. Its [binding](no-otp-directed-telemetry-proof.json)
records the source files, dependency identity and original compiled inventory.
The built-in modules and user callbacks have separate derivations.

## TEL-1: handler and span functions

`telemetry:attach/4` forwards to `attach_many/4`, whose function guard requires
arity four. The handler table's insert operation records that exact function
and config in handler records. Event execution reads those records and invokes
their function with event name, measurements, metadata and config. Callback
return values are discarded. On a callback exception, the handler is detached
before the failure event is emitted; its reason/stacktrace are metadata, not
replacement functions. Reentrant attachment still goes through the same
public callback projection.

`telemetry:span/3` invokes its caller-provided zero-argument function. Its result
is interpreted as result data and measurement/metadata maps. It is never stored
as another callable. Both functions are existing public callback boundaries;
the bodies of external callbacks are outside the no-OTP guarantee.

The full production-source and BEAM-import census establishes that none of the
nine packages calls `attach`, `attach_many`, handler-table `insert`, or `span`.
`HTTP.Telemetry`'s logger and metrics attachments are **documentation examples**,
not library-created handlers. Its actual BEAM imports only `telemetry:execute/3`
from that dependency. EventSource, Runtime, WebSocket and WebTransport likewise
only emit events. Therefore there is no hidden library callback alternative to
exclude. A compatible public library function used as a caller's callback
remains subject to its own supported-entry proof; this boundary does not exempt
library bodies.

## TEL-2: handler-table implementation

There are five mutations of the `telemetry` implementation key:

1. `init/1` creates the protected ETS table and stores literal `telemetry_ets`,
   `fun telemetry_ets:list_for_event/2`, and the table ID.
2. `persist/0` invokes the retained module's persist function. A successful
   result stores literal `telemetry_pt` and
   `fun telemetry_pt:list_for_event/2` with the returned map.
3. Insert stores the previously retained module and list function with the
   returned storage state. It does not take selectors from the result.
4. Delete preserves the selectors in the same way.
5. Termination erases the implementation key. The fallback uses literal
   `telemetry_ets` and a local two-argument function returning `[]`.

Thus every implementation-module dispatch selects `telemetry_ets` or
`telemetry_pt`, and the list invocation selects their fixed exported function
or the empty fallback closure. A concurrent persist/insert/delete may alter the
stored handler data, but every possible writer preserves this finite selector
set. There is no supported custom implementation option. Arbitrary external
`persistent_term:put`, `sys.replace_state`, or protected-table corruption is
outside the approved input boundary.

Both storage implementations operate on handler records using ETS, lists and
maps. Persistence converts an ETS table to a map; the persistent implementation
does not introduce a third storage module. Their insert/delete results contain
storage data only. No storage body invokes OTP SSL or interprets handler config
as an implementation module. Registered handler functions stay under TEL-1.

## Evidence and remaining acceptance

The reviewed version is the dependency actually present in the isolated release,
not an assumed older telemetry implementation. The binding retains the original
BEAM hashes and exact seven occurrences from artifact `13119243608`. Source
hashes identify the reviewed dependency inputs. Actual release matching must
verify the dependency source before compilation and bind the reviewed modules
to the resulting release BEAMs before accepting this proof.
All seven generic findings remain visible. This document alone does not accept
P6, replace runtime isolation checks or waive the release regressions.

## 2026-11-11 source review amendment: rc.14 timeout reason

`HTTP.Telemetry` (`c7a3c19`) no longer lists `:request_timeout` among the public
error reasons, because Fetch now reports deadline expiry as `:timeout`. One
literal list element is removed. The module still imports only
`telemetry:execute/3` from the dependency and creates no handler. TEL-1 and
TEL-2 and the seven dependency occurrences are unchanged. The amendment records
the producer hash, the current census digest and the reviewed inventory digest.
