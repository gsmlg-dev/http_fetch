# HTTP/2 Architecture

The protocol layer is pure state transformation. `HTTP.HTTP2.WireProfile`
validates a finite, versioned wire configuration; `HTTP.HTTP2.Connection` and
`HTTP.HTTP2.StreamState` model connection and stream state without socket or
Fetch-process dependencies. `HTTP.HTTP2.Fingerprint` observes serialized bytes
and produces bounded, redacted structured observations.

`HTTP.HTTP2.ConnectionOwner` owns one long-lived transport, serializes all
outbound effects through one writer, and routes inbound HEADERS/CONTINUATION
after updating the shared decoder. `HTTP.HTTP2.Pool` performs bounded,
profile-keyed reservations and monitors owners. Explicit-profile h2c fetches
use this owner and can reuse it across overlapping streams; default HTTP/1.1,
unprofiled HTTP/2, and profiled HTTPS retain their existing compatibility paths.

The owner does not synchronously call `HTTP.Stream.chunk/3` or wait on a
consumer. Explicit-profile streaming uploads use the bounded BodyBridge, and
reservations release when each stream completes. Simultaneous cold requests for
one key share a single out-of-band connection claim. GOAWAY marks pooled
owners draining so new reservations can select a replacement. The pool closes
healthy owners after a configurable idle timeout; complete drain deadlines
remain follow-up work.
