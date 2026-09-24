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
Legacy priority profiles write PRIORITY before HEADERS, while RFC 9218 profiles
use the modern `Priority` header path. Inbound RFC 9218 `PRIORITY_UPDATE` frames
are accepted only on stream 0 with a bounded target and field value.

The owner does not synchronously call `HTTP.Stream.chunk/3` or wait on a
consumer. Explicit-profile streaming uploads use the bounded BodyBridge, and
reservations release when each stream completes. A stream that reaches zero
send credit retains at most its current BodyBridge chunk and resumes it after a
validated WINDOW_UPDATE; it does not fail the upload or acknowledge early.
DATA effects are split at the peer's advertised MAX_FRAME_SIZE, with
END_STREAM applied only to the final fragment.
Simultaneous cold requests for
one key share a single out-of-band connection claim. GOAWAY marks pooled
owners draining so new reservations can select a replacement. The pool closes
healthy owners after a configurable idle timeout, and ConnectionOwner enforces
a GOAWAY drain deadline or closes immediately after the last stream releases.
