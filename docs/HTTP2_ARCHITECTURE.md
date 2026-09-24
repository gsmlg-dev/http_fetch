# HTTP/2 Architecture

The protocol layer is pure state transformation. `HTTP.HTTP2.WireProfile`
validates a finite, versioned wire configuration; `HTTP.HTTP2.Connection` and
`HTTP.HTTP2.StreamState` model connection and stream state without socket or
Fetch-process dependencies. `HTTP.HTTP2.Fingerprint` observes serialized bytes
and produces bounded, redacted structured observations.

`HTTP.HTTP2.ConnectionOwner` now owns one long-lived transport, serializes all
outbound effects through one writer, and routes inbound HEADERS/CONTINUATION
after updating the shared decoder. `HTTP.HTTP2.Pool` performs bounded,
profile-keyed reservations and monitors owners. `HTTP.SocketClient` still uses
its legacy per-request path, so this runtime is currently an explicit lower
level integration surface rather than the default Fetch transport.

The owner does not synchronously call `HTTP.Stream.chunk/3` or wait on a
consumer. Upload/response bridges and automatic reservation release on stream
completion remain the next integration boundary.
