# EventSource HTTP/3 integration

Work package: WP4 EventSource. Worktree: `.trees/http3-completion`.
Baseline: `5cf3a4776158cf0ecb8833b894b354209e73f95f`.
Environment: Elixir 1.18.5 / Erlang OTP 28. Verification date: 2026-10-05.

## Explicit selection

```elixir
source =
  HTTP.EventSource.new("https://example.test/events",
    http_version: :http3,
    ssl: [cacertfile: "/path/to/root.pem"],
    http3_profile: :ordered,
    http3_reuse: true,
    delivery: :ack
  )
```

HTTP/3 is an explicit HTTPS-only choice with no downgrade. Trust and optional
reference identity use QUIC TLS `ssl:` options. An explicit `tls_backend:` is
rejected; HTTP/1 and HTTP/2 retain their existing pinned backend behavior.
String aliases include `httpVersion: "h3"`, `http3Profile`, and `http3Reuse`.
Profiles are `:ordered` and `:compact`. UNIX sockets, proxies, TCP socket options,
HTTP/2 profile/scope overrides and infinite opening deadlines are rejected before
the source starts. The shared runtime validator permits H3 only when called with
`allow_http3: true`; WebSocket's default validation still rejects H3.

The source uses `HTTP.HTTP3.Stream` for runtime ownership and read credit. Final
headers establish `HTTP.EventSource.http_version(source) == :http3`; informational
headers and trailers do not become SSE messages. The existing parser, Open and
Message envelopes, cursor, redirect policy and acknowledged delivery API apply.
H3 raw input is bounded by 1 MiB plus one 16 KiB relay chunk and 128 parked chunks.
Application acknowledgement drives the existing bounded parser/delivery drain.

The opening deadline is finite. Established H3 streams have `timeout: :infinity`
at the runtime layer and retain the EventSource idle timer. Reconnect attempts
carry the dispatched Last-Event-ID and invalidate stale relay generations.
Closing or timing out one source cancels its request without closing pooled
siblings. EOF waits for admitted application deliveries before reconnecting.

Failed authenticated H3 establishment arrives as
`{:http3_not_established, reason}` and terminates the source. This distinction was
added by the runtime worker after the native wrong-reference-name regression
exposed an ambiguous `{:owner_down, {:shutdown, {:closed, :normal}}}` outcome.
Established connection loss retains ordinary EventSource reconnect behavior.
Protocol and TLS failures are terminal rather than triggering a downgrade.

## Verification

Commands ran from the umbrella root in the implementation worktree:

```sh
HTTP_FETCH_CI_APP=http_event_source MIX_ENV=test mix deps.get
HTTP_FETCH_CI_APP=http_event_source MIX_ENV=test mix compile --warnings-as-errors
HTTP_FETCH_CI_APP=http_event_source MIX_ENV=test mix test apps/http_event_source/test --seed 0
HTTP_FETCH_CI_APP=http_event_source MIX_ENV=test mix test apps/http_runtime/test/http/runtime/options_test.exs --seed 0
```

- Dependency preparation: PASS; locked dependencies unchanged.
- Strict compile: PASS.
- EventSource suite: PASS, 73 tests and zero failures, including all 64 baseline
  tests, two H3 options tests and seven native UDP H3 tests.
- Shared runtime options: PASS, four tests and zero failures; default validation
  continues rejecting `:http3`.
- Scoped formatting, Credo and whitespace checks: PASS. Credo inspected the six
  changed Elixir files and found no issues.

Native tests exercise Session, the actual QUIC adapter, generation handles,
runtime owner/pool/relay, and public EventSource together. They cover split
BOM/UTF-8/CRLF, informational/final/trailer handling, bounded acknowledged
delivery draining before EOF, reconnect cursors and stale generations,
same-origin redirects, wrong certificate identity, sibling cancellation
isolation, and idle timer replacement. Timer tests use current/stale tokens and
bounded public polling; they do not claim an elapsed soak duration.

Independent pinned aioquic/Caddy acceptance, isolated published artifacts and
sustained load are coordinator gates. This scoped native suite does not establish
those results. Fetch integration, WebTransport and WebSocket over H3 are outside
this worker's ownership. No commit, push or publication was performed by this
worker.
