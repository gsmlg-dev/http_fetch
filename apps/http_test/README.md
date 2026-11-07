# HTTP.Test

Owner-isolated HTTP fixtures for HTTP Family, with real Promise and acknowledged
Stream contracts. Add `{:http_test, "~> 1.0", only: :test}` to your dependencies
(use the exact prerelease version while testing release candidates).

```elixir
setup do
  HTTP.Test.verify_on_exit!()
end

test "loads JSON" do
  HTTP.Test.expect(:service, fn request ->
    assert request.url.path == "/items"
    HTTP.Test.json(%{items: [1, 2]})
  end)

  response = HTTP.fetch("https://service.test/items", adapter: {HTTP.Test, :service})
             |> HTTP.Promise.await()
  assert HTTP.Response.json(response) == {:ok, %{"items" => [1, 2]}}
end
```

`stub(name, callback)` repeats a fixture; `expect(name, count, callback)` claims
exactly `count` calls, atomically and in registration order. The count defaults
to one. A name cannot mix stub and expectation modes. Consumed expectations never
fall back to a stub. A claimed call remains consumed on cancellation.

Names are local to their registering owner. Concurrent tests can reuse the same
name. Tasks inherit the caller chain. For an independent GenServer, register
`HTTP.Test.allow(name, owner_pid, server_pid)` before it makes a request. Prepare
captures this authority in the original Fetch caller. Missing fixtures,
unauthorized callers and excess calls fail without network fallback. Explicit
production `pool` and `transport_scope` options are rejected by this adapter.

`verify!()` freezes claims, settles resources and verifies counts and callback
failures. Its final verification result remains available to the registered exit
verifier. `verify_on_exit!()` retains an opaque verification token after the test
process exits, performs the same finite teardown, and removes all records even
when verification raises. Without an exit verifier, owner death cancels resources
and removes records automatically. Callback assertions, exceptions and abnormal
exits are recorded with their cause and stacktrace; ignoring or catching a Promise
exit cannot hide the fixture failure. An external untrappable kill retains its
exit reason (there is no exception stacktrace for that signal).

## Responses and errors

`json/2`, `text/2`, `html/2`, `status/1`, `response/3` and `headers/2` construct
ordinary `HTTP.Response` values. JSON helpers emit encoded bytes. Ordered,
duplicate headers are retained. `transport_error(reason)` intentionally returns
`{:error, reason}`; Fetch applies its raw or structured error mode once.

The adapter simulates one request attempt. Default options work for nonredirect
responses. A redirect candidate has status 301/302/303/307/308 and a binary
Location. `redirect: :manual` exposes it, `:error` returns `{:error, :redirect}`,
and `:follow` returns `{:error, {:unsupported_test_policy, :redirect_follow}}`
before exposing any response body. It does not claim a second fixture. A 302
without Location or a 304 is ordinary. Compression, wire encoding, retries,
protocol negotiation and redirect chains are not simulated.

## Streams, gates and cleanup

Create streams inside callbacks:

```elixir
HTTP.Test.expect(:download, fn _ ->
  HTTP.Test.stream(["one", {:gate, test_pid, :next}, "two"],
    trailers: [{"x-checksum", "value"}], observer: test_pid)
end)
```

The body and stream alias contain the same real `HTTP.Stream` PID. Each chunk
waits for consumer ACK before producer progress. Gates send
`{:http_test_gate, tag, producer, ref}` and wait for `{:http_test_release, ref}`.
`{:error, reason}` produces a stream error after preceding chunks are acknowledged.
Trailers preserve order and arrive immediately before stream end. The optional
observer receives `{:http_test_stream, stream, producer}`. Each chunk and gate has
a finite `timeout:` (default 5 seconds). `gate(observer, tag, callback)` also gates
response headers and cooperates with cancellation.

The adapter retains actual workers, upload streams, response streams and
producers. AbortController stays attached to their guardian after the Promise
worker exits. The finite request timeout also bounds simulated resource lifetime.
Owner teardown waits at most one second for cleanup; noncooperating callbacks
receive abort, then are forcibly terminated after 100 ms. An unexplained or
forced request-worker death can truthfully leave public completion unconfirmed.

A Promise wait timeout does not cancel. Retain the original
`HTTP.Promise.completion(promise)` before chaining. Manual/error modes use the
actual lifecycle tracker; default follow retains unsupported completion, even
though owner teardown still settles its resources. Successful simulated cleanup
proves these processes ended; it provides no evidence about real sockets, TLS or
pool capacity.

## Optional Plug bridge

Plug is optional. Core HTTP.Test compiles and works without Plug installed.
Calling `HTTP.Test.plug/3` without it raises a clear error. Install Plug explicitly
to use a buffered bridge:

```elixir
HTTP.Test.stub(:service, fn request ->
  HTTP.Test.plug(request, {MyPlug, []}, body_limit: 1_048_576)
end)
```

A one-argument conn function is also supported. The finite positive body limit
(default 1 MiB) applies separately to request and response bytes. Stream uploads
and chunked Plug responses are rejected; use stream fixtures for streaming.
The bridge buffers Plug's response and does not impose a memory bound on arbitrary
code executed inside the Plug itself.
