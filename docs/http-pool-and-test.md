# HTTP pools and isolated fixtures

`http_pool` and `http_test` are independent HTTP Family packages. The dependency
flow is core → pool → runtime → Fetch → Test. Fetch also directly declares core
and pool. EventSource and WebSocket continue to share runtime's default pools.
No lower application depends on Test, even in the test environment. Ordinary
production Fetch consumers do not acquire Test, Plug, ExUnit or an ownership library.

## Configure a pool family

Add a family to your application's supervision tree:

```elixir
{HTTP.Runtime.Pool,
 name: "api",
 http1: [max_idle_per_key: 1, max_idle: 8, idle_timeout: 15_000],
 http2: [max_connections: 1, max_total_connections: 4, max_keys: 20,
         max_streams: 16, max_pending: 20, idle_timeout: 30_000]}
```

```elixir
{:ok, pool} = HTTP.Runtime.Pool.reference("api")
response = HTTP.fetch("https://example.com/data", pool: pool) |> HTTP.Promise.await()
{:ok, counts} = HTTP.Pool.snapshot(pool)
```

Passing `pool: "api"` resolves a reference in the request caller. Atoms, binaries
and family PIDs are accepted without creating atoms from external strings. The
same bound process identities follow checkout/checkin and reserve/register/release.
Unknown, dead or stale families fail explicitly without default-pool or direct-dial
fallback. A replacement family with the same name has a different generation;
old references cannot release resources in it.

H1 selection enables reuse and conflicts with explicit `http1_reuse: false`.
Request-specific `http1_pool_size` and `http1_idle_timeout` may reduce the family
policy; values exceeding it fail. H2 selection conflicts with `http2_reuse: false`.
Explicit named families support `:http1`, `:http2` and `:h2c`; automatic negotiation,
HTTP/3, opaque nonreusable identities and ManagedTransport scopes are rejected.
Requests without `pool:` preserve existing behavior, including disabled H1 reuse.

H1 limits bound **idle retention**, not active HTTP/1 requests. H2 connections,
connecting attempts and provider handoffs spend capacity; draining connections
remain in the total. Local stream capacity is capped by peer SETTINGS. Existing
reservation queues, identity hashing, cancellation and no-replay rules remain.
Snapshots expose aggregate counts, omit routing/TLS secrets and do not fabricate
active H1 observations. `http_pool` starts no duplicate default pools; runtime
continues to supervise defaults and ManagedTransport uses the extracted machinery.

## Register fixtures

Consumers normally add `{:http_test, "== VERSION", only: :test}` using the same
HTTP Family version as Fetch. For ExUnit:

```elixir
setup do
  HTTP.Test.verify_on_exit!()
  :ok
end

test "loads the record" do
  HTTP.Test.expect(:records, fn request ->
    assert request.url.path == "/records/1"
    HTTP.Test.json(%{id: 1})
  end)

  response = HTTP.fetch("https://service.test/records/1",
    adapter: {HTTP.Test, :records}) |> HTTP.Promise.await()
  assert {:ok, %{"id" => 1}} = HTTP.Response.json(response)
end
```

Fixtures belong to their registering process. Concurrent tests can use the same
name. Tasks inherit their caller chain; independent processes require
`HTTP.Test.allow(name, owner_pid, allowed_pid)`. Expectations are claimed atomically
in registration order. `expect(name, count, callback)` consumes exactly that count;
cancellation does not restore a claim. Stub and expectation modes for one name
are mutually exclusive. Missing, unauthorized and excess calls fail closed.

`verify!/0` freezes claims, settles simulated resources within a finite budget,
and checks expectation counts and callback failures. `verify_on_exit!/0` retains
an opaque owner token until ExUnit's exit callback completes; cleanup runs even
when verification fails. Callback assertions and exceptions preserve their
cause/stacktrace, and remain verification failures even if the Promise is never
awaited. `HTTP.Test.transport_error(reason)` represents an intentional transport
failure and follows Fetch's raw/structured error mode. Caller preparation and
configuration errors remain raw, matching ManagedTransport preparation errors.

JSON helpers produce encoded bytes. `response/3`, `text/2`, `html/2`, `status/1`
and `headers/2` use existing Response/Headers data and preserve duplicate fields.

## Streaming and cancellation

```elixir
HTTP.Test.expect(:download, fn _ ->
  HTTP.Test.stream(["first", "second"], trailers: [{"x-checksum", "value"}])
end)
promise = HTTP.fetch("https://service.test/file",
  adapter: {HTTP.Test, :download}, redirect: :manual)
response = HTTP.Promise.await(promise)
bytes = HTTP.Response.read_all(response)
```

Streams use actual `HTTP.Stream` processes. A chunk must be acknowledged before
the producer advances. Steps may include `{:error, reason}` or
`{:gate, observer_pid, tag}`. Gates send
`{:http_test_gate, tag, process, reference}` and await
`{:http_test_release, reference}`; use those messages and monitors for deterministic
race tests. `HTTP.Test.gate/4` controls response-header delivery. Stream `timeout:`
is finite and positive; `observer:` receives stream and producer PIDs.

A guardian tracks workers, upload sources, response streams and producers,
including after the Promise worker exits. Cancellation and owner teardown settle
these actual resources. `HTTP.Promise.await/2` timing out only stops waiting;
explicitly abort using the original Promise's completion handle when supported.
Default follow mode retains its unsupported public completion guarantee. Manual
and error modes use the existing lifecycle tracker; successful mock completion
proves simulated-resource cleanup, not socket, TLS or pool behavior.

Fixtures simulate a single request attempt. Ordinary responses work with default
options. For statuses 301/302/303/307/308 with a binary Location, manual mode
returns the response, error mode returns `:redirect`, and follow mode rejects with
`{:unsupported_test_policy, :redirect_follow}` before exposing the response/body.
No second fixture is claimed. Started response/upload resources are cleaned.
A 302 without Location and a 304 are ordinary nonredirect fixtures.

## Optional Plug bridge

Plug is optional; core fixtures compile and run without it. Consumers that need
the bridge explicitly install Plug:

```elixir
HTTP.Test.stub(:router, fn request ->
  HTTP.Test.plug(request, MyRouter, body_limit: 1_048_576)
end)
```

The bridge accepts bounded buffered requests/responses with a default 1 MiB
limit. It rejects streamed bodies and nonfinite limits. Use stream fixtures for
streaming, ACK and cancellation contracts. Fixtures do not simulate wire encoding,
TLS, compression or pool capacity; those require actual protocol integration gates.

## Verification boundaries

From the umbrella root, prepare with `MIX_ENV=test mix deps.get` and
`MIX_ENV=test mix compile --warnings-as-errors`. Unit contracts run under
`mix test apps/http_pool/test apps/http_test/test`. Real socket pool cases are
integration-tagged under runtime tests. The standalone candidate gate is:

```sh
python3 scripts/release/stage.py build VERSION /tmp/family-stage /tmp/family-archives
python3 scripts/release/consumer_gate.py VERSION /tmp/family-archives --mode family
```

This resolves signed candidate Hex packages outside the umbrella, checks actual
named H1 reuse, and exercises Test with and without Plug. Add `--published` for
fresh registry verification after publication. Publication and CI results must be
reported separately from source implementation and local checks. Backplane
migration, Req compatibility layers, active H1 admission and H3 pool extraction
remain later work.
