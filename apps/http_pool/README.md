# HTTP Pool

Independent pool policy and ownership primitives for the HTTP Family. It depends
on `http_core` and telemetry, and starts no default processes. `http_runtime`
composes protocol owners with these pools; Fetch production consumers do not
acquire testing dependencies.

```elixir
{:ok, policy} = HTTP.Pool.policy(
  http1: [max_idle_per_key: 1, max_idle: 8, idle_timeout: 10_000],
  http2: [max_connections: 1, max_total_connections: 8, max_streams: 16])
```

Use the runtime family to send actual requests:

```elixir
children = [{HTTP.Runtime.Pool, name: "api", http1: [max_idle_per_key: 1]}]
{:ok, pool} = HTTP.Runtime.Pool.reference("api")
HTTP.fetch("https://example.com", pool: pool)
{:ok, counts} = HTTP.Pool.snapshot(pool)
```

Explicit H1 selection enables reuse; an explicit false reuse flag conflicts.
Request retention limits may be smaller than the instance limits, never larger.
H2 selection requires reuse. Managed scopes, automatic protocol selection and H3
are rejected with an explicit family selection in this version. Existing default
requests retain their behavior and capacities.

H1 capacity bounds **idle retention**, not active requests. Snapshots omit active
H1 counts because checkout transfers ownership to the request. H2 snapshots
aggregate connections, connecting slots, provider handoffs, streams, pending
reservations and draining connections without exposing route or TLS identities.
Draining connections occupy total capacity even when a replacement is allowed by
the per-key serviceable limit. Peer SETTINGS cap the configured local stream limit.

Configuration is immutable. Supervise a replacement family to change policy.
Generation-bound references never follow same-name restarts; stale requests fail
without falling back to a global pool or unpooled dial. Cancellation, incomplete
response rejection, provider handoff and cleanup confirmation retain the runtime
contracts. Pool extraction adds no automatic request replay.

The internal `HTTP.HTTP1.Pool`, `HTTP.HTTP2.Pool` and `HTTP.HTTP2.PoolKey` names
remain for compatibility, but are not stable public configuration interfaces.
Provider registration requires an explicit `activate_owner` callback supplied by
runtime, after caller-orchestrated lifecycle handoff. Factories run in monitored
connector processes, never synchronously in the pool mailbox.
