# Operations and development

This guide covers inspecting a running service, understanding its counters, controlling its lifecycle, and checking changes in the repository. Examples using `endpoint` assume a service started with `datagram_handler`.

## Inspect an endpoint

```elixir
{:ok, {address, port}} = Abyss.Endpoint.local_endpoint(endpoint)
{:ok, capabilities} = Abyss.Endpoint.capabilities(endpoint)
{:ok, info} = Abyss.Endpoint.info(endpoint)
metrics = Abyss.Telemetry.get_metrics(endpoint)
```

`info` includes logical identity, socket generation, local endpoint, capabilities and mode. A datagram runtime also exposes input count, retained input bytes, key/timer counts, high-water values, receipts and egress admission state. These describe current host-managed work; they are not an application-memory budget or a kernel drop counter.

For the datagram API, `received` and `dropped` describe the current socket
generation. `dropped` is the sum of the non-overlapping `drop_counts.ingress`
and `drop_counts.runtime` fields. Ingress covers packet validation and pause;
runtime covers input admission and deferred route/key/queue rejection. Each
known network input is counted once at its definitive rejection. Repeated
inspection does not change these counters. They remain available while the same
generation is inspectable after graceful or forced drain. Generation replacement
resets them.

`internal_events_rejected` reports separate `timer` and `send_outcomes` counts.
Their rejection does not represent another lost network datagram. Callback
failure, transport-send failure and intentionally discarded queued work during
teardown are not additional network admission drops. Unknown kernel queue
loss is not included. For a truncated native packet, only the observed payload
bytes are available; the original full length is not inferred.

The endpoint facade requires one receive owner. Legacy fixed-port unicast pools can have several; inspect individual listeners with `Abyss.Listener.listener_info_cached/1` for cached local addresses rather than assuming a single endpoint.

## Metrics and events

Counters are scoped by the logical server PID. `Abyss.Telemetry.get_metrics()` aggregates all scopes; `get_metrics(handler_module)` aggregates services registered to that legacy handler module. Socket generations share the logical scope, and logical service deletion removes its rows. `reset_metrics/0` resets node-wide counters, so use it deliberately when monitoring multiple services.

| Counter | Meaning |
| --- | --- |
| `datagrams_received`, `bytes_received` | Inputs observed by Abyss reception |
| `datagrams_dropped`, `bytes_dropped` | Definitively rejected network inputs and observed payload bytes; logical-server lifetime |
| `timer_events_rejected`, `send_outcome_events_rejected` | Rejected managed events; separate from network drops |
| `accepts_total`, `connections_total`, `connections_active` | Validated admission and active work accounting |
| `responses_total`, `bytes_sent` | Successful instrumented local socket sends and payload bytes; an empty datagram counts as one send |
| `send_errors_total` | Definite failed socket-send attempts |
| `work_completed`, `work_failed` | Accounted work outcomes |
| `accepts_per_second`, `responses_per_second` | Rates over the current counter window |

Supported GenUDP and Linux native ordinary sends and strict replies record the
actual local socket outcome once. Validation/admission rejections, `await`
timeouts and repeated receipt reads do not count as sends or send errors. A
send that completes after a caller stops waiting still counts its actual
completion. Addressing controls do not contribute to payload `bytes_sent`.

Handler exit alone does not count as a response. Raw `:gen_udp` or `:socket`
sends bypass Abyss transport instrumentation. Custom transports retain their
own instrumentation contracts. A send counter or receipt does not establish
peer delivery.

```elixir
:telemetry.attach_many(
  "abyss-datagrams",
  [[:abyss, :datagram, :dropped], [:abyss, :datagram, :send],
   [:abyss, :datagram, :event_rejected]],
  fn event, measurements, metadata, _config ->
    IO.inspect({event, measurements, metadata})
  end,
  nil
)

# Detach when the observer is no longer needed.
:telemetry.detach("abyss-datagrams")
```

Drop metadata contains `server_id` and `reason`; send metadata contains
`server_id` and `result`. Network drop/send measurements use payload `bytes`.
`event_rejected` metadata contains `server_id`, `event_type` and `reason`; its
`bytes` measure the serialized internal event for admission accounting. Fixed
counter names keep cardinality bounded; route keys, peers and exception values
are not permanent metric keys. Compare public generation counters with
telemetry deltas for the same observed interval, since telemetry retains its
logical-server lifetime across generations. Listener and legacy connection spans are documented in `Abyss.Telemetry`. Connection spans are sampled by `connection_telemetry_sample_rate` (default 0.05); admission/send counters are not controlled by that sampling setting. Avoid unbounded peer or route-key labels in external metric storage.

`Abyss.Logger.attach_logger(:info)` attaches the built-in structured logger. Choose the level and event collection appropriate for the service.

## Pause, resume and stop

```elixir
:ok = Abyss.Endpoint.pause(endpoint)
:ok = Abyss.Endpoint.resume(endpoint)
:ok = Abyss.Endpoint.stop(endpoint, 5_000)
```

Pause retains the socket, port and desired memberships and lets admitted work reply. Newly received packets are dropped while paused; packets left in the kernel queue may arrive after resume. Resume reuses the existing generation unless the owner restarted.

Stop shares an absolute deadline across admitted work and forced cleanup. A finite timeout limits draining, not successful remote delivery. Cleanup may leave previously admitted send outcomes unknown. Legacy services use `Abyss.suspend/1`, `resume/1` and `stop/2`. QUIC uses its own application drain API; generic dispatcher host cleanup is not a completed QUIC session drain.

Tune `max_packet_size`, `num_connections`, datagram `runtime_options`, and writer item/byte limits together. Empty payloads still consume an item. The library's quotas do not bound arbitrary application state, hostile local mailbox messages or kernel queues. Refer to the [migration defaults](udp-runtime/migration.md) and [writer contract](dispatcher.md) before changing limits.

## Scoped verification

From the umbrella root, prepare and run scoped tests using the root project:

```sh
MIX_ENV=test mix deps.get
MIX_ENV=test mix compile --warnings-as-errors
mix format --check-formatted
MIX_ENV=test mix test apps/abyss/test --include integration --include slow
```

For targeted work, pass a test file under `apps/abyss/test` to the same root
command. Host/socket cases carry `:integration` and remain excluded by default.
The separate native package is tested from `packages/abyss_raw`; its build requires
Rust. Unit and host tests do not replace independent network fixtures. The
declared Elixir `~> 1.13` minimum is retained; the monorepo test environment is
Elixir 1.18+ and does not establish minimum-version acceptance.

The [UDP fixture instructions](../scripts/udp/README.md) describe isolated broadcast/multicast/native traffic and optional DHCP consumers. They require Linux namespace tooling and fixture privileges; setup failure or exit 77 is not acceptance. The [QUIC scripts](https://github.com/gsmlg-dev/http_fetch/tree/main/apps/abyss/scripts/phase1) check independent peers and consumers separately.

For performance comparisons, run the same workload serially on source-identified baseline and candidate checkouts without competing builds. Historical [0.8 measurements](https://github.com/gsmlg-dev/abyss/blob/main/docs/archive/udp-runtime/performance.md) include a legacy throughput regression and materially slower new-policy results for a tiny sequential workload; no universal speedup is claimed.
