# HTTP/2 beta support and operations

The existing connection owner, pool and bounded stream scheduler implement this
contract. HTTP/2 is not a new transport or an alternative pool. The candidate
and executed evidence are recorded separately in `http2-beta-validation.md`;
historical acceptance remains historical.

## Supported request contract

Start beta rollout with known HTTPS H2 origins, `http_version: :http2`,
`http2_profile: :native_v1`, verified certificates, finite request deadlines,
and application concurrency bounded to the origin's capacity. OTP `:ssl`
remains the default; `tls_backend: :ex_ssl` is explicit. h2c is for cleartext
origins that explicitly support it. Sent requests and consumed upload producers
are not transparently replayed on resets or connection loss.

Reusable `:auto` HTTPS requests acquire the same per-key and global pool
connect admission as explicit H2 before dialing. In-flight negotiations count
against connection capacity. Automatic H2 owners permit at most one initial
stream before peer SETTINGS and then honor the advertised capacity, including
zero; peers may receive the first request before their SETTINGS are acknowledged. H2 registration converts the claim into an owner;
H1 fallback releases the claim and promotes waiting negotiations. H1 fallback
bounds concurrent negotiation, not the lifetime number of HTTP/1 sockets or
application requests; bound application concurrency as well. Queue exhaustion
returns `:pending_capacity`, and cancellation/deadlines settle waiting claims.
`http2_reuse: false` explicitly bypasses pooling and its admission policy.
TLS trust, client identity, backend and fingerprint profile remain part of the
pool key; incompatible settings must not share an owner or admission identity.

| Protocol | Informational responses | Buffered trailers | Streamed trailers |
| --- | --- | --- | --- |
| H1 | Not exposed | Not exposed | Not exposed |
| H2 | Ordered `{status, HTTP.Headers}` blocks on final response | `response.trailers` when promise completes | `:stream_trailers` after acknowledged body delivery, before `:stream_end` |
| H3 beta | Ordered blocks on final response | `response.trailers` when promise completes | Existing `:stream_trailers` completion contract |

Initial headers and trailers remain separate and duplicate field values are
preserved by `HTTP.Headers.get_all/2`. The streamed response struct is immutable;
its trailer field remains empty. Consume the trailer message through the stream message protocol. Informational blocks do not stop an
upload. H2 retains up to 128 informational blocks and 65,536 bytes in total;
trailers permit 256 fields and 65,536 bytes. Byte accounting includes 32 bytes
per field. HPACK validation remains authoritative. Invalid trailer fields,
nonterminal trailers, resets and cancellation are errors, not successful EOF.
Exposing trailers does not establish gRPC support.

## Acceptance workload and budgets

The acceptance environment uses Elixir 1.18 and OTP 28. Other runtime versions
require their own verification. Independent peers are Python hyper-h2 4.2.0
(HPACK 4.1.0/hyperframe 6.1.0) and Node 24.19.0/nghttp2 1.69.0. Exercise h2c,
verified H2 with both backends, explicit H2, automatic ALPN and H1 fallback
as distinct cases.

The existing acceptance workload includes 10 MiB transfers, 10,000-request
reuse at peer stream limits 1/2/100, finite concurrency and paused consumers,
streamed uploads/early finals, mixed Fetch/SSE/WS traffic, faults and two
1,800-second soaks. The new admission workload uses six simultaneous callers
and a one-connection policy with peer-controlled handshake/response barriers.
The error budget is zero unexpected failures under this admissible workload;
intentional injected resets, cancellation and timeouts must match their exact
assertions. Existing gate request deadlines and resource bounds are retained.
No universal QPS or unlimited-concurrency claim follows from these workloads.

At quiescence, active/protocol streams, waiters, claims, reservations, upload
and receive buffers must return to baseline. Healthy idle owners may remain.
Record accepted TCP connections/handshakes, negotiated protocol, pool and owner
state, task/monitor counts, mailbox lengths, heap/referenced binaries, latencies
and reset/drain reasons. Fetch's existing gate bounds idle owner heap to 8 MiB,
referenced binaries to 2 MiB and mailbox to 16 messages; mixed-client gates
have their own retained assertions. Preserve observations and exclusion reasons
rather than relabeling skipped or interrupted checks as passed.

## Rollout and rollback

1. Pin the accepted package/source candidate and runtime. Retain old artifacts.
2. Start a small explicit-H2, native-profile, verified-TLS cohort with finite
   concurrency/deadlines. Compare request errors/latency and resource baselines
   against the application budget before increasing traffic.
3. Enable automatic negotiation, alternate backends, custom fingerprints or
   trailer-dependent applications only after their specific acceptance passes.
   Wider production traffic needs a representative longer canary; no multi-hour
   or 24-hour canary is claimed by this document.
4. Stop expansion on unexpected errors, sustained queue/deadline growth,
   incompatible reuse, sibling starvation, malformed completion or unbounded
   resource growth. Preserve candidate SHA, backend, origin policy and telemetry.
5. Roll back by routing new requests to the previously accepted candidate and
   draining old owners within application deadlines. Do not replay ambiguous
   sent requests or consumed streaming bodies. Restore the prior concurrency
   and explicit protocol configuration; verify errors and resources return to
   baseline before restarting rollout.

Package publication, deployment and release tags are separate actions from
source implementation and validation.
