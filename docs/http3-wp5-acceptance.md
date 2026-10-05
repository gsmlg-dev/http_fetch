# WP5 independent HTTP/3 acceptance

The permanent gate runs the public Fetch path against two independently
implemented HTTP/3 servers. It requires an actual `:http3` response and checks
peer identity and byte integrity. Unsupported returns, downgraded responses,
missing fixtures and any failed assertion exit unsuccessfully.

## Reproduction

Run from the umbrella root after test-environment preparation:

```sh
MIX_ENV=test mix deps.get --check-locked
MIX_ENV=test mix compile --warnings-as-errors
uv run --python 3.12 --with aioquic==1.2.0 python -m unittest discover -s scripts/http3 -p 'caddy_*_test.py' -v
HTTP3_GATE_LOG_DIR=/tmp/http3-public-peer-logs \
  uv run --python 3.12 --with aioquic==1.2.0 python scripts/http3/public_gate.py
```

Docker must be available. The launcher pulls and checks the Caddy RepoDigest;
it rejects an aioquic package version other than `1.2.0`. The gate script timeout
is 600 seconds by default. `--timeout` changes that bound; `--gate-script` selects
a bounded diagnostic driver without changing the peer or TLS contract.

The independent peers are:

| Peer | Immutable/version pin |
| --- | --- |
| Python HTTP/3 | `aioquic==1.2.0` |
| Caddy HTTP/3 reverse proxy | `caddy:2.9.1@sha256:748016f285ed8c43a9ce6e3aed6d92d3009d90ca41157950880f40beaf3ff62b` |
| Caddy HTTP/1 upstream | Repository `scripts/http3/caddy_upstream.py` |

The launcher creates an ephemeral P-256 certificate authority and leaf
certificates with DNS `example.test` and IP `127.0.0.1` subject alternative names.
The normal leaf lasts seven days. The expired leaf uses the same issuer and
reference identities and expired yesterday, so its negative case isolates
validity from trust and identity. A separate unrelated authority exercises
wrong trust. A certificate-valid QUIC peer advertising only `doq` exercises
wrong ALPN. OpenSSL independently checks the certificate fixture in the Python
suite. No verification bypass is configured.

Each launch uses dynamically allocated loopback peer ports and a unique owned
Caddy container. The launcher checks authenticated HTTPS readiness, propagates
peer ports and certificate paths, and stops/removes its container and waits
for its peer processes on completion or failure. `HTTP3_GATE_LOG_DIR` preserves
upstream framing, peer stderr and Caddy diagnostics; without it, temporary
logs disappear during cleanup. Upstream diagnostics record only request path,
framing headers and decoded byte count, never body bytes or TLS secrets.

The driver receives `HTTP3_AIOQUIC_PORT`, `HTTP3_CADDY_PORT`,
`HTTP3_EXPIRED_PORT`, `HTTP3_WRONG_ALPN_PORT`, `HTTP3_PEER_CA_FILE` and
`HTTP3_WRONG_CA_FILE` from the launcher.

## Executable gates

Before running the Elixir driver, `caddy_upload_probe.py` uses the pinned aioquic
client to upload two MiB to Caddy both without and with `Content-Length`. It
requires the exact payload SHA256 in both cases. This checks the independent
server's forwarding semantics before attributing an upload failure to Fetch.

The public driver checks both peers for GET and empty completion, binary
POST/PUT, a two-MiB producer upload digest, an eight-MiB streamed file digest,
32 simultaneous binary requests and TLS negatives. The aioquic protocol
fixture also supplies informational fields, trailers, reset, abort, SSE and
GOAWAY. Ten thousand sequential public requests require deliberate connection
rotation and observable request/lease/continuation cleanup.

The pinned aioquic 1.2.0 `send_headers` API advances its response state after
the first header block; using it for 103 followed by final headers incorrectly
classifies the final block as trailers and then rejects DATA. The fixture emits
the informational block with its QPACK encoder and a raw HTTP/3 HEADERS frame,
then uses the regular API for the final response. This limitation belongs to
the independent fixture API and does not alter the client's decoder.

`.github/workflows/http3-public.yml` runs strict root compilation, fixture
regressions and the complete public gate on relevant pushes and pull requests.
Every acceptance command must succeed. Independent peer logs are uploaded even
when a gate fails. Configuring repository branch-protection requirements and
remote workflow results are separate from the presence of this workflow.

## Local fixture evidence, 2026-10-05

| Check | Actual result |
| --- | --- |
| Real upstream framing and certificate regressions | PASS: five tests, including chunked binary echo and two-MiB upload digest |
| Owned Python syntax | PASS |
| Caddy 2.8.4, independent client, unknown upload length | FAIL: empty SHA256; native STOP_SENDING code 256 (`H3_NO_ERROR`) |
| Caddy 2.8.4, independent client, explicit upload length | PASS: exact two-MiB SHA256 |
| Caddy 2.9.1, independent client, both length modes | PASS: exact two-MiB SHA256 in both modes |
| Final launcher, permanent independent preflight and owned cleanup | PASS |
| Standalone CI workflow YAML and mandatory gate step | PASS locally; remote execution remains separate |
| Bounded native runtime fixture against both final peers | PASS: exact two-MiB producer upload, eight-MiB download, wrong CA/name, expired leaf and wrong ALPN; zero remaining leases |
| Complete public acceptance, WP4 working checkpoint | PASS: both peers, informational/trailers/reset/abort/SSE/GOAWAY, 10,000 sequential requests across 11 connections; final queued-cancellation/SSE review rerun also PASS; concurrent rotation repair remains pending |
| Corrected remote public CI | PASS: run 37286353184 on c12bbf8; source public gate and peer artifacts |
| Fresh isolated candidate after rotation repair/main merge | PASS: nine exact private Hex packages, both peers, 10,000 requests/11 connections on c12bbf8 |
| Final release artifacts and isolated published consumer | NOT RUN: final publication remains gated |
| 24-hour scoped canary | NOT RUN: required before final release |

The fixture diagnosis used the `c3fb8dd` WP3 baseline plus the concurrent WP4
worktree. It made no native QUIC or runtime implementation edits. Diagnostic
logs are under `/tmp/http3-independent-body-logs`,
`/tmp/http3-independent-caddy291-logs` and
`/tmp/http3-public-fixture-caddy291` in the local validation environment.
The parent's public checkpoint log is
`/tmp/http3-wp4-public-gate-291-2.log`; it ends with
`HTTP3 public acceptance result: PASS`. This records that working tree rather
than substituting for acceptance of subsequent runtime changes.

Caddy 2.8.4 [bundles quic-go 0.44.0](https://github.com/caddyserver/caddy/blob/v2.8.4/go.mod).
Its [HTTP/3 header parser](https://github.com/quic-go/quic-go/blob/v0.44.0/http3/headers.go) leaves an absent
content length at Go's zero default, and Caddy's reverse proxy sets the body
to nil [when `ContentLength == 0`](https://github.com/caddyserver/caddy/blob/v2.8.4/modules/caddyhttp/reverseproxy/reverseproxy.go).
Its upstream therefore received
`Content-Length: 0` despite a nonempty HTTP/3 DATA upload. The independent
client reproduced this behavior, including the empty-body hash. Caddy 2.9.1
bundles quic-go 0.48.2, whose [parser initializes unknown content length to `-1`](https://github.com/quic-go/quic-go/blob/v0.48.2/http3/headers.go).
Updating only the acceptance peer fixes both independent and native upload
integrity without synthesizing a client length or weakening STOP_SENDING
handling. The existing TLS fingerprint fixture remains a separate gate.

## Acceptance limits

These fixtures do not establish dynamic QPACK, 0-RTT, migration, Alt-Svc racing,
WebSocket over HTTP/3 or WebTransport support. Fault injection, retained-memory
bounds under slow consumers, transport unit gates, artifact consumers and
long-duration canary measurements retain their own evidence requirements.
A local fixture pass or a negotiated ALPN does not substitute for those gates.

## Scoped canary contract

`scripts/http3/canary.exs` defaults to 86,400 seconds and requires its measured
elapsed duration to meet that value. Each cycle makes 32 simultaneous strict
public PUTs against each independent peer, checks all 16KiB payloads byte for
byte, and waits for zero leases, queued requests and session continuations.
Cycles are paced five seconds apart; no assertion relies on that delay.

The predefined thresholds are zero request errors, at most 20 owners, native
connections and actual endpoint processes, at most 128 messages in each owner/
native mailbox, VM memory at most 256MiB and growth at most 64MiB from the warm
baseline, and total processes at most baseline plus 100. Native receive buffers
must return to zero. Process counts include retired endpoints independently of
owner references, and the final PASS records peak counts, memory, mailboxes,
request count and the source commit.

```sh
HTTP3_CANARY_SECONDS=86400 HTTP3_CANARY_SHA=SOURCE_COMMIT \
HTTP3_GATE_LOG_DIR=/tmp/http3-canary-peers \
  uv run --python 3.12 --with aioquic==1.2.0 \
  python scripts/http3/public_gate.py \
  --gate-script scripts/http3/canary.exs --timeout 87000
```

The initial 184-second calibration passed 1,792 requests but had not reached
the stream-allocation rotation boundary. A subsequent 600-second calibration
failed with `{:error, :goaway}` at concurrent rotation. The known-unsent admission repair subsequently passed a fresh **603-second**
calibration on `410e095`: **5,696 requests, zero errors**, peak VM memory
73,744,680 bytes, 178 processes, four owners/endpoints/native connections, and
mailbox depth one. Wrapper exit and owned fixture cleanup passed.
Neither calibration is a substitute for 24 hours. An independent final review
found a separate initial-admission watchdog classification gap. Deterministic
initial-admission and known-ref reconciliation regressions now pass, with no
replay, no producer demand and zero leases. Root runtime/Fetch/EventSource,
compile, format, Credo and Dialyzer reruns pass; the full canary remains required.

The fresh final candidate logs are `/tmp/http3-wp5-final-candidate-public.log`,
with private loaded modules under `/tmp/http-fetch-hex-consumer-yp2jtkc_` and
archives under `/tmp/http3-final-candidate-KxWRlh`. Those are candidate archives
of the current source with 0.16.5 development metadata, not a claim that immutable
published 0.16.5 artifacts contain the public H3 implementation. Final release
validation regenerates and verifies coordinated 0.16.7 artifacts separately.
