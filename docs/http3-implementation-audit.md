# HTTP/3 implementation audit

Plan: [2026-10-05 review](http_fetch_HTTP3_review_and_plan_2026-10-05.md).
Baseline: `6e33bcba7dae9acee1924af744c766b8e1d6147d`.
Implementation branch: `codex/http3-completion`.

The user authorized a commit, push, and patch release attempt after each work
package. Intermediate release failures are audit evidence; they do not authorize
weakening release checks. Existing 0.16.1 artifacts remain immutable. Final
completion requires all required gates and the final release to succeed.

| Package | Release target | State |
| --- | --- | --- |
| WP0: baseline | 0.16.2 | Local repair verified; release attempt pending |
| WP1: transport and resumable state | 0.16.3 | Pending |
| WP2: bounded HTTP/3 profile | 0.16.4 | Pending |
| WP3: runtime and pooling | 0.16.5 | Pending |
| WP4: explicit Fetch integration | 0.16.6 | Pending |
| WP5: independent acceptance | 0.16.7 | Pending |

Local validation, remote workflow results, wire interoperability, artifact
consumers, and soak/canary evidence are recorded separately. Dynamic QPACK,
0-RTT, connection migration, Alt-Svc/racing, WebSocket over H3, and WebTransport
remain outside the initial HTTP/3 profile.

## WP0

Restored isolated CI test closure without modifying WS/SSE assertions or runtime
dependencies. Fresh red builds reproduced the historical five missing-Fetch
failures. Fresh green builds: WebSocket 82 tests and EventSource 64 tests, zero
failures (historical seeds, max-cases 8). See the baseline evidence document.

Root `MIX_ENV=test mix compile --warnings-as-errors`: PASS (Elixir 1.18.5/OTP 28).
Release automation tests initially failed 1/11: `archives.exs` incorrectly called
Hex's tarball unpacker with `:none`, interpreted as a filesystem output. Inspected
the installed Hex 2.4.0 implementation and changed the output to `:memory`.
This is a release-script defect, not a Hex defect. Rerun result recorded below.

Release automation rerun: **PASS**, 11 tests, exit 0. Manifest/harness formatting
and `git diff --check`: **PASS**.
