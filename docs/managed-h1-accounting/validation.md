# #97 hardening validation

Library baseline: `ceecbf2df62ca80c361597c7303f65a153f2ce3c` (0.21.3).
Native contract: **unresolved**; these are logical/functional regression gates.
[Machine-readable results](validation.json) preserve exact summaries and failed
checkpoint hashes. Full raw local logs remain at the recorded `/tmp` paths.

Preparation: `MIX_ENV=test mix deps.get --check-locked`; isolated Python fixture
prepared with `uv venv /tmp/http-fetch-97-python` and
`uv pip install --python /tmp/http-fetch-97-python/bin/python --requirement scripts/requirements-http2-stream-clients.txt`.
No lockfile change. Runtime matches profile.json's local validation entry, not
its required certification entry. Stress uses the same patch runtime with two
normal schedulers.

PASS commands:

- `MIX_ENV=test mix compile --warnings-as-errors`
- `MIX_ENV=dev mix deps.get --check-locked` and
  `MIX_ENV=dev mix compile --warnings-as-errors`
- `MIX_ENV=test mix format --check-formatted`
- `PATH=/tmp/http-fetch-97-python/bin:$PATH MIX_ENV=test mix test --seed 28092026`
- `MIX_ENV=test mix credo`
- `MIX_ENV=test mix dialyzer --format github`: two intentional ignored warnings;
  two existing unnecessary-ignore notices retained
- `MIX_ENV=dev mix docs`
- `MIX_ENV=test mix test apps/http_runtime/test/http/http1/pool_test.exs apps/http_fetch/test/http/request_completion_test.exs apps/http_fetch/test/http/stream_writer_test.exs --seed 97`: 34 tests, zero failures
- `git diff --check`

The full suite retains 194 excluded SSL integration tests and three skipped
HTTP-core tests. SSL integration and independent wire/E2E/candidate/archive/
published-consumer gates remain the release workflow's separate required checks.
These local unit results are not publication evidence or original-profile native
certification.

Independent read-only review reproduced abnormal linked writer death and expiry
rejection after tracker handoff. Both repaired and re-reviewed. Reviewer writer/
pool runs: 16 tests, zero failures. Expired target handoff preserves monitors;
lost tracker returns handoff_unconfirmed; accepted-before-deadline handoff
survives a delayed reply.

Empirical stress reproduction from the umbrella root:

```
ERL_FLAGS='+S 2:2' MIX_ENV=test mix run docs/managed-h1-accounting/stress.exs
```

The retained stress.json samples process/port counts, control mailbox lengths,
binaries, process/total memory, heap allocator sizes and RSS after 200 reused
OTP TLS requests, a 1,000-ACK-chunk request, and retirement. One sample per phase,
no forced native flush or reclamation inference. Allocation/OS quantities and
logical request counts remain separate. This is regression evidence, not a
history-independent memory theorem.

Failed attempts are explicitly retained in validation.json: missing local `h2`,
a startup-reason test without initialization ordering, wrong read_all harness
shape, ExDoc invoked in test environment, and a new Credo readability issue.
Each was repaired or the command/environment corrected before PASS. No excluded
or failed test is relabeled as a native-accounting certificate.
