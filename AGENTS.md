# AGENTS.md

This file provides guidance to Pi Agent when working with code in this repository.

## Requirements
- Elixir 1.18+ (uses built-in `JSON` module)
- Erlang OTP with `:ssl` and `:public_key` applications

## Build, test, and lint

```bash
mix deps.get
mix compile --warnings-as-errors   # CI compiles with warnings-as-errors
mix test
mix format --check-formatted       # CI runs this; use `mix format` to fix
mix credo                          # CI runs this
mix dialyzer                       # CI runs this; PLT at apps/http_fetch/priv/plts/dialyzer.plt
mix docs                           # ExDoc HTML
```

Run a single test file or line: `mix test apps/http_fetch/test/http/response_test.exs:42`.
First-time Dialyzer setup: `mix dialyzer --plt` (2-3 min, cached in `apps/http_fetch/priv/plts/`).

### Testing an individual umbrella app

The child applications share the umbrella's `_build`, `deps`, and lockfile, but
a child Mix project does not put runtime applications of an `in_umbrella`
dependency on its own code path. Run scoped tests through the root Mix project
after the root preparation step:

```bash
MIX_ENV=test mix deps.get
MIX_ENV=test mix compile --warnings-as-errors
MIX_ENV=test mix test apps/http_fetch/test
```

Use the same root preparation and replace the path for any app under `apps/`,
including `apps/ex_ssl/test`, `apps/elixir_quic/test`, and
`apps/elixir_quic_http3/test`. Run E2E suites from the umbrella root with
`MIX_ENV=test mix test.e2e` or scope them with
`MIX_ENV=test mix test apps/<app>/e2e`. These root-scoped forms retain the
runtime dependency closure of umbrella apps.

## Project layout

This is a Mix umbrella with nine independently packaged apps under `apps/`.
`apps/http_core` owns shared HTTP primitives and the TLS/QUIC integration
boundary; `apps/http_runtime` owns pooled HTTP/2 and HTTP/3 connections. Fetch,
EventSource, and WebSocket depend on both `:http_core` and `:http_runtime`.
WebTransport and the HTTP/3 companion depend on `:http_core`; HTTP/3 also
depends on `:elixir_quic`. `:elixir_quic` depends on `:ex_ssl`.

The imported applications are `apps/ex_ssl` (`SSL`), `apps/elixir_quic`
(`Quic`), and `apps/elixir_quic_http3` (`QuicHttp3`). Their source provenance,
licenses, constraints, and current release status are recorded in
[`docs/migration-provenance.md`](docs/migration-provenance.md). Fetch and
EventSource support explicit HTTPS HTTP/3 beta with static/literal QPACK.
Dynamic QPACK, 0-RTT, migration, WebSocket over HTTP/3 and WebTransport remain
unsupported; raw `Quic.capabilities().http3` remains false. App presence and
negotiated ALPN alone do not establish application readiness or acceptance.

Entry point is `HTTP.fetch/2` in `apps/http_fetch/lib/http.ex`. It is async by default
(`Task.Supervisor` + the internal socket transport) and returns an `HTTP.Promise`.
Response handling, streaming, and telemetry emission live in the socket client and
response modules.
For module-by-module details, see the table in `CLAUDE.md` and read
`apps/http_fetch/lib/http/*.ex` plus shared primitives in
`apps/http_core/lib/http/*.ex` directly.

## Gotchas — read before editing

- **Flat fetch init options in `fetch/2`.** Pass request and transport settings
  directly (`method`, `headers`, `body`, `signal`, `redirect`, `timeout`,
  `connect_timeout`, `ssl`, `socket_opts`). Do not use legacy `options:`,
  `opts:`, or `client_opts:` buckets.
- **5MB streaming threshold.** Responses >5MB, chunked responses, or responses
  with unknown `Content-Length` stream via a separate process. Streamed
  responses have `body: nil` and `stream: pid`; consume them with
  `HTTP.Response.write_to/2` or by receiving `:stream_chunk` / `:stream_end` /
  `:stream_error` messages. Do not assume `body` is always populated.
- **Dialyzer warnings in `.dialyzer_ignore.exs` are intentional.** They cover
  the `Task.Supervisor.async_nolink/4` return shape in `HTTP.fetch/2` and the
  `HTTP.Promise.then/3` opaque `Task` return. Do not remove entries to "clean
  up" the output.
- **Telemetry prefix is `[:http_fetch, ...]`.** Event names: `[:request,
  :start | :stop | :exception]`, `[:streaming, :start | :chunk | :stop]`.
  See `apps/http_fetch/lib/http/telemetry.ex` and `HTTP.Telemetry` for the full list and
  metadata keys. Don't invent new event names without updating the module.
- **Unix Domain Sockets.** `fetch/2` accepts `unix_socket: "/path/to.sock"`.
  This routes through `HTTP.Transport.Unix`; do not assume standard TCP host
  handling when this option is set.

## Style

- `mix format` is authoritative; do not hand-format Elixir.
- The formatter scope is the umbrella root plus all nine `apps/*`
  (see `.formatter.exs` and each app's `.formatter.exs`).
- Credo is run in CI; run `mix credo` locally before pushing.

## Repo etiquette

- Conventional commits (e.g. `feat:`, `fix:`, `docs:`, `chore:`). See
  `git log --oneline` for examples.
- No release branch conventions are enforced beyond standard feature
  branches; PRs target `main` (see CI workflow files in `.github/workflows/`).
- CI, Test, and E2E use isolated app jobs. Automatic push/PR runs select only
  apps whose own `apps/<app>/` directories changed; dependency preparation
  does not select additional sibling test jobs. WebSocket and EventSource
  test closures also prepare Fetch for their cross-client tests.
- Shared configuration, tooling, and workflow changes require manual full
  regression. `workflow_dispatch` on each workflow forces all nine apps;
  manual CI also checks shared formatting, candidate consumers, and historical
  TLS compatibility. Use `gh workflow run ci.yml --ref main` (or `test.yml`
  or `e2e.yml`) after shared changes. Release validation still covers the full
  umbrella regardless of app selection.

## Reference

- API and usage examples: `README.md`
- Full module/architecture notes (legacy Claude Code guide): `CLAUDE.md`
- Known Dialyzer exceptions: `.dialyzer_ignore.exs`
- CI jobs: `.github/workflows/ci.yml`, `test.yml`, `release.yml`
