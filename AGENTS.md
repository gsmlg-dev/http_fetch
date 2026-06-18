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
mix dialyzer                       # CI runs this; PLT at priv/plts/dialyzer.plt
mix docs                           # ExDoc HTML
```

Run a single test file or line: `mix test test/http_test.exs:42`.
First-time Dialyzer setup: `mix dialyzer --plt` (2-3 min, cached in `priv/plts/`).

## Project layout

Entry point is `HTTP.fetch/2` in `lib/http.ex`. It is async by default
(`Task.Supervisor` + the internal socket transport) and returns an `HTTP.Promise`.
Response handling, streaming, and telemetry emission live in the socket client and
response modules.
For module-by-module details, see the table in `CLAUDE.md` and read
`lib/http/*.ex` directly.

## Gotchas — read before editing

- **`options:` vs `opts:`/`client_opts:` in `fetch/2`.** The keyword
  `options:` maps to request options consumed by the socket transport
  (`timeout`, `connect_timeout`, `ssl`, `autoredirect`). The `opts:` and
  `client_opts:` keywords map to compatibility client options; broad legacy
  client parity is intentionally not implemented, but `socket_opts` is consumed
  by the transports.
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
  See `lib/http/telemetry.ex` and `HTTP.Telemetry` for the full list and
  metadata keys. Don't invent new event names without updating the module.
- **Unix Domain Sockets.** `fetch/2` accepts `unix_socket: "/path/to.sock"`.
  This routes through `HTTP.Transport.Unix`; do not assume standard TCP host
  handling when this option is set.

## Style

- `mix format` is authoritative; do not hand-format Elixir.
- The formatter scope is `{mix,.formatter}.exs` and
  `{config,lib,test}/**/*.{ex,exs}` (see `.formatter.exs`).
- Credo is run in CI; run `mix credo` locally before pushing.

## Repo etiquette

- Conventional commits (e.g. `feat:`, `fix:`, `docs:`, `chore:`). See
  `git log --oneline` for examples.
- No release branch conventions are enforced beyond standard feature
  branches; PRs target `main` (see CI workflow files in `.github/workflows/`).
- CI runs on every push: compile + warnings-as-errors, format check, Credo,
  Dialyzer, and tests. A green local `mix test && mix format --check-formatted
  && mix credo && mix dialyzer` should match CI.

## Reference

- API and usage examples: `README.md`
- Full module/architecture notes (legacy Claude Code guide): `CLAUDE.md`
- Known Dialyzer exceptions: `.dialyzer_ignore.exs`
- CI jobs: `.github/workflows/ci.yml`, `test.yml`, `release.yml`
