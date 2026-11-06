# Abyss in HTTP Fetch

This app was imported from `https://github.com/gsmlg-dev/abyss` at
`89f6879edd163ff023d8bcb44b9686175dca0109` (version `0.10.0`). Its MIT license and
copyright remain in `LICENSE`. The raw package from the same commit is now at
`../../packages/abyss_raw`, outside the umbrella to keep Rust builds opt-in.

Runtime source and supervision semantics are unchanged. The manifest shares the
umbrella build/dependency/lock paths and uses Hex development helpers rather than
probing sibling repository paths. ExDoc is limited to development and test to
match shared tooling; runtime dependencies are unchanged. Both packages retain
Elixir `~> 1.13`. The source raw lock already selected Rustler `0.38.0`, whose
manifest requires Elixir `~> 1.15`; the locked native build therefore does not
establish the advertised 1.13 minimum. This migration preserves that existing
dependency constraint and reports the limitation. QUIC examples require Elixir `~> 1.18`, as before. Socket/host
test suites carry integration tags to match the monorepo's separate CI gate.

Run all imported tests from the umbrella root:

```sh
MIX_ENV=test mix test apps/abyss/test --include integration --include slow
```

The QUIC examples keep their locked published `0.21.17` engine as a historical
compatibility gate. To validate the monorepo's current engine, first stage portable
packages with the root release tooling. In an independent copy of either example,
set `ABYSS_PATH`, `ELIXIR_QUIC_PATH`, and `EX_SSL_PATH` to those staged packages;
run `mix deps.get`, then:

```sh
ABYSS_ENGINE_MODE=current mix run --no-start /absolute/path/to/apps/abyss/scripts/phase1/idle_policy.exs
```

The path dependencies are explicit opt-ins in the example consumer. Ordinary UDP
consumers install neither engine nor raw package. Current-engine provenance checks
verify the selected dependency paths and BEAM locations before live TLS/UDP tests.
The original published-engine checks remain in `published_provenance.exs`.
The root candidate gate uses `ABYSS_ENGINE_MODE=candidate` with
`ABYSS_ENGINE_VERSION` to verify exact Hex dependencies and isolated BEAM paths.

Historical evidence logs, caches and the standalone publisher were not imported.
Current package staging and release groups are owned by the monorepo root tools.
Source-attributed historical documents remain linked to the old repository; they
are not current monorepo acceptance results.
