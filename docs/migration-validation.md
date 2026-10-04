# TLS and QUIC migration validation

This 2026-10-04 pre-merge snapshot separates the already-published six-package
baseline from checks run against the imported source. A baseline result is not
evidence for the source migration. Statements about unperformed Git operations
and release publication describe the state on this snapshot date.

## Pre-migration release baseline

The six original packages were published at 0.16.1 from tag `v0.16.1`, commit
`e844ce03067fedac82c079f21c47810e671be0bb`. Release workflow `36853368836`
completed successfully. Before importing TLS/QUIC source, the umbrella unit
run had 812 tests and 20 doctests (3 skipped), and the HTTP E2E suite had 51
tests; the migration owner recorded those runs as passing. Published artifact
checksums, dependency metadata, and source files were independently verified
for all six packages. This evidence covers the pre-migration tree only.

## Imported-source migration checks

The local candidate checks below used Elixir 1.19.5 / OTP 28 unless a row says
otherwise. Logs under `/tmp` are local evidence, not published artifacts.
Preserve failed attempts and explain the final disposition; do not turn unrun
checks into passes.

| Check | Status | Evidence |
| --- | --- | --- |
| Destination source inventory | Verified with documented adaptations | All 390 tracked source-app files from `ex_quic@14974913390e12d03a78a2903d18e55a04fa89d6` are present. A blob comparison found 58 changed imported files and two destination-only files, all enumerated in [migration provenance](migration-provenance.md). |
| Root and nine-app version/dependency graph | Passed | `elixir scripts/release/versions.exs validate 0.16.1` exited 0; root app-closure checks for all nine selectors plus invalid input passed in 3.11s (`/tmp/http_fetch_final_ci_closures.json`). |
| Full umbrella unit suite | Passed with skips | All nine root-scoped app suites passed at seed 28092026: 1497 tests, 20 properties and 20 doctests, with 3 skips (24.78s; `/tmp/http_fetch_astra_round5_results.json`, `/tmp/http_fetch_astra_round5_units.log`). |
| TLS integration gate | Passed after round-three fixes | The full TLS suite passed at seed 743209: 607 tests, 20 properties, 0 failures (29.20s command / 28.3s ExUnit; `/tmp/http_fetch_astra_round5_results.json`, `/tmp/http_fetch_astra_round5_tls_integration.log`). Earlier destination and source-revision runs had failures, including a source-only resumption close timeout; those are historical attempts, not the final result. |
| Independent TLS/QUIC peer comparison | Passed after environment correction | The first wrapper attempt exited 1 with `:enoent` because its transient `uv` Python executable vanished (`/tmp/http_fetch_final_tls_quic_comparison.json`, `/tmp/http_fetch_final_tls_quic_comparison.log`). After creating a persistent `uv` virtual environment, `mix run apps/ex_ssl/e2e/quic_tls/run.exs` passed all 13 comparisons: suites 4865/4866/4867 in client and server roles with two identities each, plus an mTLS client case (2.64s, exit 0; `/tmp/http_fetch_final_tls_quic_peer.json`, `/tmp/http_fetch_final_tls_quic_peer_2.log`). The full TLS integration suite is tracked separately above. |
| E2E and independent protocol checks | Passed where run | Fresh Go build exited 0 in 0.73s, then `mix test.e2e` passed 51 tests with 0 failures in 1.83s at seed 914374 (`/tmp/http_fetch_repair_http_e2e.json`). The latest ten independent checks all exited 0 (27.07s combined): aioquic client/server, stream interop, DATAGRAM client/server, local UDP HTTP/3 smoke, TLS/QUIC peer comparison, and impaired phase-1 client/server/external-server (`/tmp/http_fetch_repair_interop.json`). The Caddy fixture remains a CI-only gate and was not run locally. |
| CI and release helper regressions | Passed | The six CI selector tests passed (0.95s), all 11 release helper tests passed (11.40s), and the workflow actionlint check exited 0 (0.57s; `/tmp/http_fetch_repair_final_helpers.json`). |
| Formatter, compile, Credo, Dialyzer, docs | Dev/test checks passed; earlier test-support Dialyzer warnings were resolved | Round five passed `mix compile --warnings-as-errors` in dev/test (0.91/1.67s), `mix format --check-formatted` (0.54s), and `mix credo --format json` (2.10s). `MIX_ENV=dev mix dialyzer --format github` and `MIX_ENV=test mix dialyzer --format github` both passed (32.41/37.82s), each reporting 4 warnings, 4 skipped, and 0 emitted; the exact `Quic.Streams.new/2` `MapSet.t()` literal exception remains anchored at `lib/quic/streams.ex:90` and linked to [elixir-lang/elixir#15673](https://github.com/elixir-lang/elixir/issues/15673) in `.dialyzer_ignore.exs` (`/tmp/http_fetch_astra_round5_results.json`, `/tmp/http_fetch_astra_round5_dialyzer_dev.log`, `/tmp/http_fetch_astra_round5_dialyzer_test.log`). Round four's 14 test-support warnings are preserved as historical evidence: `compatibility.ex` (1), `local_tls_peer.ex` (12), and `openssl_peer.ex` (1). At that point a read-only build of those three files from clean source SHA `14974913390e12d03a78a2903d18e55a04fa89d6` produced the same 14 warning terms after path/line normalization (`/tmp/http_fetch_astra_round4_support_baseline.log`, `/tmp/http_fetch_astra_round4_support_compare.log`); this was not a full source-repository CI run. Round five corrected contracts in those three test helpers without changing fixture networking or protocol behavior: the fixed implementation-pair type, complete certificate/peer states, and exact mixed client option type; it also explicitly discards the existing `System.cmd` cleanup result. The 27-test streams suite passed in round four; all nine round-five unit suites and the TLS integration suite are recorded above. `mix docs` previously exited 0 with hidden-reference warnings (`/tmp/http_fetch_repair_docs.json`); docs were not rebuilt in round five. These are local checks; no remote workflow result is claimed. |
| Nine-package archives and local Hex consumers | Round-five archives match the passing round-four candidates | Round four rebuilt, verified, and independently consumed all nine archives: build 3.88s, identities 0.38s, audit 0.10s, verify 3.60s, and production-mode all-nine consumer 36.28s, all exit 0 (`/tmp/http_fetch_round4_packages.json`). Its external consumer passed in 7.09s, real HTTP/2 traffic passed in 22.02s, and all nine TLS feature groups passed in 27.21s, all exit 0 (`/tmp/http_fetch_round4_consumers.json`). Earlier setup attempts were resolved: one feature smoke used the fixture parent path and exited 2 in 0.08s before succeeding with the `/repo` fixture path; HTTP/2 attempts first lacked `h2`, then `wsproto`, before passing with the full pinned requirements. Round five rebuilt (3.87s), checked identities (0.40s), and audited (0.10s) all nine archives, all exit 0 (`/tmp/http_fetch_astra_round5_package_results.json`). Independent SHA-256 comparison confirmed every round-five archive is byte-identical to round four and excludes `test/`, `e2e/`, `_build/`, `deps/`, and `priv/plts/` payload (`/tmp/http_fetch_astra_round5_archive_comparison.json`, `/tmp/http_fetch_astra_round5_archive_comparison.log`). Because the distributed bytes are unchanged, the round-four consumer and traffic results validate the same round-five archives; no duplicate consumer traffic was run. These local archive checks do not establish a published nine-package release. |
| Release preflight retry behavior | Passed in read-only mocked checks | Parent verification checked parsing and mismatch rejection for an actual Hex API checksum, rejection of an existing GitHub asset with different bytes before any uploads, and a matching retry that uploaded the eight missing assets then downloaded and verified all nine (0.048s). Mocks made no remote calls or writes; this does not establish a published release. |
| Published nine-package consumer | Blocked by immutable baseline; not run | Nine live, read-only Hex API GETs (0.92s; `/tmp/http_fetch_final_hex_availability.json`) confirmed that `ex_ssl`, `elixir_quic`, and `elixir_quic_http3` at `0.16.1` return 404, while the six existing `0.16.1` archives differ from the candidate and are immutable. Published `http_core` still requires `ex_ssl ~> 0.7.2` and `elixir_quic ~> 0.3.0`. As of this snapshot, no migration commit, push, release tag, release workflow dispatch, Hex publication, or GitHub release had occurred. Commit and push were authorized after final review; neither operation had been performed. A later shared package version is required before all nine packages can be consumed together from Hex. |

The local Hex registry proved candidate package metadata and real HTTP/2
traffic without publishing. It does not establish a public nine-package Hex
release. HTTP/3 and WebTransport remain unsupported and must not be represented
as passing production protocol traffic.

## Next coordinated release safeguards

The already-published six packages at 0.16.1 are immutable. Publishing new
TLS/QUIC dependencies under that version cannot repair their registry metadata;
the complete graph needs a later authorized shared version. Before release:

1. Validate all nine package versions and exact internal dependency identities,
   requirements, and umbrella metadata.
2. Build and audit all nine package archives, including package file lists,
   source correspondence, dependency metadata, and checksums.
3. Check Hex registry state before publishing. Reject an existing version when
   its package archive or assets differ; do not attempt to overwrite it.
4. Run the full umbrella suite and isolated source consumer before publication.
   After publication, resolve all nine packages from Hex in an independent
   consumer and run the agreed real-traffic gates.
5. Preflight release asset checksums and the immutable tag before any publish
   step. Publish in dependency order, verify each package before proceeding to
   its dependents, and allow a retry only when the existing package and assets
   match the preflight checksums exactly.

Release tooling is under `scripts/release/`. `stage.py build VERSION STAGE_DIR
ARCHIVE_DIR` creates portable package sources and archives; `archives.exs
VERSION ARCHIVE_DIR` and `archive_audit.py VERSION STAGE_DIR ARCHIVE_DIR`
inspect metadata and packed bytes; `consumer_gate.py VERSION ARCHIVE_DIR`
checks all nine package consumers. The release workflow also preflights
registry checksums and GitHub assets before its first remote write, and
publishes optional documentation only after all packages are verified. As of
this snapshot, no release publication or tag operation was part of the
migration validation. The authorized migration commit and push had not
occurred; they were conditional on final review.
