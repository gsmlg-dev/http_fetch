# ex_ssl v0.7.1 incremental review

Date: 2026-09-23.
Reviewed HEAD: `02eb981f59d4e182d4473e264a9f8b093ec6bf3d`.
Previous review baseline: `606087058e912b08ce20e145bcd8505744be8a78` (v0.7.0).

## Decision

**F1 is closed. No new blocking finding was identified in the reviewed incremental changes. Proceed with ex_quic against the pinned experimental public interface.** No additional ex_ssl repair prompt is issued by this review.

This decision is about the changed code, prior finding closure and readiness to start downstream development. It is not a fresh whole-library security audit or a claim of production suitability.

## Inspected changes

Commit `6cc7450006e3552dbc0ed22b697b64239539bc03` modifies four expressions in three production files:

- Config conditionals use `do/end` rather than long inline `do:`/`else:` forms. Conditions, short-circuit behavior and tagged returns are unchanged.
- The repeated-HRR guard uses an explicit block returning `true`; predicate and matching remain unchanged.
- Server certificate encoding gets a local `chain` binding immediately after the same successful secret derivation and before the same call. The field is accessed at the same semantic point, and no TLS output/transcript ordering is changed.

The rest of that commit is changelog/implementation evidence. The next commit only sets version 0.7.1 and the changelog heading. No workflow file, test, dependency minimum, public API, algorithm or certificate policy is changed in those commits. R1–R3 remain unchanged from the reviewed v0.7.0 repair. [R1,R2]

## Verified remote gate closure

The reviewed release HEAD has successful CI and Test evidence. The reviewer directly read GitHub workflow/job results, rather than inferring runtime success from a local formatter statement.

| Gate read in this review | Evidence | Result |
|---|---|---|
| Release-tag CI | Run `35828024753` | Success |
| Elixir 1.18 / OTP28 build | Job `107073980769` | Format and warnings-as-errors compile both succeed |
| Elixir 1.19 / OTP28 build | Job `107073980170` | Format and warnings-as-errors compile both succeed |
| Elixir 1.20 / OTP29 build | Job `107073980466` | Format and warnings-as-errors compile both succeed |
| Test matrix | Run `35827826151` | All three actual test jobs succeed |
| 1.18/28 test | Job `107073373485` | Test compile and unchanged suite script succeed |
| 1.19/28 test | Job `107073373370` | Test compile and unchanged suite script succeed |
| 1.20/29 test | Job `107073373268` | Test compile and unchanged suite script succeed |
| QUIC TLS reference | Run `35828024798`, job `107073980231` | Actual independent-comparison step succeeds |

The release notes additionally report 435 checks per default-test lane, 54 focused local checks and 13 independent reference scenarios. Those counts are release-recorded evidence, not tests rerun in the reviewer's environment. The notes also link successful TLS peer/downstream and Caddy JA3/JA4 workflows. [R2,R6]

The failed 1.18 formatting gate no longer blocks its compiler. This was achieved without deleting a matrix lane, weakening an assertion, disabling warnings-as-errors, adding continue-on-error, or changing required-check names.

## Boundary reconfirmed for the downstream plan

The current interface provides both certificate-handshake roles, ordered directional secret/handshake actions, raw transport parameters, public ClientHello observation and profile types. No new TLS extraction is needed for ex_quic's first milestone. [R3,R4]

Preserve these limitations explicitly:

- The API is experimental. A protocol integration is not a production security certification.
- Independent HRR coverage is not provided by the existing pinned aioquic 1.2.0 TLS-only harness. M6 needs a demonstrated independent HRR-capable network peer.
- Full QUIC networking is not part of ex_ssl's TLS-only reference suite.
- Resumption, 0-RTT, server-side mTLS and client startup with an empty-share profile are outside the current provider scope; profile simulation must not silently promise them.
- Historical macOS full-integration TCP closure/backpressure failures are not relabeled as resolved by green default Linux CI. The optional full local integration suite was not rerun for this syntax-only change according to the release record.
- A GitHub release attachment does not prove Hex publication. The release task explicitly says it did not publish to Hex; the downstream plan therefore uses the reviewed Git SHA.

## Review method and actions

Read live GitHub commits, release metadata, workflow/job summaries, the current QUIC interface/fingerprint documentation, and the current Abyss listener/connection source. The previous prompt and architecture files were also inspected from their mounted local copies.

No Elixir/Mix executable is installed in the reviewer's current container. The reviewer did not execute compilation, unit tests, a network interop suite, performance tests or a security audit. No repository code, branch, tag, issue, release or workflow was modified or triggered.

The newly generated documents are a development plan, not an implemented ex_quic release. See [sources](sources.md) for canonical evidence locations.
