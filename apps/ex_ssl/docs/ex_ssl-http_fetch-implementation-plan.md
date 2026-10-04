# Implementation Plan: ex_ssl as an http_fetch TLS Backend

**Audience:** Codex implementing changes across `gsmlg-dev/ex_ssl` and `gsmlg-dev/http_fetch`\
**Prepared:** 2026-09-20\
**Status:** Proposed implementation plan; not a claim that the work or validation below has been executed.

## 1. Objective and delivery boundaries

Expand `ex_ssl` into a dependable replacement for the **documented TCP TLS client subset used by `http_fetch`**, without rewriting working transport code or claiming complete OTP `:ssl` parity.

Deliver incrementally:

| Milestone | Completion boundary |
| --- | --- |
| A — Validated opt-in backend | Verify the existing TLS 1.3 integration and its lifecycle regressions. This milestone does not depend on adding TLS 1.2, mTLS, or resumption. |
| B — Expanded TLS 1.3 coverage | Add the selected signature/group coverage, client certificates, and documented transport/configuration compatibility in Phases 1–3. |
| C — Secure dual-version backend | Add the bounded TLS 1.2 client implementation in Phase 4. Validate TLS 1.3-only, TLS 1.2-only, and mixed-version operation. |
| D — Operational maturity | Add bounded TLS 1.3 resumption and diagnostics, then complete the production-readiness evidence. Resumption is not a prerequisite for Milestones A–C. |

**Keep `:ssl` as the default throughout this plan.** Keep explicit/configured `tls_backend: :ex_ssl`. Changing the default, removing the OTP adapter, publishing packages, or merging PRs requires a separate authorized change.

This plan deliberately does not promise compatibility with every OTP option, every TLS server, or every historical cipher suite.

## 2. Baseline: reconcile before implementing

The inspected snapshot is:

| Repository | Revision | Observation |
| --- | --- | --- |
| `ex_ssl` | `0f16c2cad34236d644b301179725c6614302fbef`, v0.3.0 | Current main at preparation time. [R1] |
| `http_fetch` main | `540225cec69cd2c1e41eb80b956fd6f1a8df7b70` | Base of the migration PR. [R2] |
| `http_fetch` PR #14 | `a1312cc40c8d6aad2cb60e750bfba84f9b3ac1cf` | Open at preparation time; contains a follow-up for cross-record HTTP/2 closure. [R2–R3] |

**Important correction to the earlier review:** that review examined PR head `010b0b8`. At `a1312cc`, `send_request/4` returns send errors without immediately destroying the receive side, and HTTP/2 can continue draining after narrowly classified ex_ssl control-write closure. Do not blindly reimplement the old fix. Validate the current implementation and preserve it when correct. The PR reports passing tests; those reports are not a substitute for rerunning your checked-out revision. [R2–R3]

Refresh both repositories and record their actual SHAs before making changes. Read `AGENTS.md`, the architecture/design documents, existing implementation plans, `docs/COMPATIBILITY.md`, `docs/HTTP_FETCH_INTEGRATION.md`, and the PR validation report. Reconcile this plan with newer changes instead of resetting repositories to the snapshot above.

Use separate worktrees/branches for the two repositories. Preserve unrelated user changes. Do not edit fetched dependencies under `deps/`; use a temporary local dependency override for cross-repository development, then validate released/buildable dependency metadata independently.

## 3. Non-negotiable architecture and security rules

**Implementation ownership.** `ex_ssl` must execute its own TLS protocol. OTP `:ssl` is permitted as a test peer and differential reference, not as a hidden implementation or fallback. Preserve `SSL` as the public module and `SSL.*` internally. Use `:crypto` and `:public_key` rather than implementing cryptographic primitives. [R4]

**Functional core.** Keep codecs, negotiation, transcripts, key schedules, and profile validation pure where practical. Keep socket ownership, deadlines, bounded queues, and effects in the existing per-connection `:gen_statem` and connection-owned writer. Avoid a second independent writer or a generic framework rewrite.

**Authentication.** Preserve certificate identity/path checks, handshake authentication, AEAD validation, fresh ephemeral keys, and bounded parsing. Keep `verify_none` unsupported. No fingerprint/profile setting may override a safety check. Authentication failures must not trigger retries with weaker options.

**Lifecycle.** Preserve one deadline per operation, ordered ciphertext, active-once delivery, send admission, cancellation, owner-death cleanup, and data-before-terminal-message ordering. Never replay uncertain request bytes. Distinguish authenticated closure from truncation, TCP reset, and process loss.

**Compatibility.** Keep backend identity fixed through redirects and EventSource reconnects. Never automatically switch from `:ex_ssl` to `:ssl`. Explicitly reject unsupported or conflicting options before I/O where possible. Do not turn invalid supplied values into defaults.

**Protocol boundary.** HTTP/3 and WebTransport remain on the QUIC path. Do not add QUIC, server TLS, DTLS, 0-RTT, post-handshake client authentication, active-N, or packet-mode emulation as part of the initial replacement.

## 4. Phase 0 — Validate and preserve the current integration

**Repositories:** primarily `http_fetch`; inspect `ex_ssl` as the dependency.\
**Deliverable:** a reproducible baseline and regression evidence, plus only fixes that remain necessary.

### P0.1 — Inventory actual consumer requirements

Audit production `:ssl` calls, the transport behaviour, public `ssl:`/`socket_opts:` handling, and tests across all five umbrella packages. Separate application runtime requirements from OTP-based test servers and QUIC dependencies.

Record each requirement as implemented, deliberately unsupported, or missing, with its test. Do not treat unused OTP facade functions as blockers. Reuse the existing adapter, ALPN dispatch, ownership handoff, WebSocket receive dispatch, and backend selection.

### P0.2 — Prove the cross-record HTTP/2 close behaviour

Focus on `apps/http_fetch/lib/http/socket_client.ex`, the existing HTTP/2 implementation/tests, and `docs/pr-14-validation.md`.

Reuse the deterministic TLS fixture to establish this sequence: the owner receives an initial HTTP/2 batch; later response bytes remain within ex_ssl; the peer's authenticated closure rejects a control write; the owner subsequently drains the remaining data. Separate TLS-record fragmentation from TCP-message fragmentation. Do not rely on sleeps or assume that two server writes automatically establish the required schedule.

Keep success conditional on HTTP/2 completion, including END_STREAM and applicable framing/length checks. Only the existing allowlisted control frames with no outstanding required request-body data may use this drain path. Never broaden tolerated errors to `:einval`, `:econnreset`, arbitrary transport failures, or TLS alerts.

Cover buffered and streamed responses, split frame headers/payloads, data exceeding the passive-buffer bound through incremental drainage, truncation, RST_STREAM, malformed frames, pending uploads, cancellation, and the original deadline under backpressure. Assert exact-once completion and resource cleanup. Keep any necessary dependency-state probe test-only and narrowly tied to the tested dependency version.

### P0.3 — Preserve the whole consumer boundary

Run verified HTTP/1.1 and real HTTP/2 exchanges, redirects, streaming, WSS passive Upgrade followed by active-once frames, and EventSource reconnects. Verify wrong CA/hostname rejection, backend pinning, absence of fallback, profile/ALPN validation, and the QUIC backend-selection boundary.

**Exit gate:** existing behaviour remains intact and the HTTP/2 regression is deterministically covered. Where the latest code already passes, update evidence rather than manufacturing a new implementation.

## 5. Phase 1 — Expand TLS 1.3 algorithm interoperability

**Repository:** `ex_ssl`, with focused consumer integration tests.\
**Deliverable:** a tested capability registry and a precisely documented expanded algorithm subset.

### P1.1 — Centralize capability truth

Audit `lib/ssl/options.ex`, `lib/ssl/crypto/signature.ex`, key exchange, ClientHello validation/materialization, certificate key decoding, and the server-flight verifier. Remove inconsistent capability decisions without broad restructuring.

Use one internal registry for wire identifiers, public option names, protocol applicability, key restrictions, and required runtime primitives. Distinguish handshake-signature support, certificate-chain signature policy, and ephemeral key exchange. A certificate's issuer signature is not its leaf CertificateVerify scheme.

Advertise an algorithm only when the complete implementation and the exact runtime prerequisites exist. Checking only whether generic RSA or ECDSA is present is insufficient. Preserve caller ordering and exact-wire profile validation.

### P1.2 — Implement the initial expansion

Target P-384 ECDSA handshake signatures, Ed25519 handshake signatures, RSA-PSS-PSS SHA-256/384/512, and P-384 ECDHE. Preserve the existing P-256 ECDSA, RSA-PSS-RSAE, X25519/P-256 key exchange, and TLS 1.3 AEAD suites. Keep P-521, Ed448, X448, finite-field groups, and post-quantum algorithms as explicit follow-up entries unless independently required by the audited endpoint contract.

Implement signing/verification abstractions that can support the next phase without conflating client and server CertificateVerify contexts. Enforce key type, EC curve, signature encoding, and restricted RSA-PSS key parameters. Do not reinterpret RSA-PSS keys as unrestricted RSA keys. Use the normative TLS specification and OTP public algorithm mappings as references. [R7–R8]

### P1.3 — Test negotiation, not just primitive operations

Add independent signature vectors, wrong-key/curve/parameter negatives, unsupported-runtime tests, and local handshakes with peers constrained to each new scheme/group. Verify both valid HelloRetryRequest handling and rejection of invalid retries. Use real HTTP requests to prove the new negotiated combinations work through `http_fetch`.

**Exit gate:** every advertised new algorithm has positive interoperability and negative authentication tests. Required CI coverage cannot pass by skipping all tests for a promised algorithm; document runtime-specific exclusions explicitly.

## 6. Phase 2 — Add initial-handshake client certificates / mTLS

**Repository:** `ex_ssl`; add HTTPS integration coverage in `http_fetch`.\
**Deliverable:** a bounded, single-client-identity configuration compatible with the documented OTP option forms.

### P2.1 — Load and validate a client identity

Implement the supported `cert`/`certfile` and `key`/`keyfile` forms after checking their documented types. Support binary and charlist paths consistently. Initially support unencrypted PEM files and the corresponding documented in-memory forms; explicitly reject encrypted keys, hardware-signing configurations, and multiple-identity selection until implemented.

Validate parse limits, chain order, key/certificate matching, and scheme availability. Separate client identity from server trust configuration. Never echo key material, passwords, entire PEM input, or sensitive option values into errors or ordinary inspection. [R7]

### P2.2 — Complete the client-authentication flight

Handle a valid CertificateRequest, choose a compatible configured identity/signature scheme, construct the client Certificate and CertificateVerify, and maintain the correct transcript through Finished. Send credentials only in response to an appropriate request. Handle an optional request without a usable identity correctly; a server requiring an identity must not be misreported as a successful HTTP exchange. Post-handshake authentication remains unsupported. [R8]

Use the existing bounded writer and handshake deadline. Audit connect completion and subsequent alert delivery rather than assuming the client can know the server accepted its identity immediately after writing Finished.

### P2.3 — Verify at the HTTP layer

Test required/optional client auth, successful RSA and ECDSA identities, wrong CA, expired/rejected client certificate, key mismatch, incompatible requested scheme, fragmented certificate flights, and cancellation during signing/output. Assert on the server which client identity was received.

Define credential propagation explicitly for redirects: configured mTLS identities must remain within their configured origin scope unless the caller deliberately authorizes broader reuse. Add regression coverage and document the policy without silently changing the OTP backend. Confirm WSS and EventSource can use the same validated identity path.

**Exit gate:** a trusted local mTLS HTTP endpoint returns a real response through ex_ssl, while required-identity failures remain failures and server authentication is never relaxed.

## 7. Phase 3 — Expand options and socket compatibility deliberately

**Repositories:** both.\
**Deliverable:** a versioned option matrix and compatible adapter mappings.

### P3.1 — Separate policy, profile, and transport options

Classify each option as TLS policy, client identity, ClientHello wire control, or TCP transport configuration. Implement the documented subset of `ciphers`, `signature_algs`, `signature_algs_cert`, and `supported_groups` using the capability registry. Preserve defaults only when no value was supplied. Invalid, unsupported, or empty effective configurations must fail explicitly. [R7]

For generated/default profiles, materialize the requested capability lists in order. For explicit profiles, validate compatibility and reject conflicts rather than rewriting the fingerprint. Preserve the existing exact ordered ALPN rule. Do not expose TLS 1.2 through option normalization until Phase 4 is complete.

### P3.2 — Add a safe TCP allowlist

Start with `nodelay`, `keepalive`, `sndbuf`, `recbuf`, local `ip`/`port`, and address-family selection where the supported socket backend can honor them. Add each option with validation and a real behaviour test; do not pass every option through blindly. Validate IPv4/IPv6 DNS and literal-address behaviour, SNI suppression for IP addresses, and IP SAN verification.

Treat raw `buffer` tuning separately from TLS parser/plaintext limits. A larger driver buffer must not bypass resource bounds. Keep raw active mode, raw packet framing, and TCP ownership private to the TLS process. Leave arbitrary socket backends, unsafe linger behaviour, and `send_timeout_close: false` unsupported unless separately designed and tested.

For mutable options, validate the complete request before applying it. Test underlying socket errors and do not claim stronger atomicity than the implementation can guarantee.

### P3.3 — Bound certificate-policy compatibility

Preserve CA overrides, depth, SNI/reference identity, and supported hostname customization. Inventory actual uses of `verify_fun`, partial-chain trust, CRL, and OCSP policies. Keep unsupported policies explicit; do not add a callback that accidentally converts all certificate failures into success.

Any required advanced policy becomes a separate reviewed task with documented trust semantics, negative tests, and availability/resource limits. It blocks compatibility for consumers relying on that policy, not the already-supported restricted backend.

**Exit gate:** no required option is silently ignored; each implemented option has validation, negative coverage, and an adapter-level test. The matrix records intentional differences from OTP instead of claiming arbitrary pass-through compatibility.

## 8. Phase 4 — Add a secure TLS 1.2 client subset

**Repository:** `ex_ssl`, followed by dual-version `http_fetch` validation.\
**Deliverable:** independent TLS 1.2 protocol support, not an OTP wrapper.

### P4.1 — Establish a version-specific protocol boundary

Write an architecture decision before code. Keep the current connection supervisor, socket owner, writer, deadlines, and delivery contract. Introduce separate pure TLS 1.2 handshake/key-schedule/record logic where TLS 1.3 rules differ; do not spread version conditionals through every connection callback.

Implement authenticated ECDHE client handshakes, signed server key exchange, client key exchange, optional client authentication, ChangeCipherSpec transitions, Finished validation, and AEAD records. Validate transcript inputs, record sequence numbers, nonce construction, and encryption-epoch changes independently. [R9]

### P4.2 — Use a bounded modern policy

Initial TLS 1.2 cipher coverage is ECDHE-RSA and ECDHE-ECDSA with AES-128/256-GCM. Keep static RSA key exchange, CBC, RC4, anonymous suites, compression, TLS 1.0, and TLS 1.1 excluded. Require Extended Master Secret for this subset and test explicit failure when it cannot be negotiated. Implement the applicable secure-renegotiation indication while leaving renegotiation itself disabled. These are deliberate compatibility boundaries, not universal TLS 1.2 support. [R10–R11]

Implement mixed-version ClientHello and downgrade protection according to the negotiated protocol rules. Negotiating TLS 1.2 within the caller's advertised versions is allowed; reconnecting with a weaker version after a failed handshake is not.

### P4.3 — Integrate and prove both versions

Accept TLS 1.3-only, TLS 1.2-only, and mixed-version lists only after their end-to-end paths exist. Keep ex_ssl's existing default TLS-1.3-only behaviour in this feature series; a default-policy change is separate. Preserve explicit profile/version agreement.

Test OTP and OpenSSL peers, bad server signatures, invalid Finished, AEAD corruption, early/duplicate ChangeCipherSpec, wrong certificate identity, truncation, downgrade attacks, and mTLS on both versions. Run HTTP/1.1, HTTP/2 with ALPN, WSS, EventSource, large bodies, backpressure, ownership, and cancellation over TLS 1.2. Check HTTP/2's TLS requirements explicitly. [R12]

**Exit gate:** a TLS-1.2-only endpoint using the documented safe subset succeeds without invoking OTP TLS; a TLS-1.3-capable endpoint still selects TLS 1.3 with mixed versions. No regression in existing TLS 1.3/profile/lifecycle tests.

## 9. Phase 5 — Add resumption and bounded diagnostics

**Repository:** primarily `ex_ssl`.\
**Deliverable:** optional TLS 1.3 resumption plus operational evidence; not 0-RTT.

Implement authenticated ticket processing, PSK derivation/binders, compatible resumption negotiation, and full-handshake continuation when a server declines resumption. This normal protocol path must not become a generic reconnect/replay mechanism. Preserve profile ordering and validate dynamic resumption extensions. [R8]

Use a bounded in-memory ticket cache with expiration and concurrency control. Partition entries by endpoint/reference identity, ALPN context, client identity, and trust/security-policy generation. Prevent reuse across incompatible callers, changed trust, or changed credentials. Until identity binding is proven, disable resumption for mTLS rather than sharing anonymous-session cache entries. Do not persist secrets in this milestone.

Add only needed public diagnostics, starting with a documented non-secret subset of `connection_information/1,2`, `peercert/1`, `peername/1`, and `sockname/1`. Do not expose traffic secrets or pretend to implement every OTP information key. [R7]

Test cache isolation, expiry, malformed/rejected tickets, resumed HTTP exchanges, server restarts, bounded memory, and cleanup. Benchmark full versus resumed handshakes and large transfers against OTP under identical conditions; record measurements rather than making unmeasured performance claims.

**Exit gate:** repeated connections prove actual resumption with independent peer evidence; cache boundaries cannot bypass authentication policy. Unsupported combinations remain explicit.

## 10. Phase 6 — Packaging, release evidence, and promotion decision

Maintain `docs/COMPATIBILITY.md`, `docs/HTTP_FETCH_INTEGRATION.md`, and README examples with each delivered phase, not only at the end. Update the existing implementation plan to point to this work without replacing unrelated roadmap history.

For each candidate release, run formatting, warnings-as-errors compilation in dev/test, unit/property/differential tests, static analysis, and configured interoperability/E2E workflows on the repository's supported OTP/Elixir matrix. Run child-app tests from the umbrella root using the repository's actual scoped commands; do not recreate the earlier transitive-dependency code-path problem. [R2]

Build all five `http_fetch` packages and run the isolated external-consumer smoke test against fresh package artifacts. Verify that `http_core` carries the required ex_ssl dependency transitively, the consumer does not depend on an umbrella lockfile or a direct ex_ssl declaration, and temporary path/Git overrides are absent from release metadata.

Exercise reconnect storms, sender/owner death, cancellation, slow readers/writers, and handshake failures. Compare process, port, timer, monitor, and retained-binary usage against baseline after repeated runs. Fuzz fragmented/malformed protocol input with bounded reproducible cases.

Prepare a readiness report stating the exact supported endpoint/option subset, executed commands and results, known gaps, measured performance, and remaining security-review concerns. Independent security review is a separate human gate; green CI does not constitute certification.

**Exit gate:** a reviewer can reproduce the evidence. This phase produces a recommendation, not an automatic default switch or package release.

## 11. Work sequencing and definition of done

Use this dependency order: **P0 → P1 → P2 → P3 → P4**. Phase 5 can follow the stable TLS 1.3 work independently of TLS 1.2. Apply the Phase 6 checks to every releasable milestone.

Keep protocol-family changes, options, and consumer integration in separate reviewable commits/PRs. Update a progress ledger after each work item with its task ID, repository/SHA, implementation status, tests executed, and remaining limitation. Proposed ledger states are `not_started`, `in_progress`, `implemented_unverified`, `verified`, and `blocked`.

A completed item includes implementation, failure-path tests, real interoperability where applicable, cleanup assertions, documentation, and exact validation output. A skipped or unavailable test is not a pass. Do not claim whole-library replacement after only a successful handshake or ALPN assertion.

When blocked by an environment dependency, preserve completed work, record the exact failed command and limitation, and continue independent tasks where safe. Never weaken tests, bypass verification, modify installed dependency sources, or widen error suppression merely to make a gate pass.

## 12. Codex execution instruction

Read this plan and both repositories' instructions. Reconcile the current heads first. Execute the phases in dependency order, reusing already-correct work and recording evidence for every completed gate. Start with Phase 0, particularly the current PR #14 regression coverage; do not assume the old `010b0b8` bug still exists.

Then implement the missing capabilities in small, testable changes. Preserve OTP as the default, explicit ex_ssl selection, peer verification, backend pinning, and the QUIC boundary. Do not merge, publish, remove the OTP backend, or switch defaults. At the end of each execution report changed files/commits, tests actually run, milestone status, known incompatibilities, and the next uncompleted work item.

## References and evidence

Repository observations are tied to the inspected revisions; refresh them before execution. Protocol/API documents define behaviour, not evidence that this implementation already complies.

**[R1]** ex_ssl baseline: `https://github.com/gsmlg-dev/ex_ssl/commit/0f16c2cad34236d644b301179725c6614302fbef`

**[R2]** http_fetch PR #14 status and validation report: `https://github.com/gsmlg-dev/http_fetch/pull/14`

**[R3]** Revised HTTP owner/send handling: `https://github.com/gsmlg-dev/http_fetch/blob/a1312cc40c8d6aad2cb60e750bfba84f9b3ac1cf/apps/http_fetch/lib/http/socket_client.ex`

**[R4]** ex_ssl implementation constraints: `https://github.com/gsmlg-dev/ex_ssl/blob/0f16c2cad34236d644b301179725c6614302fbef/AGENTS.md`

**[R5]** Implemented compatibility subset: `https://github.com/gsmlg-dev/ex_ssl/blob/0f16c2cad34236d644b301179725c6614302fbef/docs/COMPATIBILITY.md`

**[R6]** Existing algorithm validation: `https://github.com/gsmlg-dev/ex_ssl/blob/0f16c2cad34236d644b301179725c6614302fbef/lib/ssl/crypto/signature.ex` and `https://github.com/gsmlg-dev/ex_ssl/blob/0f16c2cad34236d644b301179725c6614302fbef/lib/ssl/options.ex`

**[R7]** Erlang/OTP public SSL API: `https://www.erlang.org/doc/apps/ssl/ssl.html`

**[R8]** TLS 1.3: RFC 9846, `https://www.rfc-editor.org/info/rfc9846/`

**[R9]** TLS 1.2 base protocol: RFC 5246, `https://www.rfc-editor.org/rfc/rfc5246.html`; consult its applicable updating RFCs for the selected features.

**[R10]** Secure TLS deployment policy: RFC 9325, `https://www.rfc-editor.org/rfc/rfc9325.html`

**[R11]** Extended Master Secret: RFC 7627, `https://www.rfc-editor.org/rfc/rfc7627.html`

**[R12]** HTTP/2 requirements: RFC 9113, `https://www.rfc-editor.org/rfc/rfc9113.html`
