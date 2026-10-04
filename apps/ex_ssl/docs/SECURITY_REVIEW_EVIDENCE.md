# Independent security review evidence map

**HUMAN-SECURITY-REVIEW: incomplete.** This is an index for a human reviewer,
not an approval, certification, formal verification, or production-readiness claim.
The candidate starts at `c93000d01c5321a6606092fb0113d8a56b9975b8` (ex_ssl 0.4.0).
Current executed evidence is recorded at the beginning of
[the progress ledger](EX_SSL_HTTP_FETCH_PROGRESS.md); older release entries are
historical. All paths below are relative to this repository.

## Review checklist

Each unchecked item requires independent human review. Automated coverage is
supporting evidence and cannot check these boxes.

| Review obligation | Implementation | Executable evidence | Limits to assess |
| --- | --- | --- | --- |
| [ ] TLS 1.3 state transitions, HRR and epoch changes | `lib/ssl/protocol/handshake_machine.ex`, `server_flight.ex`, `server_hello.ex`, `lib/ssl/connection.ex` | `test/ssl/protocol/handshake_machine_test.exs`, `server_flight_test.exs`, `resumption_hrr_test.exs`; `test/ssl/connection_interop_test.exs`, `input_ordering_regression_test.exs` | Client subset only; no post-handshake client authentication or server implementation. |
| [ ] TLS 1.2 EMS, version selection, downgrade protection, CCS and record sequencing | `lib/ssl/protocol/tls12.ex`, `tls12_codec.ex`, `tls12_record.ex`; `lib/ssl/crypto/tls12_key_schedule.ex` | `test/ssl/protocol/tls12_negative_test.exs`, `tls12_dispatch_test.exs`, `tls12_record_test.exs`; `test/ssl/tls12_interop_test.exs`, `tls12_machine_test.exs` | Four ECDHE AES-GCM suites only. Positive peer must support EMS; an observed OTP fixture's omission says nothing about all OTP server configurations. |
| [ ] Exact transcripts, CertificateVerify and Finished | `lib/ssl/protocol/transcript.ex`, `server_flight_verifier.ex`, `client_authentication.ex`; `lib/ssl/crypto/finished.ex`, `signature.ex` | `test/ssl/protocol/transcript_test.exs`, `server_flight_verifier_test.exs`, `resumption_verifier_test.exs`; `test/ssl/crypto/finished_test.exs`, `signature_expansion_test.exs`, `tls12_signature_test.exs` | Includes independent expected values and authentication negatives; bounded generated cases are not exhaustive. |
| [ ] PKIX reference identity, trust, validity, chain bounds and client identity selection | `lib/ssl/pkix/`, `lib/ssl/client_identity.ex`, `lib/ssl/options.ex` | `test/ssl/pkix/pkix_test.exs`, `depth_interop_test.exs`, `client_identity_test.exs`, `client_auth_interop_test.exs`, `client_auth_lifecycle_test.exs`, `certificate_policy_options_test.exs` | OTP public_key supplies path validation. Advanced trust callbacks, CRL/OCSP and recognized OID-filter value matching remain unsupported. TLS 1.2 client certificates precede encryption. |
| [ ] PSK binders, fresh ECDHE, authenticated fallback and cache partitioning | `lib/ssl/protocol/resumption.ex`, `lib/ssl/resumption_context.ex`, `lib/ssl/session_ticket.ex`, `lib/ssl/ticket_cache.ex` | `test/ssl/resumption_test.exs`, `resumption_context_test.exs`, `resumption_interop_test.exs`, `ticket_cache_test.exs`; `test/ssl/protocol/resumption_hrr_test.exs`, `resumption_verifier_test.exs` | Peer-reported reuse plus public diagnostics distinguish resumed from full. Saved chains are revalidated at checkout. No early data, TLS 1.2/mTLS resumption, persistence, reconnect or request replay. |
| [ ] Secret retention, redaction and restart boundaries | `lib/ssl/connection.ex`, `connection_writer.ex`, `client_identity.ex`, `session_ticket.ex`, `ticket_cache.ex`, `diagnostics.ex` | `test/ssl/connection_lifecycle_test.exs`, `client_identity_test.exs`, `ticket_cache_test.exs`, `resumption_cache_lifecycle_test.exs`, `resumption_resource_test.exs`, `diagnostics_test.exs` | Public diagnostics expose authenticated metadata only. BEAM garbage collection is not guaranteed memory zeroization; sensitive processes and bounded retention are not a proof against privileged process inspection. |
| [ ] Parser/framer bounds and exact unconsumed input | `lib/ssl/protocol/record_framer.ex`, `handshake_framer.ex`, `inner_plaintext.ex`, `tls12_codec.ex`; `lib/ssl/client_hello/` | `test/ssl/protocol/record_framer_test.exs`, `handshake_framer_test.exs`, `fragmented_fuzz_test.exs`, `tls12_codec_test.exs`; `test/ssl/client_hello/` | Fragmentation and 200-run mutation properties sample bounded input spaces. No exhaustive parser proof is claimed. |
| [ ] Ownership, cancellation, original deadlines and concurrent I/O | `lib/ssl.ex`, `lib/ssl/connection.ex`, `connection_writer.ex`, `iodata_cursor.ex`, `socket.ex` | `test/ssl/http_fetch_transport_contract_test.exs`, `connection_lifecycle_test.exs`, `connection_output_test.exs`, `connection_backpressure_test.exs`, `input_ordering_regression_test.exs`, `resumption_closure_test.exs`, `resumption_blocked_write_test.exs`, `resumption_resource_test.exs`, `client_auth_lifecycle_test.exs` | Assert owned process/port termination and pending-work removal. Retained plaintext drains after authenticated close_notify; abrupt TCP loss remains a fail-closed reset. Bounded campaigns do not establish indefinite stability. |

## Resumption requirement inventory

This inventory identifies baseline coverage reused and the precise additions;
it does not treat a successful second request as proof of resumption.

| Requirement | Executable evidence |
| --- | --- |
| Independent full/resumed distinction; server ticket rejection followed by full authentication on the same socket | Existing `resumption_interop_test.exs`: peer `session_reused` and public `session_resumption`, context restart, invalid binder, HRR and disabled-ticket cases. |
| Reference hostname, trust and ALPN isolation | Existing `resumption_interop_test.exs` negatives and ALPN change; `resumption_context_test.exs` partition/content replacement tests. |
| Port, profile and algorithm-policy isolation | Extended `resumption_interop_test.exs`: same OpenSSL context reached through a second port must perform a full handshake; group, ordered profile suites and signature-policy changes perform full authentication, then the original context still resumes. |
| Certificate validity revalidation and unsupported combinations | Existing `resumption_context_test.exs`: expired/untrusted/malformed cached chains cannot supply PSK; mixed versions, mTLS, manual tickets and early data reject before I/O. |
| Fragmented, delayed and interleaved tickets | Existing `protocol/handshake_machine_test.exs` splits an enabled NST across encrypted records and bounds eight processed tickets. Added explicit application-data-before-ticket and data-between-complete-tickets event ordering; incomplete-message interleaving still rejects with tickets enabled. Added real OpenSSL ticket TCP-fragmentation/cache receipt. Pure event feeds control delayed arrival without a timing knob. |
| Expiry, retained bytes, atomic consumption | Existing `ticket_cache_test.exs` and `resumption_test.exs`: clock seam, timer cleanup, binary ownership, count/byte eviction and one-use contention. |
| Cache and application restart | New `resumption_cache_lifecycle_test.exs`: monitored supervisor restart and application stop/start both discard entries. |
| Full/resumed send, recv, ownership and active-once | Extended `resumption_interop_test.exs` transfers ownership; new `resumption_closure_test.exs` checks both modes, ordered data/terminal delivery and cancellation of a resumed passive receiver. |
| Graceful versus abnormal termination | New `resumption_closure_test.exs` drains retained plaintext for close_notify and uses a peer barrier to deliver data before intentional TCP truncation, which must remain `:econnreset`. It does not require continued buffering after abnormal failure. |
| Resumed blocked writes, cancellation and deadline | New `resumption_blocked_write_test.exs`: same endpoint warmup/rebind, independent resumption confirmation, proxy pause/held barriers and nonzero raw `send_pend`; close interrupts an infinite-timeout send, and an admitted finite deadline stays unchanged after future sends are configured with infinity. Connection/writer death and raw-port removal are asserted. |
| Repeated/concurrent cleanup and owner death | Existing `resumption_resource_test.exs` runs 17 sequential attempts plus a warmup and three batches of eight connections. Added explicit peer-confirmed resumption for owner death and a termination monitor after failed authentication. Existing transport/client-auth tests retain handshake-failure/cancellation coverage. |

## Peer and runtime evidence

Required pull-request/main validation covers Elixir/OTP 1.18/28, 1.19/28 and
1.20/29 with explicit `--include integration`. Tests use OTP reference peers,
OpenSSL CLI peers, and Python's independently version-reported OpenSSL binding.
TLS 1.2 positive cases pin RSA/ECDSA AES-128/256-GCM and retain EMS. TLS 1.3
resumption uses independent peer observations rather than timing or request success.
The Caddy E2E gate verifies an authenticated request's exact JA3/JA4.

The runtime preflight must succeed before a mandatory peer suite runs. Missing
executables/capabilities and zero executed tests are failures, not exclusions that
can count as evidence. CI summaries contain version/count/status metadata only;
do not upload generated credentials, cache data, private fixtures or raw failure
logs with inspectable authentication material.

## Reproducible source-candidate and package boundary

From the ex_ssl root:

```sh
timeout 900 bash scripts/downstream_candidate.sh
```

The script fetches and verifies immutable http_fetch
`6a6c93e5c852e2e2bbffcc2186bef9bf34a79cac`, then invokes its existing
`scripts/ex_ssl_source_smoke.sh` from the temporary umbrella root with
`EX_SSL_DEP_MODE=source` and `EX_SSL_SOURCE_DIR` pointing at this checkout.
It reports both SHAs, candidate dirt, loaded module path/source and version.
An additional test asserts the actual source dependency. The fixed consumer
script uses seed 36. All fetched files, overrides and builds are temporary;
the companion checkout and installed dependencies are untouched.

The same command builds the candidate Hex package without publishing, compiles
an isolated production consumer and starts it in a fresh Elixir VM. It checks
that OTP `:ssl` is neither an ex_ssl application dependency nor a started
application. Mix/Hex's own TLS use is outside that fresh-VM boundary.

This is **source-candidate integration**, separate from running against a
published Hex package. It does not demonstrate that an unpublished change exists
on Hex. Pin changes must be reviewed in the script diff; no floating branch is run.

## External gates

- [ ] Independent human review of every area above, with recorded findings and disposition.
- [ ] Remote execution of the candidate workflows after a separately authorized push.
- [ ] Other OS and crypto-provider combinations beyond the recorded Linux environment.
- [ ] Long-duration operational validation; bounded resource campaigns are insufficient.
- [ ] Any release, dependency promotion or default-backend change: separate decision.

Mandatory verification, TLS 1.3 defaults, opt-in resumption, and the public `SSL`
facade remain the baseline. OTP `:ssl` stays the recommended consumer default.
