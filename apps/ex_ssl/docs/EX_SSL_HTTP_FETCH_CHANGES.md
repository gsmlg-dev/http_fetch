# Implementation change manifest

All paths are repository-relative in the isolated `codex/tls-backend-plan` worktrees.
This records implementation commits before the final evidence-only documentation commit.
The baseline commits were reconciled at the beginning, not reset during the work.


## ex_ssl

Baseline: `0f16c2cad34236d644b301179725c6614302fbef`. Implementation head: `18b4f859d46b077e3debb6da89d2ce1ef8c93680`.


```text
2942433 docs: reconcile TCP TLS implementation plan and Phase 0 evidence
0175097 refactor(tls): centralize implemented runtime capabilities
5463ad9 feat(tls): add P384 Ed25519 and restricted RSA-PSS interoperability
a9c5713 feat(tls): load bounded client identities with restricted key matching
fc1319d feat(tls): implement bounded initial client authentication
0712470 docs(tls): record verified packaged mTLS consumer gate
66c650c test(tls): bound advanced certificate policy compatibility
509f002 feat(tls): add explicit algorithm policies and safe TCP options
fea46a7 docs: record verified Phase 3 consumer option gate
031dcea docs(tls): establish bounded TLS 1.2 protocol boundary
844d4a6 feat(tls): implement bounded independent TLS 1.2 client
a156a7c docs(tls): define opt-in resumption authentication and cache boundaries
2330ab6 feat: add bounded in-memory TLS 1.3 ticket primitives
c2d1d0c feat(tls): authenticate opt-in TLS 1.3 resumption and bounded diagnostics
18b4f85 test(tls): add bounded fuzz, reconnect cleanup and resumption measurements
```


Changed files (95):

```text
.github/workflows/interop.yml
README.md
docs/ADR_TLS12_CLIENT.md
docs/ADR_TLS13_RESUMPTION.md
docs/ARCHITECTURE.md
docs/COMPATIBILITY.md
docs/DESIGN.md
docs/EX_SSL_HTTP_FETCH_CHANGES.md
docs/EX_SSL_HTTP_FETCH_PROGRESS.md
docs/EX_SSL_HTTP_FETCH_READINESS.md
docs/HTTP_FETCH_INTEGRATION.md
docs/IMPLEMENTATION_PLAN.md
docs/RESUMPTION_BENCHMARK.md
docs/ex_ssl-http_fetch-implementation-plan.md
lib/ssl.ex
lib/ssl/capabilities.ex
lib/ssl/client_hello/extension.ex
lib/ssl/client_hello/identifiers.ex
lib/ssl/client_hello/materializer.ex
lib/ssl/client_hello/profile.ex
lib/ssl/client_hello/wire_profile.ex
lib/ssl/client_identity.ex
lib/ssl/connection.ex
lib/ssl/crypto/aead.ex
lib/ssl/crypto/key_exchange.ex
lib/ssl/crypto/key_schedule.ex
lib/ssl/crypto/signature.ex
lib/ssl/crypto/tls12_key_schedule.ex
lib/ssl/diagnostics.ex
lib/ssl/options.ex
lib/ssl/pkix/certificate_signature_policy.ex
lib/ssl/pkix/pkix.ex
lib/ssl/pkix/verified_peer.ex
lib/ssl/protocol/client_authentication.ex
lib/ssl/protocol/client_offer.ex
lib/ssl/protocol/handshake_machine.ex
lib/ssl/protocol/resumption.ex
lib/ssl/protocol/server_flight.ex
lib/ssl/protocol/server_flight_verifier.ex
lib/ssl/protocol/server_hello.ex
lib/ssl/protocol/tls12.ex
lib/ssl/protocol/tls12_codec.ex
lib/ssl/protocol/tls12_record.ex
lib/ssl/resumption_context.ex
lib/ssl/session_ticket.ex
lib/ssl/supervisor.ex
lib/ssl/tcp_options.ex
lib/ssl/ticket_cache.ex
scripts/resumption_benchmark.exs
test/ssl/capabilities_test.exs
test/ssl/certificate_policy_options_test.exs
test/ssl/client_auth_interop_test.exs
test/ssl/client_auth_lifecycle_test.exs
test/ssl/client_hello/materializer_test.exs
test/ssl/client_hello/profile_test.exs
test/ssl/client_identity_options_test.exs
test/ssl/client_identity_test.exs
test/ssl/crypto/key_exchange_test.exs
test/ssl/crypto/key_schedule_test.exs
test/ssl/crypto/p384_key_exchange_test.exs
test/ssl/crypto/signature_expansion_test.exs
test/ssl/crypto/signature_test.exs
test/ssl/crypto/tls12_key_schedule_test.exs
test/ssl/crypto/tls12_signature_test.exs
test/ssl/diagnostics_test.exs
test/ssl/http_fetch_transport_contract_test.exs
test/ssl/options_test.exs
test/ssl/p384_interop_test.exs
test/ssl/pkix/pkix_test.exs
test/ssl/protocol/client_authentication_test.exs
test/ssl/protocol/client_offer_test.exs
test/ssl/protocol/fragmented_fuzz_test.exs
test/ssl/protocol/handshake_machine_test.exs
test/ssl/protocol/resumption_hrr_test.exs
test/ssl/protocol/resumption_verifier_test.exs
test/ssl/protocol/server_flight_test.exs
test/ssl/protocol/server_hello_test.exs
test/ssl/protocol/tls12_codec_test.exs
test/ssl/protocol/tls12_dispatch_test.exs
test/ssl/protocol/tls12_negative_test.exs
test/ssl/protocol/tls12_record_test.exs
test/ssl/resumption_context_test.exs
test/ssl/resumption_interop_test.exs
test/ssl/resumption_resource_test.exs
test/ssl/resumption_test.exs
test/ssl/tcp_options_test.exs
test/ssl/ticket_cache_test.exs
test/ssl/tls12_interop_test.exs
test/ssl/tls12_machine_test.exs
test/ssl/tls_policy_interop_test.exs
test/support/client_auth_fixtures.ex
test/support/local_tls_peer.ex
test/support/openssl_peer.ex
test/support/openssl_peer.py
test/support/signature_fixtures.ex
```


## http_fetch

Baseline: `690258ac38e50b0d1a968d9d5e510c560f45f5d4`. Implementation head: `381f198f498bb11cec4ff7879536b10211bc69e7`.


```text
b4414db fix(http2): validate bounded response completion before close drainage
93efee0 test(tls): verify expanded ex_ssl algorithms through packaged HTTP clients
cbbc2f6 feat(tls): scope client identities across HTTP redirects
f482322 feat(tls): forward validated candidate policy and TCP options
4aa8855 refactor(tls): keep option validation clear to configured Credo
381f198 test(tls): verify packaged TLS 1.2 flows and TLS 1.3 resumption
```


Changed files (18):

```text
README.md
apps/http_core/lib/http/http2.ex
apps/http_core/lib/http/transport/ex_ssl.ex
apps/http_core/test/http/http2_limits_test.exs
apps/http_core/test/http/http2_test.exs
apps/http_fetch/lib/http/socket_client.ex
apps/http_fetch/test/http/socket_client_http2_test.exs
docs/ex-ssl-consumer-contract.md
docs/pr-14-validation.md
scripts/ex_ssl_algorithms_test.exs
scripts/ex_ssl_mtls_redirects_test.exs
scripts/ex_ssl_mtls_streams_test.exs
scripts/ex_ssl_mtls_test.exs
scripts/ex_ssl_options_test.exs
scripts/ex_ssl_resumption_test.exs
scripts/ex_ssl_source_smoke.sh
scripts/ex_ssl_tls12_peer.py
scripts/ex_ssl_tls12_test.exs
```
