# Independent TLS-only QUIC boundary comparison

This harness drives `SSL.QUIC` against **aioquic 1.2.0**'s independent
`aioquic.tls.Context`, using stdin/stdout only. No TLS records, UDP, QUIC packet
protection, CRYPTO offsets or HTTP/3 implementation is involved. aioquic is a
**test-only**, BSD-3-Clause reference:
https://github.com/aiortc/aioquic/tree/1.2.0
https://github.com/aiortc/aioquic/blob/1.2.0/LICENSE

The Python dependency set is pinned in `requirements.txt`. Existing repository
certificates under `test/fixtures/server_flight` supply the trust root,
`example.test` identity, ECDSA P256 and RSA private keys. These are public test
credentials, never production keys. Both implementations verify the server;
ex_ssl's reference identity is independent of optional SNI.

```sh
python3 -m venv /tmp/ex_ssl-quic-reference-venv
/tmp/ex_ssl-quic-reference-venv/bin/pip install -r e2e/quic_tls/requirements.txt
QUIC_TLS_PYTHON=/tmp/ex_ssl-quic-reference-venv/bin/python mix run e2e/quic_tls/run.exs
```

The 13 scenarios cover ex_ssl as client and server, each of 0x1301/0x1302/0x1303,
and ECDSA/RSA server signing. Another scenario asks ex_ssl's client for an identity
during the handshake. aioquic validates its CertificateVerify/Finished; this does
not add server mTLS support or assert a client PKIX policy in ex_ssl. All cases
require both engines to reach completion, equal ALPN, matching transport parameter
payloads, and equal digests of each endpoint's complementary read/write handshake
and application traffic secrets. No secrets are written to diagnostic logs.
The comparison uses the actual independent TLS messages and key callbacks.

`peer.py` uses aioquic's version-pinned TLS internals, including its documented
in-source test-only `_request_client_certificate` switch. It asserts the runtime
version. The harness fails on exceptions, mismatched secrets, missing completion,
wrong negotiation, timeout or stalled progress. It does not silently skip.
Run it explicitly; offline `mix test` never installs or starts Python.
The `QUIC TLS reference` GitHub Actions workflow runs the same command separately.

Local result (OTP 29.0.2, Elixir 1.20.1): **13/13 passed**. This establishes
independent QUIC-TLS boundary interoperability, **not full QUIC network interop**.

HRR coverage limitation (aioquic 1.2.0): its `tls.Context` has no HRR state or
transcript-rewrite path. `_client_handle_hello` always decodes a ServerHello key
share as a full peer public key; `_server_handle_hello` selects an existing share
and asserts that a shared key was found. It cannot supply the forced-HRR
comparison required here. The 13 existing scenarios remain intact; HRR,
empty-share negotiation and cookie-budget boundaries are tested by exact protocol
unit tests, not claimed as independent HRR interoperability.
