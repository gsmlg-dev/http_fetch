# Authenticated server-flight fixture

`capture.txt` is a fixed constructed TLS 1.3 vector, not a packet
capture from an OpenSSL TLS state machine. It was generated on 2026-09-11 by
`SSL.TestServerFlightBuilder` using OTP `:crypto`/`:public_key` backed by
OpenSSL 3.6.4. The disposable test CA and leaf were generated with the
OpenSSL CLI; the leaf key is retained only to construct equivalent test
signatures. ECDSA randomness means regeneration is not byte-for-byte identical.

The vector uses fixed RFC 7748 X25519 test scalars, TLS_AES_256_GCM_SHA384,
and ECDSA P-256/SHA-256 CertificateVerify. Its ClientHello explicitly offers
the selected cipher, group, key share, signature scheme, ALPN values, OCSP
status_request, and SCT extension. No fixture key is runtime material.

`leaf-rsa.pem` and `leaf-rsa-key.pem` provide the equivalent disposable
RSA-PSS-RSAE-SHA256 full-flight control. They use the same SHA-384 transcript
algorithm, independently demonstrating that the signature hash does not select
the transcript hash.

Evidence classification:

- crypto module tests retain independent known-answer unit vectors;
- `capture.txt` is a replay of a fixed constructed vector;
- `SSL.TestServerFlightBuilder` creates independently assembled controlled
  semantic flights with real signatures and AEAD;
- no live external interoperability test is claimed by this bounded repair.
