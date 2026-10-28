# No-OTP release peer credentials

The no-OTP candidate and published-consumer workflows use this disposable
ECDSA P-256 localhost chain for both TLS 1.2 and TLS 1.3 TCP peers and the existing
QUIC/H3 profile. Its ECDSA/SHA256 certificate signature is covered by the H3
profile without changing the production signature-policy boundary.

Generated locally with OpenSSL on 2026-10-28; the leaf has DNS `localhost` and
IP `127.0.0.1` subject alternatives and serverAuth usage. These credentials are
only for independent loopback test peers. The test private key must never be
used by a deployed service. The CA private key is not retained in the repository.

SHA-256:

- `no-otp-localhost-ecdsa-ca.pem`: `e6b8d16df0b0e0ea7ac4835c79065d15529ac149fafdd0db066e36016b3e765b`
- `no-otp-localhost-ecdsa.pem`: `8afe7d5e68b086eb804e41b5b00105e2cb824f9f7740a03409c2a526c09e99b1`
- `no-otp-localhost-ecdsa.key`: `201bcb9b4ff646e6b18a95831d6a93ce8699f673c1e181eef4bed022cafa5b41`
