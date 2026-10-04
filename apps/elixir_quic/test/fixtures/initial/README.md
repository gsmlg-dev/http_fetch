# External QUIC Initial fixture

`aioquic_1_2_0_initial.hex` is one client Initial datagram emitted by the independently implemented aioquic 1.2.0 `QuicConnection` after `connect((127.0.0.1, 4433), now=0)`, with ALPN `h3`. It was captured before any peer response; the destination is a local test address and no secrets are stored. From the repository root, regenerate with the pinned environment in `apps/ex_ssl/e2e/quic_tls/requirements.txt` if needed.

SHA-256 (hex file): `9f63199c29acc837c8942e596afa00bcbc45e57ee2385a9cfcafe898d2d6085b`.
