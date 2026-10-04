# Test TLS credentials

These public, disposable test credentials are copied byte-for-byte from
`gsmlg-dev/ex_ssl` commit `f1327e0bb7fb2093b8dc2b07e72b26233a739963`,
`test/fixtures/server_flight`. They keep ex_quic's tests and development
interop scripts independent of dependency-internal test files, which Hex does
not package.

They are test-only credentials. `leaf-key.pem` is a disposable private key and
must never be used outside local tests or interop fixtures.

SHA-256:

- `leaf-key.pem`: `0d06b9f348dd4a9744085e730e907f4bd459a88cccf726fb42fba9c897ab56e1`
- `leaf.pem`: `af218bb28763f8301e21c8ce0c1c878472aefbba8f1370f2d6f0d9013b603d76`
- `root.pem`: `e7fd4d3785727195ba69f287094c756cb523348884720a04ee2562a44b35e109`

The copied files originate in ex_ssl, licensed under Apache-2.0. Its license
is available at https://github.com/gsmlg-dev/ex_ssl/blob/v0.7.2/LICENSE.
