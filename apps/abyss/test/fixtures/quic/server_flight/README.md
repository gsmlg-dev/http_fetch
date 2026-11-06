# Disposable QUIC acceptance credentials

These four PEM files are copied byte-for-byte from
`gsmlg-dev/ex_ssl` Git revision `f1327e0bb7fb2093b8dc2b07e72b26233a739963`, path
`test/fixtures/server_flight/`. The Hex `ex_ssl` 0.7.2 package omits test
fixtures, so Abyss owns a copy for its independent published-package checks.
The files contain a disposable test CA, its leaf and private key, plus a
second leaf used as an intentionally wrong trust anchor. They are not
production credentials. Do not use them outside tests or examples.

SHA-256:

- `leaf.pem`: `af218bb28763f8301e21c8ce0c1c878472aefbba8f1370f2d6f0d9013b603d76`
- `leaf-key.pem`: `0d06b9f348dd4a9744085e730e907f4bd459a88cccf726fb42fba9c897ab56e1`
- `root.pem`: `e7fd4d3785727195ba69f287094c756cb523348884720a04ee2562a44b35e109`
- `leaf-rsa.pem`: `d2eaac781e5d6a7a74ccfa35120738d46c49ce4a1602806fcd763f82eaff3579`
