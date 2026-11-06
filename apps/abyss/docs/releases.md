# Abyss package releases in the monorepo

`abyss` and `abyss_raw` retain version `0.10.0` and form the Abyss version group.
They are independent packages. The existing HTTP/TLS/QUIC group keeps its separate
release version; Hell also keeps its own version. The monorepo root release tooling
is authoritative. The old standalone publisher is not copied, to avoid publishing
from obsolete repository paths or using the old bare tag convention here.

Abyss has no dependency on `abyss_raw`, Rustler, or the QUIC engine. Applications
explicitly select the optional packages. The raw package lives at
`../../packages/abyss_raw` relative to this app and is independently buildable.
Its native library belongs to `:abyss_raw`, and its implementation module remains
`AbyssDhcpSocket.Native` with crate name `dhcp_socket`.

Run the existing independent source-package consumer gate from this app directory:

```sh
python3 scripts/udp/p5_consumers.py --no-wire
```

This builds both archives, hides Rust/Cargo for the plain UDP consumer, validates
the optional native package and a native Mix release. Linux namespace DHCP/ARP
traffic is opt-in and requires the privileges described in the
[fixture instructions](../scripts/udp/README.md). `--no-wire` records that gate as
NOT RUN. It does not establish privileged wire acceptance.

The original standalone release record remains in the
[source repository](https://github.com/gsmlg-dev/abyss/tree/89f6879edd163ff023d8bcb44b9686175dca0109).
Use the monorepo migration report for current candidate-package verification and
release policy. No publication occurs as part of this migration.
