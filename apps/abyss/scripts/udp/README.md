# Isolated UDP wire acceptance

Run from the repository root after `mix deps.get && mix compile`:

```sh
python3 scripts/udp/network_fixture.py
ABYSS_UDP_BACKEND=socket python3 scripts/udp/network_fixture.py
```

The harness requires Linux, `ip`, `setpriv`, Python 3, the locked Mix dependencies,
and passwordless `sudo` for creating/deleting network namespaces and their
interfaces. Exit 77 means fixture setup was blocked and is **not acceptance**;
the CI job treats it as a failing gate. Missing packets and socket errors fail
with exit 1. A final `{"result": "PASS", ...}` with exit 0 accepts the native `inet` full
IPv4/IPv6 matrix. The socket run accepts its IPv4 gates with
`{"result": "PASS_SUPPORTED_SUBSET", ...}` and explicitly lists scoped IPv6 wire
send as unsupported. It also asserts the returned capability error; no IPv6
wire timeout is converted to success. CI runs both backends.

All resources use a unique `abyss-udp-<id>` namespace prefix. Three endpoint
namespaces (Abyss plus two Python standard-library peers) attach to two bridges
inside a fourth, fixture-owned namespace. The networks use 192.0.2.0/24,
198.51.100.0/24, and two private IPv6 prefixes; no interface, route, firewall,
or packet is added to the ambient developer network. All traffic uses high
unprivileged ports, 239.192.74.1/2 and ff02::114/115, low send rates, and unique
epoch payloads. Fixture setup/teardown uses privilege; BEAM and peer workers drop
to the invoking uid/gid before execution. A `finally` block stops workers and
removes every created namespace on normal failure or completion. On an external
SIGKILL, delete only the reported fixture prefix manually.

The service is a real supervised Abyss endpoint with a one-shot handler. Control
acknowledgments prove socket/group readiness before sending. Tests exercise:

- Incoming and outgoing limited/directed IPv4 broadcast; two independent
  receivers and unicast replies from the original listener port.
- IPv4 and scoped IPv6 multicast in both directions; two groups, two
  subscribers, leave/rejoin and duplicate join idempotency.
- The same group on two distinct incoming interfaces; explicit egress selection
  and no delivery on the other isolated network.
- TTL/hop limits measured on received IP ancillary data, and loopback enabled
  versus disabled with a subscriber in the sending namespace plus remote peers.
- Empty payloads and distinct datagram boundaries.

The Python sockets turn Linux `IP_MULTICAST_ALL` / `IPV6_MULTICAST_ALL` off so
independent same-port subscriptions remain group-specific; each peer also binds
explicitly to the selected device for two-interface isolation. The Abyss
endpoint uses one socket for its desired groups. This harness does not claim
cross-platform reuse semantics, router multicast forwarding, source-specific
multicast, reliable UDP under overload, or strict destination metadata on
backends that do not report it. Unit/host tests cover invalid configuration,
startup rollback, truncation/size limits, ancillary tuple normalization, and
resource/lifecycle behavior separately.

## Datagram runtime and optional package gates

Use `ABYSS_UDP_BACKEND=inet|socket|native` independently of
`ABYSS_UDP_API=datagram ABYSS_UDP_EXECUTION=per_datagram|endpoint|keyed`.
The native adapter always selects the new API. The fixture runs inside isolated
namespaces and independently measures destination/interface and strict replies;
it never changes the ambient LAN. Native is Linux-only, tested on OTP 27/28.

Run these commands from `apps/abyss` in the monorepo.

```sh
ABYSS_UDP_BACKEND=native python3 scripts/udp/network_fixture.py
ABYSS_UDP_API=datagram ABYSS_UDP_EXECUTION=keyed python3 scripts/udp/network_fixture.py
bash scripts/udp/backend_boot.sh
mix run example/datagram_echo.exs
mix run scripts/udp/runtime_smoke.exs
mix run scripts/udp/runtime_stress.exs
ABYSS_STEADY_MODE=endpoint mix run scripts/udp/steady.exs
python3 scripts/udp/compare_steady.py /path/to/baseline-checkout
python3 scripts/udp/p5_consumers.py
```

`steady.exs` uses the same sequential64-byte workload on baseline/final code;
measurements are samples, not a whole-VM bound. The package consumer gate builds
fresh Hex contents outside the checkout, hides Rust/Cargo for core and explicitly
adds `abyss_raw` at the common version for native tests. It also checks the
released Abyss 0.8.1 facade and a packaged Mix release. `--no-wire` runs the
unprivileged checks while reporting isolated DHCP/ARP as NOT RUN. DHCP capabilities remain
inside the owned namespace. It performs no publication. Coordinated publication is described in
[the release guide](../../docs/releases.md).

`compare_steady.py` writes fresh paired logs and its JSON summary to
`_build/udp-evidence/`. Recorded release evidence is retained separately in
[the historical archive](https://github.com/gsmlg-dev/abyss/tree/89f6879edd163ff023d8bcb44b9686175dca0109/docs/archive). See the
[documentation guide](../../docs/README.md) for current APIs and architecture.
