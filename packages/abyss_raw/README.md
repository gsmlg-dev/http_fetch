# Abyss Raw 0.10.0

This independent OTP package owns the Rustler build and native artifact for interface-bound DHCP client UDP and raw ARP. It does not depend on Abyss or start a socket/poll thread at application startup. `AbyssDhcpSocket.Native` implements the five native operations; existing callers use the pure Elixir `Abyss.DhcpSocket.Native` facade supplied by Abyss.

DHCP users must explicitly install the optional Hex package when upgrading Abyss:

```elixir
defp deps do
  [
    {:abyss, "~> 0.10.0"},
    {:abyss_raw, "~> 0.10.0"}
  ]
end
```

The package is also usable independently with only `{:abyss_raw, "~> 0.10.0"}` and direct calls to `AbyssDhcpSocket.Native`. It has no dependency on Abyss. The implementation module `AbyssDhcpSocket.Native`, Rust crate `dhcp_socket`, and NIF registration retain their existing names for compatibility, including with the facade in Abyss 0.8.1. No `abyss_dhcp_socket` Hex dependency is needed.

Build from source with Elixir/Mix, Cargo/Rust, and a native linker. There are no precompiled NIF downloads; installing the package requires the native toolchain. The crate and Cargo.lock are preserved from Abyss. Its shared library belongs to `:abyss_raw` under `priv/native/dhcp_socket`, never the core application. The package does not ship `Abyss.DhcpSocket.Native` or require a dependency cycle.

The five operations are `open/2`, `send_broadcast/2`, `send_unicast/3`, `send_arp_probe/2`, and `close/1`. `open(interface, owner)` returns an opaque resource directly or `{:error, reason}`. Sends return `:ok` or `{:error, reason}`; `close/1` is idempotent. DHCP binds UDP port 68 and sends to port 67. Linux raw ARP needs `CAP_NET_RAW`; binding low ports may need `CAP_NET_BIND_SERVICE`. The implementation targets Unix systems; Windows is unsupported. macOS/FreeBSD raw ARP remains unavailable, as before.

Owner messages remain `{:dhcp_rx, binary}`, `{:arp_rx, binary}`, `{:dhcp_socket_down, reason}`, and `{:arp_socket_down, reason}`. Explicit close sends no down message. Owner death is observed when packet delivery fails; resource cleanup or explicit `close/1` closes the descriptors. Do not infer immediate native reclamation from process death.

The Abyss 0.9.0 facade reports `{:error, {:missing_optional_dependency, :abyss_raw}}` when this package is absent, and `{:error, {:optional_dependency_load_failed, :abyss_raw, reason}}` when its module cannot load. Native operation errors pass through unchanged.

Run independent validation:

```sh
cd packages/abyss_raw
mix deps.get
mix test
bash scripts/test_arp.sh
cargo clippy --manifest-path native/dhcp_socket/Cargo.toml --locked --all-targets -- -D warnings
```

The ARP script runs the five existing source unit tests in a disposable Rust-only harness without linking BEAM NIF symbols. Native DHCP/ARP wire validation uses `apps/abyss/scripts/udp/dhcp_fixture.py` through `python3 scripts/udp/p5_consumers.py` from `apps/abyss`. It shares the existing UDP namespace topology, confines capabilities and packets to those namespaces, and never changes the ambient LAN. This validation is opt-in and requires namespace setup permission. No publication is performed.
