# Abyss Raw

This independent OTP package owns the Rustler build and native artifact for interface-bound DHCP client UDP and raw ARP. It does not depend on Abyss or start a socket/poll thread at application startup. `AbyssDhcpSocket.Native` implements the five native operations; existing callers use the pure Elixir `Abyss.DhcpSocket.Native` facade supplied by Abyss.

Requires Elixir 1.18 or later and Erlang/OTP 27 or later.

DHCP users must explicitly install the optional Hex package when upgrading Abyss:

```elixir
defp deps do
  [
    {:abyss, "== 1.0.0-rc.12"},
    {:abyss_raw, "== 1.0.0-rc.12"}
  ]
end
```

The package is also usable independently with only `{:abyss_raw, "== 1.0.0-rc.12"}` and direct calls to `AbyssDhcpSocket.Native`. It has no dependency on Abyss. The implementation module `AbyssDhcpSocket.Native`, Rust crate `dhcp_socket`, and NIF registration retain their existing names. No `abyss_dhcp_socket` Hex dependency is needed.

Build from source with Elixir/Mix, Cargo/Rust, and a native linker. There are no precompiled NIF downloads; installing the package requires the native toolchain. The crate and Cargo.lock are preserved from Abyss. Its shared library belongs to `:abyss_raw` under `priv/native/dhcp_socket`, never the core application. The `Abyss.DhcpSocket.Native` facade was removed from Abyss; call `AbyssDhcpSocket.Native` directly.

The five operations are `open/2`, `send_broadcast/2`, `send_unicast/3`, `send_arp_probe/2`, and `close/1`. `open(interface, owner)` returns an opaque resource directly or `{:error, reason}`. Sends return `:ok` or `{:error, reason}`; `close/1` is idempotent. DHCP binds UDP port 68 and sends to port 67. Linux raw ARP needs `CAP_NET_RAW`; binding low ports may need `CAP_NET_BIND_SERVICE`. The implementation targets Unix systems; Windows is unsupported. macOS/FreeBSD raw ARP remains unavailable, as before. FreeBSD compiles, but interface binding (`IP_BOUND_IF` is macOS-only) is unsupported there, so `open/2` returns an error. Packets up to 65535 bytes are delivered untruncated. The send functions take binaries, not iodata.

Owner messages carry the socket (the term `open/2` returned) as the second element: `{:dhcp_rx, socket, binary}`, `{:arp_rx, socket, binary}`, `{:dhcp_socket_down, socket, reason}`, and `{:arp_socket_down, socket, reason}`. Explicit close sends no down message. The poll thread holds a reference to the socket, so dropping the term does not release it: call `close/1`, or exit the owner process, in which case the thread notices within about a second (or on the next failed delivery), closes the descriptors and exits. Without the optional package installed, `AbyssDhcpSocket.Native` is simply not loaded; guard with `Code.ensure_loaded?/1`.

Run independent validation:

```sh
cd packages/abyss_raw
mix deps.get
mix test
bash scripts/test_arp.sh
cargo clippy --manifest-path native/dhcp_socket/Cargo.toml --locked --all-targets -- -D warnings
```

The ARP script runs the five existing source unit tests in a disposable Rust-only harness without linking BEAM NIF symbols. Native DHCP/ARP wire validation uses `apps/abyss/scripts/udp/dhcp_fixture.py` through `python3 scripts/udp/p5_consumers.py` from `apps/abyss`. It shares the existing UDP namespace topology, confines capabilities and packets to those namespaces, and never changes the ambient LAN. This validation is opt-in and requires namespace setup permission. No publication is performed.
