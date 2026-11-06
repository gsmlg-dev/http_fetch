#!/usr/bin/env bash
set -euo pipefail
package_root=$(cd "$(dirname "$0")/.." && pwd)
arp_test_dir=$(mktemp -d /tmp/abyss-dhcp-arp.XXXXXX)
trap 'rm -rf "$arp_test_dir"' EXIT
mkdir "$arp_test_dir/src"
cp "$package_root/native/dhcp_socket/src/arp.rs" "$package_root/native/dhcp_socket/src/socket.rs" "$arp_test_dir/src/"
cat > "$arp_test_dir/Cargo.toml" <<'CARGO'
[package]
name = "abyss_dhcp_arp_tests"
version = "0.0.0"
edition = "2021"
[dependencies]
libc = "0.2"
socket2 = "0.5"
CARGO
printf '#![allow(dead_code)]\nmod arp;\nmod socket;\n' > "$arp_test_dir/src/lib.rs"
cargo test --manifest-path "$arp_test_dir/Cargo.toml" --offline
