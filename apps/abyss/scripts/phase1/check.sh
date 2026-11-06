#!/usr/bin/env bash
set -euo pipefail
abyss_root=$(cd "$(dirname "$0")/../.." && pwd)
export ABYSS_PATH="$abyss_root"
cd "$abyss_root/examples/quic_echo"
mix deps.get
mix run --no-start "$abyss_root/scripts/phase1/published_provenance.exs"
export QUIC_CERT="$abyss_root/test/fixtures/quic/server_flight/leaf.pem"
export QUIC_KEY="$abyss_root/test/fixtures/quic/server_flight/leaf-key.pem"
for check in config network faults controls lifecycle; do
  mix run "$abyss_root/scripts/phase1/$check.exs"
done
