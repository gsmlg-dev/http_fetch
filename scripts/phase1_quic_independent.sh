#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/http-fetch-quic-peer.XXXXXX")
trap 'rm -rf "$work"' EXIT
# Test fixtures only; runtime libraries must resolve from Hex through Mix.
peer_revision=c9ad458add5a496949bd1c89b50128c8ab777da9
tls_revision=f1327e0bb7fb2093b8dc2b07e72b26233a739963
curl --fail --silent --show-error --location "https://raw.githubusercontent.com/gsmlg-dev/ex_quic/$peer_revision/scripts/phase1/peer.py" -o "$work/peer.py"
for file in root.pem leaf.pem leaf-key.pem; do
  curl --fail --silent --show-error --location "https://raw.githubusercontent.com/gsmlg-dev/ex_ssl/$tls_revision/test/fixtures/server_flight/$file" -o "$work/$file"
done
export HTTP_QUIC_TLS_FIXTURES="$work"
export HTTP_QUIC_PEER_SCRIPT="$work/peer.py"
cd "$root"
mix run scripts/phase1_quic_independent.exs
