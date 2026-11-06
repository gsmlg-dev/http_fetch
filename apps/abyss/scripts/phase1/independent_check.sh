#!/usr/bin/env bash
set -euo pipefail
abyss_root=$(cd "$(dirname "$0")/../.." && pwd)
export ABYSS_PATH="$abyss_root"
export ABYSS_EXAMPLES_DIR
ABYSS_EXAMPLES_DIR=$(mktemp -d /tmp/abyss-phase1-consumers.XXXXXX)
echo "Independent consumer sources/builds: $ABYSS_EXAMPLES_DIR"
for example in udp_echo quic_echo quic_collect; do
  mkdir "$ABYSS_EXAMPLES_DIR/$example"
  cp "$abyss_root/examples/$example/mix.exs" "$abyss_root/examples/$example/mix.lock" "$ABYSS_EXAMPLES_DIR/$example/"
  cp -R "$abyss_root/examples/$example/lib" "$ABYSS_EXAMPLES_DIR/$example/"
  (cd "$ABYSS_EXAMPLES_DIR/$example" && mix deps.get)
done
(cd "$ABYSS_EXAMPLES_DIR/quic_echo" && mix run --no-start "$abyss_root/scripts/phase1/published_provenance.exs")
(cd "$ABYSS_EXAMPLES_DIR/quic_collect" && mix run --no-start "$abyss_root/scripts/phase1/published_provenance.exs")
"$abyss_root/scripts/phase1/release_check.sh"
cd "$ABYSS_EXAMPLES_DIR/quic_collect"
export QUIC_CERT="$abyss_root/test/fixtures/quic/server_flight/leaf.pem"
export QUIC_KEY="$abyss_root/test/fixtures/quic/server_flight/leaf-key.pem"
mix run -e '{:ok, {_, port}} = Abyss.QUIC.local(AbyssCollectExample.Listener); {output, 0} = System.cmd("uv", ["run", "--python", "3.12", "--with", "aioquic==1.2.0", "python", Path.join(System.fetch_env!("ABYSS_PATH"), "scripts/phase1/peer.py"), "--port", to_string(port), "--alpn", "abyss-collect-v1", "--mode", "collect", "--ca", Path.join(System.fetch_env!("ABYSS_PATH"), "test/fixtures/quic/server_flight/root.pem")], stderr_to_stdout: true); IO.write(output); IO.puts("OUTSIDE_CHECKOUT_COLLECT_PASS")'
