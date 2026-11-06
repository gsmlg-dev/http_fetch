#!/usr/bin/env bash
set -euo pipefail
abyss_root=$(cd "$(dirname "$0")/../.." && pwd)
export ABYSS_PATH="$abyss_root"
examples_root=${ABYSS_EXAMPLES_DIR:-"$abyss_root/examples"}

check_release() (
  example=$1
  app=$2
  expression=$3
  cd "$examples_root/$example"
  MIX_ENV=prod mix release --overwrite
  executable="$PWD/_build/prod/rel/$app/bin/$app"
  if [[ "$example" == quic_echo ]]; then
    export QUIC_CERT="$abyss_root/test/fixtures/quic/server_flight/leaf.pem"
    export QUIC_KEY="$abyss_root/test/fixtures/quic/server_flight/leaf-key.pem"
  fi
  "$executable" daemon
  trap '"$executable" stop' EXIT
  # Only startup RPC is retried, before any application send is admitted.
  for attempt in 1 2 3 4 5; do
    if "$executable" rpc ':ok'; then
      "$executable" rpc "$expression"
      exit "$?"
    fi
    sleep 1
  done
  exit 1
)

check_release udp_echo abyss_udp_example 'AbyssUDPExample.verify()'
check_release quic_echo abyss_quic_echo_example 'true = Code.ensure_loaded?(Quic); true = Code.ensure_loaded?(SSL.QUIC); {:ok, {_ip, port}} = Abyss.QUIC.local(AbyssEchoExample.Listener); {output, 0} = System.cmd("uv", ["run", "--python", "3.12", "--with", "aioquic==1.2.0", "python", Path.join(System.fetch_env!("ABYSS_PATH"), "scripts/phase1/peer.py"), "--port", to_string(port), "--alpn", "abyss-echo-v1", "--mode", "echo", "--ca", Path.join(System.fetch_env!("ABYSS_PATH"), "test/fixtures/quic/server_flight/root.pem")], stderr_to_stdout: true); IO.write(output); IO.puts("QUIC_RELEASE_PASS")'
