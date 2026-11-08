#!/usr/bin/env python3
"""Bounded local M2 acceptance against unmodified aioquic 1.2.0."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def run(args):
    fixture = ROOT / "apps/elixir_quic/test/fixtures/tls"
    with tempfile.TemporaryDirectory(prefix="quic-A-m2-") as directory:
        peer_log = Path(directory) / "peer.log"
        with peer_log.open("w") as output:
            peer = subprocess.Popen([args.python, str(Path(__file__).with_name("peer.py")),
                "--cert", str(fixture / "leaf.pem"), "--key", str(fixture / "leaf-key.pem")],
                stdout=output, stderr=subprocess.STDOUT, cwd=ROOT)
            try:
                deadline = time.monotonic() + 5
                while not peer_log.read_text().splitlines():
                    assert peer.poll() is None, peer_log.read_text()
                    assert time.monotonic() < deadline, "peer startup deadline"
                    time.sleep(.02)
                port = json.loads(peer_log.read_text().splitlines()[0])["port"]
                result = subprocess.run(["mix", "run", "scripts/quic_client_features/migration.exs", str(port)],
                    cwd=ROOT, env=dict(os.environ), stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, timeout=35)
                print(result.stdout, end="")
                if result.returncode:
                    print(peer_log.read_text())
                assert result.returncode == 0, f"client exit {result.returncode}"
                client = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
                remote = [json.loads(line) for line in peer_log.read_text().splitlines() if line.startswith('{')]
                phases = [item for item in client if item["event"] == "phase"]
                assert [item["phase"] for item in phases] == ["initial", "port", "ip"]
                addresses = [item["address"] for item in remote if item["event"] == "path"]
                assert len(addresses) == 3, addresses
                assert addresses[0][0] == addresses[1][0] == "127.0.0.1"
                assert addresses[0][1] != addresses[1][1]
                assert addresses[2][0] == "127.0.0.2"
                assert len([item for item in remote if item["event"] == "handshake"]) == 1
                final = [item for item in remote if item["event"] == "stream" and item["fin"]]
                assert len(final) == 1 and final[0]["handshakes"] == 1
                assert final[0]["bytes"] == phases[-1]["bytes"]
                assert final[0]["sha256"] == phases[-1]["sha256"] and phases[-1]["fin"]
                receipt = next(item["receipt"] for item in client if item["event"] == "cleanup")
                assert receipt["cleanup"] == "confirmed" and receipt["down"] == receipt["enrolled"]
                assert receipt["roles"]["io"] == receipt["roles"]["port"] == 3
                print(json.dumps({"event": "independent_m2", "passed": True, "peer": "aioquic-1.2.0",
                    "addresses": addresses, "stream": final[0]["stream"], "bytes": final[0]["bytes"],
                    "sha256": final[0]["sha256"], "fin": True, "cleanup": receipt}))
            finally:
                peer.terminate()
                peer.wait(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", required=True, help="Python environment with aioquic==1.2.0")
    run(parser.parse_args())
