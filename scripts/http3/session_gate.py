"""Fail-closed companion gate against a separately running pinned aioquic peer."""

import importlib.metadata
import os
from pathlib import Path
import selectors
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def main():
    if importlib.metadata.version("aioquic") != "1.2.0":
        raise RuntimeError("HTTP/3 acceptance requires pinned aioquic==1.2.0")
    fixtures = ROOT / "apps/elixir_quic/test/fixtures/tls"
    peer = subprocess.Popen([
        sys.executable, str(ROOT / "scripts/http3/aioquic_peer.py"),
        str(fixtures / "leaf.pem"), str(fixtures / "leaf-key.pem"),
    ], stdout=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(peer.stdout, selectors.EVENT_READ)
            if not ready.select(timeout=10):
                raise RuntimeError("independent HTTP/3 peer failed to become ready")
            port = int(peer.stdout.readline().strip())
        subprocess.run([
            "mix", "run", "scripts/http3/session_gate.exs",
        ], cwd=ROOT, env={**os.environ, "MIX_ENV": "test", "HTTP3_PEER_PORT": str(port)},
            check=True, timeout=30)
    finally:
        peer.terminate()
        try:
            peer.wait(timeout=5)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait()


if __name__ == "__main__":
    main()
