"""Bounded independent WebSocket/H3 peer gate; run with the pinned peer venv."""
import os
from pathlib import Path
import selectors
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
fixtures = ROOT / "apps/elixir_quic/test/fixtures/tls"
peer = subprocess.Popen([sys.executable, str(Path(__file__).with_name("peer.py")), str(fixtures / "leaf.pem"), str(fixtures / "leaf-key.pem")] + (["--disable-connect"] if "--settings-refusal" in sys.argv else ["--hold-settings"] if "--hold-settings" in sys.argv else []), stdout=subprocess.PIPE, text=True)
try:
    with selectors.DefaultSelector() as ready:
        ready.register(peer.stdout, selectors.EVENT_READ)
        if not ready.select(timeout=10):
            raise RuntimeError("peer readiness timeout")
        port = int(peer.stdout.readline().strip())
    subprocess.run(["mix", "run", "scripts/http3_websocket/gate.exs"], cwd=ROOT,
                   env={**os.environ, "MIX_ENV": "test", "HTTP3_PEER_PORT": str(port), "HTTP3_SETTINGS_HELD": "1" if "--hold-settings" in sys.argv else "0", "HTTP3_SETTINGS_REFUSAL": "1" if "--settings-refusal" in sys.argv else "0"}, check=True, timeout=90)
    if peer.poll() is not None:
        raise RuntimeError("independent peer exited during acceptance")
finally:
    peer.terminate()
    try:
        peer.wait(timeout=5)
    except subprocess.TimeoutExpired:
        peer.kill()
        peer.wait()
