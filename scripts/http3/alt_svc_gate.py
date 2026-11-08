"""Fail-closed Alt-Svc discovery gate against independent peers.

Run: uv run --python 3.12 --with aioquic==1.2.0 python scripts/http3/alt_svc_gate.py

Peers (all owned and terminated by this launcher):
- positive: Python stdlib `ssl` HTTP/1.1 origin advertising `h3=":Q"` where Q is
  a pinned aioquic 1.2.0 HTTP/3 peer;
- blackhole: origin advertising an h3 UDP port bound by this launcher that never
  answers (packets are silently dropped);
- closed: origin advertising an h3 UDP port with no listener.
An ephemeral CA issues one leaf with DNS example.test and IP 127.0.0.1 SANs, so
TCP and QUIC verify the same `https://127.0.0.1:<port>` origin identity without
transport-specific identity overrides. Docker is not required. Extra environment
(for example MIX_BUILD_PATH) passes through to the Elixir driver.
"""

import argparse
import importlib.metadata
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile

from public_gate import certificates


ROOT = Path(__file__).resolve().parents[2]


def spawn(processes, certs, script, *args):
    cert = [str(certs / "server.pem"), str(certs / "server-key.pem")]
    process = subprocess.Popen([sys.executable, str(ROOT / "scripts/http3" / script), *cert, *args],
                               stdout=subprocess.PIPE, text=True)
    processes.append(process)
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout, selectors.EVENT_READ)
        if not ready.select(timeout=10):
            raise RuntimeError(f"independent peer {script} failed to become ready")
    return int(process.stdout.readline().strip())


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    return sock


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main(args):
    if importlib.metadata.version("aioquic") != "1.2.0":
        raise RuntimeError("Alt-Svc acceptance requires pinned aioquic==1.2.0")
    processes = []
    directory = tempfile.TemporaryDirectory(prefix="alt-svc-gate-")
    certs = Path(directory.name)
    certificates(certs)
    blackhole = udp_socket()
    closed = udp_socket()
    closed_port = closed.getsockname()[1]
    closed.close()
    try:
        h3_port = spawn(processes, certs, "alt_svc_peer.py")
        blackhole_port = blackhole.getsockname()[1]
        env = {
            **os.environ,
            "MIX_ENV": "test",
            "ALT_SVC_CA_FILE": str(certs / "ca.pem"),
            "ALT_SVC_H3_PORT": str(h3_port),
            "ALT_SVC_BLACKHOLE_UDP": str(blackhole_port),
            "ALT_SVC_CLOSED_UDP": str(closed_port),
            "ALT_SVC_POSITIVE_ORIGIN": str(spawn(processes, certs, "alt_svc_origin.py", f'h3=":{h3_port}"; ma=60')),
            "ALT_SVC_BLACKHOLE_ORIGIN": str(spawn(processes, certs, "alt_svc_origin.py", f'h3=":{blackhole_port}"; ma=60')),
            "ALT_SVC_CLOSED_ORIGIN": str(spawn(processes, certs, "alt_svc_origin.py", f'h3=":{closed_port}"; ma=60')),
        }
        subprocess.run(["mix", "run", "scripts/http3/alt_svc_gate.exs"], cwd=ROOT, env=env,
                       check=True, timeout=args.timeout)
        if any(process.poll() is not None for process in processes):
            raise RuntimeError("independent peer exited during acceptance")
    finally:
        blackhole.close()
        for process in processes:
            stop(process)
        directory.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=300)
    main(parser.parse_args())
