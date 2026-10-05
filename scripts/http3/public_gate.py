"""Fail-closed public HTTP/3 gate with pinned, independently running peers."""
import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import importlib.metadata
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[2]
CADDY_IMAGE = "caddy:2.9.1@sha256:748016f285ed8c43a9ce6e3aed6d92d3009d90ca41157950880f40beaf3ff62b"


def certificates(directory):
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "HTTP3 acceptance root")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for stem, expired in [("server", False), ("expired", True)]:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - timedelta(days=2))
                       .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=7))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                       .sign(ca_key, hashes.SHA256()))
        (directory / f"{stem}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_file = directory / f"{stem}-key.pem"
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_file.chmod(0o600)
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    wrong_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Unrelated acceptance root")])
    wrong_ca = (x509.CertificateBuilder().subject_name(wrong_name).issuer_name(wrong_name)
                .public_key(wrong_key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .sign(wrong_key, hashes.SHA256()))
    (directory / "wrong-ca.pem").write_bytes(wrong_ca.public_bytes(serialization.Encoding.PEM))


def launch(script, args, logs, peers, stack):
    stderr = stack.enter_context((logs / f"{Path(script).stem}-{len(peers)}.log").open("w"))
    process = subprocess.Popen([sys.executable, str(script), *map(str, args)], stdout=subprocess.PIPE,
                               stderr=stderr, text=True, cwd=ROOT)
    peers.append(process)
    with selectors.DefaultSelector() as ready:
        ready.register(process.stdout, selectors.EVENT_READ)
        if not ready.select(timeout=10):
            raise RuntimeError(f"peer readiness timeout: {script}")
        line = process.stdout.readline().strip()
    if not line.isdecimal() or not 0 < int(line) < 65536 or process.poll() is not None:
        raise RuntimeError(f"peer readiness failed: {script}: {line}")
    return int(line)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
        candidate.bind(("127.0.0.1", 0))
        port = candidate.getsockname()[1]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as candidate:
        candidate.bind(("127.0.0.1", port))
    return port


def caddy_ready(port, ca_file, name):
    context = ssl.create_default_context(cafile=str(ca_file))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if subprocess.check_output(["docker", "inspect", "--format", "{{.State.Running}}", name], text=True).strip() != "true":
            raise RuntimeError("pinned Caddy exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1) as raw:
                with context.wrap_socket(raw, server_hostname="example.test") as connection:
                    connection.sendall(b"GET /empty HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
                    response = connection.recv(8192)
                    if response.startswith(b"HTTP/1.1 200 "):
                        return
        except (ConnectionError, TimeoutError, OSError):
            continue
    raise RuntimeError("pinned Caddy authenticated readiness failed")


def run(gate_script, timeout, project_dir=ROOT):
    if importlib.metadata.version("aioquic") != "1.2.0":
        raise RuntimeError("public HTTP3 acceptance requires aioquic==1.2.0")
    subprocess.run(["docker", "pull", CADDY_IMAGE], check=True, timeout=180)
    digests = json.loads(subprocess.check_output(["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", CADDY_IMAGE], text=True))
    if not any(value.endswith(CADDY_IMAGE.split("@", 1)[1]) for value in digests):
        raise RuntimeError("Caddy digest does not match pinned acceptance image")
    container = "http3-public-" + uuid.uuid4().hex
    peers = []
    created = False
    with tempfile.TemporaryDirectory(prefix="http3-public-") as temporary, ExitStack() as stack:
        directory = Path(temporary)
        certificates(directory)
        logs = Path(os.environ.get("HTTP3_GATE_LOG_DIR", str(directory / "logs")))
        logs.mkdir(parents=True, exist_ok=True)
        try:
            cert = directory / "server.pem"
            key = directory / "server-key.pem"
            aioquic = launch(ROOT / "scripts/http3/aioquic_peer.py", [cert, key], logs, peers, stack)
            expired = launch(ROOT / "scripts/http3/aioquic_peer.py", [directory / "expired.pem", directory / "expired-key.pem"], logs, peers, stack)
            alpn = launch(ROOT / "scripts/http3/caddy_negative_peer.py", [cert, key], logs, peers, stack)
            upstream = launch(ROOT / "scripts/http3/caddy_upstream.py", [], logs, peers, stack)
            caddy = free_port()
            created = True
            subprocess.run(["docker", "run", "--detach", "--name", container, "--network", "host",
                            "--mount", f"type=bind,src={directory},dst=/certs,readonly",
                            "--mount", f"type=bind,src={ROOT / 'scripts/http3/caddy_Caddyfile'},dst=/etc/caddy/Caddyfile,readonly",
                            "--env", f"HTTP3_CADDY_PORT={caddy}", "--env", f"HTTP3_UPSTREAM_PORT={upstream}",
                            CADDY_IMAGE], check=True, timeout=30)
            caddy_ready(caddy, directory / "ca.pem", container)
            environment = {**os.environ, "MIX_ENV": "test", "HTTP3_AIOQUIC_PORT": str(aioquic),
                           "HTTP3_CADDY_PORT": str(caddy), "HTTP3_EXPIRED_PORT": str(expired),
                           "HTTP3_WRONG_ALPN_PORT": str(alpn), "HTTP3_PEER_CA_FILE": str(directory / "ca.pem"),
                           "HTTP3_WRONG_CA_FILE": str(directory / "wrong-ca.pem")}
            subprocess.run([sys.executable, str(ROOT / "scripts/http3/caddy_upload_probe.py")],
                           cwd=ROOT, env=environment, check=True, timeout=75)
            subprocess.run(["mix", "run", str(gate_script)], cwd=project_dir, env=environment, check=True, timeout=timeout)
            if any(peer.poll() is not None for peer in peers):
                raise RuntimeError("independent peer exited during acceptance")
        finally:
            cleanup_errors = []
            if created:
                with (logs / "caddy.log").open("w") as output:
                    for command in [["docker", "logs", container], ["docker", "stop", "--time", "2", container], ["docker", "rm", container]]:
                        try:
                            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=10)
                        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                            cleanup_errors.append(str(error))
            for peer in peers:
                if peer.poll() is None:
                    peer.terminate()
                try:
                    peer.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    peer.kill()
                    peer.wait(timeout=5)
                peer.stdout.close()
            if cleanup_errors:
                raise RuntimeError("peer cleanup failed: " + "; ".join(cleanup_errors))



if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate-script", type=Path, default=ROOT / "scripts/http3/public_gate.exs")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--project-dir", type=Path, default=ROOT)
    arguments = parser.parse_args()
    def interrupted(signum, _frame):
        raise RuntimeError(f"HTTP3 acceptance interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    run(arguments.gate_script, arguments.timeout, arguments.project_dir)
