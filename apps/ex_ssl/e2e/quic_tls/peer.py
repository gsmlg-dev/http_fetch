"""Pinned aioquic TLS-only reference peer; stdin/stdout, no network or records."""
import hashlib
import pathlib
import sys

import aioquic
from aioquic import tls
from aioquic.buffer import Buffer

assert aioquic.__version__ == "1.2.0"
role, suite, identity, request_identity = sys.argv[1:]
fixtures = pathlib.Path(__file__).resolve().parents[2] / "test/fixtures/server_flight"
context = tls.Context(
    is_client=role == "client",
    alpn_protocols=["test"],
    cafile=str(fixtures / "root.pem"),
    server_name="example.test" if role == "client" else None,
    cipher_suites=[tls.CipherSuite(int(suite))],
)
context.certificate = tls.load_pem_x509_certificates((fixtures / f"{identity}.pem").read_bytes())[0]
context.certificate_private_key = tls.load_pem_private_key((fixtures / f"{identity}-key.pem").read_bytes())
context.handshake_extensions = [(57, b"reference-parameters")]
context._request_client_certificate = request_identity == "yes"
levels = {tls.Epoch.INITIAL: "initial", tls.Epoch.HANDSHAKE: "handshake", tls.Epoch.ONE_RTT: "application"}


def secret(direction, epoch, cipher, value):
    # Compare digests without printing raw traffic secrets to diagnostic logs.
    local = "write" if direction == tls.Direction.ENCRYPT else "read"
    print("secret", levels[epoch], local, int(cipher), hashlib.sha256(value).hexdigest(), sep="\t")


context.update_traffic_key_cb = secret
for line in sys.stdin:
    command, _, value = line.rstrip("\n").partition("\t")
    assert command in ("start", "feed")
    output = {epoch: Buffer(capacity=1048576) for epoch in levels}
    context.handle_message(bytes.fromhex(value), output)
    for epoch, buffer in output.items():
        if buffer.tell():
            print("emit", levels[epoch], buffer.data.hex(), sep="\t")
    done = context.state in (tls.State.CLIENT_POST_HANDSHAKE, tls.State.SERVER_POST_HANDSHAKE)
    parameters = dict(context.received_extensions or []).get(57, b"").hex()
    print("info", str(done).lower(), context.alpn_negotiated or "", parameters, sep="\t")
    print("end", flush=True)
