"""Pinned independent TLS provider; plaintext control pipe, no TLS records/QUIC packets."""
import hashlib
import pathlib
import sys
import aioquic
from aioquic import tls
from aioquic.buffer import Buffer

assert aioquic.__version__ == "1.2.0"
role, suite, early_arg = sys.argv[1:]
early = early_arg == "true"
fixtures = pathlib.Path(__file__).resolve().parents[2] / "apps/ex_ssl/test/fixtures/server_flight"
levels = {tls.Epoch.INITIAL: "initial", tls.Epoch.HANDSHAKE: "handshake", tls.Epoch.ONE_RTT: "application", tls.Epoch.ZERO_RTT: "early_data"}
stored = {}
last_ticket = None
context = None

def receipt(ticket):
    global last_ticket
    last_ticket = ticket
    stored[ticket.ticket] = ticket


def secret(direction, epoch, cipher, value):
    print("secret", levels[epoch], "write" if direction == tls.Direction.ENCRYPT else "read", int(cipher), hashlib.sha256(value).hexdigest(), sep="\t")


def reset():
    global context
    context = tls.Context(is_client=role == "client", alpn_protocols=["test"],
        cafile=str(fixtures / "root.pem"), server_name="example.test" if role == "client" else None,
        cipher_suites=[tls.CipherSuite(int(suite))], max_early_data=0xffffffff if early else None)
    context.certificate = tls.load_pem_x509_certificates((fixtures / "leaf.pem").read_bytes())[0]
    context.certificate_private_key = tls.load_pem_private_key((fixtures / "leaf-key.pem").read_bytes())
    context.handshake_extensions = [(57,b"reference-parameters")]
    context.update_traffic_key_cb = secret
    context.new_session_ticket_cb = receipt
    context.get_session_ticket_cb = lambda identity: stored.pop(identity,None)
    if role == "client":
        context.session_ticket = last_ticket

reset()
for line in sys.stdin:
    command, _, value = line.rstrip("\n").partition("\t")
    assert command in ("start","feed","reset")
    if command == "reset":
        reset()
    else:
        output = {epoch: Buffer(capacity=1048576) for epoch in (tls.Epoch.INITIAL,tls.Epoch.HANDSHAKE,tls.Epoch.ONE_RTT)}
        context.handle_message(bytes.fromhex(value),output)
        for epoch, buffer in output.items():
            if buffer.tell():
                print("emit",levels[epoch],buffer.data.hex(),sep="\t")
        done = context.state in (tls.State.CLIENT_POST_HANDSHAKE,tls.State.SERVER_POST_HANDSHAKE)
        print("info",str(done).lower(),str(context.session_resumed).lower(),str(context.early_data_accepted).lower(),sep="\t")
    print("end",flush=True)
