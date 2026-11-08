#!/usr/bin/env python3
"""Task-owned, bounded independent network acceptance against pinned engines."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "apps/elixir_quic/test/fixtures/tls"


def records(text):
    return [json.loads(line) for line in text.splitlines() if line.startswith('{')]


def verify_cleanup(events, roles):
    receipt = next(item["receipt"] for item in events if item["event"] == "cleanup")
    assert receipt["roles"] == roles, receipt
    assert receipt["down"] == receipt["enrolled"] == sum(roles.values()), receipt
    assert receipt["cleanup"] == "confirmed" and receipt["native_outcome"] == "resolved", receipt
    assert receipt["unresolved_births"] == receipt["unresolved_operations"] == 0, receipt


def wait_listening(process, path):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        for item in records(path.read_text()):
            if item.get("event") == "listening":
                return str(item.get("port") or item["address"].rsplit(':', 1)[1])
        assert process.poll() is None, path.read_text()
        time.sleep(.02)
    raise AssertionError("startup deadline")


def run(args):
    with tempfile.TemporaryDirectory(prefix="quic-A-wire-") as directory:
        log = Path(directory) / "peer.log"
        environment = dict(os.environ, QUIC_EARLY_BARRIER=str(Path(directory) / "finished.release"))
        if args.gate in ("migration", "reset", "early-migration"):
            command = [args.go_binary, "--cert", str(FIXTURE / "leaf.pem"), "--key", str(FIXTURE / "leaf-key.pem"),
                       "--mode", "reset" if args.gate == "reset" else ("early" if args.gate == "early-migration" else "echo")]
            script = "early_migration" if args.gate == "early-migration" else args.gate
        elif args.gate in ("resumption-client", "early-client"):
            feature = "early" if args.gate == "early-client" else "resumption"
            command = [args.python, f"scripts/quic_client_features/{feature}_peer.py", "--role", "server"]
            script = feature
        else:
            feature = "early" if args.gate == "early-server" else "resumption"
            command = ["mix", "run", f"scripts/quic_client_features/{feature}_server.exs"]
            script = None
        with log.open("w") as output:
            peer = subprocess.Popen(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT, env=environment)
            printed_remote = False
            try:
                port = wait_listening(peer, log)
                command = (["mix", "run", f"scripts/quic_client_features/{script}.exs", port] if script else
                    [args.python, f"scripts/quic_client_features/{feature}_peer.py", "--role", "client", "--port", port] +
                    (["--barrier", environment["QUIC_EARLY_BARRIER"]] if feature == "early" else []))
                client = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, timeout=35)
                print(client.stdout, end="")
                if not script:
                    peer.wait(timeout=8)
                remote_text = log.read_text()
                print(remote_text, end="")
                printed_remote = True
                assert client.returncode == 0, f"client exit {client.returncode}"
                local, remote = records(client.stdout), records(remote_text)
                if script:
                    migrations = args.gate in ("migration", "early-migration")
                    connections = 2 if args.gate in ("resumption-client", "early-client", "early-migration") else 1
                    verify_cleanup(local, {"endpoint": 1, "connection": connections,
                                           "io": 3 if migrations else 1, "port": 3 if migrations else 1})
                else:
                    cleanup = next(item for item in remote if item["event"] == "server_cleanup")
                    assert cleanup["io_down"] and cleanup["native_port_down"], cleanup
                if args.gate == "migration":
                    phases = [item for item in local if item["event"] == "phase"]
                    assert [item["phase"] for item in phases] == ["initial", "port", "ip"]
                    receipts = [item for item in remote if item["event"] == "receipt"]
                    addresses = []
                    for phase in phases:
                        match = next(item for item in receipts if item["bytes"] == phase["bytes"] and item["sha256"] == phase["sha256"])
                        addresses.append(match["remote"].rsplit(':', 1))
                    assert addresses[0][0] == addresses[1][0] == "127.0.0.1" and addresses[0][1] != addresses[1][1]
                    assert addresses[2][0] == "127.0.0.2"
                    final = next(item for item in remote if item["event"] == "stream")
                    assert final["fin"] and final["bytes"] == phases[-1]["bytes"] and final["sha256"] == phases[-1]["sha256"]
                    assert len([item for item in remote if item["event"] == "handshake"]) == 1
                    receipt = next(item["receipt"] for item in local if item["event"] == "cleanup")
                    assert receipt["down"] == receipt["enrolled"] == 8 and receipt["roles"]["port"] == 3
                elif args.gate == "reset":
                    assert next(item for item in local if item["event"] == "reliable_reset")["passed"]
                    assert next(item for item in remote if item["event"] == "client_reset")["prefix"]
                    negotiation = next(item for item in remote if item["event"] == "handshake")["reliable_reset"]
                    assert negotiation == {"Local": True, "Remote": True}
                else:
                    for events in (local, remote):
                        flights = [item for item in events if item["event"] == "handshake"]
                        assert [item["resumed"] for item in flights] == [False, True], flights
                        assert [item["early"] for item in flights] == ([False, True] if args.gate.startswith("early") else [False, False])
                    if args.gate == "early-client":
                        assert next(item for item in remote if item["event"] == "early_stream")["before_finished"]
                        assert next(item for item in remote if item["event"] == "early_datagram")["before_finished"]
                    elif args.gate == "early-migration":
                        assert len([item for item in local if item["event"] == "early_migration" and item["exact"]]) == 2
                        streams = [item for item in remote if item["event"] == "stream" and item["bytes"] == 21]
                        assert len(streams) == 2 and all(item["fin"] for item in streams), streams
                        assert [item["remote"].rsplit(':', 1)[0] for item in streams] == ["127.0.0.1", "127.0.0.2"]
                        assert all(item["sha256"] == "f72212dd3a58a2d5425daea8ad27f02ef7f94724cda11cf0b75a675953f97d80" for item in streams)
                    elif args.gate == "early-server":
                        proof = next(item for item in remote if item["event"] == "early_buffered")
                        assert proof["before_finished"] and not proof["ready"] and proof["stream_bytes"] == 274 and proof["datagram_bytes"] == 23
                print(json.dumps({"event": "independent_gate", "gate": args.gate, "passed": True}))
            finally:
                if not printed_remote:
                    print(log.read_text(), end="")
                if peer.poll() is None:
                    peer.terminate()
                    peer.wait(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", choices=["migration", "reset", "resumption-client", "resumption-server", "early-client", "early-server", "early-migration"], required=True)
    parser.add_argument("--go-binary", default="/tmp/http-fetch-quic-A-go-peer/peer")
    parser.add_argument("--python", default="/tmp/http-fetch-quic-A-peer/bin/python")
    run(parser.parse_args())
