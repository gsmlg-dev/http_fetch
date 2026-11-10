#!/usr/bin/env python3
"""Task-owned, bounded independent network acceptance against pinned engines."""
import argparse
import json
import os
from pathlib import Path
import signal
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


NEGATIVE = {
    # gate: (suite, pinned peer, {case: (io, port)}) -- exact enrolled native roles
    "migration-negative": ("matrix", "quic-go-v0.62.0", {
        "before_confirmation": (1, 1), "bind_in_use": (2, 1), "bind_unavailable": (2, 1),
        "deadline_fallback_busy": (3, 3), "duplicate_ref": (2, 2),
        "owner_death/candidate_bound": (2, 2), "owner_death/probe_sent": (2, 2),
        "owner_death/validated": (2, 2), "owner_death/old_retiring": (2, 2)}),
    "migration-no-cid": ("no-cid", "quic-go-v0.62.0", {"no_spare_cid": (1, 1)}),
    "migration-disabled": ("disabled", "quinn-0.11.11/quinn-proto-0.11.17", {"peer_disabled": (1, 1)}),
}
REQUIRED_ASSERTS = {
    "before_confirmation": ["preconfirmation", "paths"],
    "bind_in_use": ["admission", "retained", "conflict", "outcome", "retained_after_outcome", "local"],
    "bind_unavailable": ["admission", "retained", "conflict", "outcome", "retained_after_outcome", "local"],
    "deadline_fallback_busy": ["concurrent", "outcome", "busy_status", "local", "later_admission"],
    "duplicate_ref": ["admission", "retained", "retained_after_outcome", "status", "local"],
    "no_spare_cid": ["admission", "retained", "paths"],
    "peer_disabled": ["admission", "retained", "paths"],
}


def verify_negative(gate, local, remote):
    suite, peer, cases = NEGATIVE[gate]
    listening = next(item for item in remote if item["event"] == "listening")
    assert listening["peer"] == peer, listening
    if gate == "migration-no-cid":
        assert listening["zero_cid"] is True, listening
    if gate == "migration-disabled":
        assert listening["migration"] is False, listening
    assert any(item["event"] == "suite" and item["suite"] == suite and item["passed"] for item in local)
    receipts = {item["case"]: item["receipt"] for item in local if item["event"] == "cleanup"}
    for name, receipt in receipts.items():
        assert receipt["cleanup"] == "confirmed" and receipt["native_outcome"] == "resolved", (name, receipt)
        assert receipt["down"] == receipt["enrolled"], (name, receipt)
        assert receipt["unresolved_births"] == receipt["unresolved_operations"] == 0, (name, receipt)
    # Every connection, including a preconfirmation attempt that lost its race,
    # completed exactly one independent handshake.
    assert len([item for item in remote if item["event"] == "handshake"]) == len(receipts), receipts.keys()
    for name, (io, port) in cases.items():
        assert receipts[name]["roles"] == {"endpoint": 1, "connection": 1, "io": io, "port": port}, (name, receipts[name])
        labels = {item["label"] for item in local if item["event"] == "assert" and item["case"] == name}
        assert set(REQUIRED_ASSERTS.get(name, [])) <= labels, (name, labels)
        if name.startswith("owner_death/"):
            transition = name.split("/", 1)[1]
            death = [item for item in local if item["event"] == "owner_death" and item["case"] == name]
            assert len(death) == 1 and death[0]["transition"] == transition and death[0]["joined"] == 6, death
            assert f"{transition}/two_sockets" in labels, labels
        phases = [item for item in local if item["event"] == "phase" and item["case"] == name]
        assert phases, name
        if not name.startswith("owner_death/"):
            assert phases[-1]["fin"], phases
        for phase in phases:
            # The independent peer observed these exact cumulative bytes from
            # exactly the source address the engine reports.
            match = [item for item in remote if item["event"] == "receipt"
                     and item["bytes"] == phase["bytes"] and item["sha256"] == phase["sha256"]]
            assert len(match) == 1 and match[0]["remote"] == phase["local"], (phase, match)
            if phase["path"] == "old":
                assert phase["local"] == phase["initial"], phase
            else:
                assert phase["local"] != phase["initial"], phase
                assert phase["local"].rsplit(':', 1)[0] == phase["initial"].rsplit(':', 1)[0], phase
            if phase["fin"]:
                final = [item for item in remote if item["event"] == "stream" and item.get("fin")
                         and item["sha256"] == phase["sha256"] and item["bytes"] == phase["bytes"]]
                assert len(final) == 1 and final[0]["remote"] == phase["local"], (phase, final)
    old_after = {item["case"] for item in local if item["event"] == "phase" and item["path"] == "old"
                 and item["phase"] == "after"}
    for name in cases:
        if name != "duplicate_ref" and not name.startswith("owner_death/"):
            assert name in old_after, (name, "no post-negative exchange on the old path")


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
        if args.gate in NEGATIVE:
            if args.gate == "migration-disabled":
                command = [args.quinn_binary]
            else:
                command = [args.go_binary, "--mode", "echo"] + (["--zero-cid"] if args.gate == "migration-no-cid" else [])
            command += ["--cert", str(FIXTURE / "leaf.pem"), "--key", str(FIXTURE / "leaf-key.pem")]
            script = "migration_negative"
        elif args.gate in ("migration", "reset", "early-migration"):
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
            # The negative matrix pauses/resumes the peer to make a probe unanswerable.
            environment["QUIC_PEER_PID"] = str(peer.pid)
            printed_remote = False
            try:
                port = wait_listening(peer, log)
                suite = [NEGATIVE[args.gate][0]] if args.gate in NEGATIVE else []
                command = (["mix", "run", f"scripts/quic_client_features/{script}.exs", port] + suite if script else
                    [args.python, f"scripts/quic_client_features/{feature}_peer.py", "--role", "client", "--port", port] +
                    (["--barrier", environment["QUIC_EARLY_BARRIER"]] if feature == "early" else []))
                client = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True,
                                        timeout=80 if args.gate in NEGATIVE else 35)
                print(client.stdout, end="")
                if not script:
                    peer.wait(timeout=8)
                remote_text = log.read_text()
                print(remote_text, end="")
                printed_remote = True
                assert client.returncode == 0, f"client exit {client.returncode}"
                local, remote = records(client.stdout), records(remote_text)
                if args.gate in NEGATIVE:
                    verify_negative(args.gate, local, remote)
                elif script:
                    migrations = args.gate in ("migration", "early-migration")
                    connections = 2 if args.gate in ("resumption-client", "early-client", "early-migration") else 1
                    verify_cleanup(local, {"endpoint": 1, "connection": connections,
                                           "io": 3 if migrations else 1, "port": 3 if migrations else 1})
                else:
                    cleanup = next(item for item in remote if item["event"] == "server_cleanup")
                    assert cleanup["io_down"] and cleanup["native_port_down"], cleanup
                if args.gate in NEGATIVE:
                    pass
                elif args.gate == "migration":
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
                    os.kill(peer.pid, signal.SIGCONT)
                    peer.terminate()
                    peer.wait(timeout=3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate", choices=["migration", "reset", "resumption-client", "resumption-server", "early-client", "early-server", "early-migration"] + list(NEGATIVE), required=True)
    parser.add_argument("--go-binary", default="/tmp/http-fetch-quic-A-go-peer/peer")
    parser.add_argument("--python", default="/tmp/http-fetch-quic-A-peer/bin/python")
    parser.add_argument("--quinn-binary", default="/tmp/http-fetch-quic-A-quinn-peer/quinn-m2-peer")
    run(parser.parse_args())
