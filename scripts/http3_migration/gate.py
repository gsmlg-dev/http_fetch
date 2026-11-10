"""Fail-closed HTTP-level migration gate: WebSocket over HTTP/3 against quic-go/http3.

Builds the unmodified, pinned quic-go/http3 peer from this directory's go.mod /
go.sum, runs gate.exs against it, and accepts only when the peer itself reports
that post-migration WebSocket messages arrived with exact bytes, on the same
connection and stream, from the client's new address (connection RemoteAddr
switched and the per-source datagram counters attribute the large message to
the new path), and that the migrated connection then ended with an application
CONNECTION_CLOSE carrying H3_NO_ERROR rather than idling out. Usage:

    python3 scripts/http3_migration/gate.py          # port migration on 127.0.0.1
    python3 scripts/http3_migration/gate.py --ip     # plus source-IP migration to 127.0.0.2
"""
import argparse
import json
import os
import signal
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PINNED_QUIC_GO = "v0.65.0"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def alias_available(address):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind((address, 0))
        return True
    except OSError:
        return False


def records(text):
    return [json.loads(line) for line in text.splitlines() if line.startswith("{")]


def build(directory):
    print(subprocess.run(["go", "version"], check=True, capture_output=True, text=True,
                         timeout=60).stdout.strip())
    pinned = subprocess.run(["go", "list", "-mod=readonly", "-m", "github.com/quic-go/quic-go"], cwd=HERE,
                            check=True, capture_output=True, text=True, timeout=120).stdout.split()
    require(pinned == ["github.com/quic-go/quic-go", PINNED_QUIC_GO], f"quic-go pin drifted: {pinned}")
    binary = directory / "peer"
    subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary), "."], cwd=HERE, check=True,
                   timeout=300, env={**os.environ, "GOFLAGS": "-mod=readonly"})
    return binary


def verify(local, remote, ip):
    phases = [item for item in local if item["event"] == "phase"]
    expected_phases = ["initial", "port"] + (["ip"] if ip else []) + ["pooled"]
    require([item["phase"] for item in phases] == expected_phases, f"client phases {phases}")
    for marker in ("positive_closed", "pooled_refusal", "done"):
        require(any(item["event"] == marker for item in local), f"missing client {marker}")
    for bad in ("refused", "takeover_failed", "stream_error", "lifetime_expired"):
        require(not any(item["event"] == bad for item in remote), f"peer reported {bad}")

    connections = [item for item in remote if item["event"] == "connection"]
    require([item["conn"] for item in connections] == [1, 2], f"peer connections {connections}")
    opens = [item for item in remote if item["event"] == "open"]
    require([item["conn"] for item in opens] == [1, 2], f"peer CONNECT streams {opens}")
    stream = {item["conn"]: item["stream"] for item in opens}
    messages = [item for item in remote if item["event"] == "message"]

    def peer_messages(conn, wanted):
        received = [item for item in messages if item["conn"] == conn]
        expected = [message for phase in wanted for message in phase["messages"]]
        require([(item["bytes"], item["sha256"]) for item in received] ==
                [(item["bytes"], item["sha256"]) for item in expected],
                f"peer conn {conn} messages differ from client exchange")
        require(all(item["stream"] == stream[conn] for item in received), "message on an unexpected stream")
        return [received[index:index + 2] for index in range(0, len(received), 2)]

    migrated = peer_messages(1, phases[:-1])
    original = migrated[0][0]["remote"]
    require(original == connections[0]["remote"] and original.startswith("127.0.0.1:"), f"initial path {original}")
    require(all(item["remote"] == original for item in migrated[0]), "initial messages changed path")
    previous, previous_large = original, migrated[0][1]
    for phase, received in zip(phases[1:-1], migrated[1:]):
        new = phase["local"]
        host = "127.0.0.2" if phase["phase"] == "ip" else "127.0.0.1"
        require(new.startswith(host + ":") and new != previous, f"{phase['phase']} migrate returned {new}")
        # quic-go switches RemoteAddr() only after validating the new path, so the
        # first small message may still be attributed to the old address; the
        # large message must arrive on the new path.
        require(received[0]["remote"] in (new, previous),
                f"{phase['phase']} message seen from {received[0]['remote']}, client moved to {new}")
        require(received[1]["remote"] == new,
                f"{phase['phase']} large message seen from {received[1]['remote']}, client moved to {new}")
        large = received[1]
        size = large["bytes"]
        require(large["sources"].get(new, {}).get("bytes", 0) >= size,
                f"{phase['phase']}: peer read fewer than {size} bytes from {new}: {large['sources']}")
        old_delta = (large["sources"].get(previous, {}).get("bytes", 0) -
                     previous_large["sources"].get(previous, {}).get("bytes", 0))
        require(old_delta < size // 8, f"{phase['phase']}: old path {previous} carried {old_delta} bytes after migration")
        print(f"{phase['phase']} migration: {previous} -> {new}; peer read {large['sources'][new]['bytes']} bytes "
              f"from new path, {old_delta} from old path since; exact {len(received)} messages: PASS")
        previous, previous_large = new, large

    pooled = peer_messages(2, phases[-1:])
    require(all(item["remote"] == connections[1]["remote"] for item in pooled[0]), "pooled session changed path")

    for conn, reason in ((1, "migrated-done"), (2, "pooled-done")):
        close = next((item for item in remote if item["event"] == "close" and item["conn"] == conn), None)
        require(close and close["code"] == 1000 and close["reason"] == reason, f"conn {conn} close {close}")
        end = next((item for item in remote if item["event"] == "stream_end" and item["conn"] == conn), None)
        require(end and end["fin"] and end["trailing_bytes"] == 0, f"conn {conn} stream end {end}")
    # RFC 9114 section 5.2: after the clean WebSocket close the exclusive owner
    # ends the migrated connection with CONNECTION_CLOSE(H3_NO_ERROR) before its
    # cleanup receipt (asserted by gate.exs); an idle-timeout close fails.
    closed = next((item for item in remote if item["event"] == "connection_closed" and item["conn"] == 1), None)
    require(closed and closed["cause"].startswith("Application error 0x100 (remote)"),
            f"peer-observed QUIC close of the migrated connection: {closed['cause'] if closed else 'none'}")
    # Prompt, not idle: the peer saw it before the client opened the pooled connection.
    require(remote.index(closed) < remote.index(connections[1]), "migrated connection closed after the pooled one opened")
    print(f"peer-observed QUIC close of the migrated connection: {closed['cause']}: PASS")
    print("one connection, one CONNECT stream, exact bytes, clean WebSocket Close + FIN on the migrated path: PASS")
    print("pooled H3 WebSocket refuses migrate with :not_exclusive_owner and keeps exchanging: PASS")


def run(args):
    if args.ip and not alias_available("127.0.0.2"):
        raise SystemExit("--ip requires a 127.0.0.2 loopback alias (fail closed)")
    with tempfile.TemporaryDirectory(prefix="http3-migration-") as temp:
        temp = Path(temp)
        binary = Path(args.go_binary) if args.go_binary else build(temp)
        ca = temp / "ca.pem"
        lines, lock = [], threading.Lock()
        stderr = (temp / "peer-stderr.log").open("w")
        peer = subprocess.Popen([str(binary), "--ca-out", str(ca), "--lifetime", "150s"],
                                stdout=subprocess.PIPE, stderr=stderr, text=True)
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(peer.stdout, selectors.EVENT_READ)
                require(ready.select(timeout=15), "peer readiness timeout")
                first = peer.stdout.readline()
            listening = json.loads(first) if first.startswith("{") else {"event": first}
            require(listening.get("event") == "listening", f"peer did not start: {first!r}")
            require(listening["quic_go"] == PINNED_QUIC_GO, f"peer quic-go {listening['quic_go']}")
            print(f"independent peer: unmodified quic-go/http3 {listening['quic_go']} at {listening['address']}")

            def drain():
                for line in peer.stdout:
                    with lock:
                        lines.append(line)
            reader = threading.Thread(target=drain, daemon=True)
            reader.start()

            port = listening["address"].rsplit(":", 1)[1]
            # Own process group so a timeout kills the BEAM, not just the mix wrapper.
            client = subprocess.Popen(["mix", "run", "scripts/http3_migration/gate.exs"], cwd=ROOT,
                                      env={**os.environ, "MIX_ENV": "test", "HTTP3_PEER_PORT": port,
                                           "HTTP3_PEER_CA": str(ca), "HTTP3_MIGRATION_IP": "1" if args.ip else "0"},
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                      start_new_session=True)
            try:
                output, _ = client.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(client.pid, signal.SIGKILL)
                output, _ = client.communicate()
                print(output, end="")
                raise
            print(output, end="")
            require(client.returncode == 0, f"client exit {client.returncode}")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with lock:
                    if any('"stream_end"' in line and '"conn":2,' in line for line in lines) and \
                            any('"connection_closed"' in line and '"conn":1,' in line for line in lines):
                        break
                time.sleep(0.05)
            require(peer.poll() is None, "independent peer exited during acceptance")
            with lock:
                remote_text = "".join(lines)
            verify(records(output), records(remote_text), args.ip)
            print(json.dumps({"event": "independent_gate", "gate": "http3-websocket-migration" + ("-ip" if args.ip else ""),
                              "peer": f"quic-go/http3 {PINNED_QUIC_GO}", "passed": True}))
        except BaseException:
            with lock:
                print("".join(lines), end="", file=sys.stderr)
            print((temp / "peer-stderr.log").read_text(), end="", file=sys.stderr)
            raise
        finally:
            peer.terminate()
            try:
                peer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                peer.kill()
                peer.wait()
            stderr.close()
            if args.log_dir:
                logs = Path(args.log_dir)
                logs.mkdir(parents=True, exist_ok=True)
                with lock:
                    (logs / f"peer{'-ip' if args.ip else ''}.log").write_text(
                        "".join(lines) + (temp / "peer-stderr.log").read_text())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", action="store_true", help="also migrate the source IP to 127.0.0.2")
    parser.add_argument("--go-binary", help="prebuilt peer from this directory (default: build it)")
    parser.add_argument("--log-dir", help="directory for the peer's JSON event log")
    run(parser.parse_args())
