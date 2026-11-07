#!/usr/bin/env python3
"""Run the M1 localhost migration gate against an already-prepared Mix build."""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import signal
import sys

from peer import PHASES, PINNED_AIOQUIC, phase_payload, positive_timeout, validate_cid_bindings

ROOT = Path(__file__).resolve().parents[2]


def consumer_environment(project):
    # Reuse the exact Hex consumer boundary; never inherit umbrella build paths,
    # Mix project overrides, code-path flags, or registry credentials.
    sys.path.insert(0, str(ROOT / "scripts/release"))
    try:
        from server_consumer_gate import isolated_environment
        environment = isolated_environment(project.parent)
    finally:
        sys.path.pop(0)
    project = project.resolve()
    # MIX_BUILD_PATH names the environment's final directory, not its parent.
    # Retain a prepared override only inside this exact consumer project.
    build_path = project / "_build/prod"
    if inherited := os.environ.get("MIX_BUILD_PATH"):
        candidate = (project / inherited).resolve()
        if candidate.is_relative_to(project):
            build_path = candidate
    environment.update(MIX_BUILD_PATH=str(build_path), MIX_DEPS_PATH=str(project / "deps"),
                       MIX_HOME=str(project.parent / "mix"), PYTHONDONTWRITEBYTECODE="1")
    return environment


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def path_receipt(events, target, retired=False, require_mtu=True):
    latest = {}
    for event in events:
        if event.get("event") == "public_path_info":
            assert event["path_records"] == len(event["paths"]) <= 2, "unbounded/mismatched public paths"
            latest[event["connection"]] = event
    for event in latest.values():
        active = next((path for path in event["paths"] if path["id"] == event["active_path"]), None)
        if (active and active["remote"] == target and active["validated"] is True
                and (not require_mtu or active["mtu_validated"] is True)
                and (not retired or event["path_records"] == 1)):
            return event
    return None


def validate_proof(server, result):
    """Cross-check independent peer receipts against public server receipts."""
    assert result.get("passed") is True, result.get("reason", "peer failed")
    assert result["peer_version"] == PINNED_AIOQUIC, "unexpected peer version"
    proof = result["proof"]
    connections = proof["connections"]
    assert len(connections) == 2, "expected migrating and control connections"
    assert {item["label"] for item in connections} == {"migrating", "control"}
    ready = [item for item in server if item.get("event") == "connection_ready"]
    opened = [item for item in server if item.get("event") == "stream_open"]
    completed = [item for item in server if item.get("event") == "stream_complete"]
    assert len(ready) == len(opened) == len(completed) == 2, "replacement/missing server connection or stream"
    tokens = {item["connection"] for item in ready}
    assert len(tokens) == 2, "server connection identity reused"
    assert all(item["alpn"] == "ex-quic-test" for item in ready)
    assert tokens == {item["connection"] for item in opened} == {item["connection"] for item in completed}
    for item in connections:
        expected = b"".join(phase_payload(item["label"], phase) for phase in PHASES)
        digest = hashlib.sha256(expected).hexdigest()
        assert item["handshakes"] == 1, "replacement peer handshake"
        assert item["bytes"] == len(expected) and item["sha256"] == digest and item["fin"] is True
        assert item["datagrams_sent"] == [3, 3, 3]
        assert len(item["datagrams_observed"]) == 3
        assert all(1 <= count <= 3 for count in item["datagrams_observed"]), "missing phase DATAGRAM receipts"
        matches = [entry for entry in completed if entry["sha256"] == digest]
        assert len(matches) == 1, "server did not receive the exact independent phase bytes"
        match = matches[0]
        assert match["bytes"] == len(expected) and match["fin"] is True
        assert match["stream_id"] == item["stream_id"], "stream identity changed"
        assert any(entry["connection"] == match["connection"] and entry["stream_id"] == match["stream_id"]
                   for entry in opened), "server stream identity changed"
    backends = proof["backends"]
    assert len(backends) == proof["retained_backend_sockets"] == 3
    first, port, ip = backends
    assert first["address"][0] == port["address"][0] == "127.0.0.1"
    assert first["address"][1] != port["address"][1]
    assert ip["address"][0] == "127.0.0.2"
    assert all(item["sent"] > 0 and item["received"] > 0 for item in backends)
    validate_cid_bindings(backends)
    assert proof["same_stream_across_phases"] is True
    return {"peer": proof, "server": {"connections": ready, "streams": completed}}


class Process:
    def __init__(self, name, process, changed):
        self.name, self.process, self.changed = name, process, changed
        self.events = []
        self.reader = asyncio.create_task(self.read())

    @classmethod
    async def start(cls, name, command, changed, *, cwd=ROOT, env=None):
        process = await asyncio.create_subprocess_exec(
            *command, cwd=cwd, env=env, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            start_new_session=True)
        return cls(name, process, changed)

    async def read(self):
        try:
            while line := await self.process.stdout.readline():
                text = line.decode(errors="replace").rstrip()
                try:
                    event = json.loads(text)
                    if not isinstance(event, dict):
                        raise ValueError("non-object JSON")
                except ValueError:
                    emit("log", source=self.name, message=text)
                else:
                    self.events.append(event)
                    emit("receipt", source=self.name, receipt=event)
                self.changed.set()
        finally:
            self.changed.set()

    async def cleanup(self):
        # Each child owns a new process group, including uv's Python child.
        # Reap the direct child and kill any remaining owned descendants.
        def send(sig):
            try:
                os.killpg(self.process.pid, sig)
            except ProcessLookupError:
                pass

        send(signal.SIGTERM)
        try:
            await asyncio.wait_for(self.process.wait(), 2)
        except asyncio.TimeoutError:
            pass
        finally:
            send(signal.SIGKILL)
        await asyncio.wait_for(self.process.wait(), 2)
        await asyncio.wait_for(self.reader, 2)


async def wait_until(predicate, processes, changed, deadline, description="required receipt"):
    while True:
        changed.clear()
        result = predicate()
        if result:
            return result
        for process in processes:
            if process.reader.done():
                process.reader.result()
                raise RuntimeError(f"{process.name} ended before required receipt (exit {process.process.returncode})")
        remaining = deadline - asyncio.get_running_loop().time()
        if remaining <= 0:
            raise TimeoutError(f"migration gate deadline waiting for {description}")
        try:
            await asyncio.wait_for(changed.wait(), remaining)
        except asyncio.TimeoutError:
            raise TimeoutError(f"migration gate deadline waiting for {description}") from None


def phase_receipts(events, phase):
    failed = next((event for event in events
                   if event.get("event") == "result" and event.get("passed") is not True), None)
    if failed:
        raise RuntimeError(f"peer failed: {failed.get('reason')}")
    return {event["label"] for event in events
            if event.get("event") == "phase" and event["phase"] == phase} == {"migrating", "control"}


async def exercise(args):
    processes = []
    changed = asyncio.Event()
    deadline = asyncio.get_running_loop().time() + args.timeout
    try:
        project = args.project.resolve() if args.project else ROOT
        environment = consumer_environment(project) if args.project else None
        runner = await Process.start("server", [
            "mix", "run", "--no-compile", "--no-deps-check", str(ROOT / "scripts/migration/gate.exs"),
            "--mode", args.mode, "--timeout-ms", str(max(1, int(args.timeout * 1000)))], changed,
            cwd=project, env=environment)
        processes.append(runner)
        listening = await wait_until(
            lambda: next((event for event in runner.events if event.get("event") == "listening"), None),
            processes, changed, deadline)
        peer_command = ([args.peer_python] if args.peer_python else [
            "uv", "run", "--python", "3.12", "--with", f"aioquic=={PINNED_AIOQUIC}", "python"])
        peer = await Process.start("peer", peer_command + [
            str(ROOT / "scripts/migration/peer.py"), "--host", listening["host"], "--port", str(listening["port"]),
            "--ca", str(ROOT / "apps/elixir_quic/test/fixtures/tls/root.pem"),
            "--controlled",
            "--timeout", str(max(0.001, deadline - asyncio.get_running_loop().time()))], changed)
        processes.append(peer)
        relay = await wait_until(
            lambda: next((event for event in peer.events if event.get("event") == "relay_ready"), None),
            processes, changed, deadline, "peer relay addresses")
        paths = []
        for index, phase in enumerate(PHASES):
            await wait_until(lambda: phase_receipts(peer.events, phase), processes, changed, deadline,
                             f"{phase} stream/FIN/DATAGRAM receipts")
            snapshot = await wait_until(
                lambda: path_receipt(runner.events, relay["backends"][index],
                                     retired=index == 1, require_mtu=index > 0),
                processes, changed, deadline,
                f"{phase} active validated path" + (" with MTU validation" if index > 0 else "")
                + (" and old-path retirement" if index == 1 else ""))
            paths.append({"phase": phase, "snapshot": snapshot})
            emit("path_validated", phase=phase, snapshot=snapshot)
            peer.process.stdin.write(b"continue\n")
            await peer.process.stdin.drain()
        result = await wait_until(
            lambda: next((event for event in peer.events if event.get("event") == "result"), None),
            processes, changed, deadline)
        assert result.get("passed") is True, result.get("reason", "peer failed")
        await wait_until(lambda: sum(event.get("event") == "stream_complete" for event in runner.events) >= 2,
                         [runner], changed, deadline)
        proof = validate_proof(runner.events, result)
        migrating = next(item for item in proof["server"]["streams"]
                         if item["sha256"] == result["proof"]["connections"][0]["sha256"])
        assert all(item["snapshot"]["connection"] == migrating["connection"] for item in paths), "path connection changed"
        proof["server"]["paths"] = paths
        runner.process.stdin.write(b"stop\n")
        await runner.process.stdin.drain()
        runner.process.stdin.close()
        remaining = deadline - asyncio.get_running_loop().time()
        await asyncio.wait_for(asyncio.gather(*(process.process.wait() for process in processes)),
                               max(0.001, remaining))
        await asyncio.wait_for(asyncio.gather(*(process.reader for process in processes)),
                               max(0.001, deadline - asyncio.get_running_loop().time()))
        assert all(process.process.returncode == 0 for process in processes), "unclean server/peer exit"
        assert any(event.get("event") == "stopped" for event in runner.events), "missing server shutdown receipt"
        # Check again after EOF so late replacement connections cannot escape validation.
        proof = validate_proof(runner.events, result)
        proof["server"]["paths"] = paths
        return proof
    finally:
        outcomes = await asyncio.gather(*(process.cleanup() for process in processes), return_exceptions=True)
        failures = [str(result) for result in outcomes if isinstance(result, BaseException)]
        emit("cleanup", passed=not failures, processes=len(processes), errors=failures)
        if failures:
            raise RuntimeError(f"owned process cleanup failed: {failures}")


async def main(args):
    try:
        proof = await exercise(args)
    except Exception as error:
        emit("result", passed=False, mode=args.mode, reason=f"{type(error).__name__}: {error}")
        return 1
    emit("result", passed=True, mode=args.mode, proof=proof)
    return 0


if __name__ == "__main__":
    if not __debug__:
        raise RuntimeError("the acceptance gate requires Python assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("standalone", "abyss"), required=True)
    parser.add_argument("--timeout", type=positive_timeout, default=30)
    parser.add_argument("--peer-python", help="Python with aioquic==1.2.0; otherwise use pinned uv")
    parser.add_argument("--project", type=Path, help="prepared exact Hex consumer Mix project")
    raise SystemExit(asyncio.run(main(parser.parse_args())))
