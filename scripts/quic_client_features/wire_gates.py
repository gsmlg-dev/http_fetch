#!/usr/bin/env python3
"""Task-owned, bounded independent network acceptance against pinned engines."""
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

# Every verdict below is a bare `assert`; `python -O` or PYTHONOPTIMIZE would
# strip them and turn every gate into a vacuous pass.
if sys.flags.optimize:
    sys.exit("wire_gates.py: refusing to run with assertions disabled (python -O / PYTHONOPTIMIZE)")

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


QUIC_GO = ("quic-go-v0.62.0", "github.com/quic-go/quic-go@v0.62.0")
ONE_CONNECTION = {"endpoint": 1, "connection": 1, "io": 1, "port": 1}


def qlogs(directory):
    """Peer-side qlog (quic-go public qlog.DefaultConnectionTracer), keyed by client port."""
    traces = {}
    for path in Path(directory).glob("*_server.sqlog"):
        chunks = [json.loads(chunk) for chunk in path.read_text().split("\x1e") if chunk.strip()]
        header, events = chunks[0], chunks[1:]
        started = next(item for item in events if item["name"] == "transport:connection_started")
        reference = header["trace"]["common_fields"]["reference_time"]["wall_clock_time"]
        base = datetime.fromisoformat(reference).timestamp() * 1e9
        for event in events:
            event["wall_ns"] = base + event["time"] * 1e6
        traces[str(started["data"]["remote"]["port_v4"])] = events
    return traces


def qlogs_all(directory):
    """Every peer trace as (client port, events) in connection start order;
    one endpoint may own several."""
    traces = []
    for path in Path(directory).glob("*_server.sqlog"):
        chunks = [json.loads(chunk) for chunk in path.read_text().split("\x1e") if chunk.strip()]
        started = next(item for item in chunks[1:] if item["name"] == "transport:connection_started")
        reference = chunks[0]["trace"]["common_fields"]["reference_time"]["wall_clock_time"]
        traces.append((datetime.fromisoformat(reference).timestamp() + started["time"] / 1000,
                       str(started["data"]["remote"]["port_v4"]), chunks[1:]))
    return [(port, events) for _, port, events in sorted(traces, key=lambda trace: trace[0])]


def frames(events, direction, kind, stream):
    found = []
    for event in events:
        if event["name"] == f"transport:packet_{direction}":
            for frame in event["data"].get("frames", []):
                if frame["frame_type"] == kind and frame.get("stream_id") == stream:
                    found.append((event, frame))
    return found


def pattern(offset, length):
    return bytes((offset + index) % 251 for index in range(length))


def verify_reset(gate, local, remote, qlog_dir):
    negotiated = gate == "reset-negative"
    listening = next(item for item in remote if item["event"] == "listening")
    assert any(item["event"] == "peer_closed" for item in remote), "peer did not flush its traces"
    assert (listening["peer"], listening["module"]) == QUIC_GO, listening
    assert listening["mode"] == "matrix" and listening["qlog"] and listening["reliable_reset"] == negotiated, listening
    suite = "matrix" if negotiated else "not-negotiated"
    assert any(item["event"] == "suite" and item["suite"] == suite and item["passed"] for item in local), suite
    expected = (["outgoing_loss", "outgoing_reorder", "incoming_loss", "incoming_reorder", "stop_repeat",
                 "prefix_beyond_admitted"] if negotiated else ["not_negotiated"])
    cases = {item["case"]: item for item in local if item["event"] == "case"}
    assert sorted(cases) == sorted(expected), cases.keys()
    traces = qlogs(qlog_dir)
    handshakes = [item for item in remote if item["event"] == "handshake"]
    assert len(handshakes) == len(expected), handshakes
    for name, record in cases.items():
        receipt = next(item["receipt"] for item in local if item["event"] == "cleanup" and item["case"] == name)
        assert receipt["roles"] == ONE_CONNECTION and receipt["down"] == receipt["enrolled"] == 4, (name, receipt)
        assert receipt["cleanup"] == "confirmed" and receipt["native_outcome"] == "resolved", (name, receipt)
        assert receipt["unresolved_births"] == receipt["unresolved_operations"] == 0, (name, receipt)
        # One independent handshake per case, seen from this case's relay address.
        view = record["peer_view"]
        shake = [item for item in handshakes if item["remote"] == view]
        assert len(shake) == 1, (name, shake)
        assert shake[0]["reliable_reset"] == {"Local": negotiated, "Remote": True}, shake
        events = traces[view.rsplit(":", 1)[1]]
        streams = [item for item in remote if item["event"] in ("stream", "stop_sent") and item["conn"] == shake[0]["conn"]]
        for item in local:
            if item.get("case") != name:
                continue
            if item["event"] == "outgoing":
                stream = item["stream"]
                peer = next(entry for entry in streams if entry["stream"] == stream and entry["event"] == "stream")
                payload = b"sink\n" + pattern(0, 8000 - 5)
                assert peer["reset_code"] == 42 and peer["reset_remote"] and 6000 <= peer["bytes"] <= 8000, peer
                assert peer["sha256"] == hashlib.sha256(payload[:peer["bytes"]]).hexdigest(), peer
                resets = frames(events, "received", "reset_stream_at", stream)
                assert resets and all((f["error_code"], f["final_size"], f["reliable_size"]) == (42, 8000, 6000)
                                      for _, f in resets), resets
                assert not frames(events, "received", "reset_stream", stream)
                if item["mode"] == "drop":
                    # Admitted before the drop window closed, first received after it,
                    # with gaps in the runtime packet numbers quic-go received.
                    assert resets[0][0]["wall_ns"] > item["window_end_ns"] > item["admitted_ns"], (resets[0], item)
                    numbers = sorted(event["data"]["header"]["packet_number"] for event in events
                                     if event["name"] == "transport:packet_received"
                                     and event["data"]["header"]["packet_type"] == "1RTT")
                    assert len(numbers) < numbers[-1] + 1, "no runtime packet was lost"
                else:
                    # RESET_STREAM_AT reached quic-go before part of the reliable prefix.
                    first = events.index(resets[0][0])
                    later = [frame for event, frame in frames(events, "received", "stream", stream)
                             if events.index(event) > first and frame["offset"] < 6000]
                    assert later, "reset did not overtake prefix data"
            elif item["event"] == "incoming":
                stream = item["stream"]
                assert 6000 <= item["received"] <= 8000
                assert item["sha256"] == hashlib.sha256(pattern(0, item["received"])).hexdigest(), item
                sent = frames(events, "sent", "reset_stream_at", stream)
                assert sent and all((f["error_code"], f["final_size"], f["reliable_size"]) == (43, 8000, 6000)
                                    for _, f in sent), sent
                relay = next(entry for entry in local if entry["event"] == "relay" and entry["case"] == name)["stats"]["s2c"]
                if item["mode"] == "drop":
                    assert relay["dropped"] > 0 and len(sent) >= 2, (relay, sent)
                    assert any(event["name"] == "recovery:packet_lost" for event in events)
                else:
                    hold = relay["holds"][0]
                    assert hold["count"] >= 2, relay
                    reset_number = sent[0][0]["data"]["header"]["packet_number"]
                    prefix = [event for event, frame in frames(events, "sent", "stream", stream)
                              if frame["offset"] < 6000 and event["data"]["header"]["packet_number"] < reset_number]
                    assert prefix and item["armed_ns"] < prefix[0]["wall_ns"] < sent[0][0]["wall_ns"] < hold["released_ns"], (
                        item, hold, prefix[:1], sent[:1])
            elif item["event"] == "stop_answer":
                stream = item["stream"]
                stops = frames(events, "sent", "stop_sending", stream)
                assert stops and all(f["error_code"] == item["code"] for _, f in stops), stops
                if item["repeated"]:
                    # The drop was armed before quic-go's first STOP_SENDING.
                    assert len(stops) >= 2 and stops[0][0]["wall_ns"] > item["armed_ns"], (stops, item)
                answers = frames(events, "received", "reset_stream_at", stream)
                plain = frames(events, "received", "reset_stream", stream)
                if negotiated:
                    assert answers and not plain, (answers, plain)
                    assert {(f["error_code"], f["final_size"], f["reliable_size"]) for _, f in answers} == {
                        (item["code"], item["final_size"], item["reliable_size"])}, answers
                else:
                    assert plain and not answers, (answers, plain)
                    assert {(f["error_code"], f["final_size"]) for _, f in plain} == {(item["code"], item["final_size"])}
        if not negotiated:
            assert not any(frame["frame_type"] == "reset_stream_at" for event in events
                           for frame in event.get("data", {}).get("frames", [])), "RESET_STREAM_AT without negotiation"


# Per case: the peer-observed sequence for each client endpoint (in endpoint
# order): resumed flags, Used0RTT flags and decrypted flags of every presented
# ticket. "sorted" compares concurrent connections as a multiset.
RESUMPTION_CASES = {
    "r1": {
        "partition_by_remote": [{"resumed": [False, False, True], "listeners": [0, 1, 0], "tickets": [True]}],
        "endpoint_restart": [{"resumed": [False], "tickets": []}, {"resumed": [False], "tickets": []}],
        "stale_ticket": [{"resumed": [False, True, False, True], "tickets": [True, False, True], "rotated": 1}],
        "concurrent_single_use": [{"resumed": [False, False, True], "sorted": True, "tickets": [True]}],
    },
    "hrr": {
        "hrr_resumption": [{"resumed": [False, True], "early": [False, False], "tickets": [True]}],
        "hrr_early": [{"resumed": [False, True], "early": [False, False], "tickets": [True], "rejected": True}],
    },
    "r2": {
        "quota_exhaustion": [{"resumed": [False, True], "early": [False, True], "tickets": [True], "quota": True}],
        "stale_ticket_early": [{"resumed": [False, True, False], "tickets": [True, False], "rotated": 1,
                                "rejected": True}],
        "concurrent_early": [{"resumed": [False, False, True], "early": [False, False, True], "sorted": True,
                              "tickets": [True]}],
    },
    "r2-rejected": {
        "rejected_by_peer": [{"resumed": [False, True], "early": [False, False], "tickets": [True],
                              "cleared": True, "rejected": True}],
    },
    "r2-retry": {
        "retry_early": [{"resumed": [False, True], "early": [False, True], "tickets": [True], "retry": True}],
    },
}


def zero_rtt_frames(events, kind):
    return [frame for event in events if event["name"] == "transport:packet_received"
            and event["data"]["header"]["packet_type"] == "0RTT"
            for frame in event["data"].get("frames", []) if frame["frame_type"] == kind]


def verify_resumption(gate, local, remote, qlog_dir):
    suite, flags = MATRIX[gate][1], MATRIX[gate][2]
    listening = next(item for item in remote if item["event"] == "listening")
    assert any(item["event"] == "peer_closed" for item in remote), "peer did not flush its traces"
    assert (listening["peer"], listening["module"]) == QUIC_GO, listening
    assert listening["allow_0rtt"] == ("--allow-0rtt" in flags) and listening["retry"] == ("--retry" in flags), listening
    assert listening["reject_early"] == ("--reject-early" in flags) and len(listening["addresses"]) == (
        2 if "--listeners" in flags else 1), listening
    hrr = "--curves" in flags
    assert listening["curves"] == ("p256" if hrr else ""), listening
    assert any(item["event"] == "suite" and item["suite"] == suite and item["passed"] for item in local), suite
    traces = qlogs_all(qlog_dir)
    handshakes = [item for item in remote if item["event"] == "handshake"]
    presented = [item for item in remote if item["event"] == "ticket_presented"]
    peer_streams = [item for item in remote if item["event"] == "stream"]
    expected = RESUMPTION_CASES[suite]
    seen_cases = {item["case"] for item in local if item["event"] == "case_end"}
    assert seen_cases == set(expected), seen_cases
    total = 0
    for name, endpoints in expected.items():
        addresses = [item["local"] for item in local if item["event"] == "endpoint" and item["case"] == name]
        assert len(addresses) == len(endpoints), (name, addresses)
        for address, spec in zip(addresses, endpoints):
            connections = sorted((item for item in local if item["event"] == "connection" and item["local"] == address),
                                 key=lambda item: item["index"])
            shakes = sorted((item for item in handshakes if item["remote"] == address), key=lambda item: item["conn"])
            total += len(shakes)
            assert len(connections) == len(shakes) == len(spec["resumed"]), (name, connections, shakes)
            order = sorted if spec.get("sorted") else list
            # The runtime and the independent peer agree, and match the expectation.
            assert order([item["resumed"] for item in shakes]) == order([item["resumed"] for item in connections]) \
                == order(spec["resumed"]), (name, shakes, connections)
            early = [item["early"] for item in shakes]
            if "early" in spec:
                assert order(early) == order(spec["early"]), (name, shakes)
            if "listeners" in spec:
                assert [item["listener"] for item in shakes] == spec["listeners"], (name, shakes)
            assert all(item["hrr"] == hrr for item in shakes), (name, shakes)
            if hrr:
                assert all(item["curve"] == "CurveP256" for item in shakes), shakes
            tickets = [item for item in presented if item["remote"] == address]
            assert [item["decrypted"] for item in tickets] == spec["tickets"], (name, tickets)
            assert all(item["early_cleared"] == bool(spec.get("cleared")) for item in tickets if item["decrypted"]
                       and item["early"]), (name, tickets)
            rotated = [item for item in remote if item["event"] == "rotated"
                       and item["conn"] in {shake["conn"] for shake in shakes}]
            assert len(rotated) == spec.get("rotated", 0), (name, rotated)
            receipt = next(item["receipt"] for item in local if item["event"] == "cleanup" and item["local"] == address)
            assert receipt["roles"] == {"endpoint": 1, "connection": len(connections), "io": 1, "port": 1}, receipt
            assert receipt["down"] == receipt["enrolled"] and receipt["cleanup"] == "confirmed", receipt
            assert receipt["native_outcome"] == "resolved" and receipt["unresolved_births"] == 0, receipt
            assert receipt["unresolved_operations"] == 0, receipt
            # Every exact echo the runtime saw was read, with FIN, by the peer
            # application on a connection from this endpoint.
            conns = {shake["conn"] for shake in shakes}
            mine = [item for item in peer_streams if item["conn"] in conns and item["command"] == "echo"]
            for echo in (item for item in local if item["event"] == "echo" and item["local"] == address):
                match = [item for item in mine if item["sha256"] == echo["sha256"] and item["bytes"] == echo["bytes"]]
                assert len(match) == 1 and match[0]["fin"], (name, echo, match)
            # One endpoint keeps its port, so it owns one peer trace per connection,
            # in the same (sequential) order as the runtime's connection indexes.
            port_traces = [events for port, events in traces if port == address.rsplit(":", 1)[1]]
            assert len(port_traces) == len(shakes), (name, len(port_traces))
            if spec.get("rejected"):
                rejected = [item for item in connections if "rejection" in item]
                assert len(rejected) == 1 and rejected[0]["early_data"] == "rejected", rejected
                # Rejected early bytes never reached the peer application; the
                # explicit re-send did, exactly once.
                assert not [item for item in mine if item["sha256"] == rejected[0]["early_sha256"]], name
                assert len([item for item in mine if item["sha256"] == rejected[0]["resent_sha256"]]) == 1, name
                # ...and that is not vacuous: quic-go did see 0-RTT packets on that
                # connection (received and discarded, or dropped without keys).
                zero_rtt = [event for event in port_traces[rejected[0]["index"]]
                            if event["name"] in ("transport:packet_received", "transport:packet_dropped")
                            and event["data"].get("header", {}).get("packet_type") == "0RTT"]
                assert zero_rtt, (name, "no 0-RTT packet reached the peer")
            if spec.get("retry"):
                # A token on the first Initial can only come from Retry: the runtime
                # discards NEW_TOKEN (handshake_scheduler.ex, dispatch_frame :new_token)
                # and never reuses address-validation tokens across connections.
                for events in port_traces:
                    initial = next(event for event in events if event["name"] == "transport:packet_received"
                                   and event["data"]["header"]["packet_type"] == "initial")
                    assert initial["data"]["header"].get("token"), "first Initial carried no Retry token"
                early_trace = [events for events in port_traces if zero_rtt_frames(events, "stream")]
                assert len(early_trace) == 1, "no 0-RTT stream after Retry"
                streams = zero_rtt_frames(early_trace[0], "stream")
                assert any(frame["offset"] == 0 and frame.get("fin") and frame["length"] == 317 for frame in streams), streams
            if spec.get("quota"):
                early_trace = [events for events in port_traces if zero_rtt_frames(events, "stream")]
                assert len(early_trace) == 1, "no 0-RTT"
                streams = zero_rtt_frames(early_trace[0], "stream")
                ends = {}
                for frame in streams:
                    ends[frame["stream_id"]] = max(ends.get(frame["stream_id"], 0), frame["offset"] + frame["length"])
                # Never beyond the remembered limits: 8 bidi streams, 64 KiB credit.
                # (quic-go may drop 0-RTT packets that outrun its connection setup;
                # the runtime then retransmits them under 1-RTT keys.)
                assert set(ends) <= {4 * index for index in range(8)}, ends
                assert ends.get(0, 0) <= 64005 and sum(ends.values()) <= 65536, ends
                assert len(zero_rtt_frames(early_trace[0], "datagram")) <= 64
    assert total == len(handshakes), (total, len(handshakes))


def verify_late(client, server):
    """R2 late 0-RTT receipt at the runtime's server role, unmodified quic-go client."""
    started = next(item for item in client if item["event"] == "client_started")
    assert (started["peer"], started["module"]) == QUIC_GO, started
    flights = [item for item in client if item["event"] == "handshake"]
    assert [(item["resumed"], item["early"]) for item in flights] == [(False, False), (True, True), (True, True)], flights
    assert all(item["echo_exact"] and item["bytes"] == 20007 for item in flights), flights
    # Connections outlived the late datagrams (no CONNECTION_CLOSE from the runtime).
    assert [item["alive"] for item in client if item["event"] == "closing"] == [True, True, True], client
    shakes = [item for item in server if item["event"] == "handshake"]
    assert [(item["resumed"], item["early"]) for item in shakes] == [(False, False), (True, True), (True, True)], shakes
    episodes = [item for item in server if item["event"] == "late_episode"]
    assert [(item["connection"], item["delay_ms"]) for item in episodes] == [(1, 0), (2, 1000)], episodes
    for item in episodes:
        assert item["held"] >= 1 and item["phase"] == "established" and item["early_data"] == "accepted", item
        assert item["key_deadline_seen"] and not item["early_keys_after"], item
    # Delay 0 arrived while early read keys were retained; delay 1000 after they retired.
    assert [item["arrived_before_key_retirement"] for item in episodes] == [True, False], episodes
    relay = next(item for item in server if item["event"] == "relay")["stats"]["late"]
    assert [episode["held"] for episode in relay] == [item["held"] for item in episodes], relay
    assert next(item for item in server if item["event"] == "server_complete")["streams"] == 3
    cleanup = next(item for item in server if item["event"] == "server_cleanup")
    assert cleanup["io_down"] and cleanup["native_port_down"], cleanup


# gate: (driver script, suite, quic-go matrix flags, verifier)
MATRIX = {
    "reset-negative": ("reset_negative", "matrix", ["--qlog"], verify_reset),
    "reset-not-negotiated": ("reset_negative", "not-negotiated", ["--qlog", "--no-reliable-reset"], verify_reset),
    "resumption-negative": ("resumption_negative", "r1", ["--qlog", "--listeners", "2"], verify_resumption),
    "resumption-hrr": ("resumption_negative", "hrr", ["--qlog", "--curves", "p256", "--allow-0rtt"], verify_resumption),
    "early-negative": ("resumption_negative", "r2", ["--qlog", "--allow-0rtt"], verify_resumption),
    "early-rejected": ("resumption_negative", "r2-rejected", ["--qlog", "--allow-0rtt", "--reject-early"],
                       verify_resumption),
    "early-retry": ("resumption_negative", "r2-retry", ["--qlog", "--allow-0rtt", "--retry"], verify_resumption),
}


def wait_listening(process, path):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        for item in records(path.read_text()):
            if item.get("event") == "listening":
                if "addresses" in item:
                    return ",".join(address.rsplit(':', 1)[1] for address in item["addresses"])
                return str(item.get("port") or item["address"].rsplit(':', 1)[1])
        assert process.poll() is None, path.read_text()
        time.sleep(.02)
    raise AssertionError("startup deadline")


def run(args):
    with tempfile.TemporaryDirectory(prefix="quic-A-wire-") as directory:
        log = Path(directory) / "peer.log"
        environment = dict(os.environ, QUIC_EARLY_BARRIER=str(Path(directory) / "finished.release"),
                           QLOGDIR=str(Path(directory) / "qlog"))
        suite = []
        if args.gate in MATRIX:
            script, suite_name, flags, _ = MATRIX[args.gate]
            command = [args.go_binary, "--mode", "matrix"] + flags + [
                "--cert", str(FIXTURE / "leaf.pem"), "--key", str(FIXTURE / "leaf-key.pem")]
            suite = [suite_name]
        elif args.gate in NEGATIVE:
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
        elif args.gate == "early-late-server":
            feature = "late"
            command = ["mix", "run", "scripts/quic_client_features/early_late_server.exs"]
            script = None
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
                suite = [NEGATIVE[args.gate][0]] if args.gate in NEGATIVE else suite
                command = (["mix", "run", f"scripts/quic_client_features/{script}.exs", port] + suite if script else
                    [args.go_binary, "--mode", "client", "--port", port, "--ca", str(FIXTURE / "root.pem")]
                    if feature == "late" else
                    [args.python, f"scripts/quic_client_features/{feature}_peer.py", "--role", "client", "--port", port] +
                    (["--barrier", environment["QUIC_EARLY_BARRIER"]] if feature == "early" else []))
                client = subprocess.run(command, cwd=ROOT, env=environment, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True,
                                        timeout=80 if args.gate in NEGATIVE else 150 if args.gate in MATRIX else 35)
                print(client.stdout, end="")
                if not script:
                    peer.wait(timeout=8)
                if args.gate in MATRIX:
                    # The peer closes its connections on SIGTERM, flushing every qlog trace.
                    peer.terminate()
                    peer.wait(timeout=8)
                remote_text = log.read_text()
                print(remote_text, end="")
                printed_remote = True
                assert client.returncode == 0, f"client exit {client.returncode}"
                local, remote = records(client.stdout), records(remote_text)
                if args.gate in NEGATIVE:
                    verify_negative(args.gate, local, remote)
                elif args.gate in MATRIX:
                    MATRIX[args.gate][3](args.gate, local, remote, environment["QLOGDIR"])
                elif args.gate == "early-late-server":
                    verify_late(local, remote)
                elif script:
                    migrations = args.gate in ("migration", "early-migration")
                    connections = 2 if args.gate in ("resumption-client", "early-client", "early-migration") else 1
                    verify_cleanup(local, {"endpoint": 1, "connection": connections,
                                           "io": 3 if migrations else 1, "port": 3 if migrations else 1})
                else:
                    cleanup = next(item for item in remote if item["event"] == "server_cleanup")
                    assert cleanup["io_down"] and cleanup["native_port_down"], cleanup
                if args.gate in NEGATIVE or args.gate in MATRIX or args.gate == "early-late-server":
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
    parser.add_argument("--gate", choices=["migration", "reset", "resumption-client", "resumption-server", "early-client", "early-server", "early-migration", "early-late-server"] + list(NEGATIVE) + list(MATRIX), required=True)
    parser.add_argument("--go-binary", default="/tmp/http-fetch-quic-A-go-peer/peer",
                        help="quic-go v0.62.0 peer; build it from this directory's go.mod/go.sum with "
                             "GOFLAGS=-mod=readonly go build -trimpath -o <path> .")
    parser.add_argument("--python", default="/tmp/http-fetch-quic-A-peer/bin/python")
    parser.add_argument("--quinn-binary", default="/tmp/http-fetch-quic-A-quinn-peer/quinn-m2-peer")
    run(parser.parse_args())
