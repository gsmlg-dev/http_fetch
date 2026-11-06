#!/usr/bin/env python3
"""Real UDP delivery gates in fixture-owned Linux namespaces; no ambient LAN.

Only setup/teardown commands require sudo. Network participants drop to the
invoking uid/gid before running Python or BEAM. All packet assertions are hard
failures; missing namespace privilege is a separately reported BLOCKED gate.
"""
import argparse
import base64
import contextlib
import json
import os
import queue
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GROUPS = {4: ("239.192.74.1", "239.192.74.2"), 6: ("ff02::114", "ff02::115")}
PORTS = {4: 38741, 6: 38742}
OBSERVER_PORTS = {4: 38743, 6: 38744}
PAYLOAD_SIZES = set()


def encode(payload):
    # A marker also represents empty payloads in the whitespace control protocol.
    return base64.b64encode(payload).decode() or "-"


def peer_worker():
    sockets = {}
    try:
        for line in sys.stdin:
            request = json.loads(line)
            operation = request["op"]
            try:
                label = request.get("label")
                if operation == "indices":
                    result = {name: index for index, name in socket.if_nameindex()}
                elif operation == "interfaces":
                    result = {}
                    with open("/proc/net/if_inet6") as addresses:
                        for entry in addresses:
                            address, _, _, scope, _, interface = entry.split()
                            if scope == "20":
                                result[interface] = socket.inet_ntop(socket.AF_INET6, bytes.fromhex(address))
                    assert "eth0" in result and "eth1" in result, result
                elif operation == "open":
                    family = request["family"]
                    endpoint = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
                    endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    endpoint.settimeout(2)
                    interface = request.get("interface", "eth0")
                    index = socket.if_nametoindex(interface)
                    # Membership alone does not strictly filter IPv6 same-group
                    # traffic arriving/looping through another local interface.
                    # These independent observers explicitly select their device.
                    endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                        interface.encode() + b"\0")
                    if family == 4:
                        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                        endpoint.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(request["source"]))
                        endpoint.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, request.get("ttl", 1))
                        endpoint.setsockopt(socket.IPPROTO_IP, 12, 1)  # Linux IP_RECVTTL
                        endpoint.setsockopt(socket.IPPROTO_IP, 49, 0)  # Linux IP_MULTICAST_ALL
                        for group in request.get("groups", []):
                            endpoint.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                                socket.inet_aton(group) + socket.inet_aton(request["source"]))
                        bind = (request.get("bind", "0.0.0.0"), request.get("port", 0))
                    else:
                        endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
                        endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, request.get("ttl", 1))
                        endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
                        endpoint.setsockopt(socket.IPPROTO_IPV6, 29, 0)  # Linux IPV6_MULTICAST_ALL
                        for group in request.get("groups", []):
                            endpoint.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                                                socket.inet_pton(socket.AF_INET6, group) + struct.pack("@I", index))
                        bind = (request.get("bind", "::"), request.get("port", 0), 0, 0)
                    endpoint.bind(bind)
                    sockets[label] = (endpoint, family, index)
                    result = endpoint.getsockname()
                elif operation == "send":
                    endpoint, family, index = sockets[label]
                    payload = base64.b64decode(request["payload"]) if request["payload"] != "-" else b""
                    destination = (request["address"], request["port"])
                    if family == 6:
                        destination += (0, index)
                    result = endpoint.sendto(payload, destination)
                    assert result == len(payload), "partial datagram send"
                elif operation in ("recv", "none"):
                    endpoint, family, _ = sockets[label]
                    endpoint.settimeout(request.get("timeout", 2 if operation == "recv" else 0.15))
                    try:
                        payload, ancillary, flags, peer = endpoint.recvmsg(65536, 256)
                        assert not flags & socket.MSG_TRUNC, "truncated datagram"
                        ttl = None
                        for level, kind, value in ancillary:
                            if (level, kind) in ((socket.IPPROTO_IP, socket.IP_TTL),
                                                (socket.IPPROTO_IPV6, socket.IPV6_HOPLIMIT)):
                                ttl = struct.unpack("@i", value)[0]
                        assert operation != "none", f"unexpected packet {payload!r} from {peer!r}"
                        result = {"payload": encode(payload), "peer": peer, "ttl": ttl}
                    except socket.timeout:
                        assert operation == "none", "required packet was not delivered before deadline"
                        result = True
                elif operation == "close":
                    sockets.pop(label)[0].close()
                    result = True
                elif operation == "stop":
                    print(json.dumps({"ok": True}), flush=True)
                    return
                else:
                    raise AssertionError(f"unknown operation {operation}")
                print(json.dumps({"ok": result}), flush=True)
            except Exception as error:
                print(json.dumps({"error": repr(error)}), flush=True)
    finally:
        for endpoint, _, _ in sockets.values():
            endpoint.close()


class Child:
    def __init__(self, fixture, namespace, command, wire=False):
        drop = [shutil.which("setpriv"), f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups"]
        environment = [shutil.which("env"), f"PATH={os.environ['PATH']}", f"HOME={os.environ['HOME']}", "MIX_ENV=dev"]
        for key in ("MIX_HOME", "HEX_HOME", "MIX_BUILD_PATH", "ERL_FLAGS", "ELIXIR_ERL_OPTIONS", "ABYSS_UDP_BACKEND", "ABYSS_UDP_API", "ABYSS_UDP_EXECUTION"):
            if key in os.environ:
                environment.append(f"{key}={os.environ[key]}")
        if os.environ.get("CI"):
            environment.append("CI=true")
        argv = fixture.privileged + ["ip", "netns", "exec", namespace] + drop + environment + command
        self.process = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lines = queue.Queue()
        self.events = []
        self.wire = wire
        self.serial = 0
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        fixture.children.append(self)

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line.rstrip("\n"))
        self.lines.put(None)

    def wait(self, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0, f"child deadline expired; output={self.events[-15:]}"
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty:
                raise AssertionError(f"child deadline expired; output={self.events[-15:]}")
            assert line is not None, f"child exited {self.process.poll()}; output={self.events[-15:]}"
            self.events.append(line)
            if predicate(line):
                return line

    def rpc(self, **request):
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self.wait(lambda item: item.startswith('{"'), timeout=5)
        result = json.loads(line)
        assert "error" not in result, f"{request['op']} {request.get('label')}: {result.get('error')}"
        return result["ok"]

    def command(self, *arguments):
        if arguments[0] == "SEND":
            PAYLOAD_SIZES.add(len(base64.b64decode(arguments[-1])) if arguments[-1] != "-" else 0)
        self.serial += 1
        marker = str(self.serial)
        self.process.stdin.write(" ".join([marker] + [str(arg) for arg in arguments]) + "\n")
        self.process.stdin.flush()
        line = self.wait(lambda item: item.startswith(f"WIRE OK {marker}") or item.startswith(f"WIRE ERROR {marker}"))
        assert line == f"WIRE OK {marker}", line

    def received(self, family, payload, timeout=2):
        marker = f"WIRE RX{family} {encode(payload)}"
        if marker in self.events:
            self.events.remove(marker)
            return
        self.wait(lambda line: line == marker, timeout)
        self.events.remove(marker)

    def metadata(self, family, payload, destination, interface, local_address=None):
        suffix = " " + encode(payload)
        prefix = f"WIRE META {family} "
        def matches(line):
            return line.startswith(prefix) and line.endswith(suffix)
        line = next((line for line in self.events if matches(line)), None)
        if line is None:
            line = self.wait(matches, timeout=2)
        self.events.remove(line)
        _, _, actual_family, actual_dst, actual_if, actual_local, scope, hop, _ = line.split()
        assert int(actual_family) == family, line
        assert actual_dst == destination, line
        assert int(actual_if) == interface, line
        assert int(hop) > 0, line
        if local_address is not None:
            assert actual_local == local_address, line
        return dict(scope=int(scope), local=actual_local)

    def assert_no_received(self, family, payload, timeout=0.2):
        marker = f"WIRE RX{family} {encode(payload)}"
        assert marker not in self.events, f"unexpected Abyss delivery: {marker}"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                line = self.lines.get(timeout=deadline - time.monotonic())
            except queue.Empty:
                return
            assert line is not None, "Abyss exited during negative delivery gate"
            self.events.append(line)
            assert line != marker, f"unexpected Abyss delivery: {marker}"

    def stop(self):
        if self.process.poll() is None:
            with contextlib.suppress(Exception):
                if self.wire:
                    self.command("STOP")
                else:
                    self.rpc(op="stop")
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=3)
        if self.process.poll() is None:
            self.process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=2)
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=2)


class Fixture:
    def __init__(self):
        self.prefix = "abyss-udp-" + uuid.uuid4().hex[:8]
        self.namespaces = []
        self.children = []
        self.privileged = [] if os.geteuid() == 0 else ["sudo", "-n"]
        self.server = self.prefix + "-server"
        self.peers = [self.prefix + "-peer1", self.prefix + "-peer2"]
        self.fabric = self.prefix + "-fabric"

    def setup_command(self, *arguments):
        subprocess.run(self.privileged + list(arguments), check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def setup(self):
        for name in [self.fabric, self.server] + self.peers:
            self.setup_command("ip", "netns", "add", name)
            self.namespaces.append(name)
            self.setup_command("ip", "-n", name, "link", "set", "lo", "up")
        for network in range(2):
            bridge = f"br{network}"
            self.setup_command("ip", "-n", self.fabric, "link", "add", bridge, "type", "bridge", "mcast_snooping", "0")
            self.setup_command("ip", "-n", self.fabric, "link", "set", bridge, "up")
            for endpoint, name in enumerate([self.server] + self.peers):
                fabric_end, node_end = f"f{network}{endpoint}", f"n{network}{endpoint}"
                interface = f"eth{network}"
                self.setup_command("ip", "-n", self.fabric, "link", "add", fabric_end, "type", "veth", "peer", "name", node_end)
                self.setup_command("ip", "-n", self.fabric, "link", "set", fabric_end, "master", bridge)
                self.setup_command("ip", "-n", self.fabric, "link", "set", fabric_end, "up")
                self.setup_command("ip", "-n", self.fabric, "link", "set", node_end, "netns", name)
                self.setup_command("ip", "-n", name, "link", "set", node_end, "name", interface)
                self.setup_command("ip", "-n", name, "link", "set", interface, "up")
                ipv4 = f"{'192.0.2' if network == 0 else '198.51.100'}.{10 + endpoint}"
                self.setup_command("ip", "-n", name, "addr", "add", ipv4 + "/24", "broadcast", "+", "dev", interface)
                self.setup_command("ip", "-n", name, "-6", "addr", "add", f"fd00:ab:74:{network}::{10 + endpoint}/64", "dev", interface, "nodad")
                if network == 0:
                    self.setup_command("ip", "-n", name, "route", "add", "224.0.0.0/4", "dev", interface)
                    self.setup_command("ip", "-n", name, "route", "add", "255.255.255.255/32", "dev", interface)
                    self.setup_command("ip", "-n", name, "-6", "route", "add", "ff00::/8", "dev", interface)

    def cleanup(self):
        for child in reversed(self.children):
            child.stop()
        for name in reversed(self.namespaces):
            with contextlib.suppress(subprocess.CalledProcessError):
                self.setup_command("ip", "netns", "del", name)


def open_peer(peer, label, family, endpoint, port=0, groups=(), network=0, bind=None):
    source = f"{'192.0.2' if network == 0 else '198.51.100'}.{endpoint}"
    options = dict(op="open", label=label, family=family, source=source, port=port,
                   groups=list(groups), interface=f"eth{network}")
    if bind is not None:
        options["bind"] = bind
    return peer.rpc(**options)


def send(peer, label, address, port, payload):
    PAYLOAD_SIZES.add(len(payload))
    return peer.rpc(op="send", label=label, address=address, port=port, payload=encode(payload))


def expect(peer, label, payload, source=None, source_port=None, ttl=None):
    PAYLOAD_SIZES.add(len(payload))
    packet = peer.rpc(op="recv", label=label)
    assert packet["payload"] == encode(payload), packet
    if source is not None:
        assert packet["peer"][0] == source, packet
    if source_port is not None:
        assert packet["peer"][1] == source_port, packet
    if ttl is not None:
        assert packet["ttl"] == ttl, packet
    return packet


def run_gates(fixture):
    backend = os.environ.get("ABYSS_UDP_BACKEND", "inet")
    assert backend in ("inet", "socket", "native"), f"unsupported fixture backend: {backend}"
    families = (4, 6) if backend != "socket" else (4,)
    command = [sys.executable, str(Path(__file__).resolve()), "--peer"]
    peers = [Child(fixture, namespace, command) for namespace in fixture.peers]
    observer = Child(fixture, fixture.server, command)
    server = Child(fixture, fixture.server,
                   [shutil.which("mix"), "run", "--no-compile", "--no-deps-check", "scripts/udp/server.exs",
                    str(PORTS[4]), str(PORTS[6])], wire=True)
    server.wait(lambda line: line == "WIRE READY", timeout=30)
    for line in server.events:
        if line.startswith("WIRE RUNTIME "):
            print(line, flush=True)
    print(json.dumps({"os": sys.platform, "kernel": os.uname().release,
                      "offered_load": "sequential barrier-qualified low-rate probes",
                      "seed": "unique epoch per run", "payloads": "empty and unique short epoch datagrams"}), flush=True)
    epoch = uuid.uuid4().hex.encode()
    passes = []

    def passed(name):
        passes.append(name)
        print(f"PASS {name}", flush=True)

    for number, peer in enumerate(peers, 11):
        open_peer(peer, "tx4", 4, number)
        open_peer(peer, "rx4", 4, number, PORTS[4], GROUPS[4])
        if 6 in families:
            open_peer(peer, "tx6", 6, number, bind=f"fd00:ab:74:0::{number}")
            open_peer(peer, "rx6", 6, number, PORTS[6], GROUPS[6])
    # The open acknowledgments prove bind and membership readiness before sends.
    for destination, label in [("255.255.255.255", "limited"), ("192.0.2.255", "directed")]:
        incoming = b"probe:broadcast:" + label.encode() + b":" + epoch
        send(peers[0], "tx4", destination, PORTS[4], incoming)
        server.received(4, incoming)
        expect(peers[0], "tx4", b"reply:" + incoming, "192.0.2.10", PORTS[4])
        for peer in peers:
            expect(peer, "rx4", incoming, "192.0.2.11")
        outgoing = b"emit:broadcast:" + label.encode() + b":" + epoch
        server.command("SEND", 4, destination, PORTS[4], "eth0", encode(outgoing))
        for peer in peers:
            expect(peer, "rx4", outgoing, "192.0.2.10", PORTS[4])
            peer.rpc(op="none", label="rx4")
        passed("broadcast_" + label + "_bidirectional_two_receivers")

    if backend in ("inet", "native"):
        # Another local socket creates a kernel membership that our endpoint
        # does not own. The independent observer proves the packet arrived.
        foreign_group = "239.192.74.3"
        open_peer(observer, "foreign4", 4, 10, PORTS[4], [foreign_group])
        foreign_payload = b"foreign-group:" + epoch
        send(peers[0], "tx4", foreign_group, PORTS[4], foreign_payload)
        expect(observer, "foreign4", foreign_payload)
        server.assert_no_received(4, foreign_payload)
        observer.rpc(op="close", label="foreign4")
        passed("ipv4_strict_group_filter_foreign_socket_membership")

    for family in families:
        for group_number, group in enumerate(GROUPS[family]):
            payload = f"probe:multicast{family}:group{group_number}:".encode() + epoch
            send(peers[0], f"tx{family}", group, PORTS[family], payload)
            server.received(family, payload)
            expect(peers[0], f"tx{family}", b"reply:" + payload, source_port=PORTS[family])
            for peer in peers:
                expect(peer, f"rx{family}", payload)
            outgoing = f"emit:multicast{family}:group{group_number}:".encode() + epoch
            server.command("SEND", family, group, PORTS[family], "eth0", encode(outgoing))
            for peer in peers:
                expect(peer, f"rx{family}", outgoing, source_port=PORTS[family], ttl=1)
                peer.rpc(op="none", label=f"rx{family}")
        passed(f"ipv{family}_two_groups_bidirectional_two_subscribers")
        group = GROUPS[family][0]
        interface = "192.0.2.10" if family == 4 else "eth0"
        server.command("LEAVE", family, group, interface)
        removed = f"emit:after_leave{family}:".encode() + epoch
        send(peers[0], f"tx{family}", group, PORTS[family], removed)
        for peer in peers:
            expect(peer, f"rx{family}", removed)
        server.assert_no_received(family, removed)
        server.command("JOIN", family, group, interface)
        server.command("JOIN", family, group, interface)  # duplicate is idempotent
        rejoined = f"probe:rejoin{family}:".encode() + epoch
        send(peers[0], f"tx{family}", group, PORTS[family], rejoined)
        server.received(family, rejoined)
        expect(peers[0], f"tx{family}", b"reply:" + rejoined, source_port=PORTS[family])
        for peer in peers:
            expect(peer, f"rx{family}", rejoined)
            peer.rpc(op="none", label=f"rx{family}")
        passed(f"ipv{family}_leave_rejoin_idempotent_epoch_barriers")

        # Same group, distinct incoming interfaces and explicitly selected egress.
        secondary = "198.51.100.10" if family == 4 else "eth1"
        server.command("JOIN", family, group, secondary)
        for number, peer in enumerate(peers, 11):
            open_peer(peer, f"alt_rx{family}", family, number, PORTS[family], [group], network=1)
        open_peer(peers[0], f"alt_tx{family}", family, 11, network=1,
                  bind="fd00:ab:74:1::11" if family == 6 else None)
        incoming = f"emit:second_interface{family}:".encode() + epoch
        send(peers[0], f"alt_tx{family}", group, PORTS[family], incoming)
        server.received(family, incoming)
        for peer in peers:
            expect(peer, f"alt_rx{family}", incoming)
            peer.rpc(op="none", label=f"rx{family}")
        server.command("INTERFACE", family, secondary)
        outgoing = f"emit:egress_interface{family}:".encode() + epoch
        server.command("SEND", family, group, PORTS[family], "eth1", encode(outgoing))
        for peer in peers:
            expect(peer, f"alt_rx{family}", outgoing, source_port=PORTS[family])
            peer.rpc(op="none", label=f"rx{family}")
        server.command("INTERFACE", family, interface)
        server.command("LEAVE", family, group, secondary)
        passed(f"ipv{family}_two_interfaces_membership_egress_isolation")

        # Ancillary TTL/hop values demonstrate actual wire behavior, not getopts.
        hop = 3 if family == 4 else 5
        server.command("OPTIONS", family, hop, "true")
        outgoing = f"emit:hop{family}:".encode() + epoch
        server.command("SEND", family, group, PORTS[family], "eth0", encode(outgoing))
        for peer in peers:
            expect(peer, f"rx{family}", outgoing, source_port=PORTS[family], ttl=hop)
        passed(f"ipv{family}_ttl_or_hoplimit_wire_ancillary")

        # A subscriber in the sending namespace distinguishes multicast loopback.
        open_peer(observer, f"local{family}", family, 10, OBSERVER_PORTS[family], [group])
        for number, peer in enumerate(peers, 11):
            open_peer(peer, f"loop{family}", family, number, OBSERVER_PORTS[family], [group])
        server.command("OPTIONS", family, 1, "false")
        outgoing = f"emit:loop_disabled{family}:".encode() + epoch
        server.command("SEND", family, group, OBSERVER_PORTS[family], "eth0", encode(outgoing))
        for peer in peers:
            expect(peer, f"loop{family}", outgoing, ttl=1)
        observer.rpc(op="none", label=f"local{family}")
        server.command("OPTIONS", family, 1, "true")
        outgoing = f"emit:loop_enabled{family}:".encode() + epoch
        server.command("SEND", family, group, OBSERVER_PORTS[family], "eth0", encode(outgoing))
        for peer in peers:
            expect(peer, f"loop{family}", outgoing, ttl=1)
        expect(observer, f"local{family}", outgoing, ttl=1)
        passed(f"ipv{family}_loopback_local_vs_remote_delivery")

    if backend == "native":
        server_indices = observer.rpc(op="indices")
        # Same sender and byte-identical payload to different groups: no dedup.
        for family in families:
            identical = f"emit:identical{family}:".encode() + epoch
            for group in GROUPS[family]:
                send(peers[0], f"tx{family}", group, PORTS[family], identical)
                server.received(family, identical)
                server.metadata(family, identical, group, server_indices["eth0"],
                                "192.0.2.10" if family == 4 else None)
                for peer in peers:
                    expect(peer, f"rx{family}", identical)
            passed(f"ipv{family}_identical_payload_distinct_destination_metadata")
            group = GROUPS[family][0]
            secondary = "198.51.100.10" if family == 4 else "eth1"
            server.command("JOIN", family, group, secondary)
            probe = f"probe:strict_second_link{family}:".encode() + epoch
            send(peers[0], f"alt_tx{family}", group, PORTS[family], probe)
            server.received(family, probe)
            server.metadata(family, probe, group, server_indices["eth1"],
                            "198.51.100.10" if family == 4 else None)
            expect(peers[0], f"alt_tx{family}", b"reply:" + probe,
                   "198.51.100.10" if family == 4 else "fd00:ab:74:1::10", PORTS[family])
            for peer in peers:
                expect(peer, f"alt_rx{family}", probe)
                peer.rpc(op="none", label=f"rx{family}")
            server.command("LEAVE", family, group, secondary)
            passed(f"ipv{family}_strict_reply_original_socket_second_interface")
        # Link-local peer scope cannot be replaced with route fallback.
        peer_interfaces = peers[0].rpc(op="interfaces")
        server_interfaces = observer.rpc(op="interfaces")
        for network in (0, 1):
            interface = f"eth{network}"
            peer_link = peer_interfaces[interface]
            local_link = server_interfaces[interface]
            open_peer(peers[0], f"link{network}", 6, 11, network=network, bind=peer_link)
            payload = f"probe:link_scope{network}:".encode() + epoch
            send(peers[0], f"link{network}", local_link, PORTS[6], payload)
            server.received(6, payload)
            metadata = server.metadata(6, payload, local_link, server_indices[interface], local_link)
            assert metadata["scope"] == server_indices[interface], metadata
            expect(peers[0], f"link{network}", b"reply:" + payload, local_link, PORTS[6])
        passed("ipv6_two_link_local_scopes_strict_original_socket_replies")
        broadcast = b"probe:native_broadcast_metadata:" + epoch
        send(peers[0], "tx4", "192.0.2.255", PORTS[4], broadcast)
        server.received(4, broadcast)
        server.metadata(4, broadcast, "192.0.2.255", server_indices["eth0"], "192.0.2.10")
        expect(peers[0], "tx4", b"reply:" + broadcast, "192.0.2.10", PORTS[4])
        for peer in peers:
            expect(peer, "rx4", broadcast)
        passed("ipv4_directed_broadcast_truthful_metadata_strict_unicast_reply")

    send(peers[0], "tx4", "192.0.2.10", PORTS[4], b"")
    server.received(4, b"")
    expect(peers[0], "tx4", b"reply:", "192.0.2.10", PORTS[4])
    passed("empty_datagram_original_listener_reply_port")
    for index in range(3):
        payload = b"probe:distinct:" + str(index).encode() + b":" + epoch
        send(peers[0], "tx4", "192.0.2.10", PORTS[4], payload)
        server.received(4, payload)
        expect(peers[0], "tx4", b"reply:" + payload, "192.0.2.10", PORTS[4])
    passed("distinct_datagrams_preserve_boundaries")
    if backend == "socket":
        server.command("SCOPE_UNSUPPORTED")
        passed("socket_backend_scoped_sockaddr_returns_explicit_error")
        print("UNSUPPORTED ipv6_scoped_wire: OTP gen_udp_socket cannot send scoped sockaddr maps", flush=True)
    server.command("STOP")
    server.process.wait(timeout=5)
    assert server.process.returncode == 0
    return passes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", action="store_true")
    options = parser.parse_args()
    if options.peer:
        peer_worker()
        return 0
    fixture = Fixture()
    try:
        for executable in ("ip", "setpriv", "mix"):
            assert shutil.which(executable), f"missing executable: {executable}"
        try:
            fixture.setup()
        except subprocess.CalledProcessError as error:
            print("BLOCKED_ENV network_namespace_setup: " + error.stderr.decode().strip(), file=sys.stderr)
            return 77
        passes = run_gates(fixture)
        backend = os.environ.get("ABYSS_UDP_BACKEND", "inet")
        print(json.dumps({"result": "PASS_SUPPORTED_SUBSET" if backend == "socket" else "PASS",
                          "backend": backend, "gates": passes, "payload_sizes": sorted(PAYLOAD_SIZES),
                          "unsupported": ["ipv6_scoped_wire"] if backend == "socket" else [],
                          "topology": "3 endpoint namespaces, 2 isolated bridged subnets"}), flush=True)
        return 0
    except Exception as error:
        print("FAIL " + repr(error), file=sys.stderr)
        for child in fixture.children:
            if child.wire:
                print("Abyss output: " + "\n".join(child.events[-30:]), file=sys.stderr)
        return 1
    finally:
        fixture.cleanup()


if __name__ == "__main__":
    sys.exit(main())
