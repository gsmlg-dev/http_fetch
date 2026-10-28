"""Structured independent no-OTP peer and complete schema-1 plan generator.

Preparation/tests import no SSL, socket, h2, wsproto, aioquic or crypto stack.
Actual invocation requires the coordinator's separate wire/runtime permission.
One peer owns one scenario/port, including identity rejection with no HTTP.
TLS/ALPN are observations, never copied from ready/requested configuration.

python3 no_otp_peer.py plan --cert /cert.pem --key /key.pem --ca /ca.pem
python3 no_otp_peer.py serve ...  # generated argv; NO_OTP_NONCE is required

The H3 adapter follows scripts/http3/aioquic_peer.py's pinned aioquic-1.2.0
H3Connection protocol pattern. Only public QUIC events supply evidence; it does
not inspect private TLS state. H3 here exercises the existing Session consumer,
not public Fetch/SSE H3 acceptance. All actual wire checks remain separate.
"""
import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
import sys
import time

CLIENTS = ("h1", "h2", "wss", "sse", "managed_h1", "managed_h2", "h3")
ACTIONS = ("success", "invalid_identity", "timeout", "cancellation", "shutdown")
MAX_HEADERS = 65_536
MAX_BODY = 65_536
MAX_EVENTS = 256
MAX_ERRORS = 64
PINNED = {"h2": "4.2.0", "hpack": "4.1.0", "hyperframe": "6.1.0",
          "wsproto": "1.2.0", "aioquic": "1.2.0"}


class PeerError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise PeerError(message)


def protocol(client):
    return "h3" if client == "h3" else "http/1.1" if client in ("h1", "managed_h1") else "h2"


def route(case):
    return "/no-otp/" + case["id"]


def needs_gate(case):
    return (case["action"] == "cancellation" and case["client"] in
            ("h1", "h2", "managed_h1", "managed_h2")) or (
                case["client"] == "h3" and case["action"] in
                ("timeout", "cancellation", "shutdown"))


def build_plan(script, script_sha, cert, key, ca, *, tls="TLSv1.3", timeout_ms=5000,
               python="python3"):
    require(tls in ("TLSv1.2", "TLSv1.3"), "exact TLS12/13 selection required")
    require(type(timeout_ms) is int and 1 <= timeout_ms <= 30_000, "invalid finite timeout")
    require(re.fullmatch(r"[a-f0-9]{64}", script_sha or ""), "peer source SHA256 required")
    require(all(isinstance(path, str) and Path(path).is_absolute() and "\x00" not in path
                for path in (script, cert, key, ca)), "absolute input paths required")
    peers, scenarios = {}, []
    for client in CLIENTS:
        for action in ACTIONS:
            identifier = client + "." + action
            name = client + "-" + action
            version = "TLSv1.3" if client == "h3" else tls
            expected = "no-otp:" + identifier
            host = ("wrong.invalid" if client in ("managed_h1", "managed_h2") and
                    action == "invalid_identity" else "localhost")
            argv = [python, script, "serve", "--id", identifier, "--client", client,
                    "--action", action, "--tls", version, "--cert", cert, "--key", key,
                    "--run", "{run}", "--expected", expected,
                    "--timeout-ms", str(timeout_ms), "--lifetime", "1800"]
            peers[name] = dict(kind="structured", argv=argv, script=script, sha256=script_sha)
            case = dict(id=identifier, client=client, action=action, peer=name,
                        tls=version, alpn=protocol(client), expected=expected,
                        url=("wss" if client == "wss" else "https") +
                        "://" + host + ":{port}/no-otp/" + identifier,
                        ca_file=ca, timeout_ms=timeout_ms)
            if needs_gate(case):
                case["gate_file"] = "{run}/" + identifier + ".gate.json"
            scenarios.append(case)
    return dict(schema=1, peers=peers, scenarios=scenarios)


def publish_gate(run, identifier, nonce, *, opener=None, linker=None, unlinker=None):
    require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", identifier or "") and
            identifier not in (".", ".."), "invalid gate scenario id")
    require(isinstance(nonce, str) and 0 < len(nonce) <= 128, "fresh nonce required")
    root = Path(run)
    require(root.is_absolute() and ".." not in root.parts, "absolute fresh run required")
    path = root / (identifier + ".gate.json")
    temporary = root / ("." + identifier + ".gate.tmp")
    # Publish only a complete, closed file. Hard linking is atomic and cannot
    # overwrite an existing gate. The orchestrator owns the fresh run directory.
    open_file = opener or (lambda target, mode: target.open(mode, encoding="utf-8"))
    created = False
    try:
        with open_file(temporary, "x") as handle:
            created = True
            handle.write(json.dumps(dict(peer_gate=True, id=identifier, nonce=nonce)) + "\n")
        (linker or os.link)(temporary, path)
    finally:
        if created:
            (unlinker or (lambda target: target.unlink()))(temporary)


class Oracle:
    """Bounded facts for exactly one independently observed scenario."""

    def __init__(self, case, nonce, identity, emit, gate=None, lock=None):
        require(case.get("client") in CLIENTS and case.get("action") in ACTIONS,
                "unknown mandatory scenario")
        require(isinstance(nonce, str) and 0 < len(nonce) <= 128, "fresh nonce required")
        require(isinstance(identity, str) and identity, "independent peer identity required")
        self.case, self.nonce, self.identity, self.emit = case, nonce, identity, emit
        self.gate, self.lock = gate, lock or nullcontext()
        self.connections, self.streams, self.holds = {}, set(), set()
        self.requests, self.response_ok, self.gated = 0, False, False
        self.resets, self.closures, self.errors, self.events = [], [], [], []
        self.identity_errors, self.last_event_id, self.sse_ids = [], None, []
        self.ws_messages, self.ws_closes, self.masked_frames = 0, 0, 0
        self.emitted, self.stopping = False, False
        self.pending_stats = 0

    def error(self, message):
        message = str(message)[:1024]
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(message)
        self.emit(dict(kind="error", id=self.case["id"], nonce=self.nonce,
                       peer_identity=self.identity, error=message))

    def event(self, kind, **facts):
        require(len(self.events) < MAX_EVENTS, "independent event retention bound exceeded")
        self.events.append(dict(kind=kind, **facts))

    def opened(self, cid):
        require(cid not in self.connections, "duplicate connection identity")
        require(len(self.connections) < 2, "connection observation bound exceeded")
        self.connections[cid] = dict(active=True, tls=None, alpn=None, source=None)
        self.event("connection", connection=cid)
        if len(self.connections) != 1:
            self.error("duplicate/replayed connection")

    def negotiated(self, cid, tls, alpn, source):
        entry = self.connections[cid]
        if entry["tls"] is not None and (entry["tls"], entry["alpn"]) != (tls, alpn):
            self.error("conflicting actual negotiation evidence")
        entry.update(tls=tls, alpn=alpn, source=source)
        self.event("negotiated", connection=cid, tls=tls, alpn=alpn, source=source)
        if (tls, alpn) != (self.case["tls"], self.case["alpn"]):
            self.error("missing/wrong actual TLS or ALPN")

    def handshake_failed(self, cid, error, *, identity_alert=False):
        detail = dict(connection=cid, error=str(error)[:1024])
        if self.case["action"] == "invalid_identity" and identity_alert:
            self.identity_errors.append(detail)
        else:
            self.error("unexpected handshake failure: " + detail["error"])
        self.event("handshake_error", **detail)

    def request(self, cid, sid, pairs):
        self.requests += 1
        require(self.connections[cid]["active"], "request on closed connection")
        require(len(pairs) <= 100 and sum(len(k) + len(v) for k, v in pairs) <= MAX_HEADERS,
                "request headers bound exceeded")
        fields = dict(pairs)
        require(len(fields) == len(pairs), "duplicate request header")
        require(fields.get(":path") == route(self.case), "wrong independent scenario route")
        expected_method = "CONNECT" if self.case["client"] == "wss" else "GET"
        require(fields.get(":method") == expected_method, "wrong request method")
        require(fields.get(":scheme") == "https" and
                re.fullmatch(r"localhost:[0-9]{1,5}", fields.get(":authority", "")),
                "wrong request authority/scheme")
        require((cid, sid) not in self.streams and self.requests == 1,
                "duplicate/replayed request")
        if self.case["client"] == "wss":
            require(fields.get(":protocol") == "websocket" and
                    fields.get("sec-websocket-version") == "13", "invalid extended CONNECT")
            require(not set(fields) & {"upgrade", "connection", "sec-websocket-key"},
                    "HTTP1 fallback headers on extended CONNECT")
        require(self.case["action"] != "invalid_identity", "HTTP received after invalid identity")
        self.streams.add((cid, sid))
        self.last_event_id = fields.get("last-event-id")
        self.event("request", connection=cid, stream=sid, method=expected_method,
                   path=fields[":path"], last_event_id=self.last_event_id)

    def held(self, cid, sid):
        require((cid, sid) in self.streams, "hold before observed request")
        self.holds.add((cid, sid))
        if needs_gate(self.case) and not self.gated:
            require(self.gate is not None, "independent gate publisher missing")
            self.gate(self.case["id"], self.nonce)
            self.gated = True

    def response(self, cid, sid, payload, *, sse=False):
        require((cid, sid) in self.streams, "response without observed request")
        expected = self.case["expected"].encode()
        if sse:
            require(payload == b"id: no-otp-1\ndata: " + expected + b"\n\n",
                    "incorrect independent SSE payload")
            self.sse_ids.append("no-otp-1")
        else:
            require(payload == expected, "incorrect independent response payload")
        self.response_ok = True
        self.event("response_submitted", connection=cid, stream=sid, bytes=len(payload))

    def reset(self, cid, sid, code):
        require((cid, sid) in self.streams, "reset for unknown stream")
        self.resets.append(dict(connection=cid, stream=sid, error_code=code))
        self.event("received_stream_reset", connection=cid, stream=sid, error_code=code)

    def closed(self, cid, observation):
        require(cid in self.connections and self.connections[cid]["active"], "duplicate/unknown close")
        self.connections[cid]["active"] = False
        self.closures.append(observation)
        self.event("connection_closed", connection=cid, observation=observation)
        if observation not in ("received_eof", "tls_alert", "transport_reset", "quic_connection_close"):
            self.error("closure not independently received: " + observation)

    def finish(self):
        active = sum(entry["active"] for entry in self.connections.values())
        observed = list(self.connections.values())
        tls = observed[0]["tls"] if len(observed) == 1 else None
        alpn = observed[0]["alpn"] if len(observed) == 1 else None
        expected_count = 0 if self.case["action"] == "invalid_identity" else 1
        checks = [len(observed) == 1, active == 0, self.requests == expected_count,
                  (tls, alpn) == (self.case["tls"], self.case["alpn"]), bool(self.closures)]
        action, client = self.case["action"], self.case["client"]
        if action in ("timeout", "cancellation", "shutdown"):
            checks.append(bool(self.holds))
        if action == "success" or (client in ("wss", "sse") and action == "shutdown"):
            checks.append(self.response_ok)
        if client == "wss" and action in ("success", "shutdown"):
            checks.extend([self.ws_messages == 1, self.ws_closes == 1, self.masked_frames >= 2])
        if not all(checks) and "incomplete independent scenario observations" not in self.errors:
            self.errors.append("incomplete independent scenario observations")
        return dict(kind="scenario", id=self.case["id"], nonce=self.nonce,
                    client=client, action=action, result="FAIL" if self.errors else "PASS",
                    executed=1, peer_identity=self.identity, tls=tls, alpn=alpn,
                    requests=self.requests, connections=len(observed), streams=len(self.streams),
                    active_connections=active, fallback=any(e["alpn"] not in (None, self.case["alpn"])
                                                           for e in observed),
                    replay=self.requests > expected_count or len(observed) > 1,
                    resets=list(self.resets), closure_observations=list(self.closures),
                    negotiation_observations=observed, events=list(self.events),
                    expected_identity_handshake_errors=list(self.identity_errors),
                    sse_last_event_id=self.last_event_id, sse_event_ids_sent=list(self.sse_ids),
                    websocket_messages=self.ws_messages, websocket_close_frames=self.ws_closes,
                    masked_frames=self.masked_frames, errors=list(self.errors),
                    observation_scope="owned independent peer endpoint")

    def flush_stats(self):
        if self.pending_stats and not any(entry["active"] for entry in self.connections.values()):
            pending, self.pending_stats = self.pending_stats, 0
            for _ in range(pending):
                self.stats()

    def stats(self):
        if self.case["client"] == "h3" and any(entry["active"] for entry in self.connections.values()):
            require(self.pending_stats < MAX_EVENTS, "pending stats bound exceeded")
            self.pending_stats += 1
            return
        record = self.finish()
        if not self.emitted:
            self.emit(record)
            self.emitted = True
        self.emit(dict(kind="stats", id=self.case["id"], nonce=self.nonce,
                       peer_identity=self.identity, errors=list(self.errors),
                       active_connections=record["active_connections"],
                       connections=len(self.connections), requests=self.requests))


class H1Adapter:
    def __init__(self, oracle, cid, send):
        self.oracle, self.cid, self.send = oracle, cid, send
        self.buffer, self.received = bytearray(), False

    def receive(self, data):
        require(not self.received, "unexpected/replayed HTTP1 bytes")
        self.buffer.extend(data)
        require(len(self.buffer) <= MAX_HEADERS, "HTTP1 header retention bound exceeded")
        if b"\r\n\r\n" not in self.buffer:
            return
        head, extra = bytes(self.buffer).split(b"\r\n\r\n", 1)
        require(not extra, "unexpected upload/pipelined bytes")
        lines = head.decode("ascii").split("\r\n")
        method, path, version = lines[0].split(" ")
        require(version == "HTTP/1.1", "HTTP1 protocol fallback")
        pairs = []
        for line in lines[1:]:
            key, value = line.split(":", 1)
            pairs.append((key.lower(), value.strip()))
        fields = dict(pairs)
        require(len(fields) == len(pairs), "duplicate HTTP1 header")
        self.oracle.request(self.cid, 1, [(":method", method), (":scheme", "https"),
                                          (":authority", fields.get("host", "")),
                                          (":path", path)] + pairs)
        self.received, self.buffer = True, bytearray()
        action = self.oracle.case["action"]
        if action == "success":
            body = self.oracle.case["expected"].encode()
            self.send(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                      b"\r\nConnection: close\r\n\r\n" + body)
            self.oracle.response(self.cid, 1, body)
        else:
            if action == "shutdown":
                self.send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n")
            self.oracle.held(self.cid, 1)


class FrameOracle:
    def __init__(self, oracle):
        self.oracle, self.buffer = oracle, bytearray()

    def receive(self, data):
        self.buffer.extend(data)
        require(len(self.buffer) <= MAX_BODY + 14, "WebSocket frame retention bound exceeded")
        while len(self.buffer) >= 2:
            first, second = self.buffer[:2]
            opcode, length, offset = first & 15, second & 127, 2
            require(not first & 112 and opcode in (0, 1, 2, 8, 9, 10) and second & 128,
                    "invalid/unmasked client WebSocket frame")
            if length in (126, 127):
                width = 2 if length == 126 else 8
                if len(self.buffer) < 2 + width:
                    return
                length, offset = int.from_bytes(self.buffer[2:2 + width], "big"), 2 + width
                require((width == 2 and length >= 126) or (width == 8 and length > 65535),
                        "nonminimal WebSocket frame length")
            require(length <= MAX_BODY, "WebSocket payload bound exceeded")
            if opcode >= 8:
                require(first & 128 and length <= 125, "invalid WebSocket control frame")
            if opcode == 8:
                require(length != 1, "one-byte WebSocket close payload")
            if len(self.buffer) < offset + 4 + length:
                return
            del self.buffer[:offset + 4 + length]
            self.oracle.masked_frames += 1


class H2Adapter:
    def __init__(self, oracle, cid, connection, events, *, ws_factory=None, ws_events=None):
        self.oracle, self.cid, self.conn, self.types = oracle, cid, connection, events
        self.ws_factory, self.ws_types = ws_factory, ws_events
        self.ws, self.frames, self.message = None, FrameOracle(oracle), bytearray()

    def receive(self, data):
        for event in self.conn.receive_data(data):
            if isinstance(event, self.types.RequestReceived):
                self.open(event.stream_id, event.headers)
            elif isinstance(event, self.types.DataReceived):
                require((self.cid, event.stream_id) in self.oracle.streams, "DATA for unknown stream")
                if self.oracle.case["client"] == "wss":
                    # An empty H2 DATA frame adds no WebSocket bytes after Close.
                    if event.data:
                        self.websocket(event.stream_id, event.data)
                else:
                    require(not event.data, "unexpected GET request body")
                self.conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            elif isinstance(event, self.types.StreamReset):
                self.oracle.reset(self.cid, event.stream_id, event.error_code)
            elif isinstance(event, self.types.StreamEnded):
                self.oracle.event("received_end_stream", connection=self.cid, stream=event.stream_id)
            elif isinstance(event, self.types.ConnectionTerminated):
                self.oracle.event("received_goaway", connection=self.cid, error_code=event.error_code)
                require(event.error_code == 0, "unexpected peer GOAWAY error")

    def open(self, sid, fields):
        self.oracle.request(self.cid, sid, fields)
        action, client = self.oracle.case["action"], self.oracle.case["client"]
        if action == "timeout" or (action == "cancellation" and client not in ("wss", "sse")):
            self.oracle.held(self.cid, sid)
            return
        if client == "wss":
            require(self.ws_factory is not None, "wsproto collaborator missing")
            self.ws = self.ws_factory()
            self.conn.send_headers(sid, [(":status", "200")])
            self.oracle.held(self.cid, sid)
        elif client == "sse":
            self.conn.send_headers(sid, [(":status", "200"), ("content-type", "text/event-stream")])
            if action != "cancellation":
                body = b"id: no-otp-1\ndata: " + self.oracle.case["expected"].encode() + b"\n\n"
                self.conn.send_data(sid, body, end_stream=False)
                self.oracle.response(self.cid, sid, body, sse=True)
            self.oracle.held(self.cid, sid)
        elif action == "shutdown":
            self.conn.send_headers(sid, [(":status", "200")])
            self.conn.send_data(sid, b"x", end_stream=False)
            self.oracle.held(self.cid, sid)
        else:
            body = self.oracle.case["expected"].encode()
            self.conn.send_headers(sid, [(":status", "200"), ("content-length", str(len(body)))])
            self.conn.send_data(sid, body, end_stream=True)
            self.oracle.response(self.cid, sid, body)

    def websocket(self, sid, data):
        require(self.ws is not None, "WebSocket DATA before accepted CONNECT")
        self.frames.receive(data)
        self.ws.receive_data(data)
        for event in self.ws.events():
            if isinstance(event, (self.ws_types.TextMessage, self.ws_types.BytesMessage)):
                part = event.data.encode() if isinstance(event.data, str) else event.data
                self.message.extend(part)
                require(len(self.message) <= MAX_BODY, "WebSocket message bound exceeded")
                if event.message_finished:
                    self.oracle.ws_messages += 1
                    require(self.oracle.ws_messages == 1, "duplicate WebSocket message")
                    body = bytes(self.message)
                    self.oracle.response(self.cid, sid, body)
                    outgoing = self.ws_types.TextMessage(data=body.decode())
                    self.conn.send_data(sid, self.ws.send(outgoing), end_stream=False)
                    self.message.clear()
            elif isinstance(event, self.ws_types.CloseConnection):
                self.oracle.ws_closes += 1
                require(self.oracle.ws_closes == 1 and event.code != 1006,
                        "invalid/duplicate WebSocket close")
                if self.oracle.case["action"] in ("success", "shutdown"):
                    require(event.code == 1000, "clean WebSocket scenario lacked normal close code")
                require(not self.frames.buffer, "truncated client WebSocket frame")
                self.conn.send_data(sid, self.ws.send(event.response()), end_stream=True)
            elif isinstance(event, self.ws_types.Ping):
                self.conn.send_data(sid, self.ws.send(event.response()), end_stream=False)
            else:
                require(isinstance(event, self.ws_types.Pong), "unexpected wsproto event")


def dependencies(names):
    # Called only by an explicitly invoked real peer, never during import/tests.
    from importlib.metadata import version
    result = {name: version(name) for name in names}
    require(all(result[name] == PINNED[name] for name in names), "pinned peer dependency mismatch")
    return result


def command(line, oracle):
    require(0 < len(line) <= 4096, "stdin command bound exceeded")
    value = json.loads(line)
    require(value in ({"command": "stats"}, {"command": "stop"}), "unknown peer stdin command")
    if value["command"] == "stats":
        oracle.stats()
    return value["command"]


class ServerHelloObserver:
    """Retain only the actual plaintext ServerHello, before Finished can fail."""

    def __init__(self):
        self.records, self.handshakes = bytearray(), bytearray()
        self.version = None

    def feed(self, data):
        if self.version is not None:
            return
        require(len(self.records) + len(data) <= MAX_HEADERS,
                "ServerHello record retention bound exceeded")
        self.records.extend(data)
        while len(self.records) >= 5:
            length = int.from_bytes(self.records[3:5], "big")
            require(self.records[0] == 22 and self.records[1:3] in
                    (b"\x03\x01", b"\x03\x02", b"\x03\x03") and 0 < length <= 16384,
                    "invalid plaintext ServerHello record")
            if len(self.records) < length + 5:
                return
            self.handshakes.extend(self.records[5:length + 5])
            del self.records[:length + 5]
            require(len(self.handshakes) <= MAX_HEADERS,
                    "ServerHello handshake retention bound exceeded")
            if len(self.handshakes) < 4:
                continue
            size = int.from_bytes(self.handshakes[1:4], "big")
            require(self.handshakes[0] == 2 and 38 <= size <= MAX_HEADERS - 4,
                    "invalid ServerHello handshake")
            if len(self.handshakes) < size + 4:
                continue
            self.version = self.selected_version(bytes(self.handshakes[4:size + 4]))
            self.records.clear()
            self.handshakes.clear()
            return

    @staticmethod
    def selected_version(body):
        require(body[:2] == b"\x03\x03" and body[34] <= 32,
                "invalid ServerHello legacy version/session id")
        offset = 35 + body[34]
        require(len(body) >= offset + 3 and body[offset + 2] == 0,
                "invalid ServerHello cipher/compression fields")
        offset += 3
        if len(body) == offset:
            return "TLSv1.2"
        require(len(body) >= offset + 2 and
                int.from_bytes(body[offset:offset + 2], "big") == len(body) - offset - 2,
                "invalid ServerHello extension length")
        offset += 2
        seen, version = set(), "TLSv1.2"
        while offset < len(body):
            require(len(body) - offset >= 4, "truncated ServerHello extension")
            kind = int.from_bytes(body[offset:offset + 2], "big")
            size = int.from_bytes(body[offset + 2:offset + 4], "big")
            offset += 4
            require(kind not in seen and size <= len(body) - offset,
                    "duplicate/truncated ServerHello extension")
            seen.add(kind)
            if kind == 43:
                require(body[offset:offset + size] == b"\x03\x04",
                        "invalid ServerHello supported version")
                version = "TLSv1.3"
            offset += size
        return version


class TLSStream:
    """Public OpenSSL MemoryBIO driver; no private SSL state or policy inference."""

    def __init__(self, raw, context, api):
        self.raw, self.api = raw, api
        self.incoming, self.outgoing = api.MemoryBIO(), api.MemoryBIO()
        self.tls = context.wrap_bio(self.incoming, self.outgoing, server_side=True)
        self.observed = ServerHelloObserver()

    def remaining(self, deadline):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("independent TLS operation timed out")
            self.raw.settimeout(remaining)

    def flush(self, deadline=None):
        while self.outgoing.pending:
            self.remaining(deadline)
            data = self.outgoing.read(min(self.outgoing.pending, 16384))
            self.raw.sendall(data)
            self.observed.feed(data)

    def drive(self, operation):
        timeout = self.raw.gettimeout()
        deadline = None if timeout is None else time.monotonic() + timeout
        try:
            while True:
                self.remaining(deadline)
                try:
                    result = operation()
                except self.api.SSLWantReadError:
                    self.flush(deadline)
                    self.remaining(deadline)
                    data = self.raw.recv(16384)
                    if data:
                        self.incoming.write(data)
                    else:
                        self.incoming.write_eof()
                except self.api.SSLWantWriteError:
                    self.flush(deadline)
                except self.api.SSLError:
                    self.flush(deadline)
                    raise
                else:
                    self.flush(deadline)
                    return result
        finally:
            self.raw.settimeout(timeout)

    def do_handshake(self):
        return self.drive(self.tls.do_handshake)

    def recv(self, size):
        try:
            return self.drive(lambda: self.tls.read(size))
        except self.api.SSLEOFError:
            # Match SSLSocket's default suppress_ragged_eofs behavior. The
            # oracle still distinguishes received EOF from local teardown.
            return b""

    def sendall(self, data):
        remaining = memoryview(data)

        def write():
            nonlocal remaining
            while remaining:
                size = self.tls.write(remaining)
                require(0 < size <= len(remaining), "invalid TLS write progress")
                remaining = remaining[size:]

        self.drive(write)

    def version(self):
        actual, observed = self.tls.version(), self.observed.version
        require(actual is None or observed is None or actual == observed,
                "conflicting actual TLS version evidence")
        return actual or observed

    def selected_alpn_protocol(self):
        return self.tls.selected_alpn_protocol()


def run_tcp(args, oracle, ready):
    import select
    import socket
    import ssl
    import threading

    versions = {}
    if oracle.case["alpn"] == "h2":
        versions = dependencies(("h2", "hpack", "hyperframe") +
                                (("wsproto",) if args.client == "wss" else ()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    chosen = ssl.TLSVersion.TLSv1_2 if args.tls == "TLSv1.2" else ssl.TLSVersion.TLSv1_3
    context.minimum_version = context.maximum_version = chosen
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols([oracle.case["alpn"]])
    oracle.lock = threading.RLock()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    sockets, threads = [], []
    deadline = time.monotonic() + args.lifetime

    def serve(raw, cid):
        observation = "local_stop"
        try:
            raw.settimeout(args.timeout_ms / 1000 + 2)
            sock = TLSStream(raw, context, ssl)
            try:
                sock.do_handshake()
            except ssl.SSLError as error:
                actual_tls, actual_alpn = sock.version(), sock.selected_alpn_protocol()
                with oracle.lock:
                    if actual_tls is not None or actual_alpn is not None:
                        oracle.negotiated(cid, actual_tls, actual_alpn,
                                          "OpenSSL MemoryBIO/ServerHello after handshake error")
                    reason = str(getattr(error, "reason", error))
                    oracle.handshake_failed(cid, str(error), identity_alert=any(
                        token in reason.upper() for token in ("CERTIFICATE", "UNKNOWN_CA")))
                observation = "tls_alert"
                return
            with oracle.lock:
                oracle.negotiated(cid, sock.version(), sock.selected_alpn_protocol(),
                                  "OpenSSL MemoryBIO/ServerHello")
            if oracle.case["alpn"] == "h2":
                from h2.config import H2Configuration
                from h2.connection import H2Connection
                import h2.events
                from h2.settings import SettingCodes, Settings
                connection = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
                connection.local_settings = Settings(client=False, initial_values={
                    SettingCodes.MAX_CONCURRENT_STREAMS: 1, SettingCodes.ENABLE_CONNECT_PROTOCOL: 1})
                connection.initiate_connection()
                factory, ws_events = None, None
                if args.client == "wss":
                    from wsproto.connection import Connection, ConnectionType
                    import wsproto.events
                    factory, ws_events = lambda: Connection(ConnectionType.SERVER), wsproto.events
                adapter = H2Adapter(oracle, cid, connection, h2.events,
                                    ws_factory=factory, ws_events=ws_events)
                sock.sendall(connection.data_to_send())
            else:
                connection = None
                adapter = H1Adapter(oracle, cid, sock.sendall)
            while time.monotonic() < deadline and not oracle.stopping:
                data = sock.recv(16_384)
                if not data:
                    observation = "received_eof"
                    break
                with oracle.lock:
                    adapter.receive(data)
                if connection is not None:
                    outgoing = connection.data_to_send()
                    if outgoing:
                        sock.sendall(outgoing)
        except ConnectionResetError:
            observation = "transport_reset"
        except ssl.SSLError as error:
            observation = "tls_alert"
            with oracle.lock:
                # A received alert after handshake is retained. Only the identity
                # cell expects certificate alerts; other protocol errors fail.
                if args.action != "invalid_identity":
                    oracle.error(str(error))
                else:
                    reason = str(getattr(error, "reason", error)).upper()
                    oracle.handshake_failed(cid, str(error), identity_alert=any(
                        token in reason for token in ("CERTIFICATE", "UNKNOWN_CA")))
        except Exception as error:
            with oracle.lock:
                oracle.error(type(error).__name__ + ": " + str(error))
        finally:
            with oracle.lock:
                oracle.closed(cid, observation)
            raw.close()

    try:
        ready(listener.getsockname()[1], dict(python_ssl=ssl.OPENSSL_VERSION, dependencies=versions))
        while time.monotonic() < deadline:
            available, _, _ = select.select([listener, sys.stdin], [], [], min(1, max(0, deadline - time.monotonic())))
            if sys.stdin in available:
                line = sys.stdin.readline(4097)
                if not line:
                    break
                with oracle.lock:
                    if command(line, oracle) == "stop":
                        break
            if listener in available:
                raw, _ = listener.accept()
                sockets.append(raw)
                with oracle.lock:
                    cid = len(oracle.connections) + 1
                    oracle.opened(cid)
                worker = threading.Thread(target=serve, args=(raw, cid))
                threads.append(worker)
                worker.start()
        else:
            oracle.error("owned peer lifetime expired")
    finally:
        oracle.stopping = True
        listener.close()
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        for worker in threads:
            worker.join(5)
            require(not worker.is_alive(), "owned peer thread did not stop")


def quic_protocol(api, oracle):
    """Public event adapter, parameterized for pure mocked protocol tests."""
    class Protocol(api.QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.http = api.H3Connection(self._quic)
            self.cid = len(oracle.connections) + 1
            self.locally_closed = False
            oracle.opened(self.cid)

        def quic_event_received(self, event):
            try:
                if isinstance(event, api.ProtocolNegotiated):
                    # Pinned aioquic QUIC-v1 is TLS1.3-only. This actual public
                    # negotiated event supplies ALPN; requested config is not evidence.
                    oracle.negotiated(self.cid, "TLSv1.3", event.alpn_protocol,
                                      "QUIC-v1 TLS1.3-only public ProtocolNegotiated")
                elif isinstance(event, api.StreamReset):
                    oracle.reset(self.cid, event.stream_id, event.error_code)
                elif isinstance(event, api.ConnectionTerminated):
                    oracle.event("quic_termination", connection=self.cid,
                                 error_code=event.error_code, frame_type=event.frame_type,
                                 reason=str(event.reason_phrase)[:1024])
                    # H3_NO_ERROR is an application close. The same transport
                    # error value denotes CRYPTO_ERROR(0), not successful H3.
                    normal_close = event.error_code == 0 or (
                        event.error_code == 0x100 and event.frame_type is None)
                    if not normal_close or oracle.case["action"] == "invalid_identity":
                        identity_alert = event.frame_type is not None and event.error_code in (
                            0x12A, 0x12B, 0x12C, 0x12D, 0x12E, 0x130)
                        oracle.handshake_failed(self.cid, event.reason_phrase,
                                                identity_alert=identity_alert)
                    oracle.closed(self.cid, "local_stop" if oracle.stopping or self.locally_closed or
                                  "idle timeout" in str(event.reason_phrase).lower()
                                  else "quic_connection_close")
                for item in self.http.handle_event(event):
                    if isinstance(item, api.HeadersReceived):
                        fields = [(key.decode("ascii"), value.decode("ascii")) for key, value in item.headers]
                        oracle.request(self.cid, item.stream_id, fields)
                        if oracle.case["action"] == "success":
                            body = oracle.case["expected"].encode()
                            self.http.send_headers(item.stream_id, [(b":status", b"200"),
                                                   (b"content-length", str(len(body)).encode())])
                            self.http.send_data(item.stream_id, body, end_stream=True)
                            self.transmit()
                            oracle.response(self.cid, item.stream_id, body)
                        else:
                            oracle.held(self.cid, item.stream_id)
                    elif isinstance(item, api.DataReceived):
                        require((self.cid, item.stream_id) in oracle.streams and not item.data,
                                "unexpected QUIC upload/body")
            except Exception as error:
                oracle.error(type(error).__name__ + ": " + str(error))
                self.locally_closed = True
                self.close(error_code=0x100, reason_phrase="independent peer rejected scenario")
            # Flush only after all handling of the public terminal event, so
            # a later adapter failure in this callback remains part of verdict.
            oracle.flush_stats()
    return Protocol


def run_quic(args, oracle, ready):
    import asyncio
    versions = dependencies(("aioquic",))
    from importlib.metadata import version
    versions["cryptography"] = version("cryptography")
    from aioquic.asyncio import serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated, StreamReset
    from aioquic.quic.packet import QuicProtocolVersion
    from types import SimpleNamespace

    api = SimpleNamespace(QuicConnectionProtocol=QuicConnectionProtocol, H3Connection=H3Connection,
                          DataReceived=DataReceived, HeadersReceived=HeadersReceived,
                          ConnectionTerminated=ConnectionTerminated, ProtocolNegotiated=ProtocolNegotiated,
                          StreamReset=StreamReset)

    async def run():
        config = QuicConfiguration(is_client=False, alpn_protocols=["h3"],
                                   supported_versions=[QuicProtocolVersion.VERSION_1],
                                   max_data=MAX_BODY * 2, max_stream_data=MAX_BODY,
                                   idle_timeout=min(args.timeout_ms / 1000 + 5, 40))
        config.load_cert_chain(args.cert, args.key)
        server = await serve("127.0.0.1", 0, configuration=config,
                             create_protocol=quic_protocol(api, oracle))
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()

        def stdin():
            try:
                line = sys.stdin.readline(4097)
                if not line or command(line, oracle) == "stop":
                    stopped.set()
            except Exception as error:
                oracle.error(type(error).__name__ + ": " + str(error))
                stopped.set()

        try:
            # Same pinned harness readiness seam as scripts/http3/aioquic_peer.py;
            # no TLS evidence is extracted from private protocol/crypto state.
            ready(server._transport.get_extra_info("sockname")[1], dict(dependencies=versions))
            loop.add_reader(sys.stdin.fileno(), stdin)
            try:
                await asyncio.wait_for(stopped.wait(), args.lifetime)
            except TimeoutError:
                oracle.error("owned peer lifetime expired")
        finally:
            loop.remove_reader(sys.stdin.fileno())
            oracle.stopping = True
            server.close()
    asyncio.run(run())


def source_hash(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan_parser = sub.add_parser("plan")
    serve_parser = sub.add_parser("serve")
    for child in (plan_parser, serve_parser):
        child.add_argument("--cert", required=True)
        child.add_argument("--key", required=True)
        child.add_argument("--tls", choices=("TLSv1.2", "TLSv1.3"), default="TLSv1.3")
        child.add_argument("--timeout-ms", type=int, default=5000)
    plan_parser.add_argument("--ca", required=True)
    plan_parser.add_argument("--output")
    serve_parser.add_argument("--id", required=True)
    serve_parser.add_argument("--client", choices=CLIENTS, required=True)
    serve_parser.add_argument("--action", choices=ACTIONS, required=True)
    serve_parser.add_argument("--expected", required=True)
    serve_parser.add_argument("--run", required=True)
    serve_parser.add_argument("--lifetime", type=int, default=1800)
    args = parser.parse_args(argv)
    script = str(Path(__file__).resolve())
    if args.command == "plan":
        result = build_plan(script, source_hash(script), args.cert, args.key, args.ca,
                            tls=args.tls, timeout_ms=args.timeout_ms, python=sys.executable)
        data = json.dumps(result, indent=2) + "\n"
        if args.output:
            with Path(args.output).open("x", encoding="utf-8") as handle:
                handle.write(data)
        else:
            sys.stdout.write(data)
        return
    require(1 <= args.timeout_ms <= 30_000 and 1 <= args.lifetime <= 1800, "finite peer bounds required")
    require(re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", args.id or ""), "bounded scenario id required")
    require(len(args.expected.encode()) <= 4096 and "\n" not in args.expected and "\r" not in args.expected,
            "bounded single-line expected payload required")
    require(args.client != "h3" or args.tls == "TLSv1.3", "QUIC requires TLS1.3")
    nonce = os.environ.get("NO_OTP_NONCE")
    # Only the public certificate and this source are hashed, never private keys.
    identity = source_hash(script) + ":" + source_hash(args.cert) + ":" + args.id
    case = dict(id=args.id, client=args.client, action=args.action, tls=args.tls,
                alpn=protocol(args.client), expected=args.expected, timeout_ms=args.timeout_ms)

    def emit(record):
        print(json.dumps(record, ensure_ascii=True), flush=True)

    oracle = Oracle(case, nonce, identity, emit,
                    lambda identifier, fresh: publish_gate(args.run, identifier, fresh))

    def ready(port, runtime):
        runtime.update(python=sys.version, executable=sys.executable)
        emit(dict(kind="ready", port=port, identity=identity, id=args.id, nonce=nonce,
                  requested_tls=args.tls, required_alpn=case["alpn"], runtime=runtime,
                  source_sha256=source_hash(script), private_key_content_logged=False))

    try:
        (run_quic if args.client == "h3" else run_tcp)(args, oracle, ready)
    except Exception as error:
        oracle.error(type(error).__name__ + ": " + str(error))
        raise
    finally:
        emit(dict(kind="final_stats", id=args.id, nonce=nonce, peer_identity=identity,
                  errors=list(oracle.errors), requests=oracle.requests,
                  active_connections=sum(entry["active"] for entry in oracle.connections.values())))


if __name__ == "__main__":
    main()
