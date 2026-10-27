"""Pure one-VM tests; network, native protocol stacks and gate I/O are mocked."""
import builtins
from contextlib import nullcontext
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import no_otp_peer as peer
import no_otp_consumer_gate as gate


def plan(tls="TLSv1.3"):
    return peer.build_plan("/source/no_otp_peer.py", "a" * 64,
                           "/inputs/cert.pem", "/inputs/key.pem", "/inputs/ca.pem",
                           tls=tls)


def case(client="h1", action="success"):
    return next(c for c in plan()["scenarios"]
                if (c["client"], c["action"]) == (client, action))


def oracle(client="h1", action="success"):
    records, gates = [], []
    value = peer.Oracle(case(client, action), "fresh-nonce", "pinned-peer", records.append,
                        lambda identifier, nonce: gates.append((identifier, nonce)))
    return value, records, gates


def headers(spec, method="GET"):
    return [(":method", method), (":scheme", "https"),
            (":authority", "localhost:443"), (":path", peer.route(spec))]


def connected(value):
    value.opened(1)
    value.negotiated(1, value.case["tls"], value.case["alpn"], "mock actual socket")


class FakeH2:
    def __init__(self):
        self.events = []
        self.headers, self.payloads = [], []

    def receive_data(self, data):
        return self.events

    def send_headers(self, stream_id, fields, end_stream=False):
        self.headers.append((stream_id, fields, end_stream))

    def send_data(self, stream_id, data, end_stream=False):
        self.payloads.append((stream_id, data, end_stream))

    def acknowledge_received_data(self, length, stream_id):
        pass


class RequestReceived:
    def __init__(self, spec, method="GET", stream_id=1):
        self.stream_id, self.headers = stream_id, headers(spec, method)
        if spec["client"] == "wss":
            self.headers += [(":protocol", "websocket"), ("sec-websocket-version", "13")]


class StreamReset:
    def __init__(self, stream_id=1, error_code=8):
        self.stream_id, self.error_code = stream_id, error_code


class DataReceived:
    def __init__(self, data=b"x", stream_id=1):
        self.data, self.stream_id, self.flow_controlled_length = data, stream_id, len(data)


class StreamEnded:
    def __init__(self, stream_id=1):
        self.stream_id = stream_id


class ProtocolNegotiated:
    def __init__(self, alpn_protocol="h3"):
        self.alpn_protocol = alpn_protocol


class HeadersReceived:
    def __init__(self, spec, stream_id=0):
        self.stream_id = stream_id
        self.headers = [(key.encode(), value.encode()) for key, value in headers(spec)]


class QuicBase:
    def __init__(self):
        self._quic = MagicMock()
        self.transmit = MagicMock()
        self.close = MagicMock()


class ConnectionTerminated:
    def __init__(self, error_code=0, reason_phrase=""):
        self.error_code, self.reason_phrase = error_code, reason_phrase


H2_EVENTS = SimpleNamespace(RequestReceived=RequestReceived, StreamReset=StreamReset,
                            DataReceived=DataReceived, StreamEnded=StreamEnded,
                            ConnectionTerminated=ConnectionTerminated)


class PlanTests(unittest.TestCase):
    def test_exact_complete_plan_passes_actual_accepted_validator(self):
        for tls in ("TLSv1.2", "TLSv1.3"):
            generated = gate.validate_plan(plan(tls))
            self.assertEqual(len(generated["scenarios"]), 35)
            self.assertEqual(len(generated["peers"]), 35)
            self.assertEqual(len({c["url"] for c in generated["scenarios"]}), 35)
            for spec in generated["scenarios"]:
                config = generated["peers"][spec["peer"]]
                self.assertEqual(config["sha256"], "a" * 64)
                self.assertIn("{run}", config["argv"])
                self.assertEqual(spec["tls"], "TLSv1.3" if spec["client"] == "h3" else tls)

    def test_bad_plan_inputs_fail_without_file_access(self):
        for options in ({"tls": "auto"}, {"timeout_ms": 0}, {"timeout_ms": 30001}):
            with self.subTest(options=options), self.assertRaises(peer.PeerError):
                peer.build_plan("/source/peer.py", "a" * 64, "/cert", "/key", "/ca", **options)
        with self.assertRaises(peer.PeerError):
            peer.build_plan("relative.py", "bad", "/cert", "/key", "/ca")

    def test_import_and_plan_cli_do_not_load_native_protocol_stacks(self):
        original = builtins.__import__
        blocked = {"ssl", "socket", "h2", "wsproto", "aioquic", "cryptography", "hashlib"}

        def guarded(name, *args, **kwargs):
            if name.split(".")[0] in blocked:
                raise AssertionError("native import during preparation: " + name)
            return original(name, *args, **kwargs)

        source = Path(peer.__file__).read_text()
        with patch("builtins.__import__", side_effect=guarded):
            exec(compile(source, peer.__file__, "exec"), {"__name__": "preparation_only"})
            with patch.object(peer, "source_hash", return_value="a" * 64), \
                 patch("sys.stdout", new_callable=io.StringIO) as stdout:
                peer.main(["plan", "--cert", "/cert", "--key", "/key", "--ca", "/ca"])
            self.assertEqual(len(gate.validate_plan(json.loads(stdout.getvalue()))["scenarios"]), 35)


class ServerHelloObservationTests(unittest.TestCase):
    @staticmethod
    def hello(tls="TLSv1.2", extensions=None):
        if extensions is None:
            extensions = b"\x00\x2b\x00\x02\x03\x04" if tls == "TLSv1.3" else b""
        body = (b"\x03\x03" + b"r" * 32 + b"\x00\x13\x02\x00" +
                len(extensions).to_bytes(2, "big") + extensions)
        handshake = b"\x02" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

    def test_version_comes_from_complete_server_hello_under_any_fragmentation(self):
        for tls in ("TLSv1.2", "TLSv1.3"):
            encoded = self.hello(tls)
            for size in range(1, len(encoded) + 1):
                with self.subTest(tls=tls, fragment=size):
                    observed = peer.ServerHelloObserver()
                    for start in range(0, len(encoded), size):
                        observed.feed(encoded[start:start + size])
                    self.assertEqual(observed.version, tls)
                    observed.feed(b"application bytes are no longer retained")
                    self.assertEqual(observed.version, tls)
                    self.assertFalse(observed.records)
                    self.assertFalse(observed.handshakes)

    def test_fragmented_handshake_across_tls_records_and_no_policy_guess(self):
        handshake = self.hello("TLSv1.3")[5:]
        observed = peer.ServerHelloObserver()
        for part in (handshake[:3], handshake[3:9], handshake[9:]):
            observed.feed(b"\x16\x03\x03" + len(part).to_bytes(2, "big") + part)
        self.assertEqual(observed.version, "TLSv1.3")
        missing = peer.ServerHelloObserver()
        missing.feed(self.hello("TLSv1.3")[:-1])
        self.assertIsNone(missing.version)

    def test_invalid_duplicate_or_unbounded_hello_is_never_observation_evidence(self):
        for data in (self.hello(extensions=b"\x00\x2b\x00\x02\x03\x05"),
                     self.hello(extensions=b"\x00\x2b\x00\x02\x03\x04" * 2),
                     self.hello(extensions=b"\x00\x2b\x00\x03\x03\x04"),
                     b"\x16\x03\x03\xff\xff", b"x" * (peer.MAX_HEADERS + 1)):
            with self.subTest(data=data[:12]), self.assertRaises(peer.PeerError):
                peer.ServerHelloObserver().feed(data)

    def test_public_bio_driver_preserves_selected_version_before_failed_finished(self):
        class BIO:
            def __init__(self):
                self.data = bytearray()

            @property
            def pending(self):
                return len(self.data)

            def read(self, size):
                chunk = bytes(self.data[:size])
                del self.data[:size]
                return chunk

        api = SimpleNamespace(MemoryBIO=BIO)
        for tls in ("TLSv1.2", "TLSv1.3"):
            with self.subTest(tls=tls):
                raw, context = MagicMock(), MagicMock()
                context.wrap_bio.return_value.version.return_value = None
                stream = peer.TLSStream(raw, context, api)
                stream.outgoing.data.extend(self.hello(tls))
                stream.flush()
                self.assertEqual(stream.version(), tls)
                raw.sendall.assert_called_once_with(self.hello(tls))
                context.wrap_bio.return_value.version.return_value = "TLSv1.3" if tls == "TLSv1.2" else "TLSv1.2"
                with self.assertRaises(peer.PeerError):
                    stream.version()

    def test_public_bio_driver_handles_fragmented_io_short_writes_and_received_eof(self):
        class SSLError(Exception):
            pass

        class WantRead(SSLError):
            pass

        class WantWrite(SSLError):
            pass

        class EOF(SSLError):
            pass

        class BIO:
            def __init__(self):
                self.data, self.eof = bytearray(), False

            @property
            def pending(self):
                return len(self.data)

            def read(self, size):
                data = bytes(self.data[:size])
                del self.data[:size]
                return data

            def write(self, data):
                self.data.extend(data)

            def write_eof(self):
                self.eof = True

        api = SimpleNamespace(MemoryBIO=BIO, SSLError=SSLError, SSLWantReadError=WantRead,
                              SSLWantWriteError=WantWrite, SSLEOFError=EOF)
        raw, context = MagicMock(), MagicMock()
        raw.gettimeout.return_value = 1.0
        raw.recv.side_effect = [b"fragment one", b"fragment two", b""]
        tls = context.wrap_bio.return_value
        tls.do_handshake.side_effect = [WantWrite(), WantRead(), WantRead(), None]
        stream = peer.TLSStream(raw, context, api)
        stream.outgoing.data.extend(self.hello("TLSv1.3"))
        stream.do_handshake()
        self.assertEqual(stream.incoming.data, b"fragment onefragment two")
        self.assertEqual(stream.observed.version, "TLSv1.3")
        tls.write.side_effect = [2, 3]
        stream.sendall(b"hello")
        self.assertEqual([bytes(call.args[0]) for call in tls.write.call_args_list],
                         [b"hello", b"llo"])
        tls.read.side_effect = [WantRead(), EOF()]
        self.assertEqual(stream.recv(16384), b"")
        self.assertTrue(stream.incoming.eof)
        raw.settimeout.assert_called_with(1.0)

        with patch.object(peer.time, "monotonic", side_effect=[0.0, 1.1]):
            with self.assertRaises(TimeoutError):
                stream.do_handshake()
        raw.settimeout.assert_called_with(1.0)

        stream = peer.TLSStream(raw, context, api)
        stream.outgoing.data.extend(self.hello())
        raw.sendall.side_effect = BrokenPipeError("not transmitted")
        with self.assertRaises(BrokenPipeError):
            stream.flush()
        self.assertIsNone(stream.observed.version)


class ObservationTests(unittest.TestCase):
    def good(self, action="success"):
        value, records, gates = oracle("h1", action)
        connected(value)
        value.request(1, 1, headers(value.case))
        if action == "success":
            value.response(1, 1, value.case["expected"].encode())
        else:
            value.held(1, 1)
        value.closed(1, "received_eof")
        return value, records, gates

    def test_actual_facts_join_accepted_consumer_validator(self):
        value, records, _ = self.good()
        record = value.finish()
        consumer = dict(record, requested_tls=value.case["tls"], required_alpn=value.case["alpn"],
                        fallback_isolated=True, requests_submitted=1, cleanup="confirmed",
                        cleanup_kind="request_completion")
        gate.validate_scenario(value.case, consumer, record, "fresh-nonce")
        self.assertEqual(record["requests"], 1)
        self.assertEqual(record["connections"], 1)
        self.assertEqual(record["closure_observations"], ["received_eof"])

    def test_requested_policy_never_fills_missing_negotiation(self):
        value, _, _ = oracle()
        value.opened(1)
        value.request(1, 1, headers(value.case))
        value.response(1, 1, value.case["expected"].encode())
        value.closed(1, "received_eof")
        record = value.finish()
        self.assertEqual(record["result"], "FAIL")
        self.assertIsNone(record["tls"])
        self.assertIsNone(record["alpn"])

    def test_wrong_actual_tls_alpn_and_nonce_fail_closed(self):
        for tls, alpn in (("TLSv1.2", "http/1.1"), ("TLSv1.3", "h2"), (None, None)):
            value, _, _ = self.good()
            value.negotiated(1, tls, alpn, "socket")
            self.assertEqual(value.finish()["result"], "FAIL")
        with self.assertRaises(peer.PeerError):
            peer.Oracle(case(), "", "peer", lambda record: None)

    def test_duplicate_request_connection_and_wrong_route_are_replay(self):
        for mutate in (lambda v: v.request(1, 3, headers(v.case)),
                       lambda v: v.opened(2),
                       lambda v: v.request(1, 1, [(":method", "GET"), (":path", "/wrong")])):
            value, _, _ = self.good()
            try:
                mutate(value)
            except peer.PeerError as error:
                value.error(str(error))
            record = value.finish()
            self.assertEqual(record["result"], "FAIL")
            self.assertTrue(record["replay"] or record["errors"])

    def test_close_is_not_reset_and_local_teardown_never_passes(self):
        value, _, _ = self.good("cancellation")
        record = value.finish()
        self.assertEqual(record["resets"], [])
        self.assertEqual(record["result"], "PASS")
        value, _, _ = oracle("h1", "cancellation")
        connected(value)
        value.request(1, 1, headers(value.case))
        value.held(1, 1)
        value.closed(1, "local_stop")
        self.assertEqual(value.finish()["result"], "FAIL")

    def test_active_missing_hold_wrong_payload_and_unknown_reset_fail(self):
        value, _, _ = self.good()
        value.opened(2)
        self.assertNotEqual(value.finish()["result"], "PASS")
        value, _, _ = oracle("h1", "timeout")
        connected(value)
        value.request(1, 1, headers(value.case))
        value.closed(1, "received_eof")
        self.assertEqual(value.finish()["result"], "FAIL")
        value, _, _ = self.good()
        with self.assertRaises(peer.PeerError):
            value.response(1, 1, b"wrong")
        with self.assertRaises(peer.PeerError):
            value.reset(1, 77, 8)

    def test_gate_only_after_actual_valid_request_is_held(self):
        value, _, gates = oracle("h2", "cancellation")
        connected(value)
        self.assertEqual(gates, [])
        with self.assertRaises(peer.PeerError):
            value.held(1, 1)
        value.request(1, 1, headers(value.case))
        self.assertEqual(gates, [])
        value.held(1, 1)
        value.held(1, 1)
        self.assertEqual(gates, [(value.case["id"], "fresh-nonce")])

    def test_invalid_identity_retains_handshake_error_without_fake_protocol(self):
        value, _, _ = oracle("h1", "invalid_identity")
        value.opened(1)
        value.handshake_failed(1, "SSL: CERTIFICATE_UNKNOWN", identity_alert=True)
        value.closed(1, "tls_alert")
        record = value.finish()
        self.assertEqual(record["requests"], 0)
        self.assertIsNone(record["tls"])
        self.assertEqual(record["result"], "FAIL")
        self.assertEqual(len(record["expected_identity_handshake_errors"]), 1)

    def test_completed_identity_rejection_with_actual_protocol_can_join(self):
        value, _, _ = oracle("h2", "invalid_identity")
        connected(value)
        value.closed(1, "tls_alert")
        self.assertEqual(value.finish()["result"], "PASS")

    def test_stats_emit_exactly_one_scenario_and_errors_are_retained(self):
        value, records, _ = self.good()
        value.stats()
        value.stats()
        self.assertEqual(sum(r["kind"] == "scenario" for r in records), 1)
        self.assertEqual(records[-1]["active_connections"], 0)
        value.error("raw independent failure")
        value.stats()
        self.assertIn("raw independent failure", records[-1]["errors"])


class AdapterTests(unittest.TestCase):
    def test_all_non_websocket_tcp_action_routes_use_actual_request_adapter(self):
        for client in ("h1", "h2", "managed_h1", "managed_h2", "sse"):
            for action in peer.ACTIONS:
                with self.subTest(client=client, action=action):
                    value, _, gates = oracle(client, action)
                    connected(value)
                    if action == "invalid_identity":
                        value.closed(1, "tls_alert")
                    elif client in ("h1", "managed_h1"):
                        adapter = peer.H1Adapter(value, 1, MagicMock())
                        adapter.receive(b"GET " + peer.route(value.case).encode() +
                                        b" HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
                        value.closed(1, "received_eof")
                    else:
                        transport = FakeH2()
                        transport.events = [RequestReceived(value.case)]
                        peer.H2Adapter(value, 1, transport, H2_EVENTS).receive(b"headers")
                        value.closed(1, "received_eof")
                    self.assertEqual(value.finish()["result"], "PASS")
                    self.assertEqual(bool(gates), peer.needs_gate(value.case))

    def test_h1_parses_wire_before_gate_and_sends_exact_fixed_body(self):
        value, _, gates = oracle()
        connected(value)
        wire = MagicMock()
        adapter = peer.H1Adapter(value, 1, wire.sendall)
        adapter.receive(b"GET " + peer.route(value.case).encode() +
                        b" HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
        self.assertEqual(value.requests, 1)
        self.assertIn(value.case["expected"].encode(), wire.sendall.call_args.args[0])
        self.assertEqual(gates, [])

    def test_h1_cancellation_and_shutdown_are_wire_held_not_synthetic(self):
        for action in ("timeout", "cancellation", "shutdown"):
            value, _, gates = oracle("h1", action)
            connected(value)
            wire = MagicMock()
            peer.H1Adapter(value, 1, wire.sendall).receive(
                b"GET " + peer.route(value.case).encode() + b" HTTP/1.1\r\nHost: localhost:443\r\n\r\n")
            self.assertTrue(value.holds)
            self.assertEqual(bool(gates), action == "cancellation")
            self.assertEqual(wire.sendall.called, action == "shutdown")
            if action == "shutdown":
                self.assertIn(b"Transfer-Encoding: chunked", wire.sendall.call_args.args[0])

    def test_h1_bounds_and_pipelining_reject_instead_of_ignoring(self):
        for data in (b"x" * (peer.MAX_HEADERS + 1),
                     b"GET /wrong HTTP/1.1\r\nHost: localhost\r\n\r\n",
                     b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"):
            value, _, _ = oracle()
            connected(value)
            with self.assertRaises(peer.PeerError):
                peer.H1Adapter(value, 1, lambda data: None).receive(data)

    def test_h2_actual_request_reset_and_held_gate_flow(self):
        value, _, gates = oracle("h2", "cancellation")
        connected(value)
        transport = FakeH2()
        adapter = peer.H2Adapter(value, 1, transport, H2_EVENTS)
        transport.events = [RequestReceived(value.case)]
        adapter.receive(b"mock h2 bytes")
        self.assertEqual(transport.headers, [])
        self.assertEqual(gates, [(value.case["id"], "fresh-nonce")])
        transport.events = [StreamReset()]
        adapter.receive(b"mock reset bytes")
        value.closed(1, "received_eof")
        self.assertEqual(value.finish()["resets"], [{"connection": 1, "stream": 1, "error_code": 8}])

    def test_h2_response_and_sse_event_have_independent_payload_facts(self):
        for client in ("h2", "sse"):
            value, _, _ = oracle(client)
            connected(value)
            transport = FakeH2()
            transport.events = [RequestReceived(value.case)]
            peer.H2Adapter(value, 1, transport, H2_EVENTS).receive(b"wire")
            payload = transport.payloads[0][1]
            self.assertIn(value.case["expected"].encode(), payload)
            self.assertEqual(transport.payloads[0][2], client == "h2")
            if client == "sse":
                self.assertIn(b"id: no-otp-1\n", payload)
                self.assertIsNone(value.last_event_id)

    def test_wss_rejects_unmasked_frames_with_mocked_wsproto(self):
        value, _, _ = oracle("wss")
        connected(value)
        transport = FakeH2()
        transport.events = [RequestReceived(value.case, "CONNECT")]
        adapter = peer.H2Adapter(value, 1, transport, H2_EVENTS, ws_factory=MagicMock())
        adapter.receive(b"headers")
        transport.events = [DataReceived(b"\x81\x01x")]
        with self.assertRaises(peer.PeerError):
            adapter.receive(b"unmasked")

    def test_gate_writer_binds_exact_fresh_path_and_never_overwrites(self):
        opener = MagicMock()
        handle = opener.return_value.__enter__.return_value
        linker, unlinker = MagicMock(), MagicMock()
        peer.publish_gate("/fresh/run", "h2.cancellation", "fresh-nonce", opener=opener,
                          linker=linker, unlinker=unlinker)
        self.assertEqual(opener.call_args.args, (Path("/fresh/run/.h2.cancellation.gate.tmp"), "x"))
        linker.assert_called_once_with(Path("/fresh/run/.h2.cancellation.gate.tmp"),
                                       Path("/fresh/run/h2.cancellation.gate.json"))
        unlinker.assert_called_once_with(Path("/fresh/run/.h2.cancellation.gate.tmp"))
        record = json.loads(handle.write.call_args.args[0])
        self.assertEqual(record, {"peer_gate": True, "id": "h2.cancellation", "nonce": "fresh-nonce"})
        for identifier in ("../escape", "x/y", ""):
            with self.assertRaises(peer.PeerError):
                peer.publish_gate("/fresh/run", identifier, "nonce", opener=opener)

    def test_gate_publication_follows_complete_close_and_preserves_existing_gate(self):
        events = []
        handle = MagicMock()
        handle.__enter__.return_value = handle
        handle.write.side_effect = lambda content: events.append(("write", content))
        handle.__exit__.side_effect = lambda *args: events.append(("close", None))
        opener = MagicMock(return_value=handle)

        def existing_gate(source, destination):
            events.append(("publish", destination))
            raise FileExistsError("existing generation gate must survive")

        unlinker = MagicMock()
        with self.assertRaises(FileExistsError):
            peer.publish_gate("/fresh/run", "h3.timeout", "nonce", opener=opener,
                              linker=existing_gate, unlinker=unlinker)
        self.assertEqual([kind for kind, _ in events], ["write", "close", "publish"])
        unlinker.assert_called_once_with(Path("/fresh/run/.h3.timeout.gate.tmp"))

    def test_wss_mocked_protocol_echo_close_and_masked_wire_facts(self):
        class TextMessage:
            def __init__(self, data, message_finished=True):
                self.data, self.message_finished = data, message_finished

        class BytesMessage(TextMessage):
            pass

        class CloseConnection:
            code = 1000

            def response(self):
                return self

        class Ping:
            pass

        class Pong:
            pass

        types = SimpleNamespace(TextMessage=TextMessage, BytesMessage=BytesMessage,
                                CloseConnection=CloseConnection, Ping=Ping, Pong=Pong)
        value, _, _ = oracle("wss")
        connected(value)
        transport, websocket = FakeH2(), MagicMock()
        websocket.send.return_value = b"mock server frame"
        adapter = peer.H2Adapter(value, 1, transport, H2_EVENTS,
                                ws_factory=lambda: websocket, ws_events=types)
        transport.events = [RequestReceived(value.case, "CONNECT")]
        adapter.receive(b"CONNECT")

        def masked(opcode, payload):
            mask = b"1234"
            return bytes([128 | opcode, 128 | len(payload)]) + mask + bytes(
                byte ^ mask[index % 4] for index, byte in enumerate(payload))

        body = value.case["expected"].encode()
        websocket.events.return_value = [TextMessage(body.decode())]
        transport.events = [DataReceived(masked(1, body))]
        adapter.receive(b"text")
        websocket.events.return_value = [CloseConnection()]
        transport.events = [DataReceived(masked(8, b"\x03\xe8"))]
        adapter.receive(b"close")
        value.closed(1, "received_eof")
        record = value.finish()
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["masked_frames"], 2)
        self.assertEqual(record["websocket_close_frames"], 1)
        self.assertTrue(transport.payloads[-1][2])

    def test_sse_last_event_id_is_read_from_actual_headers(self):
        value, _, _ = oracle("sse")
        connected(value)
        transport = FakeH2()
        event = RequestReceived(value.case)
        event.headers.append(("last-event-id", "41"))
        transport.events = [event]
        peer.H2Adapter(value, 1, transport, H2_EVENTS).receive(b"headers")
        self.assertEqual(value.last_event_id, "41")
        self.assertEqual(value.sse_ids, ["no-otp-1"])

    def test_stdin_only_stats_and_stop_with_bound_and_no_fake_progress(self):
        value, records, _ = oracle()
        self.assertEqual(peer.command('{"command":"stats"}', value), "stats")
        self.assertEqual(records[0]["result"], "FAIL")
        self.assertEqual(peer.command('{"command":"stop"}', value), "stop")
        for bad in ('{"command":"pass"}', "x" * 4097, "not JSON"):
            with self.assertRaises((peer.PeerError, ValueError)):
                peer.command(bad, value)


class QuicAdapterTests(unittest.TestCase):
    def setup_protocol(self, action):
        value, records, gates = oracle("h3", action)
        http = MagicMock()
        http.handle_event.side_effect = lambda event: [event] if isinstance(
            event, (HeadersReceived, DataReceived)) else []
        api = SimpleNamespace(QuicConnectionProtocol=QuicBase, H3Connection=lambda quic: http,
                              ProtocolNegotiated=ProtocolNegotiated, StreamReset=StreamReset,
                              ConnectionTerminated=ConnectionTerminated,
                              HeadersReceived=HeadersReceived, DataReceived=DataReceived)
        protocol = peer.quic_protocol(api, value)()
        return value, records, gates, http, protocol

    def test_quic_actual_negotiation_request_payload_and_close(self):
        value, _, gates, http, protocol = self.setup_protocol("success")
        protocol.quic_event_received(ProtocolNegotiated())
        protocol.quic_event_received(HeadersReceived(value.case))
        self.assertEqual(http.send_data.call_args.args[1], value.case["expected"].encode())
        self.assertTrue(http.send_data.call_args.kwargs["end_stream"])
        self.assertEqual(gates, [])
        protocol.quic_event_received(ConnectionTerminated())
        self.assertEqual(value.finish()["result"], "PASS")

    def test_all_three_quic_held_actions_publish_only_after_wire_headers(self):
        for action in ("timeout", "cancellation", "shutdown"):
            value, _, gates, http, protocol = self.setup_protocol(action)
            protocol.quic_event_received(ProtocolNegotiated())
            self.assertEqual(gates, [])
            protocol.quic_event_received(HeadersReceived(value.case))
            self.assertEqual(gates, [(value.case["id"], "fresh-nonce")])
            http.send_data.assert_not_called()
            if action == "cancellation":
                protocol.quic_event_received(StreamReset(stream_id=0, error_code=0x10C))
            protocol.quic_event_received(ConnectionTerminated())
            record = value.finish()
            self.assertEqual(record["result"], "PASS")
            self.assertEqual(bool(record["resets"]), action == "cancellation")

    def test_quic_invalid_identity_retains_actual_first_flight_and_alert(self):
        value, _, _, _, protocol = self.setup_protocol("invalid_identity")
        protocol.quic_event_received(ProtocolNegotiated())
        protocol.quic_event_received(ConnectionTerminated(0x12A, "bad certificate"))
        record = value.finish()
        self.assertEqual(record["result"], "PASS")
        self.assertEqual(record["requests"], 0)
        self.assertEqual(len(record["expected_identity_handshake_errors"]), 1)

    def test_quic_absent_negotiation_idle_and_unknown_crypto_errors_fail(self):
        value, _, _, _, protocol = self.setup_protocol("invalid_identity")
        protocol.quic_event_received(ConnectionTerminated(0x12A, "bad certificate"))
        self.assertIsNone(value.finish()["tls"])
        self.assertEqual(value.finish()["result"], "FAIL")
        for code, reason in ((1, "Idle timeout"), (0x101, "unexpected message")):
            value, _, _, _, protocol = self.setup_protocol("invalid_identity")
            protocol.quic_event_received(ProtocolNegotiated())
            protocol.quic_event_received(ConnectionTerminated(code, reason))
            self.assertEqual(value.finish()["result"], "FAIL")

    def test_local_quic_teardown_and_unknown_stream_reset_cannot_confirm(self):
        value, _, _, _, protocol = self.setup_protocol("cancellation")
        protocol.quic_event_received(ProtocolNegotiated())
        protocol.quic_event_received(StreamReset(stream_id=99))
        protocol.close.assert_called_once()
        protocol.quic_event_received(ConnectionTerminated())
        self.assertEqual(value.finish()["result"], "FAIL")
        self.assertEqual(value.closures, ["local_stop"])


class ManualHandshakeTests(unittest.TestCase):
    def test_real_tcp_adapter_reads_actual_socket_selection_even_on_rejection(self):
        class SSLFailure(Exception):
            reason = "CERTIFICATE_UNKNOWN"

        class WantRead(SSLFailure):
            pass

        class WantWrite(SSLFailure):
            pass

        class InlineThread:
            def __init__(self, target, args):
                self.target, self.args = target, args

            def start(self):
                self.target(*self.args)

            def join(self, timeout):
                pass

            def is_alive(self):
                return False

        for selection in ((None, None), ("TLSv1.3", "http/1.1")):
            with self.subTest(selection=selection):
                value, records, _ = oracle("h1", "invalid_identity")
                listener, raw, wrapped, context = (MagicMock() for _ in range(4))
                listener.accept.return_value = (raw, ("127.0.0.1", 1))
                listener.getsockname.return_value = ("127.0.0.1", 443)
                raw.gettimeout.return_value = 7.0
                wrapped.do_handshake.side_effect = SSLFailure("certificate alert from client")
                wrapped.version.return_value, wrapped.selected_alpn_protocol.return_value = selection
                context.wrap_bio.return_value = wrapped
                incoming, outgoing = MagicMock(), MagicMock()
                outgoing.pending = 0
                fake_ssl = SimpleNamespace(SSLContext=MagicMock(return_value=context),
                    PROTOCOL_TLS_SERVER=1, TLSVersion=SimpleNamespace(TLSv1_2=2, TLSv1_3=3),
                    MemoryBIO=MagicMock(side_effect=[incoming, outgoing]),
                    SSLWantReadError=WantRead, SSLWantWriteError=WantWrite,
                    SSLError=SSLFailure, OPENSSL_VERSION="mock OpenSSL; no native invocation")
                fake_socket = SimpleNamespace(socket=MagicMock(return_value=listener),
                    AF_INET=1, SOCK_STREAM=2, SOL_SOCKET=3, SO_REUSEADDR=4, SHUT_RDWR=5)
                stdin = io.StringIO('{"command":"stats"}\n{"command":"stop"}\n')
                fake_select = SimpleNamespace(select=MagicMock(side_effect=[
                    ([listener], [], []), ([stdin], [], []), ([stdin], [], [])]))
                fake_threading = SimpleNamespace(RLock=nullcontext, Thread=InlineThread)
                args = SimpleNamespace(tls="TLSv1.3", cert="/cert", key="/key",
                    client="h1", action="invalid_identity", timeout_ms=5000, lifetime=30)
                with patch.dict(sys.modules, {"ssl": fake_ssl, "socket": fake_socket,
                                              "select": fake_select, "threading": fake_threading}), \
                     patch("sys.stdin", stdin):
                    ready = MagicMock()
                    peer.run_tcp(args, value, ready)
                context.wrap_bio.assert_called_once_with(incoming, outgoing, server_side=True)
                self.assertEqual(context.minimum_version, context.maximum_version)
                scenario = next(record for record in records if record["kind"] == "scenario")
                self.assertEqual(scenario["tls"], selection[0])
                self.assertEqual(scenario["alpn"], selection[1])
                self.assertEqual(scenario["result"], "PASS" if selection[0] else "FAIL")
                self.assertEqual(scenario["requests"], 0)
                self.assertEqual(len(scenario["expected_identity_handshake_errors"]), 1)
                context.load_cert_chain.assert_called_once_with("/cert", "/key")


if __name__ == "__main__":
    unittest.main()
