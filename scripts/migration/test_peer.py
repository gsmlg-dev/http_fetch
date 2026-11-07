"""Pure controls for the migration relay and receipt-based acceptance proof."""

import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from peer import Backend, PHASES, Receipts, Relay, phase_payload, validate_cid_bindings
from gate import consumer_environment, path_receipt, phase_receipts, validate_proof


class Transport:
    def __init__(self, address):
        self.address = address
        self.sent = []
        self.closed = False

    def get_extra_info(self, name):
        assert name == "sockname"
        return self.address

    def sendto(self, data, address):
        self.sent.append((data, address))

    def close(self):
        self.closed = True


class RelayTest(unittest.TestCase):
    def setUp(self):
        self.server = ("127.0.0.1", 4433)
        self.client = ("127.0.0.1", 9999)
        self.relay = Relay(self.server)
        self.front = Transport(("127.0.0.1", 8888))
        self.relay.connection_made(self.front)
        self.backends = []
        for index, address in enumerate([
            ("127.0.0.1", 10001), ("127.0.0.1", 10002), ("127.0.0.2", 10003)
        ]):
            backend = Backend(self.relay, index)
            backend.connection_made(Transport(address))
            self.backends.append(backend)
        self.relay.backends = self.backends

    def test_switch_changes_only_the_upstream_socket_and_requires_real_traffic(self):
        self.relay.datagram_received(b"initial", self.client)
        self.relay.switch(1)
        self.assertEqual(self.backends[1].transport.sent, [])
        self.relay.datagram_received(b"port", self.client)
        self.relay.switch(2)
        self.relay.datagram_received(b"ip", self.client)
        self.assertEqual(self.front.sent, [])
        for backend, payload in zip(self.backends, [b"initial", b"port", b"ip"]):
            self.assertEqual(backend.transport.sent, [(payload, self.server)])
        self.assertEqual(self.relay.client, self.client)

    def test_old_backend_traffic_still_reaches_client_but_response_uses_new_path(self):
        self.relay.datagram_received(b"start", self.client)
        self.relay.switch(2)
        self.backends[0].datagram_received(b"old-path-challenge", self.server)
        self.assertEqual(self.front.sent, [(b"old-path-challenge", self.client)])
        self.relay.datagram_received(b"response", self.client)
        self.assertEqual(self.backends[2].transport.sent, [(b"response", self.server)])
        self.assertEqual(self.backends[0].late_received, 1)

    def test_unrelated_remote_cannot_replace_the_client_or_spoof_server_response(self):
        self.relay.datagram_received(b"start", self.client)
        self.relay.datagram_received(b"other", ("127.0.0.1", 2222))
        self.backends[0].datagram_received(b"spoof", ("127.0.0.2", 4433))
        self.assertEqual(self.backends[0].transport.sent, [(b"start", self.server)])
        self.assertEqual(self.front.sent, [])

    def test_cid_observation_is_taken_from_forwarded_short_header_packets(self):
        self.relay.datagram_received(b"\xc0long-header", self.client)
        self.relay.datagram_received(b"\x40abcdefghprotected", self.client)
        self.relay.switch(2)
        self.relay.datagram_received(b"\x40ijklmnopprotected", self.client)
        self.assertEqual(self.backends[0].dcids, [b"abcdefgh".hex()])
        self.assertEqual(self.backends[2].dcids, [b"ijklmnop".hex()])
        self.assertEqual(self.backends[1].dcids, [])

    def test_cleanup_closes_every_retained_backend_and_frontend(self):
        self.relay.close()
        self.assertTrue(self.front.closed)
        self.assertTrue(all(item.transport.closed for item in self.backends))

    def test_server_cids_are_observed_per_backend_and_phase_from_actual_short_headers(self):
        self.relay.datagram_received(b"initial", self.client)
        self.backends[0].datagram_received(b"\xc0long-header", self.server)
        self.backends[0].datagram_received(b"\x40client00protected", self.server)
        self.relay.switch(2)
        self.backends[0].datagram_received(b"\x40client00old-probe", self.server)
        self.backends[2].datagram_received(b"\x40client01new-probe", self.server)
        self.assertEqual(self.backends[0].server_dcids, [b"client00".hex()])
        self.assertEqual(self.backends[0].server_dcids_by_phase,
                         [[b"client00".hex()], [], [b"client00".hex()]])
        self.assertEqual(self.backends[2].server_dcids, [b"client01".hex()])


class ReceiptsTest(unittest.TestCase):
    def test_stream_bytes_alone_or_old_phase_datagrams_cannot_complete_new_phase(self):
        receipts = Receipts("migrating", 0)
        receipts.stream_data(0, phase_payload("migrating", PHASES[0]), False)
        self.assertFalse(receipts.phase_complete(0))
        receipts.datagram(receipts.markers(0)[0])
        self.assertTrue(receipts.phase_complete(0))
        receipts.stream_data(0, phase_payload("migrating", PHASES[1]), False)
        self.assertFalse(receipts.phase_complete(1))
        receipts.datagram(receipts.markers(1)[2])
        self.assertTrue(receipts.phase_complete(1))

    def test_exact_fragmented_stream_requires_final_fin_and_preserves_datagram_loss(self):
        receipts = Receipts("control", 4)
        for index, phase in enumerate(PHASES):
            payload = phase_payload("control", phase)
            receipts.stream_data(4, payload[:17], False)
            receipts.stream_data(4, payload[17:], False)
            # One of three unique messages is enough; delivery is unreliable.
            receipts.datagram(receipts.markers(index)[1])
            self.assertEqual(receipts.phase_complete(index), index < 2)
        receipts.stream_data(4, b"", True)
        self.assertTrue(receipts.phase_complete(2))
        self.assertEqual(receipts.proof()["datagrams_observed"], [1, 1, 1])

    def test_wrong_bytes_wrong_stream_early_fin_and_unknown_datagrams_fail(self):
        for operation in [
            lambda r: r.stream_data(0, b"incorrect", False),
            lambda r: r.stream_data(4, b"", False),
            lambda r: r.stream_data(0, b"", True),
            lambda r: r.datagram(b"unexpected"),
        ]:
            with self.assertRaises(AssertionError):
                operation(Receipts("migrating", 0))


class GateProofTest(unittest.TestCase):
    def setUp(self):
        self.server = []
        connections = []
        for token, label in enumerate(("migrating", "control"), 1):
            receipts = Receipts(label, 0)
            for index, phase in enumerate(PHASES):
                receipts.stream_data(0, phase_payload(label, phase), index == 2)
                receipts.datagram(receipts.markers(index)[0])
            proof = receipts.proof()
            connections.append(proof | {"handshakes": 1})
            self.server += [
                {"event": "connection_ready", "connection": token, "alpn": "ex-quic-test"},
                {"event": "stream_open", "connection": token, "stream_id": 0},
                {"event": "stream_complete", "connection": token, "stream_id": 0,
                 "bytes": proof["bytes"], "sha256": proof["sha256"], "fin": True},
            ]
        self.result = {"passed": True, "peer_version": "1.2.0", "proof": {
            "connections": connections, "retained_backend_sockets": 3,
            "same_stream_across_phases": True,
            "backends": [
                {"address": ["127.0.0.1", 10001], "sent": 3, "received": 2, "dcids": ["a"]},
                {"address": ["127.0.0.1", 10002], "sent": 2, "received": 2, "dcids": ["a"]},
                {"address": ["127.0.0.2", 10003], "sent": 2, "received": 2, "dcids": ["b"]},
            ]}}
        for index, backend in enumerate(self.result["proof"]["backends"]):
            backend["server_dcids"] = ["old" if index < 2 else "new"]
            backend["server_dcids_by_phase"] = ([[], ["old"], ["old"]] if index == 1
                                                 else [["old"], [], []] if index == 0
                                                 else [[], [], ["new"]])

    def test_exact_bidirectional_proof_accepts_unreliable_datagram_delivery(self):
        self.assertEqual(validate_proof(self.server, self.result)["peer"], self.result["proof"])

    def test_missing_or_replacement_server_connection_fails(self):
        for server in (self.server[:-1], self.server + [self.server[0]]):
            with self.assertRaises(AssertionError):
                validate_proof(server, self.result)

    def test_wrong_bytes_stream_fin_handshake_or_missing_datagram_fails(self):
        mutations = [
            lambda r: r["proof"]["connections"][0].update(sha256="wrong"),
            lambda r: r["proof"]["connections"][0].update(stream_id=4),
            lambda r: r["proof"]["connections"][0].update(fin=False),
            lambda r: r["proof"]["connections"][0].update(handshakes=2),
            lambda r: r["proof"]["connections"][0].update(datagrams_observed=[1, 0, 1]),
            lambda r: r["proof"]["backends"][2].update(dcids=["a"]),
            lambda r: r.update(passed=False),
        ]
        for mutate in mutations:
            result = copy.deepcopy(self.result)
            mutate(result)
            with self.assertRaises(AssertionError):
                validate_proof(self.server, result)

    def test_path_approval_requires_selected_validated_mtu_and_old_slot_retirement(self):
        event = {"event": "public_path_info", "connection": 1,
                 "active_path": "new", "path_records": 1,
                 "paths": [{"id": "new", "remote": ["127.0.0.1", 10002],
                            "validated": True, "mtu_validated": True}]}
        self.assertEqual(path_receipt([event], ["127.0.0.1", 10002], retired=True), event)
        for field, value in [("validated", False), ("mtu_validated", False),
                             ("remote", ["127.0.0.1", 10001])]:
            changed = copy.deepcopy(event)
            changed["paths"][0][field] = value
            self.assertIsNone(path_receipt([changed], ["127.0.0.1", 10002]))
        retained = copy.deepcopy(event)
        retained["path_records"] = 2
        retained["paths"].append({"id": "old"})
        self.assertIsNone(path_receipt([retained], ["127.0.0.1", 10002], retired=True))
        # An earlier valid receipt cannot override newer unvalidated state.
        self.assertIsNone(path_receipt([event, changed], ["127.0.0.1", 10002]))

    def test_phase_progress_requires_both_connections_and_surfaces_peer_failure(self):
        migrating = {"event": "phase", "label": "migrating", "phase": "port"}
        self.assertFalse(phase_receipts([migrating], "port"))
        self.assertTrue(phase_receipts([migrating, migrating | {"label": "control"}], "port"))
        with self.assertRaisesRegex(RuntimeError, "peer failed"):
            phase_receipts([{"event": "result", "passed": False, "reason": "lost"}], "port")

    def test_initial_path_requires_reachability_but_migrated_paths_require_mtu_proof(self):
        target = ["127.0.0.1", 10001]
        initial = {"event": "public_path_info", "connection": 1,
                   "active_path": "initial", "path_records": 1,
                   "paths": [{"id": "initial", "remote": target,
                              "validated": True, "mtu_validated": False}]}
        self.assertEqual(path_receipt([initial], target, require_mtu=False), initial)
        self.assertIsNone(path_receipt([initial], target))
        for field, value in [("validated", False), ("remote", ["127.0.0.1", 10002])]:
            unreachable = copy.deepcopy(initial)
            unreachable["paths"][0][field] = value
            self.assertIsNone(path_receipt([unreachable], target, require_mtu=False))
        migrated = copy.deepcopy(initial)
        migrated["paths"][0]["mtu_validated"] = True
        self.assertEqual(path_receipt([migrated], target), migrated)

    def test_ip_migration_requires_distinct_outgoing_cid_and_old_probe_binding(self):
        for mutate in (
            lambda b: b[2].update(server_dcids=["old"]),
            lambda b: b[1].update(server_dcids_by_phase=[[], ["old"], ["changed"]]),
            lambda b: b[1].update(server_dcids_by_phase=[[], ["old"], []]),
        ):
            backends = copy.deepcopy(self.result["proof"]["backends"])
            mutate(backends)
            with self.assertRaises(AssertionError):
                validate_cid_bindings(backends)
        backends = copy.deepcopy(self.result["proof"]["backends"])
        # Reusing the outgoing CID for port-only NAT rebinding is allowed.
        validate_cid_bindings(backends)
        # Rotating it for NAT rebinding is allowed too, provided IPs remain distinct.
        backends[1]["server_dcids"] = ["port"]
        backends[1]["server_dcids_by_phase"] = [[], ["port"], ["port"]]
        validate_cid_bindings(backends)

    def test_consumer_project_environment_cannot_reuse_source_build_or_inject_code(self):
        with patch.dict(os.environ, {
            "MIX_BUILD_PATH": "/source/build", "MIX_DEPS_PATH": "/source/deps",
            "MIX_EXS": "/source/mix.exs", "HTTP_FETCH_CI_APP": "hell",
            "ERL_LIBS": "/source/lib", "ERL_FLAGS": "-pa /source/ebin",
            "ELIXIR_ERL_OPTIONS": "-pa /source/ebin", "HEX_MIRROR": "https://wrong.example",
        }):
            env = consumer_environment(Path("/isolated/quic"))
        self.assertEqual(env["MIX_BUILD_PATH"], "/isolated/quic/_build/prod")
        self.assertEqual(env["MIX_DEPS_PATH"], "/isolated/quic/deps")
        self.assertEqual(env["MIX_HOME"], "/isolated/mix")
        self.assertEqual(env["MIX_ENV"], "prod")
        for key in ("MIX_EXS", "HTTP_FETCH_CI_APP", "ERL_LIBS", "ERL_FLAGS",
                    "ELIXIR_ERL_OPTIONS", "HEX_MIRROR"):
            self.assertNotIn(key, env)

    def test_consumer_environment_finds_mix_default_production_application(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "quic"
            application = project / "_build/prod/lib/server_consumer/ebin/server_consumer.app"
            application.parent.mkdir(parents=True)
            application.touch()
            with patch.dict(os.environ, {"MIX_BUILD_PATH": "/workspace/_build/test"}):
                env = consumer_environment(project)
            self.assertTrue((Path(env["MIX_BUILD_PATH"]) /
                             "lib/server_consumer/ebin/server_consumer.app").is_file())

    def test_consumer_environment_preserves_only_project_local_prepared_build_path(self):
        project = Path("/isolated/quic")
        for build_path in ("/isolated/quic/_build/candidate", "_build/candidate"):
            with self.subTest(build_path=build_path), \
                    patch.dict(os.environ, {"MIX_BUILD_PATH": build_path}):
                env = consumer_environment(project)
            self.assertEqual(env["MIX_BUILD_PATH"], "/isolated/quic/_build/candidate")


if __name__ == "__main__":
    unittest.main()
