"""Published no-OTP releases retain source, traffic and cleanup gates."""

from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import no_otp_consumer_gate as gate
from test_no_otp_consumer_gate import plan


class PublishedNoOTPTests(unittest.TestCase):
    def run_to_release(self, preflight):
        stack = ExitStack()
        self.addCleanup(stack.close)
        runner_type = stack.enter_context(patch.object(gate, "Runner"))
        runner = runner_type.return_value
        runner.command.side_effect = ["a" * 40, "versions ok", "archives ok", preflight, "release ran"]
        runner.remaining.return_value = 10
        build = stack.enter_context(patch.object(gate, "build_release"))
        verify = stack.enter_context(patch.object(gate, "verify_source", return_value={"file": "source-pin"}))
        registry = stack.enter_context(patch.object(gate.consumer_gate, "setup_registry"))
        local = stack.enter_context(patch.object(gate.consumer_gate, "local_registry"))
        peer_type = stack.enter_context(patch.object(gate, "Peer"))
        peer_type.return_value.name = "peer"
        peer_type.return_value.ready = dict(port=12345, identity="actual-peer-ready")
        peer_type.return_value.config = {"sha256": "a" * 64}
        stack.enter_context(patch.object(gate.shutil, "copyfile"))
        stack.enter_context(patch.object(Path, "resolve", lambda path: path))
        stack.enter_context(patch.object(Path, "exists", return_value=False))
        stack.enter_context(patch.object(Path, "mkdir"))
        stack.enter_context(patch.object(Path, "read_bytes", return_value=b"input"))
        stack.enter_context(patch.object(Path, "write_bytes"))
        stack.enter_context(patch.object(Path, "read_text", return_value='{"artifacts": {}}'))
        writes = {}
        stack.enter_context(patch.object(Path, "write_text", lambda path, value: writes.update({str(path): value})))
        error = None
        try:
            gate.run("1.2.3", Path("/archives"), Path("/stage"), Path("/source"), "a" * 40,
                     plan(), Path("/fresh"), published=True)
        except gate.GateError as caught:
            error = caught
        self.assertIsNotNone(error, "mocked release has no passing artifact/runtime evidence")
        report = json.loads(writes["/fresh/gate-report.json"])
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["dependency_source"], "published")
        registry.assert_not_called()
        local.assert_not_called()
        verify.assert_called_once()
        return runner, build, peer_type, report

    def test_matching_published_archives_build_without_candidate_registry(self):
        preflight = "".join(f"{package}: matching\n" for package in gate.PACKAGES)
        runner, build, peers, report = self.run_to_release(preflight)
        build.assert_called_once()
        commands = [item.args[0] for item in runner.command.call_args_list]
        self.assertEqual(commands[3], [sys.executable, "/source/scripts/release/hex_packages.py",
                                      "preflight", "1.2.3", "/archives"])
        self.assertEqual(commands[-1], ["/fresh/release/bin/no_otp_consumer", "eval", "NoOTP.Consumer.run()"])
        self.assertEqual(report["published_archives"], {package: "matching" for package in gate.PACKAGES})
        peers.assert_called_once()
        peers.return_value.close.assert_called_once()
        self.assertEqual(report["teardown_errors"], [])

    def test_partial_missing_duplicate_or_wrong_preflight_stops_before_build(self):
        matching = [f"{package}: matching" for package in gate.PACKAGES]
        for output in ("\n".join(matching[:-1]), "\n".join(matching[:-1] + [matching[-1].replace("matching", "missing")]),
                       "\n".join(matching + [matching[-1]]), "\n".join(reversed(matching))):
            with self.subTest(output=output):
                runner, build, peers, report = self.run_to_release(output)
                build.assert_not_called()
                peers.assert_not_called()
                self.assertEqual(runner.command.call_count, 4)
                self.assertIn("all nine published archives", report["error"])

    def test_failed_or_timed_out_preflight_never_falls_back(self):
        for code in (1, 124):
            with self.subTest(code=code):
                runner, build, peers, report = self.run_to_release(
                    gate.GateError(f"owned command failed: exit={code}"))
                build.assert_not_called()
                peers.assert_not_called()
                self.assertEqual(runner.command.call_count, 4)
                self.assertIn(f"exit={code}", report["error"])

    def test_published_build_has_cold_hex_state_and_retains_prod_isolation(self):
        inherited = {"HEX_HOME": "/candidate/hex", "HEX_CONFIG_HOME": "/candidate/config",
                     "HEX_CACHE_HOME": "/candidate/cache", "HEX_OFFLINE": "true",
                     "HEX_MIRROR": "http://candidate", "HEX_TRUSTED_MIRROR": "http://candidate",
                     "ERL_LIBS": "/host/lib", "MIX_BUILD_PATH": "/old/build"}
        with patch.dict(os.environ, inherited):
            _, build, _, _ = self.run_to_release("".join(f"{package}: matching\n" for package in gate.PACKAGES))
        env = build.call_args.args[2]
        self.assertEqual(env["HEX_HOME"], "/fresh/project/hex")
        self.assertEqual(env["HEX_CONFIG_HOME"], "/fresh/project/hex")
        self.assertEqual(env["HEX_CACHE_HOME"], "/fresh/project/hex-cache")
        self.assertEqual(env["MIX_ENV"], "prod")
        self.assertEqual(env["MIX_BUILD_PATH"], "/fresh/project/build")
        self.assertEqual(env["MIX_DEPS_PATH"], "/fresh/project/deps")
        for key in ("HEX_OFFLINE", "HEX_MIRROR", "HEX_TRUSTED_MIRROR", "ERL_LIBS"):
            self.assertNotIn(key, env)

    def test_cli_published_switch_reaches_the_same_production_gate(self):
        argv = ["no_otp_consumer_gate.py", "1.2.3", "/archives", "/stage", "--source-root", "/source",
                "--source-sha", "a" * 40, "--peer-plan", "/plan.json", "--output", "/fresh"]
        for flags, published in (([], False), (["--published"], True)):
            with self.subTest(published=published), patch.object(sys, "argv", argv + flags), \
                    patch.object(Path, "read_text", return_value=json.dumps(plan())), \
                    patch.object(gate, "run", return_value={"gate": "no_otp_production_release",
                                                          "status": "PASS", "output": "/fresh"}) as run, \
                    redirect_stdout(io.StringIO()):
                gate.main()
                self.assertEqual(run.call_args.kwargs, {"published": published})


if __name__ == "__main__":
    unittest.main()
