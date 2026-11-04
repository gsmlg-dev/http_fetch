"""In-memory request-path controls for the current TLS benchmark peer."""
import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "tls_migration_benchmark_peer.py"
SPEC = importlib.util.spec_from_file_location("tls_benchmark_peer", SOURCE)
PEER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PEER)


class BenchmarkRoutingTest(unittest.TestCase):
    def test_accepts_current_benchmark_routes(self):
        self.assertTrue(callable(getattr(PEER, "parse_path", None)))
        for workload, operation in [
            ("cold", "small"),
            ("upload", "upload"),
            ("upload", "close"),
            ("download", "download"),
            ("download", "close"),
            ("reuse", "small"),
            ("reuse", "close"),
        ]:
            with self.subTest(workload=workload, operation=operation):
                self.assertEqual(
                    PEER.parse_path(f"/ex_ssl/{workload}/{operation}"),
                    ("ex_ssl", workload, operation),
                )

    def test_rejects_retired_backend(self):
        self.assertTrue(callable(getattr(PEER, "parse_path", None)))
        with self.assertRaises(ValueError):
            PEER.parse_path("/ssl/cold/small")

    def test_rejects_unknown_and_mismatched_routes(self):
        self.assertTrue(callable(getattr(PEER, "parse_path", None)))
        for path in [
            "/ex_ssl/unknown/small", "/ex_ssl/cold/unknown",
            "/ex_ssl/cold/upload", "/ex_ssl/cold/close",
            "/ex_ssl/upload/small", "/ex_ssl/download/upload",
            "/ex_ssl/reuse/download",
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                PEER.parse_path(path)

    def test_rejects_traversal_and_noncanonical_paths(self):
        self.assertTrue(callable(getattr(PEER, "parse_path", None)))
        for path in [
            "", "ex_ssl/cold/small", "//ex_ssl/cold/small",
            "/ex_ssl/cold", "/ex_ssl/cold/small/extra", "/ex_ssl/cold/small/",
            "/ex_ssl/../small", "/ex_ssl/cold/..", "/ex_ssl/./small",
            "/ex_ssl/%2e%2e/small", "/ex_ssl/cold/%2e%2e",
            "/ex_ssl/cold/small?query=1", "/ex_ssl/cold/small#fragment",
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                PEER.parse_path(path)


if __name__ == "__main__":
    unittest.main()
