"""In-memory framing controls for the independent TLS lifecycle peer."""
import importlib.util
import io
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "apps/http_fetch/test/support/ex_ssl_proxy_lifecycle_peer.py"
SPEC = importlib.util.spec_from_file_location("lifecycle_peer", SOURCE)
PEER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PEER)


class FragmentedSocket:
    def __init__(self, data, fragment=1):
        self.data = io.BytesIO(data)
        self.fragment = fragment

    def recv(self, count):
        return self.data.read(min(count, self.fragment))


class RequestBodyTest(unittest.TestCase):
    def chunked(self, data, **options):
        return PEER.request_body(FragmentedSocket(data), {"transfer-encoding": "chunked"}, **options)

    def test_fragmented_chunks_preserve_binary_payload_and_next_request(self):
        sock = FragmentedSocket(b"3\r\na\x00b\r\n2\r\n\r\n\r\n0\r\n\r\nNEXT")
        self.assertEqual(PEER.request_body(sock, {"transfer-encoding": "chunked"}), b"a\x00b\r\n")
        self.assertEqual(sock.data.read(), b"NEXT")

    def test_empty_chunks_and_bounded_trailers(self):
        self.assertEqual(self.chunked(b"0\r\n\r\n"), b"")
        self.assertEqual(self.chunked(b"1\r\nx\r\n0\r\nX-End: yes\r\n\r\n"), b"x")

    def test_content_length_retains_fragmented_body_and_following_bytes(self):
        sock = FragmentedSocket(b"onceNEXT", fragment=2)
        self.assertEqual(PEER.request_body(sock, {"content-length": "4"}), b"once")
        self.assertEqual(sock.data.read(), b"NEXT")
        self.assertEqual(PEER.request_body(FragmentedSocket(b""), {}), b"")
        self.assertIsNone(PEER.request_body(FragmentedSocket(b"x"), {"content-length": "2"}))

    def test_truncation_is_never_a_complete_request(self):
        for data in [b"", b"1\r", b"2\r\nx", b"1\r\nx\r", b"0\r\n", b"0\r\nX: y\r\n"]:
            with self.subTest(data=data), self.assertRaises(EOFError):
                self.chunked(data)

    def test_invalid_chunk_framing_is_rejected(self):
        for data in [b"-1\r\n", b"+1\r\n", b"z\r\n", b"1\r\nx!!", b"0\r\ninvalid\r\n\r\n"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.chunked(data)

    def test_body_and_framing_limits(self):
        for data in [b"5\r\n", b"3\r\nabc\r\n2\r\n"]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.chunked(data, max_body=4)
        for data in [b"1" * 8193, b"0\r\n" + (b"X: " + b"x" * 8000 + b"\r\n") * 5]:
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.chunked(data)

    def test_ambiguous_or_unsupported_transfer_coding_is_rejected(self):
        for headers in [{"transfer-encoding": "gzip, chunked"},
                        {"transfer-encoding": "chunked", "content-length": "1"}]:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                PEER.request_body(FragmentedSocket(b"0\r\n\r\n"), headers)


if __name__ == "__main__":
    unittest.main()
