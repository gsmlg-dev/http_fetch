"""Actual upstream traffic regressions, including Caddy's chunked upload shape."""
import hashlib
import http.client
from pathlib import Path
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parent))
from caddy_upstream import Peer


class UpstreamTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        if cls.thread.is_alive():
            raise RuntimeError("upstream fixture did not stop")

    def request(self, path, body=None, chunked=False, method="POST"):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=body, encode_chunked=chunked)
            response = connection.getresponse()
            return response.status, response.read(), response.getheaders()
        finally:
            connection.close()

    def test_chunked_binary_echo_without_content_length(self):
        chunks = [bytes(range(256)) * 257, b"\x00\xff\r\n" * 12345]
        status, body, _ = self.request("/echo", iter(chunks), chunked=True)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"".join(chunks))

    def test_two_megabyte_chunked_digest(self):
        chunks = [bytes([n, 255, 0, 128]) * 4096 for n in range(128)]
        status, body, _ = self.request("/digest", iter(chunks), chunked=True)
        self.assertEqual(status, 200)
        self.assertEqual(body, hashlib.sha256(b"".join(chunks)).hexdigest().encode())

    def test_empty_and_large_response_integrity(self):
        self.assertEqual(self.request("/empty", method="GET")[:2], (200, b""))
        status, body, _ = self.request("/large", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(body, bytes(range(256)) * 32768)

    def test_sse_content_type_and_trailer_framing(self):
        status, body, fields = self.request("/sse", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"id: 42\ndata: h3-event\n\n")
        self.assertIn(("Content-Type", "text/event-stream"), fields)
        self.assertEqual(self.request("/trailers", method="GET")[:2], (200, b"abc"))


if __name__ == "__main__":
    unittest.main()
