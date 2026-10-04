"""Qualify impairment mechanics using previously archived independent wire bytes."""
import asyncio
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from aioquic.quic.crypto import CryptoContext
from aioquic.tls import CipherSuite, Epoch

from peer import Capture


class ImpairmentTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        records = [json.loads(line) for line in
                   Path('apps/elixir_quic/test/fixtures/interop/aioquic-1.2.0/client-udp.jsonl').read_text().splitlines()]
        self.flight = next(base64.b64decode(r['payload']) for r in records if r['direction'] == 'send')
        self.address = ('127.0.0.1', 443)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def capture(self, scenario):
        capture = Capture(str(Path(self.directory.name) / 'udp.jsonl'), 'server', scenario)
        self.addCleanup(capture.file.close)
        return capture

    async def test_drop_duplicate_and_corrupt_have_actual_delivery_effects(self):
        for scenario in ['drop_handshake', 'duplicate', 'corrupt']:
            capture = self.capture(scenario)
            delivered = []
            with contextlib.redirect_stdout(io.StringIO()) as events:
                capture.route('send', self.flight, self.address, lambda data, addr: delivered.append(data))
            event = json.loads(events.getvalue())
            self.assertEqual(event['action'], scenario)
            self.assertIn('HANDSHAKE', event['packet_types'])
            if scenario == 'drop_handshake':
                self.assertEqual(delivered, [])
            elif scenario == 'duplicate':
                self.assertEqual(delivered, [self.flight, self.flight])
            else:
                self.assertEqual(len(delivered), 1)
                self.assertEqual(len(delivered[0]), len(self.flight))
                self.assertEqual(sum((a ^ b).bit_count() for a, b in zip(delivered[0], self.flight)), 1)

    async def test_handshake_done_drop_requires_authenticated_frame_not_just_short_header(self):
        crypto = CryptoContext()
        crypto.setup(cipher_suite=CipherSuite.AES_128_GCM_SHA256, secret=bytes(32), version=1)
        capture = self.capture('drop_handshake_done')
        capture.connections = [SimpleNamespace(_cryptos={Epoch.ONE_RTT: SimpleNamespace(send=crypto)}, _packet_number=0)]
        header = bytes([0x40]) + b'12345678' + bytes([0])
        ping = crypto.encrypt_packet(header, bytes([1, 0, 0]), 0)
        done = crypto.encrypt_packet(header, bytes([0x1E, 0, 0]), 0)
        damaged = done[:-1] + bytes([done[-1] ^ 1])
        delivered = []
        output = lambda data, addr: delivered.append(data)
        with contextlib.redirect_stdout(io.StringIO()) as events:
            capture.route('send', ping, self.address, output)
            capture.route('send', damaged, self.address, output)
            self.assertFalse(capture.applied)
            capture.route('send', done, self.address, output)
        self.assertEqual(delivered, [ping, damaged])
        self.assertEqual(json.loads(events.getvalue())['action'], 'drop_handshake_done')

    async def test_reorder_requires_a_second_datagram_and_delivers_it_first(self):
        capture = self.capture('reorder')
        delivered = []
        output = lambda data, addr: delivered.append(data)
        with contextlib.redirect_stdout(io.StringIO()) as events:
            capture.route('send', self.flight, self.address, output)
            self.assertEqual(delivered, [])
            self.assertEqual(events.getvalue(), '')
            capture.route('send', b'next datagram', self.address, output)
        self.assertEqual(delivered, [b'next datagram', self.flight])
        self.assertEqual(json.loads(events.getvalue())['action'], 'reorder')

    async def test_delay_without_reordering_is_not_reported_as_impairment_success(self):
        capture = self.capture('reorder')
        delivered = []
        with contextlib.redirect_stdout(io.StringIO()) as events:
            capture.route('send', self.flight, self.address, lambda data, addr: delivered.append(data))
            capture.hold_timer.cancel()
            capture.release()
        self.assertEqual(delivered, [self.flight])
        self.assertEqual(json.loads(events.getvalue())['event'], 'reorder_timeout')


if __name__ == '__main__':
    unittest.main()
