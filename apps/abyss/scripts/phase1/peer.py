#!/usr/bin/env python3
"""Independent raw-stream consumer for aioquic==1.2.0; no HTTP or DNS."""
import argparse
import asyncio
import hashlib
import json
import struct
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, ConnectionTerminated, StreamReset, StopSendingReceived

OBSERVATIONS = {"retry_received": 0, "retry_dropped": 0, "token_changed": False}

class Peer(QuicConnectionProtocol):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.data, self.finished, self.resets = {}, set(), {}
        self.changed = asyncio.Event()
        self.termination = None
        self.stopped = {}
        self.hold_until = 0

    def datagram_received(self, data, addr):
        if data and data[0] & 0xF0 == 0xF0:
            OBSERVATIONS['retry_received'] += 1
            if args.scenario == 'retry_loss' and OBSERVATIONS['retry_dropped'] == 0:
                OBSERVATIONS['retry_dropped'] += 1
                return
        super().datagram_received(data, addr)

    def transmit(self):
        if args.scenario in ['invalid_token', 'expired_token'] and self._quic._peer_token and not OBSERVATIONS['token_changed']:
            OBSERVATIONS['token_changed'] = True
            if args.scenario == 'invalid_token':
                token = self._quic._peer_token
                self._quic._peer_token = token[:-1] + bytes([token[-1] ^ 1])
            else:
                self.hold_until = asyncio.get_running_loop().time() + 0.05
                asyncio.get_running_loop().call_later(0.05, self.transmit)
        if asyncio.get_running_loop().time() < self.hold_until:
            return
        super().transmit()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            self.data[sid] = self.data.get(sid, b'') + event.data
            if event.end_stream:
                self.finished.add(sid)
                # Respond to server bidi after its FIN to verify independent halves.
                if sid % 4 == 1:
                    self._quic.send_stream_data(sid, self.data[sid], end_stream=True)
                    self.transmit()
            self.changed.set()
        elif isinstance(event, StreamReset):
            self.resets[event.stream_id] = event.error_code
            self.changed.set()
        elif isinstance(event, StopSendingReceived):
            self.stopped[event.stream_id] = event.error_code
            self.changed.set()
        elif isinstance(event, ConnectionTerminated):
            self.termination = event.error_code
            self.termination_reason = event.reason_phrase
            self.changed.set()

    async def wait_for(self, predicate):
        try:
            async with asyncio.timeout(25):
                while not predicate():
                    self.changed.clear()
                    await self.changed.wait()
        except TimeoutError:
            print(json.dumps({'failure':'deadline','bytes':{k:len(v) for k,v in self.data.items()},'fins':sorted(self.finished),'termination':self.termination,'termination_reason':getattr(self,'termination_reason',None)}),flush=True)
            raise

async def run(args):
    config = QuicConfiguration(is_client=True, alpn_protocols=[args.alpn], max_data=16384, max_stream_data=16384, idle_timeout=3 if args.expect_failure else 30)
    config.server_name = 'example.test'
    config.load_verify_locations(args.ca)
    async with connect('127.0.0.1', args.port, configuration=config, create_protocol=Peer) as p:
        if args.mode == 'echo':
            values = {}
            for n in range(4):
                sid = p._quic.get_next_available_stream_id(is_unidirectional=False)
                data = bytes([n + 1]) * 262144
                values[sid] = data
                for offset in range(0, len(data), 16384):
                    p._quic.send_stream_data(sid, data[offset:offset+16384], end_stream=offset+16384 == len(data))
            uni = p._quic.get_next_available_stream_id(is_unidirectional=True)
            p._quic.send_stream_data(uni, b'client-uni', end_stream=True)
            p.transmit()
            await p.wait_for(lambda: all(sid in p.finished for sid in values) and 1 in p.finished and 3 in p.finished)
            assert all(p.data[sid] == data for sid, data in values.items())
            assert p.data[1] == b'x' * 16384 and p.data[3] == b'server-uni'
            print(json.dumps({'status':'PASS','mode':args.mode,'bytes':sum(map(len,values.values())), 'bidi':5,'uni':2,'server_single_write':16384,'receive_after_fin':True}), flush=True)
        elif args.mode == 'collect':
            sid = p._quic.get_next_available_stream_id(is_unidirectional=False)
            value = b'c' * 1048576
            p._quic.send_stream_data(sid, value[:1], end_stream=False)
            p.transmit()
            await p.wait_for(lambda: sid in p.finished)
            # Server sent FIN before these bytes; it must continue reading them.
            for offset in range(1, len(value), 16384):
                part = value[offset:offset+16384]
                p._quic.send_stream_data(sid, part, end_stream=offset+len(part) == len(value))
            p.transmit()
            await p.wait_for(lambda: 3 in p.finished)
            count = struct.unpack('!Q',p.data[3][:8])[0]
            assert count == len(value) and p.data[3][8:] == hashlib.sha256(value).digest()
            print(json.dumps({'status':'PASS','mode':args.mode,'bytes':count,'receive_after_fin':True,'digest':hashlib.sha256(value).hexdigest()}), flush=True)
        elif args.mode == 'controls':
            for sid in [0, 4]:
                p._quic.send_stream_data(sid, b'control', end_stream=False)
            p.transmit()
            await p.wait_for(lambda: 0 in p.resets and 4 in p.stopped)
            assert p.resets[0] == 0x12345 and p.stopped[4] == 0x54321
            p._quic.send_stream_data(8, b'close', end_stream=False)
            p.transmit()
            await p.wait_for(lambda: p.termination is not None)
            assert p.termination == 0x111111
            print(json.dumps({'status':'PASS','mode':'opaque_controls','reset':p.resets[0],'stop':p.stopped[4],'close':p.termination}),flush=True)
        elif args.mode == 'isolation':
            async with connect('127.0.0.1', args.port, configuration=config, create_protocol=Peer) as other:
                p.close(error_code=0x9876, reason_phrase='one connection only')
                await asyncio.wait_for(p.wait_closed(), 5)
                value = b'i' * 1048576
                for offset in range(0,len(value),16384):
                    other._quic.send_stream_data(0,value[offset:offset+16384],end_stream=offset+16384 == len(value))
                other.transmit()
                await other.wait_for(lambda: 0 in other.finished)
                assert other.data[0] == value
                print(json.dumps({'status':'PASS','mode':'connection_close_isolation','surviving_bytes':len(value)}),flush=True)
        elif args.mode == 'hold':
            await asyncio.sleep(0.5)
            print(json.dumps({'status':'PASS','mode':'handshake_hold'}),flush=True)
        elif args.mode == 'close':
            p.close(error_code=0x12345, reason_phrase='opaque')
            print(json.dumps({'status':'PASS','mode':'opaque_client_close','code':0x12345}),flush=True)

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, required=True)
parser.add_argument('--ca', required=True)
parser.add_argument('--alpn', required=True)
parser.add_argument('--mode', choices=['echo','collect','close','controls','hold','isolation'], required=True)
parser.add_argument('--expect-failure', action='store_true')
parser.add_argument('--scenario', choices=['normal','retry_loss','invalid_token','expired_token'], default='normal')
args=parser.parse_args()
if args.expect_failure:
    try:
        asyncio.run(run(args))
    except ConnectionError:
        if args.scenario in ['invalid_token', 'expired_token']:
            assert OBSERVATIONS['retry_received'] > 0 and OBSERVATIONS['token_changed']
        print(json.dumps({'status':'PASS','mode':'negative_handshake','alpn':args.alpn}),flush=True)
    else:
        raise AssertionError('negative handshake unexpectedly succeeded')
else:
    asyncio.run(run(args))
    if args.scenario == 'retry_loss':
        assert OBSERVATIONS['retry_received'] >= 2 and OBSERVATIONS['retry_dropped'] == 1
    print(json.dumps({'observations':OBSERVATIONS,'scenario':args.scenario}),flush=True)
