#!/usr/bin/env python3
"""Unmodified aioquic 1.2.0 with fixture-owned UDP flight barriers."""
import argparse
import asyncio
import json
from importlib.metadata import version
from pathlib import Path
from aioquic.asyncio import QuicConnectionProtocol, serve, connect
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import pull_quic_header, QuicPacketType
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, DatagramFrameReceived

FIXTURE = Path(__file__).resolve().parents[2] / 'apps/elixir_quic/test/fixtures/tls'
TICKETS = {}
LATEST = None
CONNECTIONS = 0
PAYLOAD = b'early/independent/' + bytes(range(256))
MESSAGE = b'early/datagram/boundary'

def emit(**values):
    print(json.dumps(values), flush=True)

def ticket_received(ticket):
    global LATEST
    LATEST = ticket
    TICKETS[ticket.ticket] = ticket
    emit(event='ticket', early=ticket.max_early_data_size is not None)

def has_handshake(data):
    while data:
        if data[0] == 0:  # datagram padding after the final long-header packet
            return False
        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
        if header.packet_type == QuicPacketType.HANDSHAKE:
            return True
        data = data[header.packet_length:]
    return False

class FlightBarrier:
    def __init__(self, transport, owner, handshake_only=False):
        self.transport, self.owner, self.handshake_only = transport, owner, handshake_only
        self.held = []
    def __getattr__(self, name):
        return getattr(self.transport, name)
    def sendto(self, data, address):
        if self.owner.block and (not self.handshake_only or has_handshake(data)):
            assert len(self.held) < 32 and sum(len(d) for d, _ in self.held) + len(data) <= 65536
            self.held.append((data, address))
        else:
            self.transport.sendto(data, address)
    def release(self):
        self.owner.block = False
        for data, address in self.held:
            self.transport.sendto(data, address)
        emit(event='flight_released', packets=len(self.held))
        self.held.clear()

class Echo(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        global CONNECTIONS
        super().__init__(*args, **kwargs)
        self.index = CONNECTIONS
        CONNECTIONS += 1
        self.block = self.index == 1
        self.early_stream = False
        self.early_datagram = False
    def connection_made(self, transport):
        # aioquic exposes max_data/max_stream_data in configuration, but its
        # stream-count fixture limits use these connection-owned Limit values.
        self._quic._local_max_streams_bidi.value = 8
        self._quic._local_max_streams_uni.value = 8
        self.barrier = FlightBarrier(transport, self)
        super().connection_made(self.barrier)
    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            emit(event='handshake', resumed=event.session_resumed, early=event.early_data_accepted)
        elif isinstance(event, StreamDataReceived):
            if self.index == 1:
                assert not self._quic._handshake_complete, 'early packet arrived after Finished'
                self.early_stream = True
                emit(event='early_stream', before_finished=True, bytes=len(event.data), fin=event.end_stream)
            self._quic.send_stream_data(event.stream_id, event.data, event.end_stream)
        elif isinstance(event, DatagramFrameReceived):
            if self.index == 1:
                assert not self._quic._handshake_complete
                self.early_datagram = True
                emit(event='early_datagram', before_finished=True, bytes=len(event.data))
            self._quic.send_datagram_frame(event.data)
        if self.block and self.early_stream and self.early_datagram:
            self.barrier.release()
        self.transmit()

class Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.block = False
        self.received = b''
        self.handshake = asyncio.get_running_loop().create_future()
        self.done = asyncio.get_running_loop().create_future()
        self.datagram = asyncio.get_running_loop().create_future()
    def connection_made(self, transport):
        self.barrier = FlightBarrier(transport, self, handshake_only=True)
        super().connection_made(self.barrier)
    def quic_event_received(self, event):
        if isinstance(event, HandshakeCompleted):
            self.handshake.set_result(event)
            emit(event='handshake', resumed=event.session_resumed, early=event.early_data_accepted)
        elif isinstance(event, StreamDataReceived):
            self.received += event.data
            if event.end_stream and not self.done.done():
                self.done.set_result(self.received)
        elif isinstance(event, DatagramFrameReceived) and not self.datagram.done():
            self.datagram.set_result(event.data)

async def main(args):
    assert version('aioquic') == '1.2.0'
    config = QuicConfiguration(is_client=args.role == 'client', alpn_protocols=['ex-quic-r1'],
        server_name='example.test' if args.role == 'client' else None,
        max_data=65536, max_stream_data=65536, max_datagram_frame_size=1200)
    config.load_verify_locations(str(FIXTURE / 'root.pem'))
    if args.role == 'server':
        config.load_cert_chain(str(FIXTURE / 'leaf.pem'), str(FIXTURE / 'leaf-key.pem'))
        server = await serve('127.0.0.1', 0, configuration=config, create_protocol=Echo,
            session_ticket_handler=ticket_received, session_ticket_fetcher=lambda identity: TICKETS.pop(identity, None))
        emit(event='listening', port=server._transport.get_extra_info('sockname')[1])
        try:
            await asyncio.sleep(35)
        finally:
            server.close()
    else:
        for index in range(2):
            config.session_ticket = LATEST
            async with connect('127.0.0.1', args.port, configuration=config, create_protocol=Client,
                    session_ticket_handler=ticket_received, wait_connected=index == 0) as protocol:
                protocol.block = index == 1
                protocol._quic.send_stream_data(0, PAYLOAD, end_stream=True)
                protocol._quic.send_datagram_frame(MESSAGE)
                protocol.transmit()
                if index == 1:
                    deadline = asyncio.get_running_loop().time() + 8
                    while not Path(args.barrier).exists():
                        assert asyncio.get_running_loop().time() < deadline, 'Finished barrier deadline'
                        await asyncio.sleep(.01)
                    assert protocol.barrier.held, 'no Finished flight retained'
                    protocol.barrier.release()
                    await asyncio.wait_for(protocol.handshake, 8)
                assert await asyncio.wait_for(protocol.done, 8) == PAYLOAD
                assert await asyncio.wait_for(protocol.datagram, 8) == MESSAGE
                assert LATEST is not None
                emit(event='stream', index=index, bytes=len(PAYLOAD), fin=True, datagram_bytes=len(MESSAGE))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=['client', 'server'], required=True)
    parser.add_argument('--port', type=int)
    parser.add_argument('--barrier')
    asyncio.run(main(parser.parse_args()))
