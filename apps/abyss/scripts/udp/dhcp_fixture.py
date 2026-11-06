#!/usr/bin/env python3
"""DHCP/ARP compatibility in the existing fixture-owned namespace topology."""
import argparse
import base64
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import sys
import threading

from network_fixture import Child, Fixture, ROOT, encode


class NativeChild(Child):
    def __init__(self, fixture, namespace, command, cwd, wire=False):
        caps = '-all,+net_raw,+net_bind_service'
        drop = [shutil.which('setpriv'), f'--reuid={os.getuid()}', f'--regid={os.getgid()}',
                '--init-groups', '--bounding-set='+caps, '--inh-caps='+caps,
                '--ambient-caps='+caps, '--no-new-privs']
        environment = [shutil.which('env'), f"PATH={os.environ['PATH']}",
                       f"HOME={os.environ['HOME']}", 'MIX_ENV=prod', 'CI=true']
        for key in ('MIX_HOME', 'HEX_HOME', 'ERL_FLAGS', 'ELIXIR_ERL_OPTIONS'):
            if key in os.environ:
                environment.append(f'{key}={os.environ[key]}')
        argv = fixture.privileged + ['ip', 'netns', 'exec', namespace] + drop + environment + command
        self.process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lines = queue.Queue()
        self.events = []
        self.wire = wire
        self.serial = 0
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()
        fixture.children.append(self)


def peer_worker():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'eth0\0')
    udp.bind(('0.0.0.0', 67))
    udp.settimeout(3)
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    raw.bind(('eth0', 0))
    raw.settimeout(3)
    print(json.dumps({'ok': 'ready'}), flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            try:
                op = request['op']
                if op == 'recv':
                    packet, peer = udp.recvfrom(4096)
                    result = {'payload': encode(packet), 'peer': peer}
                elif op == 'send':
                    packet = base64.b64decode(request['payload'])
                    result = udp.sendto(packet, ('192.0.2.10', 68))
                    assert result == len(packet)
                elif op == 'probe':
                    while True:
                        frame = raw.recv(4096)
                        if len(frame) >= 42 and frame[28:32] == b'\0'*4 and frame[38:42] == bytes([192, 0, 2, 99]):
                            assert frame[:6] == b'\xff'*6
                            assert frame[12:22] == bytes.fromhex('08060001080006040001')
                            assert frame[32:38] == b'\0'*6
                            result = encode(frame)
                            break
                elif op == 'arp_send':
                    mac = raw.getsockname()[4]
                    frame = b'\xff'*6 + mac + bytes.fromhex('08060001080006040001')
                    frame += mac + bytes([192, 0, 2, 77]) + b'\0'*6 + bytes([192, 0, 2, 99])
                    assert raw.send(frame) == len(frame)
                    result = encode(frame)
                elif op == 'stop':
                    print(json.dumps({'ok': True}), flush=True)
                    return
                else:
                    raise AssertionError(op)
                print(json.dumps({'ok': result}), flush=True)
            except Exception as error:
                print(json.dumps({'error': repr(error)}), flush=True)
    finally:
        udp.close()
        raw.close()


def run_gates(fixture, consumer):
    peer = NativeChild(fixture, fixture.peers[0], [sys.executable, str(Path(__file__).resolve()), '--peer'], ROOT)
    peer.wait(lambda line: line == '{"ok": "ready"}')
    server = NativeChild(fixture, fixture.server,
                         ['mix', 'run', str(ROOT / 'scripts/udp/p5_native_consumer.exs')], consumer, wire=True)
    server.wait(lambda line: line == 'WIRE READY DHCP')
    epoch = fixture.prefix.encode()
    for mode in ('BROADCAST', 'UNICAST'):
        payload = epoch + mode.encode()
        server.command(mode, encode(payload))
        packet = peer.rpc(op='recv')
        assert packet == {'payload': encode(payload), 'peer': ['192.0.2.10', 68]}, packet
    inbound = epoch + b'DHCP_OWNER'
    peer.rpc(op='send', payload=encode(inbound))
    server.wait(lambda line: line == 'WIRE DHCP '+encode(inbound))
    server.command('PROBE')
    peer.rpc(op='probe')
    expected = peer.rpc(op='arp_send')
    server.wait(lambda line: line == 'WIRE ARP '+expected)
    server.command('CLOSE')
    # close/1 joins native I/O; independently inspect kernel bind state.
    sockets = subprocess.check_output(fixture.privileged + ['ip', 'netns', 'exec', fixture.server,
                                      'cat', '/proc/net/udp'], text=True)
    assert ':0044' not in sockets, sockets
    server.command('DEAD_OWNER')
    peer.rpc(op='send', payload=encode(epoch+b'DEAD_OWNER'))
    server.command('CLOSE_ORPHAN')
    sockets = subprocess.check_output(fixture.privileged + ['ip', 'netns', 'exec', fixture.server,
                                      'cat', '/proc/net/udp'], text=True)
    assert ':0044' not in sockets, sockets
    server.command('STOP')
    assert server.process.wait(timeout=5) == 0
    return ['native_bind_68', 'broadcast_source_68', 'unicast_source_68', 'dhcp_owner_payload',
            'arp_probe_wire', 'arp_owner_frame', 'idempotent_close', 'closed_send_errors',
            'close_kernel_release', 'owner_death_explicit_close', 'orphan_kernel_release']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--peer', action='store_true')
    parser.add_argument('--consumer', type=Path)
    args = parser.parse_args()
    if args.peer:
        peer_worker()
        return 0
    assert args.consumer and args.consumer.is_dir(), 'packaged optional consumer is required'
    fixture = Fixture()
    try:
        try:
            fixture.setup()
        except subprocess.CalledProcessError as error:
            print('BLOCKED_ENV network_namespace_setup: '+error.stderr.decode().strip(), file=sys.stderr)
            return 77
        gates = run_gates(fixture, args.consumer)
        print(json.dumps({'result': 'PASS', 'gates': gates, 'consumer': str(args.consumer),
                          'capabilities': ['CAP_NET_RAW', 'CAP_NET_BIND_SERVICE']}), flush=True)
        return 0
    except Exception as error:
        print('FAIL '+repr(error), file=sys.stderr)
        for child in fixture.children:
            print('\n'.join(child.events[-20:]), file=sys.stderr)
        return 1
    finally:
        fixture.cleanup()


if __name__ == '__main__':
    sys.exit(main())
