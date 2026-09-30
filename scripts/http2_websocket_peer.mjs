// Independent Node/nghttp2 RFC 8441 mixed peer; no project protocol codecs.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http2 from 'node:http2';

const log = record => console.log(JSON.stringify(record));
const tls = process.env.H2_PEER_TLS === '1';
const limits = { connections: 16, streams: 16, outgoingBytes: 67_108_864, frameBytes: 16_777_230 };
const settings = { enableConnectProtocol: true, maxConcurrentStreams: limits.streams };
const server = tls
  ? http2.createSecureServer({ settings, allowHTTP1: false,
      key: fs.readFileSync(process.env.H2_PEER_KEY), cert: fs.readFileSync(process.env.H2_PEER_CERT) })
  : http2.createServer({ settings });
const connections = new WeakMap();
let nextConnection = 0, activeConnections = 0;
const decoder = new TextDecoder('utf-8', { fatal: true });

function frame(opcode, payload) {
  const header = Buffer.alloc(payload.length < 126 ? 2 : payload.length <= 65535 ? 4 : 10);
  header[0] = 128 | opcode;
  if (header.length === 2) header[1] = payload.length;
  else if (header.length === 4) { header[1] = 126; header.writeUInt16BE(payload.length, 2); }
  else { header[1] = 127; header.writeBigUInt64BE(BigInt(payload.length), 2); }
  return Buffer.concat([header, payload]);
}

function outgoing(stream, connection) {
  const state = { frames: [], offset: 0, retained: 0, waiting: false, ending: false, split: 0 };
  const sizes = [1, 7, 113, 4096, 8192];
  const flush = () => {
    while (!state.waiting && !stream.destroyed && !stream.closed) {
      if (!state.frames.length) {
        if (state.ending) stream.end();
        return;
      }
      const first = state.frames[0];
      const size = Math.min(first.length - state.offset, sizes[state.split++ % sizes.length]);
      const part = first.subarray(state.offset, state.offset + size);
      state.offset += size; state.retained -= size;
      if (state.offset === first.length) { state.frames.shift(); state.offset = 0; }
      if (!stream.write(part)) {
        state.waiting = true;
        stream.once('drain', () => { state.waiting = false; flush(); });
      }
    }
  };
  state.enqueue = (data, end = false) => {
    if (data.length) { state.frames.push(data); state.retained += data.length; }
    state.ending ||= end;
    const retained = [...connection.outgoing.values()].reduce(
      (sum, value) => sum + value.retained, 0);
    assert(retained <= limits.outgoingBytes, 'peer outgoing retention bound exceeded');
    flush();
  };
  state.close = data => {
    // Preserve a partly written frame and already accepted writable bytes.
    // Drop only application frames that have not started before the Close reply.
    state.frames = state.offset ? [state.frames[0]] : [];
    state.retained = state.frames.length ? state.frames[0].length - state.offset : 0;
    state.enqueue(data, true);
  };
  connection.outgoing.set(stream.id, state);
  return state;
}

class MaskOracle {
  constructor(message, control) {
    this.buffer = Buffer.alloc(0); this.frames = {}; this.masks = new Set();
    this.maximum = 0; this.closeCode = null; this.fragment = null;
    this.parts = []; this.messageBytes = 0; this.message = message; this.control = control;
  }
  receive(data) {
    this.buffer = Buffer.concat([this.buffer, data]);
    assert(this.buffer.length <= limits.frameBytes, 'peer raw frame retention bound exceeded');
    while (this.buffer.length >= 2) {
      const first = this.buffer[0], second = this.buffer[1], opcode = first & 15;
      assert(!(first & 112) && [0, 1, 2, 8, 9, 10].includes(opcode), 'invalid client opcode/RSV');
      assert(second & 128, 'client frame was not masked');
      let length = second & 127, offset = 2;
      if (length === 126) {
        if (this.buffer.length < 4) return;
        length = this.buffer.readUInt16BE(2); offset = 4;
        assert(length >= 126, 'nonminimal client length');
      } else if (length === 127) {
        if (this.buffer.length < 10) return;
        const value = this.buffer.readBigUInt64BE(2);
        assert(value > 65535n && value <= 16777216n, 'invalid client length');
        length = Number(value); offset = 10;
      }
      if (opcode >= 8) assert(first & 128 && length <= 125, 'invalid control framing');
      if (this.buffer.length < offset + 4 + length) return;
      const mask = this.buffer.subarray(offset, offset + 4);
      const payload = Buffer.alloc(length);
      for (let n = 0; n < length; n++) payload[n] = this.buffer[offset + 4 + n] ^ mask[n % 4];
      this.buffer = Buffer.from(this.buffer.subarray(offset + 4 + length));
      this.frames[opcode] = (this.frames[opcode] || 0) + 1;
      this.maximum = Math.max(this.maximum, length);
      if (this.masks.size < 32) this.masks.add(mask.toString('hex'));
      if (opcode >= 8) {
        if (opcode === 8) {
          assert(length !== 1, 'one-byte Close payload');
          this.closeCode = length ? payload.readUInt16BE() : null;
          assert(![1005, 1006, 1015].includes(this.closeCode), 'reserved Close transmitted');
          decoder.decode(payload.subarray(2));
        }
        this.control(opcode, payload);
      } else {
        if (opcode === 0) assert(this.fragment !== null, 'unexpected continuation');
        else { assert(this.fragment === null, 'interleaved data message'); this.fragment = opcode; }
        this.parts.push(payload); this.messageBytes += payload.length;
        assert(this.messageBytes <= 16_777_216 && this.parts.length <= 16_384, 'message retention bound');
        if (first & 128) {
          const complete = Buffer.concat(this.parts);
          if (this.fragment === 1) decoder.decode(complete);
          this.message(this.fragment, complete);
          this.fragment = null; this.parts = []; this.messageBytes = 0;
        }
      }
    }
  }
  summary() {
    return { client_frames: this.frames, masked_frames: Object.values(this.frames).reduce((a, b) => a + b, 0),
      maximum_client_payload: this.maximum, client_close_code: this.closeCode,
      mask_samples: this.masks.size, retained_frame_bytes: this.buffer.length };
  }
}

server.on('connection', socket => socket.setNoDelay(true));
server.on('session', session => {
  const id = ++nextConnection;
  const connection = { id, ws: new Map(), held: new Map(), outgoing: new Map() };
  connections.set(session, connection);
  assert(++activeConnections <= limits.connections, 'peer active connection bound');
  log({ kind: 'connection', connection: id, protocol: tls ? 'h2' : 'h2c',
    alpn: tls ? session.socket.alpnProtocol : null, capability: 1 });
  session.on('localSettings', value => log({ kind: 'settings_advertised', connection: id,
    enable_connect_protocol: value.enableConnectProtocol, max_concurrent_streams: value.maxConcurrentStreams }));
  session.on('error', error => log({ peer_error: error.code, connection: id }));
  session.on('close', () => {
    activeConnections--;
    log({ kind: 'connection_closed', connection: id, active_ws: connection.ws.size,
      active_sse: connection.held.size });
  });
});

server.on('stream', (stream, headers, flags, rawHeaders) => {
  const connection = connections.get(stream.session), cid = connection.id, sid = stream.id;
  const send = outgoing(stream, connection);
  let state;
  const complete = () => {
    if (!state || state.completed || !state.localEnd || !state.remoteEnd) return;
    assert.equal(state.oracle.frames[8], 1, 'clean tunnel lacked one masked Close');
    assert.equal(state.oracle.buffer.length, 0, 'partial client frame at END_STREAM');
    assert.equal(state.oracle.fragment, null, 'partial client message at END_STREAM');
    state.completed = true; connection.ws.delete(sid);
    log({ kind: 'wire_complete', connection: cid, stream: sid, endpoint: state.path,
      messages: state.messages, peer_messages: state.peerMessages,
      client_end_stream: true, peer_end_stream: true, ...state.oracle.summary() });
  };
  const guarded = action => {
    try { action(); }
    catch (error) { log({ peer_error: error.name, detail: error.message, connection: cid, stream: sid }); stream.destroy(); }
  };
  stream.on('error', error => {
    if (!(error.code === 'ERR_HTTP2_STREAM_ERROR' && stream.rstCode === 8))
      log({ peer_error: error.code, connection: cid, stream: sid });
  });
  stream.on('end', () => guarded(() => { if (state) { state.remoteEnd = true; complete(); } }));
  stream.on('finish', () => guarded(() => { if (state) { state.localEnd = true; complete(); } }));
  stream.on('close', () => {
    connection.outgoing.delete(sid); connection.held.delete(sid); connection.ws.delete(sid);
    if (stream.rstCode) log({ kind: 'client_reset', connection: cid, stream: sid, code: stream.rstCode,
      case: state?.case ?? null });
  });
  guarded(() => {
    const target = new URL(headers[':path'], 'http://localhost'), path = target.pathname;
    const respond = body => {
      const bodyAfterRequestEnd = () => guarded(() => {
        stream.respond({ ':status': 200, 'content-length': String(body.length) });
        send.enqueue(body, true);
      });
      if (stream.readableEnded) bodyAfterRequestEnd();
      else {
        stream.once('end', bodyAfterRequestEnd);
        stream.resume();
      }
    };
    if (headers[':method'] === 'CONNECT') {
      assert(!(flags & http2.constants.NGHTTP2_FLAG_END_STREAM), 'initial CONNECT END_STREAM');
      const names = rawHeaders.filter((_, index) => index % 2 === 0);
      assert.equal(new Set(names).size, names.length, 'duplicate CONNECT field');
      assert.deepEqual(names.slice(0, 5), [':method', ':protocol', ':scheme', ':authority', ':path']);
      assert(names.every(name => name === name.toLowerCase()), 'uppercase CONNECT field');
      assert(!names.some(name => ['connection', 'upgrade', 'host', 'sec-websocket-key', 'sec-websocket-accept', 'content-length'].includes(name)), 'HTTP/1/framing CONNECT field');
      assert.equal(headers[':protocol'], 'websocket');
      assert.equal(headers[':scheme'], tls ? 'https' : 'http');
      assert.equal(headers[':authority'], `localhost:${server.address().port}`);
      assert.equal(headers['sec-websocket-version'], '13');
      assert(['/ws/echo', '/ws/pressure'].includes(path), 'unsupported WS mixed endpoint');
      const caseName = target.searchParams.get('case') || 'echo';
      const count = Number(target.searchParams.get('count') || 1);
      assert(Number.isSafeInteger(count) && count > 0 && count <= 64, 'invalid mixed workload count');
      log({ kind: 'connect', connection: cid, stream: sid, endpoint: path, case: caseName,
        expected_count: count, initial_end_stream: false, wire_oracle: 'PASS',
        wire_headers: Object.fromEntries(Object.entries(headers).filter(([name]) => name.startsWith(':') || name === 'sec-websocket-version')) });
      stream.respond({ ':status': 200 });
      state = { path, case: caseName, messages: 0, peerMessages: 0, localEnd: false, remoteEnd: false, completed: false };
      state.oracle = new MaskOracle((opcode, payload) => {
        state.messages++; state.peerMessages++; send.enqueue(frame(opcode, payload));
      }, (opcode, payload) => {
        if (opcode === 8) { send.close(frame(8, payload)); log({ kind: 'client_close', connection: cid, stream: sid, code: state.oracle.closeCode }); }
        else if (opcode === 9) send.enqueue(frame(10, payload));
      });
      connection.ws.set(sid, state);
      stream.on('data', data => guarded(() => state.oracle.receive(data)));
      if (caseName === 'pressure') {
        for (let n = 1; n <= count; n++) {
          send.enqueue(frame(1, Buffer.from(`pressure-${n}:` + 'x'.repeat(4096)))); state.peerMessages++;
        }
      }
    } else if (path === '/sse/hold') {
      stream.respond({ ':status': 200, 'content-type': 'text/event-stream' });
      connection.held.set(sid, send); send.enqueue(Buffer.from('id: 1\ndata: sibling-1\n\n'));
      log({ kind: 'sse', connection: cid, stream: sid, endpoint: path });
    } else if (path === '/control/held') {
      for (const held of connection.held.values()) held.enqueue(Buffer.from('id: 2\ndata: sibling-2\n\n'));
      respond(Buffer.from(String(connection.held.size)));
      log({ kind: 'control', connection: cid, stream: sid, endpoint: path });
    } else if (path === '/peer/state') {
      respond(Buffer.from(JSON.stringify({ active_ws: connection.ws.size, active_sse: connection.held.size, withheld_bytes: 0 })));
    } else if (path.startsWith('/fetch/')) {
      log({ kind: 'ordinary_request', connection: cid, stream: sid,
        request_end_stream: Boolean(flags & http2.constants.NGHTTP2_FLAG_END_STREAM),
        readable_ended: stream.readableEnded });
      stream.once('finish', () => log({ kind: 'ordinary_response_finished', connection: cid,
        stream: sid, readable_ended: stream.readableEnded, reset_code: stream.rstCode }));
      stream.once('close', () => log({ kind: 'ordinary_stream_closed', connection: cid,
        stream: sid, readable_ended: stream.readableEnded, reset_code: stream.rstCode }));
      respond(Buffer.from(path)); log({ kind: 'fetch', connection: cid, stream: sid, endpoint: path });
    } else throw new Error('unknown mixed fixture endpoint');
  });
});

server.listen(0, '127.0.0.1', () => log({ kind: 'ready', port: server.address().port,
  peer: 'node/nghttp2/raw-websocket', node: process.versions.node, nghttp2: process.versions.nghttp2,
  tls, capability: 1, limits }));
