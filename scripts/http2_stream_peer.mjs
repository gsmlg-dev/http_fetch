// Independent Node/nghttp2 loopback SSE peer. No project protocol codecs.
import http2 from 'node:http2';
import fs from 'node:fs';
import { addAbortSignal } from 'node:stream';
const log = record => console.log(JSON.stringify(record));
const tls = process.env.H2_PEER_TLS === '1';
const settings = { maxConcurrentStreams: Number(process.env.H2_PEER_LIMIT || 16) };
const server = tls
  ? http2.createSecureServer({ settings, key: fs.readFileSync(process.env.H2_PEER_KEY), cert: fs.readFileSync(process.env.H2_PEER_CERT), allowHTTP1: false })
  : http2.createServer({ settings });
let nextConnection = 0;
const connections = new WeakMap();
const event = n => Buffer.from(`id: ${n}\ndata: event-${n}-λ\n\n`);
function* batches(first, last) {
  let parts = [], size = 0;
  for (let n = first; n <= last; n++) {
    const part = event(n); parts.push(part); size += part.length;
    if (size >= 8192) { yield Buffer.concat(parts); parts = []; size = 0; }
  }
  if (size) yield Buffer.concat(parts);
}
function write(stream, chunks, keep = false, complete) {
  const iterator = chunks[Symbol.iterator]();
  const sizes = [1, 7, 113, 4096, 8192];
  let chunk = Buffer.alloc(0), offset = 0, split = 0;
  const drain = () => {
    while (!stream.destroyed && !stream.closed) {
      if (offset === chunk.length) {
        const next = iterator.next();
        if (next.done) {
          if (complete) log({ kind: 'range_complete', connection: connections.get(stream.session).id, stream: stream.id, ...complete });
          if (!keep) stream.end();
          return;
        }
        chunk = next.value; offset = 0;
      }
      const n = Math.min(sizes[split++ % sizes.length], chunk.length - offset);
      const part = chunk.subarray(offset, offset + n); offset += n;
      if (!stream.write(part)) { stream.once('drain', drain); return; }
    }
  };
  drain();
}
server.on('session', session => {
  const id = ++nextConnection;
  connections.set(session, { id, held: new Map() });
  log({ kind: 'connection', connection: id, protocol: tls ? 'h2' : 'h2c', alpn: tls ? session.socket.alpnProtocol : null });
  session.on('remoteSettings', value => log({ kind: 'settings', connection: id, settings: value }));
  session.on('error', error => log({ peer_error: error.code, connection: id }));
  session.on('close', () => log({ kind: 'connection_closed', connection: id }));
});
server.on('stream', (stream, headers) => {
  const session = stream.session;
  const { id, held } = connections.get(session);
  const target = new URL(headers[':path'], 'http://localhost');
  const path = target.pathname, cursor = headers['last-event-id'] || '';
  const count = Number(target.searchParams.get('count') || 10000);
  const first = Number(cursor || 0) + 1;
  let resetRequested = false;
  log({ kind: 'request', connection: id, stream: stream.id, endpoint: path, method: headers[':method'], cursor });
  stream.on('error', error => {
    if (resetRequested && error.code === 'ABORT_ERR' && stream.rstCode === 8) {
      log({ kind: 'intentional_abort', connection: id, stream: stream.id, code: 8 });
      return;
    }
    if (error.code !== 'ERR_HTTP2_STREAM_ERROR') log({ peer_error: error.code, connection: id, stream: stream.id });
  });
  stream.on('close', () => {
    held.delete(stream.id);
    if (stream.rstCode) log({ kind: 'client_reset', connection: id, stream: stream.id, code: stream.rstCode });
  });
  const respond = (chunks, keep = false, extra = {}, complete) => {
    stream.respond({ ':status': 200, 'content-type': 'text/event-stream', ...extra });
    write(stream, chunks, keep, complete);
  };
  if (path === '/sse/numbered' || path === '/sse/churn') {
    const last = Math.min(count, path.endsWith('churn') ? first : (first === 1 ? Math.floor(count / 2) : count));
    function* numbered() { yield Buffer.from('retry: 1\n\n'); yield* batches(first, last); }
    respond(numbered(), last === count, {}, { first, last, count: last - first + 1 });
  } else if (path === '/sse/semantics') {
    if (cursor === 'done') { stream.respond({ ':status': 204 }); stream.end(); }
    else respond([Buffer.from('\ufeff: comment\r\nretry: 1\r\nid: 7\revent: custom\ndata: λ\r\ndata: second\n\nid:\ndata: reset\n\nid: done\ndata: final\n\ndata: incomplete')]);
  } else if (path === '/sse/large') {
    const payload = Buffer.from('id: 1\n' + ('data: ' + 'x'.repeat(64) + '\n').repeat(2048) + '\n');
    respond([payload], true, { 'content-length': String(payload.length) });
  } else if (path === '/sse/overflow') {
    function* lines() { for (let n = 0; n < 1024; n++) yield Buffer.from('data: ' + 'x'.repeat(64) + '\n'); }
    respond(lines(), true);
  } else if (path === '/sse/pressure') respond(batches(1, count), true);
  else if (['/sse/hold', '/sse/reset', '/sse/goaway'].includes(path)) {
    const abort = new AbortController();
    addAbortSignal(abort.signal, stream);
    held.set(stream.id, { stream, endpoint: path, abort: () => {
      resetRequested = true;
      abort.abort();
    } });
    respond([event(first)], true);
  } else if (path.startsWith('/control/')) {
    let affected = 0;
    for (const item of held.values()) {
      if (path === '/control/held' && item.endpoint === '/sse/hold') { write(item.stream, [event(2)], true); affected++; }
      else if (path === '/control/reset' && item.endpoint === '/sse/reset') {
        // close(8) ends the writable side first and can emit END_STREAM before
        // RST_STREAM. Aborting destroys it directly with NGHTTP2_CANCEL.
        item.abort(); affected++;
        log({ kind: 'reset', connection: id, stream: item.stream.id, code: 8 });
      } else if (path === '/control/goaway' && item.endpoint === '/sse/goaway') {
        const last = Math.max(stream.id, ...held.keys());
        session.goaway(http2.constants.NGHTTP2_NO_ERROR, last);
        held.delete(item.stream.id); write(item.stream, [event(2)]); affected++;
        log({ kind: 'goaway', connection: id, stream: item.stream.id, last_stream: last });
      }
    }
    const payload = Buffer.from(String(affected)); stream.respond({ ':status': 200, 'content-length': String(payload.length) }); stream.end(payload);
  } else if (path.startsWith('/fetch/')) {
    const payload = Buffer.from(path); stream.respond({ ':status': 200, 'content-length': String(payload.length) }); stream.end(payload);
  } else { log({ peer_error: 'unknown fixture endpoint', endpoint: path }); stream.close(http2.constants.NGHTTP2_PROTOCOL_ERROR); }
});
server.listen(0, '127.0.0.1', () => log({ kind: 'ready', port: server.address().port, peer: 'node', node: process.versions.node, nghttp2: process.versions.nghttp2, tls, limit: settings.maxConcurrentStreams }));
