// Independent Node/nghttp2 acceptance peer (loopback only).
import http2 from 'node:http2';
import fs from 'node:fs';
import crypto from 'node:crypto';
const settings = { maxConcurrentStreams: Number(process.env.H2_PEER_LIMIT || 100) };
const server = process.env.H2_PEER_TLS === '1'
  ? http2.createSecureServer({ settings, key: fs.readFileSync(process.env.H2_PEER_KEY), cert: fs.readFileSync(process.env.H2_PEER_CERT), allowHTTP1: false })
  : http2.createServer({ settings });
server.on('sessionError', error => console.log(JSON.stringify({peer_error: error.code})));
const barriers = new WeakMap();
function respond(stream, payload, remaining, barrierCount, headersSent = false) {
  const headers = { ':status': 200, 'content-length': String(remaining), 'x-peer': `node-${process.versions.node}-nghttp2-${process.versions.nghttp2}` };
  if (barrierCount !== undefined) headers['x-gate-barrier'] = String(barrierCount);
  if (!headersSent) stream.respond(headers);
  if (payload !== null) { stream.end(payload); return; }
  const write = () => {
    while (remaining > 0 && !stream.destroyed) {
      const n = Math.min(16384, remaining);
      remaining -= n;
      if (!stream.write(Buffer.alloc(n, 'x'))) { stream.once('drain', write); return; }
    }
    if (!stream.destroyed) stream.end();
  };
  write();
}
server.on('stream', (stream, headers) => {
  const hash = crypto.createHash('sha256');
  let size = 0;
  stream.on('error', () => {});
  stream.on('data', chunk => { size += chunk.length; hash.update(chunk); });
  stream.on('end', () => {
    const path = headers[':path'];
    if (path === '/metadata/buffer' || path === '/metadata/stream') {
      stream.additionalHeaders({ ':status': 103, link: 'first' });
      stream.additionalHeaders({ ':status': 103, link: 'second' });
      const final = { ':status': 200, 'x-peer': `node-${process.versions.node}` };
      if (path.endsWith('/buffer')) final['content-length'] = '4';
      stream.respond(final, { waitForTrailers: true });
      stream.on('wantTrailers', () => stream.sendTrailers({ 'x-checksum': 'verified' }));
      stream.end('body');
      return;
    }
    if (path.startsWith('/concurrent/')) {
      const match = /^\/concurrent\/(\d+)\/(\d+)$/.exec(path);
      const number = match && Number(match[1]);
      const length = match && Number(match[2]);
      let barrier = barriers.get(stream.session);
      if (!barrier) { barrier = new Map(); barriers.set(stream.session, barrier); }
      if (!match || number < 0 || number >= 100 || barrier.has(number) ||
          length !== (number === 0 ? 6 * 1024 * 1024 : 1000 + number * 97)) {
        stream.close(http2.constants.NGHTTP2_PROTOCOL_ERROR);
        return;
      }
      barrier.set(number, { stream, length });
      if (barrier.size === 100) {
        const slow = barrier.get(0);
        // Send its headers first, then let the 99 fast responses use flow credit.
        slow.stream.respond({ ':status': 200, 'content-length': String(slow.length),
          'x-peer': `node-${process.versions.node}-nghttp2-${process.versions.nghttp2}`,
          'x-gate-barrier': '100' });
        for (let n = 1; n < 100; n++) {
          const item = barrier.get(n);
          respond(item.stream, null, item.length, 100);
        }
        // The client deliberately keeps this streamed response unread until the others finish.
        respond(slow.stream, null, slow.length, 100, true);
      }
      return;
    }
    const payload = path.startsWith('/bytes/') ? null : Buffer.from(headers[':method'] === 'POST' ? `${size}:${hash.digest('hex')}` : path);
    const remaining = payload === null ? Number(path.split('/').pop()) : payload.length;
    respond(stream, payload, remaining);
  });
});
server.listen(0, '127.0.0.1', () => console.log(JSON.stringify({port: server.address().port, peer: 'node', node: process.versions.node, nghttp2: process.versions.nghttp2})));
