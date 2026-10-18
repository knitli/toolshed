import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { test } from 'node:test';
import { exchange } from './child.mjs';

// Only HTTP parsing is real: TLS authorization and the peer are fixture values.
async function wire(t, bytes, maximum = 8) {
  t.mock.method(net.Socket.prototype, 'connect', () => { throw new Error('network_forbidden'); });
  let requests = 0;
  const sockets = [];
  const agent = new http.Agent({ keepAlive: false });
  const cleanup = () => {
    agent.destroy();
    for (const socket of sockets) socket.destroy();
  };
  t.after(cleanup);
  agent.createConnection = () => {
    const socket = new Duplex({ read() {}, write(_chunk, _encoding, done) { done(); } });
    Object.assign(socket, { authorized: true, remoteAddress: '140.82.112.5' });
    sockets.push(socket);
    return socket;
  };
  try {
    const result = await exchange({
      url: 'https://api.github.com/repos/knitli/knitli-site/actions/runs/1',
      headers: {}, maximum, remainingMs: 1000,
    }, async () => [{ address: '140.82.112.5', family: 4 }], (options, callback) => {
      requests++;
      const request = http.request({ ...options, protocol: 'http:', agent }, callback);
      request.on('finish', () => {
        // Fragment every byte, including framing delimiters, through the real parser.
        for (const byte of Buffer.from(bytes)) sockets[0].push(Buffer.from([byte]));
        sockets[0].push(null);
      });
      return request;
    });
    return result;
  } finally {
    cleanup();
    assert.equal(requests, 1);
    assert.equal(sockets.length, 1);
    assert.ok(sockets.every(socket => socket.destroyed));
  }
}

test('real parser accepts fragmented content-length, chunked, and close-delimited bodies', { timeout: 2000 }, async t => {
  for (const response of [
    'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok',
    'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\no\r\n1\r\nk\r\n0\r\n\r\n',
    'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok',
  ]) {
    const result = await wire(t, response);
    assert.equal(result.status, 200);
    assert.equal(result.body.toString(), 'ok');
  }
});

const refused = {
  'duplicate content length': 'Content-Length: 2\r\nContent-Length: 2\r\n\r\nok',
  'conflicting content length': 'Content-Length: 2\r\nContent-Length: 3\r\n\r\nok',
  'content length with transfer encoding': 'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
  'invalid content length': 'Content-Length: nope\r\n\r\nok',
  'truncated fixed body': 'Content-Length: 3\r\n\r\nok',
  'malformed chunk length': 'Transfer-Encoding: chunked\r\n\r\nz\r\nok\r\n0\r\n\r\n',
  'missing final chunk': 'Transfer-Encoding: chunked\r\n\r\n2\r\nok\r\n',
  'short chunk': 'Transfer-Encoding: chunked\r\n\r\n3\r\nok',
  'declared body over ceiling': 'Content-Length: 9\r\n\r\n123456789',
  'chunked body over ceiling': 'Transfer-Encoding: chunked\r\n\r\n9\r\n123456789\r\n0\r\n\r\n',
  'close-delimited body over ceiling': 'Connection: close\r\n\r\n123456789',
  'duplicate ordinary headers': 'X-Test: a\r\nx-test: b\r\nContent-Length: 2\r\n\r\nok',
  'too many header fields': `${Array.from({ length: 65 }, (_, i) => `X-${i}: a\r\n`).join('')}\r\nok`,
  'parser header byte ceiling': `X-Test: ${'a'.repeat(32768)}\r\n\r\nok`,
  'partial headers': 'Content-Length: 2\r\n',
};
for (const [name, response] of Object.entries(refused)) {
  test(`real parser refuses ${name}`, { timeout: 2000 }, async t => {
    await assert.rejects(wire(t, `HTTP/1.1 200 OK\r\n${response}`), { message: 'https_refused' });
  });
}

test('real parser informational response cannot qualify a later success', { timeout: 2000 }, async t => {
  await assert.rejects(wire(t, 'HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok'), { message: 'https_refused' });
});

test('real parser returns redirect without making a second request', { timeout: 2000 }, async t => {
  const result = await wire(t, 'HTTP/1.1 302 Found\r\nLocation: https://storage.example/fixture\r\nContent-Length: 0\r\n\r\n');
  assert.equal(result.status, 302);
  assert.equal(result.body.length, 0);
});
