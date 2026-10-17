import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { test } from 'node:test';
import { exchange, publicIPv4, responseHeaders, validateInput } from './child.mjs';

const input = () => ({ url: 'https://api.github.com/repos/knitli/knitli-site/actions/runs/1', headers: { Authorization: 'Bearer SECRET', 'Accept-Encoding': 'identity' }, maximum: 8, remainingMs: 1000 });
const lookup = async () => [{ address: '140.82.112.5', family: 4 }];
function fake({ status = 200, headers = [], chunks = [Buffer.from('ok')], address = '140.82.112.5', authorized = true, complete = true } = {}) {
  const calls = [];
  const request = (options, callback) => {
    calls.push(options);
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => queueMicrotask(() => {
      const response = new EventEmitter();
      Object.assign(response, { socket: { authorized, remoteAddress: address }, rawHeaders: headers, statusCode: status, complete, destroy() {} });
      callback(response);
      for (const chunk of chunks) response.emit('data', chunk);
      response.emit('end');
    });
    return req;
  };
  return { calls, request };
}

test('public IPv4 policy denies special ranges and mapped/ambiguous forms', () => {
  for (const ip of ['0.1.2.3', '10.1.2.3', '100.64.1.2', '127.0.0.1', '169.254.1.1', '172.31.1.1', '192.0.0.9', '192.0.2.1', '192.88.99.2', '192.168.1.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '240.0.0.1', '255.255.255.255', '::ffff:140.82.112.5', '0140.82.112.5', '256.1.1.1']) assert.equal(publicIPv4(ip), false, ip);
  assert.equal(publicIPv4('140.82.112.5'), true);
});
test('reject any forbidden DNS answer before request, even after public answer', async () => {
  const { request, calls } = fake();
  await assert.rejects(exchange(input(), async () => [...await lookup(), { address: '127.0.0.1', family: 4 }], request));
  assert.equal(calls.length, 0);
});
test('fixed TLS roots, hostname verification, pinned address, no second DNS or pooling', async () => {
  const { request, calls } = fake();
  assert.equal((await exchange(input(), lookup, request)).body.toString(), 'ok');
  const options = calls[0];
  assert.equal(options.hostname, '140.82.112.5');
  assert.equal(options.servername, 'api.github.com');
  assert.equal(options.headers.Host, 'api.github.com');
  assert.equal(options.headers.Authorization, 'Bearer SECRET');
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.agent, false);
  assert.equal(options.minVersion, 'TLSv1.2');
  assert.equal(options.ca.length, 121);
  assert.ok(options.checkServerIdentity('ignored', { subjectaltname: 'DNS:wrong.example' }));
  options.lookup('api.github.com', {}, error => assert.ok(error));
});
test('manual 302 returned once; signed URL never requested', async () => {
  const { request, calls } = fake({ status: 302, headers: ['Location', 'https://storage.example/private?secret=SIGNED'] });
  const result = await exchange(input(), lookup, request);
  assert.equal(result.status, 302);
  assert.equal(calls.length, 1);
});
test('all download hosts refused before DNS, with or without authorization', async () => {
  for (const headers of [{}, { Authorization: 'Bearer SECRET' }]) {
    let called = false;
    await assert.rejects(exchange({ ...input(), url: 'https://storage.example/private?secret=SIGNED', headers }, async () => { called = true; return lookup(); }));
    assert.equal(called, false);
  }
});
test('reject ambiguous origin and unexpected/auth-smuggling headers', () => {
  for (const url of ['http://api.github.com/', 'https://api.github.com:443/', 'https://api.github.com@evil.example/', 'https://API.GITHUB.COM/', 'https://api.github.com/#x', 'https://api.github.com/#']) assert.throws(() => validateInput({ ...input(), url }));
  for (const headers of [{ Cookie: 'x' }, { authorization: 'x', Authorization: 'y' }, { Authorization: 'x\r\nx: y' }, { 'Accept-Encoding': 'gzip' }]) assert.throws(() => validateInput({ ...input(), headers }));
});
test('headers: duplicates, framing ambiguity, compression and limits rejected', () => {
  for (const raw of [['X', 'a', 'x', 'b'], ['Content-Length', '1', 'Transfer-Encoding', 'chunked'], ['Content-Length', '-1'], ['Content-Encoding', 'gzip'], ['Transfer-Encoding', 'gzip'], ['X', 'a'.repeat(8193)], Array.from({ length: 65 }, (_, i) => [`X-${i}`, 'a']).flat(), Array.from({ length: 5 }, (_, i) => [`X-${i}`, 'a'.repeat(8192)]).flat()]) assert.throws(() => responseHeaders(raw));
});
test('response body, truncation, peer mismatch, unauthenticated TLS refused', async () => {
  for (const config of [{ chunks: [Buffer.alloc(9)] }, { headers: ['Content-Length', '9'] }, { headers: ['Content-Length', '3'] }, { complete: false }, { address: '127.0.0.1' }, { authorized: false }, { headers: ['X', '1', 'x', '2'] }]) await assert.rejects(exchange(input(), lookup, fake(config).request));
});
